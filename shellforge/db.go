package shellforge

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type AccessKeyRecord struct {
	PubKey           string         `json:"pubkey"`
	KeyExpiresAfter  time.Duration  `json:"key_expires_afer"` // Nanoseconds in DB
	Environment      EnvConfigSlice `json:"environment"`      // Auto-serialized JSON
	MaxSessions      int            `json:"max_sessions,omitempty"`
	MaxContainers    int            `json:"max_containers,omitempty"`
	MaxUsers         int            `json:"max_users,omitempty"`
	MaxNamespaces    int            `json:"max_namespaces,omitempty"`
	LoginsUsed       int
	SysUsersCount    int
	ContaintersCount int
	NamespacesCount  int
	CreatedAt        time.Time
}

type EnvConfigSlice []EnvConfig

type EnvConfig struct {
	Type       string     `json:"type"` // "container", "systemUser", or "HostSharedNamespace"
	Setting    EnvSetting `json:"setting"`
	MaxLogins  int        `json:"max_logins,omitempty"`
	LifeSpan   string     `json:"life_span"` // Raw string (e.g., "2h", "0")
	Timeout    string     `json:"timeout,omitempty"`
	OneTimeUse bool       `json:"one_time_use,omitempty"`
}

type EnvSetting struct {
	// Container Configuration
	DockerfilePath string  `json:"dockerfile_path,omitempty"`
	MemoryLimit    string  `json:"memory_limit,omitempty"`
	CPULimit       float64 `json:"cpu_limit,omitempty"`
	GPULimit       string  `json:"gpu_limit,omitempty"`

	// System User Configuration
	Shell     string `json:"shell,omitempty"`
	HomeDir   string `json:"HomeDir,omitempty"`
	GroupName string `json:"groupname,omitempty"`

	// Host Shared Namespace Configuration
	Mount []string `json:"mount,omitempty"`

	SurviveReboot bool `json:"survive_reboot,omitempty"`
}

type ENVs struct {
	ID                string
	PubKey            string `json:"pubkey"`
	EnvType           string `json:"env_type"` // "container", "systemUser", "HostSharedNamespace"
	Name              string `json:"name"`     // container name, system username, jail directory name
	ImageName         string // if EnvType = container
	UserRequestedName string
	Setting           EnvSetting `json:"setting"` // State of the configured environment
	ExpiresAt         time.Time
	CreatedAt         time.Time
	SurviveReboot     bool `json:"survive_reboot,omitempty"`
}

// =====================================================================
// ENTERPRISE JSON SERIALIZATION HELPERS
// =====================================================================

type DB struct {
	db *sql.DB
}

func OpenDB(path string) (*DB, error) {
	dir := filepath.Dir(path)

	// os.MkdirAll is safe: it recursively creates all missing folders with 0755 permissions.
	// If the folders already exist, it instantly does nothing and returns nil.
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory structure at %s: %w", dir, err)
	}

	// "sqlite3" is the standard driver name (requires github.com/mattn/go-sqlite3
	// or the pure-Go modernc.org/sqlite driver)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// =====================================================================
	// CRITICAL SQLITE CONCURRENCY OPTIMIZATION
	// =====================================================================
	// SQLite is an in-process database and only supports exactly ONE writer
	// at a time. Go's database/sql package naturally spawns multiple connection
	// threads. If two Go threads try to write to SQLite simultaneously,
	// you will get a fatal "database is locked" error.
	//
	// We restrict the connection pool to exactly 1 open connection to completely
	// eliminate write deadlocks and transaction conflicts.
	// =====================================================================
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	d := &DB{db: db}

	// Automatically run database table creations and migrations on boot [1]
	if err := d.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return d, nil
}

func (d *DB) initSchema() error {
	// Table 1: Configuration table for allowed public keys
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS allowed_keys (
			pubkey TEXT PRIMARY KEY,
			key_expires_after INTEGER DEFAULT 0, -- Stored as nanoseconds [2]
			environment TEXT DEFAULT '[]',       -- JSON string of EnvConfigSlice [1]
			max_sessions INTEGER DEFAULT 0,
			max_containers INTEGER DEFAULT 0,        
			max_users      INTEGER DEFAULT 0,        
			max_namespaces INTEGER DEFAULT 0,        
			logins_used INTEGER DEFAULT 0,
			system_user_count INTEGER DEFAULT 0,
			containters_count INTEGER DEFAULT 0,
			namespaces_Count INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			
		);
	`)
	if err != nil {
		return err
	}

	// Table 2: Tracks all actively spawned containers, system users, and namespaces [3]
	_, err = d.db.Exec(`
		CREATE TABLE IF NOT EXISTS created_envs (
			id TEXT PRIMARY KEY,
			pubkey TEXT,
			env_type TEXT,                       -- "container", "systemUser", "HostSharedNamespace"
			name TEXT,              -- username, container name, or jail dir
			image_name TEXT DEFAULT '',
			user_requested_name TEXT,
			setting TEXT DEFAULT '{}',           -- JSON representation of EnvSetting [1]
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			survive_reboot INTEGER DEFAULT 1 -- 0 for false, 1 for true
		);
	`)
	return err
}

// HasColumn helper for schema migrations
func (d *DB) HasColumn(tableName, columnName string) (bool, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	rows, err := d.db.Query(query)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue any

		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err == nil {
			if name == columnName {
				return true, nil
			}
		}
	}
	return false, nil
}

// GetRecord retrieves the configuration of a specific allowed public key
func (d *DB) GetRecord(key string) (*AccessKeyRecord, error) {
	query := `
		SELECT pubkey,
		key_expires_after,
		environment,
		max_sessions,
		max_containers,	
		max_users,
		max_namespaces,
		logins_used,
		system_user_count,
		containters_count,
		namespaces_Count ,
		created_at
		FROM allowed_keys 
		WHERE pubkey = ?`

	record := &AccessKeyRecord{}
	err := d.db.QueryRow(query, key).Scan(
		&record.PubKey,
		&record.KeyExpiresAfter, // Scans directly into time.Duration! [2]
		&record.Environment,     // Scans JSON string directly into EnvConfigSlice! [1]
		&record.MaxSessions,
		&record.MaxContainers,
		&record.MaxUsers,
		&record.MaxNamespaces,
		&record.LoginsUsed,
		&record.SysUsersCount,
		&record.ContaintersCount,
		&record.NamespacesCount,
		&record.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return record, nil
}

func (d *DB) IsEligibleKey(key string) bool {
	query := `SELECT EXISTS(SELECT 1 FROM allowed_keys WHERE pubkey = ? LIMIT 1)`

	var exists bool
	err := d.db.QueryRow(query, key).Scan(&exists)
	if err != nil {
		log.Printf("[DB] Failed to check key eligibility: %v", err)
		return false
	}

	return exists
}

// HasActiveEnv checks if there is an active environment of a specific type
// (e.g., "container" or "system-user") currently running for the given public key.
func (d *DB) HasActiveEnv(key, envType string) bool {
	// We use an optimized multi-column EXISTS check [1].
	// This instantly stops scanning the table the moment the first match is found.
	query := `
		SELECT EXISTS(
			SELECT 1 FROM created_envs 
			WHERE pubkey = ? AND env_type = ? 
			LIMIT 1
		)`

	var exists bool
	// Both parameters are safely bound to prevent SQL Injection [1, 2]
	err := d.db.QueryRow(query, key, envType).Scan(&exists)
	if err != nil {
		log.Printf("[DB] Failed to check active env (%s) for key %s...: %v", envType, key[:8], err)
		return false
	}

	return exists
}

func (d *DB) GetENVByUserReqestedName(name, pubKey string) (*ENVs, error) {
	// 1. Prepare the query matching your schema exactly [8]
	query := `
		SELECT id, pubkey, env_type, name, image_name, user_requested_name, setting, expires_at, created_at, survive_reboot
		FROM created_envs 
		WHERE user_requested_name = ? AND pubkey = ?`

	env := &ENVs{}
	var surviveRebootInt int

	// 2. Execute and Scan into the struct
	// Both parameters are bound to prevent SQL Injection [1, 2]
	err := d.db.QueryRow(query, name, pubKey).Scan(
		&env.ID,
		&env.PubKey,
		&env.EnvType,
		&env.Name,
		&env.ImageName,
		&env.UserRequestedName,
		&env.Setting, // Automatically unmarshals the JSON using EnvSetting.Scan()! [1]
		&env.ExpiresAt,
		&env.CreatedAt,
		&surviveRebootInt, // Read as integer from SQLite
	)

	// 3. Handle errors
	if err != nil {
		// Return nil, nil if the record doesn't exist (this is an expected logic event, not a system failure)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		log.Printf("failed to query environment by requested name: %v", err)
		return nil, ErrFailedToQueryByReqNmae
	}

	// 4. Map the integer state back to Go boolean
	env.SurviveReboot = surviveRebootInt == 1

	return env, nil
}

func (d *DB) GetENVByname(name, pubKey string) (*ENVs, error) {
	// 1. Prepare the query matching your schema exactly [8]
	query := `
		SELECT id, pubkey, env_type, name, image_name, user_requested_name, setting, expires_at, created_at, survive_reboot
		FROM created_envs 
		WHERE name = ? AND pubkey = ?`

	env := &ENVs{}
	var surviveRebootInt int

	// 2. Execute and Scan into the struct
	// Both parameters are bound to prevent SQL Injection [1, 2]
	err := d.db.QueryRow(query, name, pubKey).Scan(
		&env.ID,
		&env.PubKey,
		&env.EnvType,
		&env.Name,
		&env.ImageName,
		&env.UserRequestedName,
		&env.Setting, // Automatically unmarshals the JSON using EnvSetting.Scan()! [1]
		&env.ExpiresAt,
		&env.CreatedAt,
		&surviveRebootInt, // Read as integer from SQLite
	)

	// 3. Handle errors
	if err != nil {
		// Return nil, nil if the record doesn't exist (this is an expected logic event, not a system failure)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		log.Printf("failed to query environment by requested name: %v", err)
		return nil, ErrFailedToQueryByReqNmae
	}

	// 4. Map the integer state back to Go boolean
	env.SurviveReboot = surviveRebootInt == 1

	return env, nil
}

// GetENVs retrieves all active environments associated with a specific public key.
// It returns a slice of environment records, or an error if the query fails.
func (d *DB) GetENVs(key string) ([]*ENVs, error) {
	// 1. Prepare the query to grab all columns [8]
	query := `
		SELECT id, pubkey, env_type, name, image_name, user_requested_name, setting, expires_at, created_at ,survive_reboot
		FROM created_envs 
		WHERE pubkey = ?`

	// 2. Execute the query
	rows, err := d.db.Query(query, key)
	if err != nil {
		return nil, fmt.Errorf("failed to query created_envs: %w", err)
	}
	// CRITICAL: Always defer rows.Close() immediately to prevent database connection leaks!
	defer rows.Close()

	var envs []*ENVs

	// 3. Iterate through the database rows
	for rows.Next() {
		env := &ENVs{}

		// Go's sql package automatically calls EnvSetting.Scan() behind the scenes,
		// converting the database's JSON string back into your structured struct! [1, 8]
		err := rows.Scan(
			&env.ID,
			&env.PubKey,
			&env.EnvType,
			&env.Name,
			&env.ImageName,
			&env.UserRequestedName,
			&env.Setting, // Automatically unmarshaled [1]
			&env.ExpiresAt,
			&env.CreatedAt,
			&env.SurviveReboot,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan environment row: %w", err)
		}

		envs = append(envs, env)
	}

	// 4. Check for any errors that occurred during the row iteration [8]
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error occurred during row iteration: %w", err)
	}

	return envs, nil
}

func (d *DB) GetEnvsByType(key string, envType string) ([]*ENVs, error) {
	// 1. Prepare the query to grab all columns [8]
	query := `
		SELECT id, pubkey, env_type, name, image_name, user_requested_name, setting, expires_at, created_at ,survive_reboot
		FROM created_envs 
		WHERE pubkey = ? AND env_type = ?`

	// 2. Execute the query
	rows, err := d.db.Query(query, key, envType)
	if err != nil {
		return nil, fmt.Errorf("failed to query created_envs: %w", err)
	}
	// CRITICAL: Always defer rows.Close() immediately to prevent database connection leaks!
	defer rows.Close()

	var envs []*ENVs

	// 3. Iterate through the database rows
	for rows.Next() {
		env := &ENVs{}

		// Go's sql package automatically calls EnvSetting.Scan() behind the scenes,
		// converting the database's JSON string back into your structured struct! [1, 8]
		err := rows.Scan(
			&env.ID,
			&env.PubKey,
			&env.EnvType,
			&env.Name,
			&env.ImageName,
			&env.UserRequestedName,
			&env.Setting, // Automatically unmarshaled [1]
			&env.ExpiresAt,
			&env.CreatedAt,
			&env.SurviveReboot,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan environment row: %w", err)
		}

		envs = append(envs, env)
	}

	// 4. Check for any errors that occurred during the row iteration [8]
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error occurred during row iteration: %w", err)
	}

	return envs, nil
}

func (d *DB) GetEnvByTypeAndName(key, name, envType string) (*ENVs, error) {
	// 1. Prepare the query matching your schema exactly [8]
	query := `
		SELECT id, pubkey, env_type, name, image_name, user_requested_name, setting, expires_at, created_at, survive_reboot
		FROM created_envs 
		WHERE name = ? AND pubkey = ? AND env_type =?`

	env := &ENVs{}
	var surviveRebootInt int

	// 2. Execute and Scan into the struct
	// Both parameters are bound to prevent SQL Injection [1, 2]
	err := d.db.QueryRow(query, name, key, envType).Scan(
		&env.ID,
		&env.PubKey,
		&env.EnvType,
		&env.Name,
		&env.ImageName,
		&env.UserRequestedName,
		&env.Setting, // Automatically unmarshals the JSON using EnvSetting.Scan()! [1]
		&env.ExpiresAt,
		&env.CreatedAt,
		&surviveRebootInt, // Read as integer from SQLite
	)

	// 3. Handle errors
	if err != nil {
		// Return nil, nil if the record doesn't exist (this is an expected logic event, not a system failure)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		log.Printf("failed to query environment by requested name: %v", err)
		return nil, ErrFailedToQueryByReqNmae
	}

	// 4. Map the integer state back to Go boolean
	env.SurviveReboot = surviveRebootInt == 1

	return env, nil
}

var ErrDuplicateEnvName = errors.New("an active environment with this name already exists for this key")

func (d *DB) AddENV(env *ENVs) error {
	// 1. Generate a unique ID if none was provided by the caller
	if env.ID == "" {
		env.ID = hex.EncodeToString(randomBytes(16)) // Generates a unique 32-character hex string
	}
	if env.CreatedAt.IsZero() {
		env.CreatedAt = time.Now()
	}

	// 2. SECURITY CHECK: Ensure the requested name is unique for this specific user [1]
	// We only run this check if the user actually requested a custom name alias
	if env.UserRequestedName != "" {
		existing, err := d.GetENVByUserReqestedName(env.UserRequestedName, env.PubKey)
		if err != nil {
			return fmt.Errorf("failed to verify name uniqueness: %w", err)
		}
		if existing != nil {
			// A duplicate active environment name already exists! Reject. [1]
			return ErrDuplicateEnvName
		}
	}

	// FIXED: Added the 10th placeholder "?" to match the 10 columns exactly!
	query := `
		INSERT INTO created_envs (id, pubkey, env_type, name, image_name, user_requested_name, setting, expires_at, created_at, survive_reboot)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Convert Go bool to standard SQL 0/1 integer
	surviveRebootInt := 0
	if env.SurviveReboot {
		surviveRebootInt = 1
	}

	// 3. Execute insertion
	_, err := d.db.Exec(
		query,
		env.ID,
		env.PubKey,
		env.EnvType,
		env.Name,
		env.ImageName,
		env.UserRequestedName,
		env.Setting, // Automatically serialized to JSON [1]
		env.ExpiresAt,
		env.CreatedAt,
		surviveRebootInt,
	)
	if err != nil {
		log.Printf("[DB] Failed to insert created_env %s (%s): %v", env.Name, env.EnvType, err)
		return fmt.Errorf("failed to insert created_env: %w", err)
	}

	return nil
}

func (e EnvConfigSlice) Value() (driver.Value, error) {
	if e == nil {
		return "[]", nil
	}
	b, err := json.Marshal(e)
	return string(b), err
}

func (e *EnvConfigSlice) Scan(value any) error {
	if value == nil {
		*e = EnvConfigSlice{}
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return errors.New("unsupported scan type for EnvConfigSlice")
	}
	return json.Unmarshal(bytes, e)
}

func (es EnvSetting) Value() (driver.Value, error) {
	b, err := json.Marshal(es)
	return string(b), err
}

func (es *EnvSetting) Scan(value any) error {
	if value == nil {
		*es = EnvSetting{}
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return errors.New("unsupported scan type for EnvSetting")
	}
	return json.Unmarshal(bytes, es)
}

// Strict whitelist for table and column names to prevent SQL Injection [1, 2]
var safeIdentifiers = map[string]bool{
	"allowed_keys":      true,
	"created_envs":      true,
	"shell":             true,
	"groupname":         true,
	"logins_used":       true,
	"expires_at":        true,
	"env_type":          true,
	"name":              true,
	"image_name":        true,
	"sys_users_active":  true,
	"containers_active": true,
	"SysUsersCount":     true,
	"ContaintersCount":  true,
	"NamespacesCount":   true,
}

// UpdateField safely updates a single column on a table using strict parameterization [1, 2]
func (d *DB) UpdateField(table, publickey, column string, newValue any) error {
	table = strings.ToLower(strings.TrimSpace(table))
	column = strings.ToLower(strings.TrimSpace(column))

	if !safeIdentifiers[table] || !safeIdentifiers[column] {
		return fmt.Errorf("unsafe table (%s) or column (%s) name provided", table, column)
	}

	query := fmt.Sprintf("UPDATE %s SET %s = ? WHERE pubkey = ?", table, column)

	_, err := d.db.Exec(query, newValue, publickey)
	if err != nil {
		log.Printf("[DB] Failed to update %s.%s for key %s: %v", table, column, publickey[:8], err)
		return fmt.Errorf("failed to execute update: %w", err)
	}

	return nil
}

// PurgeExpiredKeys actively scans the database, deletes any expired public keys,
// and forcefully wipes any active system users associated with those keys [3, 4].
func (d *DB) PurgeExpired() {
	now := time.Now()

	// 1. Purge expired keys from the database [1]
	// If created_at + key_expires_after is in the past, the key is expired [1, 2]
	rows, err := d.db.Query("SELECT pubkey, key_expires_after, created_at FROM allowed_keys WHERE key_expires_after > 0")
	if err != nil {
		log.Printf("[DB] Reaper: Failed to query keys for purging: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var pubkey string
		var expiresAfter time.Duration
		var createdAt time.Time

		if err := rows.Scan(&pubkey, &expiresAfter, &createdAt); err == nil {
			if createdAt.Add(expiresAfter).Before(now) {
				log.Printf("[DB] Reaper: Actively removing expired public key: %s...", pubkey[:8])

				// Clean up any dynamic active environments linked to this key [3]
				d.purgeEnvironmentsByPubKey(pubkey)

				_, _ = d.db.Exec("DELETE FROM allowed_keys WHERE pubkey = ?", pubkey)
			}
		}
	}

	// 2. Purge expired individual environments (Containers, SystemUsers, Jails) [3]
	envRows, err := d.db.Query("SELECT id, name, env_type FROM created_envs WHERE expires_at < ?", now)
	if err != nil {
		log.Printf("[DB] Reaper: Failed to query expired environments: %v", err)
		return
	}
	defer envRows.Close()

	for envRows.Next() {

		var id, name, envType string
		if err := envRows.Scan(&id, &name, &envType); err == nil {

			log.Printf("[DB] Reaper: Environment %s expired! Forcefully destroying.", name)
			d.destroyEnvironment(name, envType)
			_, _ = d.db.Exec("DELETE FROM created_envs WHERE id = ?", id)
		}
	}
}

// RunStartupSweeper scans created_envs and purges any orphaned system accounts
// left behind by an abrupt server crash or reboot [3, 4].
func (d *DB) RunStartupSweeper() {
	rows, err := d.db.Query("SELECT id,name, env_type,survive_reboot FROM created_envs")
	if err != nil {
		log.Printf("[DB] Failed to query created_envs for sweeping: %v", err)
		return
	}
	defer rows.Close()

	purgedCount := 0
	for rows.Next() {
		var id, name, envType string
		var survive bool
		if err := rows.Scan(&id, &name, &envType, &survive); err == nil {
			if survive {
				continue
			}
			d.destroyEnvironment(name, envType)
			_, _ = d.db.Exec("DELETE FROM created_envs WHERE id = ?", id)
			log.Printf("[DB] Sweeper: Forcefully removing orphaned system user: %s", name)
			purgedCount++
		}
	}

	log.Printf("[DB] Sweeper finished. Successfully purged %d orphaned environments.", purgedCount)

}

// destroyEnvironment performs the actual physical OS-level unmounting, deletion, and containment shutdown [4]
func (d *DB) destroyEnvironment(name, envType string) {
	switch envType {
	case "system-user":
		// Forcefully kill user's processes and delete their home directory [4]
		DeleteSystemUser(name)
	case "container":
		// Forcefully kill and remove the running container [4]
		KillAndRemoveContainer(context.Background(), name)

	case "HostSharedNamespace":
		// Forcefully detach the on-demand bind mounts and delete directory [4]
		DestroyOnDemandJail(name)
	}
}

func (d *DB) purgeEnvironmentsByPubKey(pubkey string) {
	rows, err := d.db.Query("SELECT name, env_type FROM created_envs WHERE pubkey = ?", pubkey)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, envType string
		if err := rows.Scan(&name, &envType); err == nil {
			d.destroyEnvironment(name, envType)
		}
	}
	_, _ = d.db.Exec("DELETE FROM created_envs WHERE pubkey = ?", pubkey)
}

// Helper to support 'd' (days) in JSON strings [1.3.1]
func parseDurationWithDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" || s == "always" || s == "onetime" {
		return 0, nil
	}

	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days format: %w", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}

// LoadAccessKeysConf reads the JSON file, parses durations, and saves to SQLite [1, 2].
func (d *DB) LoadAccessKeysConf(filepath string) (map[string]AccessKeyRecord, error) {
	fileBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var rawList []struct {
		PubKey          string      `json:"pubkey"`
		KeyExpiresAfter string      `json:"key_expires_afer"`
		Environment     []EnvConfig `json:"environment"`
		MaxSessions     int         `json:"max_sessions"`
		MaxContainers   int         `json:"max_containers,omitempty"`
		MaxUsers        int         `json:"max_users,omitempty"`
		MaxNamespaces   int         `json:"max_namespaces,omitempty"`
	}

	if err := json.Unmarshal(fileBytes, &rawList); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	records := make(map[string]AccessKeyRecord)

	// Start database transaction [2]
	tx, err := d.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO allowed_keys (pubkey, key_expires_after, environment, max_sessions, max_containers, max_users, max_namespaces, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(pubkey) DO UPDATE SET
			environment = excluded.environment;
	`
	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	for _, item := range rawList {
		expireDuration, err := parseDurationWithDays(item.KeyExpiresAfter)
		if err != nil {
			return nil, fmt.Errorf("key %s has invalid key_expires_after: %w", item.PubKey[:8], err)
		}

		record := AccessKeyRecord{
			PubKey:          item.PubKey,
			KeyExpiresAfter: expireDuration,
			Environment:     item.Environment,
			MaxSessions:     item.MaxSessions,
			MaxContainers:   item.MaxContainers,
			MaxUsers:        item.MaxUsers,
			MaxNamespaces:   item.MaxNamespaces,
		}

		// Perform safe SQL upsert [1, 2]
		_, err = stmt.Exec(
			record.PubKey,
			record.KeyExpiresAfter,
			record.Environment,
			record.MaxSessions,
			record.MaxContainers,
			record.MaxUsers,
			record.MaxNamespaces,
			time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to sync key %s: %w", record.PubKey[:8], err)
		}

		records[record.PubKey] = record
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// If an existing configuration is being updated in SQLite,
	// proactively delete the compiled image to force a rebuild on the next login [4].
	//imageName := fmt.Sprintf("wf_custom_%s", record.PubKey[:8])
	//_ = exec.Command("podman", "rmi", "-f", imageName).Run()

	return records, nil
}
