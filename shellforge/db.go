package shellforge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// =====================================================================
// CORE TYPES
// =====================================================================

type EnvConfigSlice []EnvConfig

type EnvConfig struct {
	Type    string     `json:"type"` // "container" (only supported type for now)
	Setting EnvSetting `json:"setting"`
}

type EnvSetting struct {
	// Container Configuration
	DockerfilePath string  `json:"dockerfile_path,omitempty"`
	MemoryLimit    string  `json:"memory_limit,omitempty"`
	CPULimit       float64 `json:"cpu_limit,omitempty"`
	GPULimit       string  `json:"gpu_limit,omitempty"`
	SurviveReboot  bool    `json:"survive_reboot"`
	StopAfterExit  bool    `json:"stop_after_exit"`
	KillAfterExit  bool    `json:"kill_after_exit"`
	Shell          string  `json:"shell,omitempty"`
}

// AccessKeyRecord represents one entry in keys.json (the allow-list config).
type AccessKeyRecord struct {
	IsActive         bool           `json:"active"`
	SurviveReboot    bool           `json:"survive_reboot,omitempty"`
	PubKeys          []string       `json:"pubkey"`
	KeyExpiresAfter  time.Duration  `json:"key_expires_afer"` // Nanoseconds in DB
	Environment      EnvConfigSlice `json:"environment"`
	MaxContainers    int            `json:"max_containers,omitempty"`
	ContaintersCount int            `json:"containters_count,omitempty"`
	CreatedAt        time.Time      `json:"created_at,omitempty"`
	ExpiresAfter     time.Duration  `json:"expires_after,omitempty"`
}

// ENVs represents one currently-running/created environment in envs.json.
type ENVs struct {
	ID                string     `json:"id"`
	PubKey            string     `json:"pubkey"`
	EnvType           string     `json:"env_type"` // "container" (only supported type for now)
	Name              string     `json:"name"`
	ImageName         string     `json:"image_name,omitempty"`
	UserRequestedName string     `json:"user_requested_name,omitempty"`
	Setting           EnvSetting `json:"setting"`
	ExpiresAt         time.Time  `json:"expires_at"`
	CreatedAt         time.Time  `json:"created_at"`
	SurviveReboot     bool       `json:"survive_reboot,omitempty"`
}

var (
	ErrDuplicateEnvName = errors.New("an active environment with this name already exists for this key")
)

// =====================================================================
// DB — JSON FILE BACKED STORE
// =====================================================================
//
// Two flat JSON files act as our "tables":
//   <dir>/keys.json  -> []AccessKeyRecord  (allow-listed keys + their limits)
//   <dir>/envs.json  -> []ENVs             (actively created environments)
//
// A single RWMutex guards in-memory state; every mutation is flushed to
// disk atomically (write to temp file, then rename) so a crash mid-write
// can never corrupt the JSON.

type DB struct {
	mu sync.RWMutex

	keysPath string
	envsPath string

	keys []AccessKeyRecord
	envs []ENVs
}

// OpenDB takes a directory path (e.g. "/var/lib/shellforge") and ensures
// keys.json / envs.json exist inside it, loading them into memory.
func OpenDB(path string) (*DB, error) {
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory structure at %s: %w", path, err)
	}

	d := &DB{
		keysPath: filepath.Join(path, "keys.json"),
		envsPath: filepath.Join(path, "envs.json"),
	}

	if err := d.loadKeysLocked(); err != nil {
		return nil, fmt.Errorf("failed to load keys.json: %w", err)
	}
	if err := d.loadEnvsLocked(); err != nil {
		return nil, fmt.Errorf("failed to load envs.json: %w", err)
	}

	return d, nil
}

// =====================================================================
// LOW LEVEL LOAD / SAVE (atomic write via temp file + rename)
// =====================================================================

func (d *DB) loadKeysLocked() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bytes, err := os.ReadFile(d.keysPath)
	if errors.Is(err, os.ErrNotExist) {
		d.keys = []AccessKeyRecord{}
		return d.saveKeysUnlocked()
	}
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(bytes))) == 0 {
		d.keys = []AccessKeyRecord{}
		return nil
	}
	var keys []AccessKeyRecord
	if err := json.Unmarshal(bytes, &keys); err != nil {
		return fmt.Errorf("malformed keys.json: %w", err)
	}
	d.keys = keys
	return nil
}

func (d *DB) loadEnvsLocked() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bytes, err := os.ReadFile(d.envsPath)
	if errors.Is(err, os.ErrNotExist) {
		d.envs = []ENVs{}
		return d.saveEnvsUnlocked()
	}
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(bytes))) == 0 {
		d.envs = []ENVs{}
		return nil
	}
	var envs []ENVs
	if err := json.Unmarshal(bytes, &envs); err != nil {
		return fmt.Errorf("malformed envs.json: %w", err)
	}
	d.envs = envs
	return nil
}

// saveKeysUnlocked / saveEnvsUnlocked assume the caller already holds d.mu.
func (d *DB) saveKeysUnlocked() error {
	return atomicWriteJSON(d.keysPath, d.keys)
}

func (d *DB) saveEnvsUnlocked() error {
	return atomicWriteJSON(d.envsPath, d.envs)
}

func atomicWriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON for %s: %w", path, err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return fmt.Errorf("failed to write temp file %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed to atomically replace %s: %w", path, err)
	}
	return nil
}

// =====================================================================
// ACCESS KEY LOOKUPS
// =====================================================================

// GetRecord retrieves the configuration of a specific allowed public key.
// Matches against the PubKeys slice on each record.
func (d *DB) GetRecord(key string) (*AccessKeyRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := range d.keys {
		for _, pk := range d.keys[i].PubKeys {
			if pk == key {
				rec := d.keys[i] // copy
				return &rec, nil
			}
		}
	}
	return nil, nil
}

func (d *DB) IsEligibleKey(key string) bool {
	rec, err := d.GetRecord(key)
	if err != nil {
		log.Printf("[DB] Failed to check key eligibility: %v", err)
		return false
	}
	return rec != nil && rec.IsActive
}

// HasActiveEnv checks if there is an active environment of a specific type
// (e.g. "container") currently running for the given public key.
func (d *DB) HasActiveEnv(key, envType string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, e := range d.envs {
		if e.PubKey == key && e.EnvType == envType {
			log.Printf("confirmed:the key has active env")
			return true
		}
	}
	log.Printf("found no active env for the key ")
	return false
}

// =====================================================================
// ENV LOOKUPS
// =====================================================================

func (d *DB) GetENVByUserReqestedName(name, pubKey string) (*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := range d.envs {
		e := &d.envs[i]
		if e.UserRequestedName == name && e.PubKey == pubKey {
			cp := *e
			return &cp, nil
		}
	}
	return nil, nil
}

func (d *DB) GetENVByname(name, pubKey string) (*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := range d.envs {
		e := &d.envs[i]
		if e.Name == name && e.PubKey == pubKey {
			cp := *e
			return &cp, nil
		}
	}
	return nil, nil
}

// GetENVs retrieves all environments associated with a specific public key.
func (d *DB) GetENVs(key string) ([]*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var out []*ENVs
	for i := range d.envs {
		if d.envs[i].PubKey == key {
			cp := d.envs[i]
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (d *DB) GetEnvsByType(key string, envType string) ([]*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var out []*ENVs
	for i := range d.envs {
		if d.envs[i].PubKey == key && d.envs[i].EnvType == envType {
			cp := d.envs[i]
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (d *DB) GetEnvByTypeAndName(key, name, envType string) (*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := range d.envs {
		e := &d.envs[i]
		if e.Name == name && e.PubKey == key && e.EnvType == envType {
			cp := *e
			return &cp, nil
		}
	}
	return nil, nil
}

// =====================================================================
// MUTATIONS
// =====================================================================

func (d *DB) AddENV(env *ENVs) error {
	if env.ID == "" {
		env.ID = hex.EncodeToString(randomBytes(16))
	}
	if env.CreatedAt.IsZero() {
		env.CreatedAt = time.Now()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Uniqueness check on UserRequestedName per pubkey, same semantics as before.
	if env.UserRequestedName != "" {
		for _, e := range d.envs {
			if e.UserRequestedName == env.UserRequestedName && e.PubKey == env.PubKey {
				return ErrDuplicateEnvName
			}
		}
	}

	d.envs = append(d.envs, *env)
	if err := d.saveEnvsUnlocked(); err != nil {
		// roll back in-memory append on failed flush
		d.envs = d.envs[:len(d.envs)-1]
		log.Printf("[DB] Failed to persist new env %s (%s): %v", env.Name, env.EnvType, err)
		return fmt.Errorf("failed to insert created_env: %w", err)
	}
	return nil
}

// UpdateKeyField safely updates a single field on an AccessKeyRecord,
// matched by one of its PubKeys, then persists keys.json.
func (d *DB) UpdateKeyField(pubkey, field string, newValue any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	idx := -1
	for i := range d.keys {
		for _, pk := range d.keys[i].PubKeys {
			if pk == pubkey {
				idx = i
				break
			}
		}
		if idx != -1 {
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("no access key record found for pubkey %s", shortKey(pubkey))
	}

	rec := &d.keys[idx]
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "active":
		v, ok := newValue.(bool)
		if !ok {
			return fmt.Errorf("field %q expects bool", field)
		}
		rec.IsActive = v
	case "survive_reboot":
		v, ok := newValue.(bool)
		if !ok {
			return fmt.Errorf("field %q expects bool", field)
		}
		rec.SurviveReboot = v
	case "key_expires_afer", "keyexpiresafter":
		v, ok := newValue.(time.Duration)
		if !ok {
			return fmt.Errorf("field %q expects time.Duration", field)
		}
		rec.KeyExpiresAfter = v
	case "max_containers", "maxcontainers":
		v, ok := newValue.(int)
		if !ok {
			return fmt.Errorf("field %q expects int", field)
		}
		rec.MaxContainers = v
	case "containters_count", "containerscount":
		v, ok := newValue.(int)
		if !ok {
			return fmt.Errorf("field %q expects int", field)
		}
		rec.ContaintersCount = v
	case "expires_after", "expiresafter":
		v, ok := newValue.(time.Duration)
		if !ok {
			return fmt.Errorf("field %q expects time.Duration", field)
		}
		rec.ExpiresAfter = v
	default:
		return fmt.Errorf("unsupported field %q on AccessKeyRecord", field)
	}

	if err := d.saveKeysUnlocked(); err != nil {
		log.Printf("[DB] Failed to update %s for key %s: %v", field, shortKey(pubkey), err)
		return fmt.Errorf("failed to persist update: %w", err)
	}
	return nil
}

// UpdateEnvField safely updates a single field on an ENVs record by ID,
// then persists envs.json.
func (d *DB) UpdateEnvField(id, field string, newValue any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	idx := -1
	for i := range d.envs {
		if d.envs[i].ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("no environment found with id %s", id)
	}

	e := &d.envs[idx]
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "name":
		v, ok := newValue.(string)
		if !ok {
			return fmt.Errorf("field %q expects string", field)
		}
		e.Name = v
	case "image_name", "imagename":
		v, ok := newValue.(string)
		if !ok {
			return fmt.Errorf("field %q expects string", field)
		}
		e.ImageName = v
	case "expires_at", "expiresat":
		v, ok := newValue.(time.Time)
		if !ok {
			return fmt.Errorf("field %q expects time.Time", field)
		}
		e.ExpiresAt = v
	case "survive_reboot", "survivereboot":
		v, ok := newValue.(bool)
		if !ok {
			return fmt.Errorf("field %q expects bool", field)
		}
		e.SurviveReboot = v
	case "stop_after_exit":
		v, ok := newValue.(bool)
		if !ok {
			return fmt.Errorf("field %q expects bool", field)
		}
		e.Setting.StopAfterExit = v
	case "kill_after_exit":
		v, ok := newValue.(bool)
		if !ok {
			return fmt.Errorf("field %q expects bool", field)
		}
		e.Setting.KillAfterExit = v
	default:
		return fmt.Errorf("unsupported field %q on ENVs", field)
	}

	if err := d.saveEnvsUnlocked(); err != nil {
		log.Printf("[DB] Failed to update %s for env %s: %v", field, id, err)
		return fmt.Errorf("failed to persist update: %w", err)
	}
	return nil
}

func (d *DB) deleteEnvByIDLocked(id string) {
	for i := range d.envs {
		if d.envs[i].ID == id {
			d.envs = append(d.envs[:i], d.envs[i+1:]...)
			return
		}
	}
}

func (d *DB) deleteKeyLocked(pubkey string) {
	for i := range d.keys {
		for _, pk := range d.keys[i].PubKeys {
			if pk == pubkey {
				d.keys = append(d.keys[:i], d.keys[i+1:]...)
				return
			}
		}
	}
}

// =====================================================================
// REAPER / SWEEPER
// =====================================================================

// PurgeExpired scans the store, deletes any expired access keys, and
// forcefully tears down any active environments associated with them.
// It also purges individually-expired environments.
func (d *DB) PurgeExpired() {
	now := time.Now()

	// ---- PART 1: purge expired access keys ----
	d.mu.Lock()
	var expiredKeys []string
	for _, rec := range d.keys {
		if rec.KeyExpiresAfter > 0 && rec.CreatedAt.Add(rec.KeyExpiresAfter).Before(now) {
			expiredKeys = append(expiredKeys, rec.PubKeys...)
		}
	}
	d.mu.Unlock()

	for _, pubkey := range expiredKeys {
		log.Printf("[DB] Reaper: Actively removing expired public key: %s...", shortKey(pubkey))
		d.purgeEnvironmentsByPubKey(pubkey)

		d.mu.Lock()
		d.deleteKeyLocked(pubkey)
		if err := d.saveKeysUnlocked(); err != nil {
			log.Printf("[DB] Reaper: failed to persist key deletion: %v", err)
		}
		d.mu.Unlock()
	}

	// ---- PART 2: purge individually-expired environments ----
	d.mu.RLock()
	type expiredEnv struct{ id, name, envType string }
	var expiredEnvs []expiredEnv
	for _, e := range d.envs {
		if e.ExpiresAt.Before(now) {
			expiredEnvs = append(expiredEnvs, expiredEnv{e.ID, e.Name, e.EnvType})
		}
	}
	d.mu.RUnlock()

	for _, e := range expiredEnvs {
		log.Printf("[DB] Reaper: Environment %s expired! Forcefully destroying.", e.name)
		d.destroyEnvironment(e.name, e.envType)

		d.mu.Lock()
		d.deleteEnvByIDLocked(e.id)
		if err := d.saveEnvsUnlocked(); err != nil {
			log.Printf("[DB] Reaper: failed to persist env deletion: %v", err)
		}
		d.mu.Unlock()
	}
}

// RunStartupSweeper purges any orphaned environments left behind by an
// abrupt crash or reboot, unless they were configured with SurviveReboot.
func (d *DB) RunStartupSweeper() {
	d.mu.RLock()
	type orphanedEnv struct {
		id, name, envType string
		survive           bool
	}
	orphaned := make([]orphanedEnv, 0, len(d.envs))
	for _, e := range d.envs {
		orphaned = append(orphaned, orphanedEnv{e.ID, e.Name, e.EnvType, e.SurviveReboot})
	}
	d.mu.RUnlock()

	purgedCount := 0
	for _, e := range orphaned {
		if e.survive {
			continue // Let environments configured with 'survive_reboot = true' live!
		}
		d.destroyEnvironment(e.name, e.envType)

		d.mu.Lock()
		d.deleteEnvByIDLocked(e.id)
		if err := d.saveEnvsUnlocked(); err != nil {
			log.Printf("[DB] Sweeper: failed to persist env deletion: %v", err)
		}
		d.mu.Unlock()

		log.Printf("[DB] Sweeper: Forcefully removing orphaned environment: %s", e.name)
		purgedCount++
	}
	log.Printf("[DB] Sweeper finished. Successfully purged %d orphaned environments.", purgedCount)
}

// destroyEnvironment performs the actual physical OS-level / container
// teardown. Only "container" is supported for now.
func (d *DB) destroyEnvironment(name, envType string) {
	switch envType {
	case "container":
		KillAndRemoveContainer(context.Background(), name)
	default:
		log.Printf("[DB] destroyEnvironment: unsupported env type %q for %s (only \"container\" is currently supported)", envType, name)
	}
}

func (d *DB) purgeEnvironmentsByPubKey(pubkey string) {
	d.mu.RLock()
	type target struct{ id, name, envType string }
	var targets []target
	for _, e := range d.envs {
		if e.PubKey == pubkey {
			targets = append(targets, target{e.ID, e.Name, e.EnvType})
		}
	}
	d.mu.RUnlock()

	for _, t := range targets {
		d.destroyEnvironment(t.name, t.envType)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	filtered := d.envs[:0]
	for _, e := range d.envs {
		if e.PubKey != pubkey {
			filtered = append(filtered, e)
		}
	}
	d.envs = filtered
	if err := d.saveEnvsUnlocked(); err != nil {
		log.Printf("[DB] Failed to persist env purge for pubkey %s: %v", shortKey(pubkey), err)
	}
}

// =====================================================================
// CONFIG LOADER (keys.json source-of-truth import)
// =====================================================================

// parseDurationWithDays supports a trailing 'd' suffix (e.g. "30d") in
// addition to standard Go duration strings, plus "0"/"always"/"onetime".
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

// LoadAccessKeysConf reads the source JSON config file (the format you
// hand-author / ship), parses durations, and upserts each entry into the
// in-memory + on-disk keys.json store, keyed by matching PubKeys slices.
func (d *DB) LoadAccessKeysConf(filePath string) (map[string]AccessKeyRecord, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var rawList []struct {
		IsActive        bool           `json:"active"`
		SurviveReboot   bool           `json:"survive_reboot"`
		PubKeys         []string       `json:"pubkey"`
		KeyExpiresAfter string         `json:"key_expires_afer"`
		MaxContainers   int            `json:"max_containers"`
		Environment     EnvConfigSlice `json:"environment"`
		CreatedAt       string         `json:"created_at"`
		ExpiresAfter    string         `json:"expires_after"`
	}
	if err := json.Unmarshal(fileBytes, &rawList); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	records := make(map[string]AccessKeyRecord, len(rawList))

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, item := range rawList {
		keyExpire, err := parseDurationWithDays(item.KeyExpiresAfter)
		if err != nil {
			id := "unknown"
			if len(item.PubKeys) > 0 {
				id = shortKey(item.PubKeys[0])
			}
			return nil, fmt.Errorf("key %s has invalid key_expires_after: %w", id, err)
		}

		// Validate only the "container" type is used, per current scope.
		for _, env := range item.Environment {
			if env.Type != "container" {
				return nil, fmt.Errorf("unsupported environment type %q (only \"container\" is currently supported)", env.Type)
			}
		}

		createdAt := time.Now()
		if item.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, item.CreatedAt); err == nil {
				createdAt = t
			}
		}
		var expiresAfter time.Duration
		if item.ExpiresAfter != "" {
			if v, err := parseDurationWithDays(item.ExpiresAfter); err == nil {
				expiresAfter = v
			}
		}

		record := AccessKeyRecord{
			IsActive:        item.IsActive,
			SurviveReboot:   item.SurviveReboot,
			PubKeys:         item.PubKeys,
			KeyExpiresAfter: keyExpire,
			Environment:     item.Environment,
			MaxContainers:   item.MaxContainers,
			CreatedAt:       createdAt,
			ExpiresAfter:    expiresAfter,
		}

		// Upsert: match an existing record sharing ANY pubkey, else append.
		matchedIdx := -1
		for i := range d.keys {
			if sliceShareElement(d.keys[i].PubKeys, item.PubKeys) {
				matchedIdx = i
				break
			}
		}
		if matchedIdx != -1 {
			// Preserve original CreatedAt / counters, refresh the rest.
			existing := d.keys[matchedIdx]
			record.CreatedAt = existing.CreatedAt
			record.ContaintersCount = existing.ContaintersCount
			d.keys[matchedIdx] = record
		} else {
			d.keys = append(d.keys, record)
		}

		for _, pk := range item.PubKeys {
			records[pk] = record
		}
	}

	if err := d.saveKeysUnlocked(); err != nil {
		return nil, fmt.Errorf("failed to persist keys.json: %w", err)
	}

	log.Printf("ENV confs loaded into memoey from %s\n", filePath)

	return records, nil
}

func sliceShareElement(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}
