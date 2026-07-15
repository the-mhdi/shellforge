package shellforge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

// AccessKeysPath is the only place access keys are read from. Operators
// edit this file by hand; it cannot be overridden at runtime.
const AccessKeysPath = "/etc/shellforge/access_keys.toml"

// =====================================================================
// CORE TYPES
// =====================================================================

type EnvConfig struct {
	Type    string     `toml:"type"` // "container" (only supported type for now)
	Setting EnvSetting `toml:"setting"`
}

type EnvSetting struct {
	// Container Configuration
	DockerfilePath string  `toml:"dockerfile_path,omitempty"`
	MemoryLimit    string  `toml:"memory_limit,omitempty"`
	CPULimit       float64 `toml:"cpu_limit,omitempty"`
	GPULimit       string  `toml:"gpu_limit,omitempty"`
	SurviveReboot  bool    `toml:"survive_reboot"`
	StopAfterExit  bool    `toml:"stop_after_exit"`
	KillAfterExit  bool    `toml:"kill_after_exit"`
	Shell          string  `toml:"shell,omitempty"`
}

// AccessKeyRecord represents one [[key]] entry in access_keys.toml (the
// operator-edited allow list). Only containers are supported, so all
// container settings live flat on the key itself.
type AccessKeyRecord struct {
	IsActive         bool   `toml:"active"`
	PubKey           string `toml:"pubkey"`
	KeyExpiresAt     string `toml:"key_expires_at"` // "2006-01-02" (year-month-day); "", "0" or "never" = no expiry
	KeyMaxContainers int    `toml:"key_max_containers"`

	DockerfilePath string `toml:"dockerfile_path"`

	ContainersExpireAfter     string  `toml:"containers_expire_after"`
	ContainersSurviveReboot   bool    `toml:"containers_survive_reboot"`
	ContainersKilledAfterExit bool    `toml:"containers_killed_after_exit"`
	ContainersStopAfterExit   bool    `toml:"containers_stop_after_exit"`
	ContainersMemoryLimit     string  `toml:"containers_memory_limit"`
	ContainersCPULimit        float64 `toml:"containers_cpu_limit"`
	ContainersGPULimit        string  `toml:"containers_gpu_limit"`
}

// IsExpired reports whether the key is past its key_expires_at date
// ("2006-01-02", i.e. year-month-day). Empty, "0", or "never" mean the
// key never expires. The key expires at 00:00 local time on that date.
// An unparseable date is treated as expired (and logged) so a typo can
// never silently grant permanent access.
func (r *AccessKeyRecord) IsExpired(now time.Time) bool {
	s := strings.TrimSpace(strings.ToLower(r.KeyExpiresAt))
	if s == "" || s == "0" || s == "never" {
		return false
	}
	t, err := time.ParseInLocation("2006-01-02", s, time.Local)
	if err != nil {
		log.Printf("[DB] key %s has invalid key_expires_at %q (want year-month-day): %v",
			shortKey(r.PubKey), r.KeyExpiresAt, err)
		return true
	}
	return !now.Before(t)
}

// ContainerSetting maps the flat container fields onto the EnvSetting
// shape stored per-environment in envs.toml (which stays unchanged).
func (r *AccessKeyRecord) ContainerSetting() EnvSetting {
	return EnvSetting{
		DockerfilePath: r.DockerfilePath,
		MemoryLimit:    r.ContainersMemoryLimit,
		CPULimit:       r.ContainersCPULimit,
		GPULimit:       r.ContainersGPULimit,
		SurviveReboot:  r.ContainersSurviveReboot,
		StopAfterExit:  r.ContainersStopAfterExit,
		KillAfterExit:  r.ContainersKilledAfterExit,
	}
}

// ENVs represents one currently-running/created environment in envs.toml.
type ENVs struct {
	ID                string     `toml:"id"`
	PubKey            string     `toml:"pubkey"`
	EnvType           string     `toml:"env_type"` // "container" (only supported type for now)
	Name              string     `toml:"name"`
	ImageName         string     `toml:"image_name,omitempty"`
	UserRequestedName string     `toml:"user_requested_name,omitempty"`
	Setting           EnvSetting `toml:"setting"`
	ExpiresAt         time.Time  `toml:"expires_at"`
	CreatedAt         time.Time  `toml:"created_at"`
	SurviveReboot     bool       `toml:"survive_reboot,omitempty"`
}

var (
	ErrDuplicateEnvName = errors.New("an active environment with this name already exists for this key")
)

// =====================================================================
// DB — TOML FILE BACKED STORE
// =====================================================================
//
// Two flat TOML files act as our "tables":
//   /etc/shellforge/access_keys.toml -> [[key]]   (operator-edited allow list)
//   <dir>/envs.toml                  -> [[envs]]  (actively created environments)
//
// TOML cannot represent a top-level array, so each file wraps its rows
// in a named array-of-tables ([[key]] / [[envs]]).
//
// A single RWMutex guards in-memory state; every mutation is flushed to
// disk atomically (write to temp file, then rename) so a crash mid-write
// can never corrupt the TOML.

// accessKeysFile / envsFile are the on-disk document shapes.
type accessKeysFile struct {
	Keys []AccessKeyRecord `toml:"key"`
}

type envsFile struct {
	Envs []ENVs `toml:"envs"`
}

// accessKeysTemplate seeds access_keys.toml on first start so operators
// know the expected format.
const accessKeysTemplate = `# ShellForge access keys.
# One [[key]] block per allow-listed public key. Only containers are
# supported. The daemon flips "active" to false once key_expires_at
# (year-month-day) has passed; that key's containers are torn down and
# no new ones can be created until the operator re-enables it.
#
# [[key]]
# active = true
# pubkey = "c161cd235cab272ee9e8e1ad3de0009d31f2da3c8bac927d3148fc6f1dff2e8f"
# key_expires_at = "2027-01-01" # year-month-day; "" or "never" = no expiry
# key_max_containers = 10
#
# dockerfile_path = "/etc/shellforge/"
#
# containers_expire_after = "30m"
# containers_survive_reboot = true
# containers_killed_after_exit = false
# containers_stop_after_exit = false
# containers_memory_limit = "1g"
# containers_cpu_limit = 1.5
# containers_gpu_limit = "0"
`

type DB struct {
	mu sync.RWMutex

	keysPath string
	envsPath string

	keys []AccessKeyRecord
	envs []ENVs
}

// OpenDB takes a directory path (e.g. "/var/lib/shellforge") and ensures
// envs.toml exists inside it, loading it into memory together with the
// access keys from AccessKeysPath.
func OpenDB(path string) (*DB, error) {
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory structure at %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(AccessKeysPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", filepath.Dir(AccessKeysPath), err)
	}

	d := &DB{
		keysPath: AccessKeysPath,
		envsPath: filepath.Join(path, "envs.toml"),
	}

	if err := d.loadKeysLocked(); err != nil {
		return nil, fmt.Errorf("failed to load access_keys.toml: %w", err)
	}
	if err := d.loadEnvsLocked(); err != nil {
		return nil, fmt.Errorf("failed to load envs.toml: %w", err)
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
		// Seed a commented template so operators know the expected format.
		d.keys = []AccessKeyRecord{}
		if werr := os.WriteFile(d.keysPath, []byte(accessKeysTemplate), 0644); werr != nil {
			return fmt.Errorf("failed to create %s: %w", d.keysPath, werr)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(bytes))) == 0 {
		d.keys = []AccessKeyRecord{}
		return nil
	}
	var kf accessKeysFile
	if err := toml.Unmarshal(bytes, &kf); err != nil {
		return fmt.Errorf("malformed access_keys.toml: %w", err)
	}
	if kf.Keys == nil {
		kf.Keys = []AccessKeyRecord{}
	}
	d.keys = kf.Keys
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
	var ef envsFile
	if err := toml.Unmarshal(bytes, &ef); err != nil {
		return fmt.Errorf("malformed envs.toml: %w", err)
	}
	if ef.Envs == nil {
		ef.Envs = []ENVs{}
	}
	d.envs = ef.Envs
	return nil
}

// ReloadAccessKeys re-reads access_keys.toml from disk so hand-edits made
// by the operator while the daemon is running are picked up. The reaper
// calls this at the start of every sweep.
func (d *DB) ReloadAccessKeys() error {
	return d.loadKeysLocked()
}

// saveKeysUnlocked / saveEnvsUnlocked assume the caller already holds d.mu.
func (d *DB) saveKeysUnlocked() error {
	return atomicWriteTOML(d.keysPath, accessKeysFile{Keys: d.keys})
}

func (d *DB) saveEnvsUnlocked() error {
	return atomicWriteTOML(d.envsPath, envsFile{Envs: d.envs})
}

func atomicWriteTOML(path string, v any) error {
	b, err := toml.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal TOML for %s: %w", path, err)
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
func (d *DB) GetRecord(key []byte) (*AccessKeyRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := range d.keys {
		if AreEqual(d.keys[i].PubKey, key) == true {
			rec := d.keys[i] // copy
			return &rec, nil
		}

	}
	return nil, nil
}

func (d *DB) IsEligibleKey(key []byte) bool {
	rec, err := d.GetRecord(key)
	if err != nil {
		log.Printf("[DB] Failed to check key eligibility: %v", err)
		return false
	}
	return rec != nil && rec.IsActive && !rec.IsExpired(time.Now())
}

// HasActiveEnv checks if there is an active environment of a specific type
// (e.g. "container") currently running for the given public key.
func (d *DB) HasActiveEnv(key []byte, envType string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, e := range d.envs {
		if AreEqual(e.PubKey, key) && e.EnvType == envType {
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

func (d *DB) GetENVByUserReqestedName(name string, key []byte) (*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := range d.envs {
		e := &d.envs[i]
		if e.UserRequestedName == name && AreEqual(e.PubKey, key) {
			cp := *e
			return &cp, nil
		}
	}
	return nil, nil
}

func (d *DB) GetENVByname(name string, key []byte) (*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := range d.envs {
		e := &d.envs[i]
		if e.Name == name && AreEqual(e.PubKey, key) {
			cp := *e
			return &cp, nil
		}
	}
	return nil, nil
}

// GetENVs retrieves all environments associated with a specific public key.
func (d *DB) GetENVs(key []byte) ([]*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var out []*ENVs
	for i := range d.envs {
		if AreEqual(d.envs[i].PubKey, key) {
			cp := d.envs[i]
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (d *DB) GetEnvsByType(key []byte, envType string) ([]*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var out []*ENVs
	for i := range d.envs {
		if AreEqual(d.envs[i].PubKey, key) && d.envs[i].EnvType == envType {
			cp := d.envs[i]
			out = append(out, &cp)
		}
	}
	return out, nil
}

// CountEnvsByType returns how many environments of the given type are
// currently active for a public key (used to enforce key_max_containers).
func (d *DB) CountEnvsByType(key []byte, envType string) int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	count := 0
	for i := range d.envs {
		if AreEqual(d.envs[i].PubKey, key) && d.envs[i].EnvType == envType {
			count++
		}
	}
	return count
}

func (d *DB) GetEnvByTypeAndName(key []byte, name, envType string) (*ENVs, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := range d.envs {
		e := &d.envs[i]
		if e.Name == name && AreEqual(e.PubKey, key) && e.EnvType == envType {
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
// matched by its pubkey, then persists access_keys.toml.
func (d *DB) UpdateKeyField(pubkey, field string, newValue any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	idx := -1
	for i := range d.keys {
		if d.keys[i].PubKey == pubkey {
			idx = i
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
	case "key_expires_at", "keyexpiresat":
		v, ok := newValue.(string)
		if !ok {
			return fmt.Errorf("field %q expects string", field)
		}
		rec.KeyExpiresAt = v
	case "key_max_containers", "keymaxcontainers":
		v, ok := newValue.(int)
		if !ok {
			return fmt.Errorf("field %q expects int", field)
		}
		rec.KeyMaxContainers = v
	case "dockerfile_path", "dockerfilepath":
		v, ok := newValue.(string)
		if !ok {
			return fmt.Errorf("field %q expects string", field)
		}
		rec.DockerfilePath = v
	case "containers_expire_after", "containersexpireafter":
		v, ok := newValue.(string)
		if !ok {
			return fmt.Errorf("field %q expects string", field)
		}
		rec.ContainersExpireAfter = v
	case "containers_survive_reboot", "containerssurvivereboot":
		v, ok := newValue.(bool)
		if !ok {
			return fmt.Errorf("field %q expects bool", field)
		}
		rec.ContainersSurviveReboot = v
	case "containers_killed_after_exit", "containerskilledafterexit":
		v, ok := newValue.(bool)
		if !ok {
			return fmt.Errorf("field %q expects bool", field)
		}
		rec.ContainersKilledAfterExit = v
	case "containers_stop_after_exit", "containersstopafterexit":
		v, ok := newValue.(bool)
		if !ok {
			return fmt.Errorf("field %q expects bool", field)
		}
		rec.ContainersStopAfterExit = v
	case "containers_memory_limit", "containersmemorylimit":
		v, ok := newValue.(string)
		if !ok {
			return fmt.Errorf("field %q expects string", field)
		}
		rec.ContainersMemoryLimit = v
	case "containers_cpu_limit", "containerscpulimit":
		v, ok := newValue.(float64)
		if !ok {
			return fmt.Errorf("field %q expects float64", field)
		}
		rec.ContainersCPULimit = v
	case "containers_gpu_limit", "containersgpulimit":
		v, ok := newValue.(string)
		if !ok {
			return fmt.Errorf("field %q expects string", field)
		}
		rec.ContainersGPULimit = v
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
// then persists envs.toml.
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

// =====================================================================
// REAPER / SWEEPER
// =====================================================================

// PurgeExpired scans the store, flips any expired access keys from
// active to disabled (persisting the change to access_keys.toml), and
// forcefully tears down any active environments associated with them.
// It also purges individually-expired environments.
func (d *DB) PurgeExpired() {
	now := time.Now()

	// ---- PART 1: disable expired access keys ----
	// Re-read access_keys.toml first so operator hand-edits are honored.
	if err := d.ReloadAccessKeys(); err != nil {
		log.Printf("[DB] Reaper: failed to reload access keys: %v", err)
	}

	d.mu.Lock()
	var expiredKeys []string
	for i := range d.keys {
		rec := &d.keys[i]
		if rec.IsActive && rec.IsExpired(now) {
			rec.IsActive = false
			expiredKeys = append(expiredKeys, rec.PubKey)
		}
	}
	if len(expiredKeys) > 0 {
		if err := d.saveKeysUnlocked(); err != nil {
			log.Printf("[DB] Reaper: failed to persist disabled keys: %v", err)
		}
	}
	d.mu.Unlock()

	for _, pubkey := range expiredKeys {
		log.Printf("[DB] Reaper: access key %s... expired, state changed to disabled", shortKey(pubkey))
		d.purgeEnvironmentsByPubKey(pubkey)
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
// PARSING HELPERS
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

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}

func AreEqual(key string, WireKey []byte) bool {
	log.Println(key)
	Found_pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		log.Printf("[auth] skipping malformed accesskey_keys line: invalid: %v", err)

	}
	Found_pubKeyBytes := Found_pubKey.Marshal()

	SSH_presentedPubKey, err := ssh.NewPublicKey(ed25519.PublicKey(WireKey))
	if err != nil {
		log.Printf("[auth] presented key invalid: %v", err)
		return false
	}

	SSH_presentedPubKey_bytes := SSH_presentedPubKey.Marshal()

	if !bytes.Equal(SSH_presentedPubKey_bytes, Found_pubKeyBytes) {
		log.Printf("[auth] skipping authorized_keys line presented key not egual with the key server found \n")
		return false
	}
	return true
}
