package shellforge

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // Ensure you have go-sqlite3 in your go.mod
)

// setupTestDB helper to create a clean, in-memory testing database.
func setupTestDB(t *testing.T) *DB {
	// ":memory:" runs the entire database inside RAM, preventing disk writes.
	db, err := OpenDB(":memory:")

	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	return db
}

func TestDB_InitSchemaAndMigrations(t *testing.T) {

	t.Log("=== Starting TestDB_InitSchemaAndMigrations ===")

	db := setupTestDB(t)
	defer db.db.Close()

	// Verify that critical tables were created successfully
	hasAllowedKeys, err := db.HasColumn("allowed_keys", "pubkey")
	if err != nil || !hasAllowedKeys {
		t.Errorf("Expected 'allowed_keys' table with 'pubkey' column to exist")
	}

	hasCreatedEnvs, err := db.HasColumn("created_envs", "id")
	if err != nil || !hasCreatedEnvs {
		t.Errorf("Expected 'created_envs' table with 'id' column to exist")
	}
}

func TestDB_GetRecord_RoundTrip(t *testing.T) {
	t.Log("=== Starting TestDB_GetRecord_RoundTrip ===")
	db := setupTestDB(t)
	defer db.db.Close()

	pubkey := "test_pubkey_hex_12345"
	original := &AccessKeyRecord{
		PubKey:          pubkey,
		KeyExpiresAfter: 5 * time.Hour,
		Environment: EnvConfigSlice{
			{
				Type: "container",
				Setting: EnvSetting{
					DockerfilePath: "/etc/wireforge/docker",
					MemoryLimit:    "500m",
					CPULimit:       1.5,
					GPULimit:       "device=0",
				},
				MaxLogins:  10,
				LifeSpan:   "2h",
				OneTimeUse: false,
			},
		},
		MaxSessions:   5,
		MaxContainers: 2,
		CreatedAt:     time.Now().Truncate(time.Second), // Truncate to match SQLite datetime resolution
	}

	// Insert into allowed_keys manually for testing
	query := `
		INSERT INTO allowed_keys (pubkey, key_expires_after, environment, max_sessions, max_containers, max_users, max_namespaces, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.db.Exec(query,
		original.PubKey,
		original.KeyExpiresAfter,
		original.Environment,
		original.MaxSessions,
		original.MaxContainers,
		original.MaxUsers,
		original.MaxNamespaces,
		original.CreatedAt,
	)
	if err != nil {
		t.Fatalf("Failed to insert mock record: %v", err)
	}

	// Retrieve the record
	parsed, err := db.GetRecord(pubkey)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}

	if parsed == nil {
		t.Fatal("GetRecord returned nil record")
	}

	// Align calculated tracker fields that default to 0 on insert
	original.LoginsUsed = parsed.LoginsUsed
	original.SysUsersCount = parsed.SysUsersCount
	original.ContaintersCount = parsed.ContaintersCount
	original.NamespacesCount = parsed.NamespacesCount
	// FIX 1: Safely compare the times using .Equal() to ignore timezone metadata [1]
	if !original.CreatedAt.Equal(parsed.CreatedAt) {
		t.Errorf("CreatedAt mismatch:\nOriginal: %v\nParsed: %v", original.CreatedAt, parsed.CreatedAt)
	}

	// FIX 2: Set both to a zero-value time so reflect.DeepEqual ignores the
	// location pointer discrepancies when comparing the rest of the struct!
	original.CreatedAt = time.Time{}
	parsed.CreatedAt = time.Time{}

	// Verify structural equivalence
	if !reflect.DeepEqual(original, parsed) {
		t.Errorf("Database serialization round-trip failed!\nOriginal: %+v\nParsed: %+v", original, parsed)
	}
}

func TestDB_AddAndGetENVs(t *testing.T) {
	t.Log("=== Starting TestDB_AddAndGetENVs ===")
	db := setupTestDB(t)
	defer db.db.Close()

	pubkey := "test_pubkey_hash"
	envRecord := &ENVs{
		PubKey:            pubkey,
		EnvType:           "container",
		Name:              "shf_container_test1",
		ImageName:         "alpine:latest",
		UserRequestedName: "my_workspace",
		Setting: EnvSetting{
			MemoryLimit: "256m",
			CPULimit:    0.5,
		},
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		CreatedAt:     time.Now(),
		SurviveReboot: true,
	}

	// 1. Insert into database
	err := db.AddENV(envRecord)
	if err != nil {
		t.Fatalf("AddENV failed: %v", err)
	}

	// 2. Test duplicate name prevention
	duplicateEnv := &ENVs{
		ID:                "env_xyz987",
		PubKey:            pubkey,
		EnvType:           "container",
		Name:              "another_container",
		UserRequestedName: "my_workspace", // Duplicate name!
	}
	err = db.AddENV(duplicateEnv)
	if !errors.Is(err, ErrDuplicateEnvName) {
		t.Errorf("Expected ErrDuplicateEnvName, got: %v", err)
	}

	// 3. Retrieve it using GetENVs
	envs, err := db.GetENVs(pubkey)
	if err != nil {
		t.Fatalf("GetENVs failed: %v", err)
	}

	if len(envs) != 1 {
		t.Fatalf("Expected exactly 1 active environment, got %d", len(envs))
	}

	parsedEnv := envs[0]
	if parsedEnv.Name != envRecord.Name || parsedEnv.EnvType != envRecord.EnvType {
		t.Errorf("Retrieved environment details mismatch. Original Name: %s, Got: %s", envRecord.Name, parsedEnv.Name)
	}

	t.Logf("Successfully verified active environment tracking: %s (%s)", parsedEnv.Name, parsedEnv.EnvType)
}

func TestDB_JSON_Config_Sync(t *testing.T) {
	t.Log("=== Starting TestDB_SyncJSONConfig ===")
	db := setupTestDB(t)
	defer db.db.Close()

	// Write a mock JSON file to /tmp for testing
	jsonFile := "/tmp/wireforge_test_keys.json"
	jsonData := []byte(`[
	  {
		"pubkey": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u14f2c96350f968987483758",
		"key_expires_afer": "5d",
		"environment": [
		  {
			"type": "container",
			"setting": {
				"memory_limit": "1g",
				"cpu_limit": 1.5
			},
			"max_logins": 10,
			"life_span": "2h",
			"one_time_use": false
		  }
		],
		"max_sessions": 2
	  }
	]`)

	err := os.WriteFile(jsonFile, jsonData, 0644)
	if err != nil {
		t.Fatalf("Failed to create temporary JSON config: %v", err)
	}
	defer os.Remove(jsonFile)

	// Sync the JSON file to SQLite!
	records, err := db.LoadAccessKeysConf(jsonFile)
	if err != nil {
		t.Fatalf("LoadAccessKeysConf failed: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("Expected 1 synchronized record, got %d", len(records))
	}

	record, exists := records["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u14f2c96350f968987483758"]
	if !exists {
		t.Fatalf("Expected key was not synchronized to memory map")
	}

	if record.KeyExpiresAfter != 5*24*time.Hour {
		t.Errorf("Expected 5-day expiration (in nanoseconds), got %v", record.KeyExpiresAfter)
	}

	t.Logf("Successfully validated config loader. Extracted %d allowed environments.", len(record.Environment))
}
