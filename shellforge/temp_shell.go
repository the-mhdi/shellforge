package shellforge

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

const (
	TEMPSHELL_SESSION_HEADER_KEY string = "tempSession" //included in client hello headers
	TEMPSHELL_USER_PREFIX        string = "wf_tmp_"
)

// has two phases: 1 . create 2. connect, first one doesnt need regular shell authentication, second needs it's own authenticaion

// a temp shell/user:
// MUST have a hard deadline after that the user gets deleted
// gets deleted after system reboot

// architecture of temp shell/user::
// cleint sends a tempuserreq
// server creates a shell and user + auth suite
// client uses these credentials to auth and get temp access
// server validates the request, creates a temp user with a random name
// server then exits the tempSessionHandler and client and connect use the given username and thier passwd to get shell access
type TempShellConnect struct {
}

// GenerateTempUsername creates a unique name like "wf_tmp_a1b2c3d4"
// to prevent collisions with existing system users.
func GenerateTempUsername() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s%s", TEMPSHELL_USER_PREFIX, hex.EncodeToString(b))
}
func CreateSystemUser(username, group, shell string) error {
	if SysUserExists(username) {
		return errors.New("user already exists. Skipping creation.")
	}

	// 1. Sanitize input defaults
	if group == "" {
		group = "wireforge_users" // Fallback group
	}
	if shell == "" {
		shell = "/bin/sh"
	}

	// 2. Ensure the primary group exists on the host OS
	// groupadd -f returns 0 if the group already exists
	var groupaddStderr bytes.Buffer
	groupCmd := exec.Command("groupadd", "-f", group)
	groupCmd.Stderr = &groupaddStderr
	if err := groupCmd.Run(); err != nil {
		return fmt.Errorf("groupadd failed for group %s: %s: %w", group, strings.TrimSpace(groupaddStderr.String()), err)
	}

	// 3. Prepare the useradd command
	// -m (create home) -g (primary group) -s (shell) -N (no user-private group)
	cmd := exec.Command("useradd", "-m", "-g", group, "-s", shell, "-N", username)

	// 4. Capture stderr to provide precise system error messages
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("useradd failed for user %s: %s: %w", username, strings.TrimSpace(stderr.String()), err)
	}

	return nil
}

// DeleteSystemUser forcefully terminates any remaining processes run by the
// temporary user, cleanly wipes their home directory, and deletes passwd entries.
// It includes strict security boundaries to prevent accidental deletion of host accounts [4].
func DeleteSystemUser(username string) error {
	// 1. CRITICAL SECURITY GUARDRAIL:
	// Ephemeral sandbox users created by Wireforge always start with the prefix "wf_tmp_".
	// We strictly reject deleting any user without this prefix to protect real system accounts
	// (like "root", "admin", "bin", or "daemon") from accidental deletion!
	if !strings.HasPrefix(username, TEMPSHELL_USER_PREFIX) {
		return fmt.Errorf("security block: refuse to delete non-ephemeral system user %q", username)
	}

	// 2. Execute userdel
	// -r (remove home directory) -f (force kill running processes)
	cmd := exec.Command("userdel", "-r", "-f", username)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Log the error but return it so the caller (like the DB reaper) knows something failed
		log.Printf("[wireforge] Warning: userdel failed for %s: %s: %v", username, strings.TrimSpace(stderr.String()), err)
		return fmt.Errorf("userdel failed: %s: %w", strings.TrimSpace(stderr.String()), err)
	}

	return nil
}

func isTempUser(username string) bool {
	return strings.HasPrefix(username, TEMPSHELL_USER_PREFIX)
}

// sqlite tabe for user management
//tabel:
//user login_limit expiration publickey home_dir groupname
/*
{
pubkey xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
shell bin/sh
home_dir
Duration 9999s or onetime or xtime or
groupname xxx
}
*/
