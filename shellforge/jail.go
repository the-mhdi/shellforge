package shellforge

import (
	"fmt"
	"os"
	"syscall"
)

// On-Demand, Ephemeral Bind-Mount Jail

const JAIL_DIR string = "/tmp/wf_jail_"

// CreateOnDemandJail builds a completely isolated, temporary filesystem
// using the host's existing binaries, but excluding sensitive directories [1.2.6].
func CreateOnDemandJail(key string) (string, error) {
	jailDir := fmt.Sprintf("%s%s", JAIL_DIR, key)

	// 1. Create the temporary directory structure
	_ = os.MkdirAll(jailDir, 0755)
	_ = os.MkdirAll(jailDir+"/bin", 0755)
	_ = os.MkdirAll(jailDir+"/home", 0755)
	_ = os.MkdirAll(jailDir+"/lib", 0755)
	_ = os.MkdirAll(jailDir+"/lib64", 0755)
	_ = os.MkdirAll(jailDir+"/usr", 0755)
	_ = os.MkdirAll(jailDir+"/proc", 0755)
	_ = os.MkdirAll(jailDir+"/sys", 0755)
	_ = os.MkdirAll(jailDir+"/tmp", 0777) // Writeable temp space in memory
	_ = os.MkdirAll(jailDir+"/etc", 0755)

	// 2. Bind-mount the host's binaries as READ-ONLY [1.2.6]
	// MS_BIND (4096) tells Linux to mirror the folder.
	// MS_RDONLY (1) ensures the sandboxed user cannot modify your host's binaries.
	const flags = syscall.MS_BIND | syscall.MS_RDONLY

	if err := syscall.Mount("/bin", jailDir+"/bin", "", flags, ""); err != nil {
		return "", fmt.Errorf("failed to bind /bin: %w", err)
	}
	if err := syscall.Mount("/lib", jailDir+"/lib", "", flags, ""); err != nil {
		return "", fmt.Errorf("failed to bind /lib: %w", err)
	}
	// On 64-bit systems, lib64 is required for dynamic linking
	if _, err := os.Stat("/lib64"); err == nil {
		_ = syscall.Mount("/lib64", jailDir+"/lib64", "", flags, "")
	}
	if err := syscall.Mount("/usr", jailDir+"/usr", "", flags, ""); err != nil {
		return "", fmt.Errorf("failed to bind /usr: %w", err)
	}

	// 3. Safely pass DNS config so they can resolve hosts if they use the network,
	// but keep the rest of your host's /etc (like /etc/shadow) completely hidden! [1.2.6]
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		_ = os.WriteFile(jailDir+"/etc/resolv.conf", []byte{}, 0644) // Create placeholder file
		_ = syscall.Mount("/etc/resolv.conf", jailDir+"/etc/resolv.conf", "", flags, "")
	}

	return jailDir, nil
}

// DestroyOnDemandJail forcefully unmounts the mirrored host folders
// and completely erases the temporary directory from disk.
func DestroyOnDemandJail(key string) {
	jailDir := fmt.Sprintf("%s%s", JAIL_DIR, key)

	// Forcefully detach the bind mounts [4]
	_ = syscall.Unmount(jailDir+"/bin", syscall.MNT_DETACH)
	_ = syscall.Unmount(jailDir+"/lib", syscall.MNT_DETACH)
	_ = syscall.Unmount(jailDir+"/lib64", syscall.MNT_DETACH)
	_ = syscall.Unmount(jailDir+"/usr", syscall.MNT_DETACH)
	_ = syscall.Unmount(jailDir+"/etc/resolv.conf", syscall.MNT_DETACH)

	// Clean up the entire temporary jail directory [4]
	_ = os.RemoveAll(jailDir)
}
