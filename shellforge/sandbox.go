package shellforge

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// SetupCgroupV2 creates a resource-limited cgroup for the session.
// It limits memory to 500MB and CPU usage to 50% (50ms quota out of 100ms period).
// example:
// cpu = 50000 100000
// memory = 500M
func SetupCgroupV2(sessionID string, memory, cpu string) error {
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/wireforge_%s", sessionID)

	// Create cgroup directory
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup dir: %w", err)
	}

	// 1. Set Memory Max Limit (500MB) memory = 500M
	if err := os.WriteFile(cgroupPath+"/memory.max", []byte(memory), 0644); err != nil {
		return fmt.Errorf("failed to set memory limit: %w", err)
	}

	// 2. Set CPU Quota (50% CPU allocation)  cpu = 50000 100000
	if err := os.WriteFile(cgroupPath+"/cpu.max", []byte(cpu), 0644); err != nil {
		return fmt.Errorf("failed to set CPU limit: %w", err)
	}

	return nil
}

// MoveProcessToCgroup moves the spawned PTY process into the configured cgroup.
func MoveProcessToCgroup(sessionID string, pid int) error {
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/wireforge_%s", sessionID)
	pidStr := strconv.Itoa(pid)

	// Writing the PID to 'cgroup.procs' migrates the process and its threads
	return os.WriteFile(cgroupPath+"/cgroup.procs", []byte(pidStr), 0644)
}

// DestroyCgroup deletes the cgroup directory once the session exits.
func DestroyCgroup(sessionID string) {
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/wireforge_%s", sessionID)
	_ = os.Remove(cgroupPath)
}

// SetupContainerNetwork creates a veth pair, binds one side to a host bridge,
// and moves the other side into the container's PID/Network namespace [1.1.6].
func SetupContainerNetwork(pid int, bridgeName, vethHost, vethCont string) error {
	pidStr := strconv.Itoa(pid)

	// 1. Create the veth pair
	if err := exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethCont).Run(); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}

	// 2. Attach the host side of the veth pair to the bridge
	if err := exec.Command("ip", "link", "set", vethHost, "master", bridgeName).Run(); err != nil {
		return fmt.Errorf("failed to attach veth to bridge: %w", err)
	}

	// 3. Move the container side of the veth pair into the container's namespace
	if err := exec.Command("ip", "link", "set", vethCont, "netns", pidStr).Run(); err != nil {
		return fmt.Errorf("failed to move veth to namespace: %w", err)
	}

	// 4. Bring the host interface and bridge up
	_ = exec.Command("ip", "link", "set", bridgeName, "up").Run()
	_ = exec.Command("ip", "link", "set", vethHost, "up").Run()

	return nil
}
