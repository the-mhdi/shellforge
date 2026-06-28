package shellforge

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

const IMAGE_NAME_PREFIX string = "shf_image_"
const CONTAINER_NAME_PREFIX string = "shf_container_"

type ContainerShellRequset struct {
	// client sends EnvRequest with  message type MsgClientGetContainer
}

type ContainersListResponse struct {
	//server sends a list of containers owned by the key if the ContainerShellRequset has no requestedusername
	RequestID      uint32
	PublicKey      []byte // 32 bytes (Ed25519)
	ContainersList []string
}

// Daemon replies, confirming the RequestID and providing the official ChannelID
type ContainerShellRequsetResponse struct {
	// server sends ShellRequsetResponse with  message type MsgServerShellReqResponse
}

// Type satisfies your Packet interface
func (res *ContainersListResponse) Type() uint8 {
	// Assumed message type, ensure you define MsgServerContainersListResponse in your protocol.go!
	return MsgServerContainersListResponse
}

// Unmarshal parses the binary payload and populates the receiver struct in-place [1].
func (res *ContainersListResponse) Unmarshal(data []byte) error {
	parsed, err := ParseContainersListResponse(data)
	if err != nil {
		return err
	}

	*res = *parsed
	return nil
}

// ParseContainersListResponse extracts the payload securely with strict bounds checking [2].
func ParseContainersListResponse(data []byte) (*ContainersListResponse, error) {
	res := &ContainersListResponse{}
	offset := 0

	// 1. Base Bounds check: RequestID(4) + PublicKey(32) + Count(2) = 38 bytes minimum
	if len(data) < offset+38 {
		return nil, ErrMalformedControlPacket
	}

	res.RequestID = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	res.PublicKey = data[offset : offset+32]
	offset += 32

	count := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Parse the dynamic string list sequentially
	if count > 0 {
		// Allocate the slice exactly once to optimize Garbage Collection memory overhead! [1, 2]
		res.ContainersList = make([]string, 0, count)

		for i := 0; i < int(count); i++ {
			// Read string length (2 bytes)
			if len(data) < offset+2 {
				return nil, ErrMalformedControlPacket
			}
			strLen := binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2

			// Read string bytes [1, 2]
			if len(data) < offset+int(strLen) {
				return nil, ErrMalformedControlPacket
			}
			strVal := string(data[offset : offset+int(strLen)])
			offset += int(strLen)

			res.ContainersList = append(res.ContainersList, strVal)
		}
	}

	return res, nil
}

// Marshal converts the ContainersListResponse struct into a binary network payload
func (res *ContainersListResponse) Marshal() []byte {
	// 1. Calculate the exact total size needed
	totalSize := 38 // Base size
	for _, s := range res.ContainersList {
		totalSize += 2 + len(s) // 2 bytes length prefix + characters
	}

	out := make([]byte, totalSize)
	offset := 0

	// 2. Write RequestID (4 bytes)
	binary.BigEndian.PutUint32(out[offset:], res.RequestID)
	offset += 4

	// 3. Write PublicKey (Exactly 32 bytes)
	if len(res.PublicKey) != 32 {
		panic("wireforge: ContainersListResponse PublicKey must be exactly 32 bytes")
	}
	offset += copy(out[offset:], res.PublicKey)

	// 4. Write Count (2 bytes)
	binary.BigEndian.PutUint16(out[offset:], uint16(len(res.ContainersList)))
	offset += 2

	// 5. Write each string in the slice
	for _, s := range res.ContainersList {
		binary.BigEndian.PutUint16(out[offset:], uint16(len(s)))
		offset += 2
		offset += copy(out[offset:], s)
	}

	return out
}

// BuildDockerfileOnDemand compiles a local Dockerfile if it hasn't been built yet [2]
// It runs once (usually when an administrator registers a new user key or updates the Dockerfile configuration).
// BuildDockerfileOnDemand compiles a local Dockerfile if it hasn't been built yet [2].
func BuildDockerfileOnDemand(ctx context.Context, pipe *PipeStream, dockerfilePath, pubKeyHex string) (string, error) {
	if dockerfilePath == "" {
		return "", nil
	}
	imageName := fmt.Sprintf("%s%s", IMAGE_NAME_PREFIX, pubKeyHex[:8])
	// 1. FAST PATH: Check if the compiled image already exists in local storage.
	// 'podman image exists' returns exit code 0 if found, and non-zero if not [3].
	existsCmd := exec.CommandContext(ctx, "podman", "image", "exists", imageName)
	if existsCmd.Run() == nil {

		log.Printf("[Container] Image %s already exists. Skipping build.", imageName)

		return "", nil // Bypasses the build entirely!
	}

	// 2. Verification: Ensure the Dockerfile actually exists on disk before starting
	if _, err := os.Stat(dockerfilePath + "/Dockerfile"); os.IsNotExist(err) {
		return "", fmt.Errorf("Dockerfile not found at: %s", dockerfilePath)
	}

	log.Printf("[Container] Compiling custom Dockerfile at %s to tag %s...", dockerfilePath, imageName)
	cmd := exec.CommandContext(ctx, "podman", "build", "-t", imageName, dockerfilePath)

	cmd.Stdout = pipe
	cmd.Stderr = pipe

	return imageName, cmd.Run()
}

// CreatePodmanContainer parses the configuration and pre-stages the container on disk.
// It uses "podman create" instead of "run" so that the container is registered
// but remains in a "stopped" state until the user actually logs in [1.2.2].
func CreateContainer(ctx context.Context, pubKeyHex, imageName, memoryLimit string, cpuLimit float64, gpuLimit string) (string, error) {

	containerName := fmt.Sprintf("%s%s", CONTAINER_NAME_PREFIX, pubKeyHex[:8])
	// 1. Check if the container already exists on the host [1.2.3]
	existsCmd := exec.Command("podman", "container", "exists", containerName)
	if existsCmd.Run() == nil {
		return "", nil // Already created, nothing to do!
	}

	// 2. Prepare the creation arguments (No "-it" needed for raw creation)
	args := []string{
		"create", "-it", // Keep STDIN open even if not attached
		"--name", containerName,
		fmt.Sprintf("--memory=%s", memoryLimit),
		fmt.Sprintf("--cpus=%f", cpuLimit),
	}

	if gpuLimit != "" {
		args = append(args, "--gpus", gpuLimit)
	}

	args = append(args, imageName)

	// 3. Create the container (This allocates the persistent filesystem on disk!)
	cmd := exec.CommandContext(ctx, "podman", args...)
	return containerName, cmd.Run()
}

// RunPodmanContainer dynamically starts a fresh container or resumes an existing stopped one [1, 2, 3].
func (d *Daemon) RunContainer(ctx context.Context, containerName, imageName, memoryLimit string, cpuLimit float64, gpuLimit string, rows, cols uint16, ch io.ReadWriter) error {

	// 1. Check if a container with this name already exists on the host [1, 3]
	// 'podman container exists' returns exit code 0 if it exists, and non-zero if it doesn't.
	existsCmd := exec.Command("podman", "container", "exists", containerName)
	containerExists := existsCmd.Run() == nil

	var cmd *exec.Cmd

	if containerExists {
		// --- RESUME EXISTING CONTAINER --- [2, 3]
		// The container already exists from a previous session.
		// We start and attach (-a -i) directly to it. All previous files and states are intact!
		log.Printf("[Container] Resuming existing stopped container: %s", containerName)
		args := []string{"start", "-a", "-i", containerName}
		cmd = exec.CommandContext(ctx, "podman", args...)
	} else {
		// --- CREATE FRESH CONTAINER --- [2]
		// First-time login. We run a new container.
		// NOTE: We intentionally OMIT the "--rm" flag so the container persists when we exit!
		log.Printf("[Container] Creating fresh persistent container: %s", containerName)
		args := []string{
			"run", "-it",
			"--name", containerName,
			fmt.Sprintf("--memory=%s", memoryLimit),
			fmt.Sprintf("--cpus=%f", cpuLimit),
		}

		if gpuLimit != "" {
			args = append(args, "--gpus", gpuLimit)
		}

		args = append(args, imageName)
		cmd = exec.CommandContext(ctx, "podman", args...)
	}

	// 2. Spawn the container inside the PTY [3]
	ptyFd, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		return err
	}
	defer ptyFd.Close()

	if pipe, ok := ch.(*PipeStream); ok {
		pipe.SetPTY(ptyFd)
		defer pipe.SetPTY(nil)
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(ptyFd, ch)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(ch, ptyFd)
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		// Gracefully stop the container instead of killing it,
		// allowing internal database/file writes to finish cleanly [4].
		log.Printf("[Container] Gracefully stopping container %s...", containerName)
		_ = exec.Command("podman", "stop", "-t", "5", containerName).Run()
		return ctx.Err()
	case <-errCh:
		// If connection drops, send SIGTERM and give it 5 seconds to stop gracefully [4]
		_ = exec.Command("podman", "stop", "-t", "5", containerName).Run()
	}

	return cmd.Wait()
}

// KillAndRemoveContainer forcefully terminates a running container (SIGKILL)
// and deletes its persistent filesystem from the disk in a single step [3, 4].
func KillAndRemoveContainer(ctx context.Context, containerName string) error {
	// Equivalent to: podman rm -f [containerName]
	// (You can safely change "podman" to "docker" depending on your engine)
	cmd := exec.CommandContext(ctx, "podman", "rm", "-f", containerName)

	// Run executes the command and blocks until it completes
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to forcefully remove container %s: %w", containerName, err)
	}

	return nil
}

// DeleteContainerImage forcefully removes a compiled container image from the host's disk.
// It works identically with either "podman" or "docker" as the command.
func DeleteContainerImage(ctx context.Context, imageName string) error {
	// Equivalent to: podman rmi -f [imageName]
	cmd := exec.CommandContext(ctx, "podman", "rmi", "-f", imageName)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete container image %s: %w", imageName, err)
	}

	return nil
}
