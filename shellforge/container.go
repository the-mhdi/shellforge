package shellforge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

var ErrMalformedContainerOpRequest = errors.New("malformed ContainerOpRequest packet: out of bounds")

const IMAGE_NAME_PREFIX string = "shf_image_"
const CONTAINER_NAME_PREFIX string = "shf_container_"

type ContainerGetRequset struct {
	// client sends EnvRequest with  message type MsgClientGetContainerShell
}

type ContainersListResponse struct {
	//server sends a list of containers owned by the key if the ContainerShellRequset has no requestedusername
	RequestID      uint32
	PublicKey      []byte // 32 bytes (Ed25519)
	ContainersList []string
}

const (
	// Container operation types
	ContainerOpShell   uint8 = 1
	ContainerOpLogs    uint8 = 2
	ContainerOpCommand uint8 = 3
	ContainerOpTop     uint8 = 4
	ContainerOpStats   uint8 = 5
	ContainerOpInspect uint8 = 6
	ContainerOpStop    uint8 = 7
	ContainerOpKill    uint8 = 8
	ContainerOpRestart uint8 = 9
)

// container operation request sent by client to daemon to get a shell/log/stats etc in the container
type ContainerOpRequest struct {
	RequestID uint32
	PublicKey []byte // 32 bytes (Ed25519)
	NameLen   uint8
	Name      []byte // Container name alias

	OpType uint8 // 1=shell, 2=logs, 3=command(exec) , 4=top , 5=stats, 6=inspect, 7=stop, 8=kill, 9=restart

	CommandLen uint16 // Only used if OpType == 3
	Command    []byte // The command to execute

	// For shell access (OpType == 1 or OpType == 3 if interactive)
	Row  uint16
	Cols uint16
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

	res.PublicKey = cloneBytes(data[offset : offset+32]) // copy: detach from reused rdBuf
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
	log.Printf("[Container] running as uid=%d, XDG_RUNTIME_DIR=%s", os.Getuid(), os.Getenv("XDG_RUNTIME_DIR"))
	if dockerfilePath == "" {
		return "", nil
	}
	imageName := fmt.Sprintf("%s%s", IMAGE_NAME_PREFIX, pubKeyHex[:8])

	// 1. FAST PATH: Check if the compiled image already exists in local storage.
	existsCmd := exec.CommandContext(ctx, "podman", "image", "exists", imageName)
	if existsCmd.Run() == nil {
		log.Printf("[Container] Image %s already exists. Skipping build.", imageName)
		return imageName, nil // <-- return the name, not ""
	}

	// 2. Verification: Ensure the Dockerfile actually exists on disk before starting
	if _, err := os.Stat(dockerfilePath + "/Dockerfile"); os.IsNotExist(err) {
		return "", fmt.Errorf("Dockerfile not found at: %s", dockerfilePath)
	}

	log.Printf("[Container] Compiling custom Dockerfile at %s to tag %s...", dockerfilePath, imageName)
	cmd := exec.CommandContext(ctx, "podman", "build", "-t", imageName, dockerfilePath)
	cmd.Stdout = pipe
	cmd.Stderr = pipe
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("podman build failed: %w", err)
	}
	return imageName, nil
}

// CreatePodmanContainer parses the configuration and pre-stages the container on disk.
// It uses "podman create" instead of "run" so that the container is registered
// but remains in a "stopped" state until the user actually logs in [1.2.2].
func CreateContainer(ctx context.Context, pipe *PipeStream, pubKeyHex, imageName, memoryLimit string, cpuLimit float64, gpuLimit string) (string, error) {
	log.Printf("[Container] running as uid=%d, XDG_RUNTIME_DIR=%s", os.Getuid(), os.Getenv("XDG_RUNTIME_DIR"))
	containerName := fmt.Sprintf("%s%s", CONTAINER_NAME_PREFIX, pubKeyHex[:8])

	// 1. Check if the container already exists on the host [1.2.3]
	existsCmd := exec.Command("podman", "container", "exists", containerName)
	if existsCmd.Run() == nil {
		return containerName, nil // Already created, nothing to do!
	}

	// 2. Prepare the creation arguments (No "-it" needed for raw creation)
	args := []string{
		"create", "-it", // Keep STDIN open even if not attached
		"--name", containerName,
	}

	// Only pass --memory if a non-empty value was actually provided.
	// "--memory=" (empty) is rejected by podman as an invalid value.
	if memoryLimit != "" {
		args = append(args, fmt.Sprintf("--memory=%s", memoryLimit))
	}

	// Only pass --cpus if a sane positive value was provided.
	// "--cpus=0.000000" is rejected by podman.
	if cpuLimit > 0 {
		args = append(args, fmt.Sprintf("--cpus=%f", cpuLimit))
	}

	//	var validGPUDevice = regexp.MustCompile(`^(all|[0-9]+(,[0-9]+)*)$`)
	//
	//	// podman doesn't support docker's "--gpus" flag — it uses CDI device specs instead.
	//	// e.g. "--device nvidia.com/gpu=all" or "--device nvidia.com/gpu=0"
	//	if gpuLimit != "" {
	//		cleaned := strings.Trim(gpuLimit, `"' `) // strip stray quotes/whitespace
	//		if !validGPUDevice.MatchString(cleaned) {
	//			return "", fmt.Errorf("invalid gpuLimit value %q: expected \"all\" or comma-separated device indices", gpuLimit)
	//		}
	//		args = append(args, "--device", fmt.Sprintf("nvidia.com/gpu=%s", cleaned))
	//
	//	}

	args = append(args, imageName)

	// 3. Create the container (This allocates the persistent filesystem on disk!)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "podman", args...)

	cmd.Stdout = pipe
	cmd.Stderr = pipe
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return containerName, fmt.Errorf("podman create failed: %w (stderr: %s)", err, stderr.String())
	}
	return containerName, nil
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

func getContainerState(containerName string) string {
	cmd := exec.Command("podman", "inspect", "--format", "{{.State.Status}}", containerName)
	out, err := cmd.Output()
	if err != nil {
		return "" // doesn't exist
	}
	return strings.TrimSpace(string(out))
}

func waitForContainerState(ctx context.Context, containerName string, target string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state := getContainerState(containerName)
		if state == target {
			return nil
		}
		// Check context cancellation so we don't spin forever if client disconnects
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
			// poll again
		}
	}
	return fmt.Errorf("container %s did not reach state %q within %s (current: %s)",
		containerName, target, timeout, getContainerState(containerName))
}

// Type satisfies your Packet interface
func (cr *ContainerOpRequest) Type() uint8 {
	return MsgClientContainerOpRequest // e.g., define this as 27 in protocol.go
}

// Unmarshal parses the binary payload and populates the receiver struct in-place
func (cr *ContainerOpRequest) Unmarshal(data []byte) error {
	parsed, err := ParseContainerOpRequest(data)
	if err != nil {
		return err
	}
	*cr = *parsed
	return nil
}

// ParseContainerOpRequest extracts the payload securely with strict bounds checking
func ParseContainerOpRequest(data []byte) (*ContainerOpRequest, error) {
	cr := &ContainerOpRequest{}
	offset := 0

	// 1. Base Bounds check: RequestID(4) + PublicKey(32) + NameLen(1) = 37 bytes minimum
	if len(data) < offset+37 {
		return nil, ErrMalformedContainerOpRequest
	}

	cr.RequestID = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	cr.PublicKey = cloneBytes(data[offset : offset+32]) // copy: detach from reused rdBuf
	offset += 32

	cr.NameLen = data[offset]
	offset += 1

	// 2. Read Name
	if len(data) < offset+int(cr.NameLen) {
		return nil, ErrMalformedContainerOpRequest
	}
	cr.Name = cloneBytes(data[offset : offset+int(cr.NameLen)]) // copy: detach from reused rdBuf
	offset += int(cr.NameLen)

	// 3. Read OpType (1 byte)
	if len(data) < offset+1 {
		return nil, ErrMalformedContainerOpRequest
	}
	cr.OpType = data[offset]
	offset += 1

	// 4. Handle Command Payload (Only if OpType is 3 - Command Exec)
	if cr.OpType == 3 {
		if len(data) < offset+2 {
			return nil, ErrMalformedContainerOpRequest
		}
		cr.CommandLen = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		if len(data) < offset+int(cr.CommandLen) {
			return nil, ErrMalformedContainerOpRequest
		}
		cr.Command = cloneBytes(data[offset : offset+int(cr.CommandLen)]) // copy: detach from reused rdBuf
		offset += int(cr.CommandLen)
	}

	// 5. Bounds check: Row (2) + Cols (2) = 4 bytes
	if len(data) < offset+4 {
		return nil, ErrMalformedContainerOpRequest
	}
	cr.Row = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	cr.Cols = binary.BigEndian.Uint16(data[offset : offset+2])

	return cr, nil
}

// Marshal converts the ContainerOpRequest struct into a binary network payload
func (cr *ContainerOpRequest) Marshal() []byte {
	// Base size: RequestID(4) + PublicKey(32) + NameLen(1) + Name + OpType(1) + Row(2) + Cols(2)
	totalSize := 4 + 32 + 1 + len(cr.Name) + 1 + 2 + 2

	// Include command bytes if OpType == 3
	if cr.OpType == 3 {
		totalSize += 2 + len(cr.Command)
	}

	out := make([]byte, totalSize)
	offset := 0

	// Write RequestID (4 bytes)
	binary.BigEndian.PutUint32(out[offset:], cr.RequestID)
	offset += 4

	// Write PublicKey (Exactly 32 bytes)
	if len(cr.PublicKey) != 32 {
		panic("wireforge: ContainerOpRequest PublicKey must be exactly 32 bytes")
	}
	offset += copy(out[offset:], cr.PublicKey)

	// Write NameLen (1 byte)
	out[offset] = uint8(len(cr.Name))
	offset += 1

	// Write Name
	offset += copy(out[offset:], cr.Name)

	// Write OpType (1 byte)
	out[offset] = cr.OpType
	offset += 1

	// Write CommandLen and Command (only if OpType == 3)
	if cr.OpType == 3 {
		binary.BigEndian.PutUint16(out[offset:], uint16(len(cr.Command)))
		offset += 2
		offset += copy(out[offset:], cr.Command)
	}

	// Write Row (2 bytes)
	binary.BigEndian.PutUint16(out[offset:], cr.Row)
	offset += 2

	// Write Cols (2 bytes)
	binary.BigEndian.PutUint16(out[offset:], cr.Cols)

	return out
}
