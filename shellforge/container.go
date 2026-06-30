package shellforge

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
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
