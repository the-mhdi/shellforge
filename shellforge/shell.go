package shellforge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

// the remote shell that daemon opens
type Shell struct {
	ID  uint32 // 8== channel id this shell runs on
	PTY *os.File
	//Pipe   io.ReadWriteCloser
	fileMu sync.Mutex
}

func newShell(ID uint32) *Shell {
	return &Shell{
		ID: ID,
	}
}

func (p *Shell) SetPTY(f *os.File) {
	p.fileMu.Lock()
	p.PTY = f
	p.fileMu.Unlock()
}
func (p *Shell) ResizePTY(rows, cols uint16) error {
	p.fileMu.Lock()
	defer p.fileMu.Unlock()

	if p.PTY == nil {
		return errors.New("no active PTY to resize")
	}

	// This sends the SIGWINCH signal directly to the remote bash process!
	return pty.Setsize(p.PTY, &pty.Winsize{Rows: rows, Cols: cols})
}

// Client requests a shell and provides a temporary RequestID
type ShellRequest struct {
	RequestID   uint32 // Used by the client to track pending requests
	UsernameLen uint8
	User        []byte // e.g., "root"
	ShellLen    uint16
	Shell       []byte // e.g., "/bin/bash"
	Row         uint16
	Cols        uint16
}

// Daemon replies, confirming the RequestID and providing the official ChannelID
type ShellRequestResponse struct {
	RequestID uint32 // Matches the client's request
	ChannelID uint32 // ASSIGNED BY THE SERVER!
	Success   bool
}

type WindowResize struct {
	ChannelID uint32 // same as ShellRequestResponse.ChannelID
	Rows      uint16
	Cols      uint16
}

// RunInteractiveShell spawns a shell and pipes it to our multiplexed Channel.
func (she *Shell) RunInteractiveShell(ctx context.Context, shellReq *ShellRequest, pipe *channel, rows, cols uint16) error {

	var shell string
	shell = "/bin/bash"
	if _, err := exec.LookPath(string(shellReq.Shell)); err != nil {
		shell = "/bin/bash"
		// If bash isn't installed, fall back to sh
		if _, err := exec.LookPath(string(shellReq.Shell)); err != nil {
			shell = "/bin/sh"
		}

	}
	cmd := exec.CommandContext(ctx, shell)

	// Default to inheriting the daemon's environment
	cmdEnv := os.Environ()

	// 1. INJECT SYSTEM CREDENTIALS & SANITIZE ENVIRONMENT
	if runtime.GOOS != "windows" && string(shellReq.User) != "" {
		u, err := user.Lookup(string(shellReq.User))
		if err != nil {
			return fmt.Errorf("user system lookup failed: %w", err)
		}

		cred, err := getSysCredentials(u)
		if err != nil {
			return fmt.Errorf("failed to get process credentials: %w", err)
		}

		// Set process permissions to the target user
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: cred,
		}
		cmd.Dir = u.HomeDir
		// FIX: Sanitize the environment so the shell doesn't look at /root!
		cmdEnv = sanitizeEnv(cmdEnv, map[string]string{
			"HOME":    u.HomeDir,  // e.g. "/home/alice"
			"USER":    u.Username, // e.g. "alice"
			"LOGNAME": u.Username, // e.g. "alice"
			"SHELL":   shell,      // e.g. "/bin/bash"
		})
	}

	// Set terminal emulator capabilities
	cmd.Env = append(cmdEnv, "TERM=xterm-256color")

	var ptyFd *os.File
	var err error

	if runtime.GOOS == "windows" {
		cmd.Stdin = pipe
		cmd.Stdout = pipe
		cmd.Stderr = pipe
		err = cmd.Start()
	} else {
		ptyFd, err = pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})

	}

	if err != nil {
		return err
	}
	//defer ptyFd.Close()

	// =================================================================
	// CLEAR SCREEN IMPLEMENTATION
	// =================================================================
	// We write the ANSI escape codes directly to the channel 'ch'.
	// \x1b[H  -> Moves the cursor to the home position (top-left)
	// \x1b[2J -> Clears the entire screen
	// \x1b[3J -> Clears the terminal's scrollback buffer (optional, but clean)
	// =================================================================
	//_, _ = pipe.Write([]byte("\x1b[H\x1b[2J\x1b[3J"))
	//sh := newShell(pipe)

	she.SetPTY(ptyFd)
	defer func() { _ = ptyFd.Close() }() // Best effort.
	defer she.SetPTY(nil)                // Clean up on exit

	errCh := make(chan error, 2)

	// Copy from our secure channel into the shell's input
	go func() {
		_, err := io.Copy(ptyFd, pipe) //calls pipe.Read()
		errCh <- err
	}()

	// Copy from the shell's stdout back into our secure channel
	go func() {
		_, err := io.Copy(pipe, ptyFd) //calls pipe.Write()
		errCh <- err
	}()

	// Wait for the command to finish or the connection to drop
	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		return ctx.Err()
	case <-errCh:
		// If either read or write loop fails, terminate the shell process
		cmd.Process.Kill()
	}

	return cmd.Wait()
}

func (p *ShellRequest) Type() uint8 {
	return MsgClientShellRequest
}

func (p *ShellRequest) Unmarshal(data []byte) error {
	parsed, err := ParseShellRequest(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func ParseShellRequest(data []byte) (*ShellRequest, error) {
	sr := &ShellRequest{}
	offset := 0

	// 1. Bounds check: RequestID (4) + UsernameLen (1) = 5 bytes minimum
	if len(data) < offset+5 {
		return nil, ErrMalformedControlPacket
	}
	sr.RequestID = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	sr.UsernameLen = data[offset]
	offset += 1

	// 2. Read User
	if len(data) < offset+int(sr.UsernameLen) {
		return nil, ErrMalformedControlPacket
	}
	sr.User = cloneBytes(data[offset : offset+int(sr.UsernameLen)]) // copy: detach from reused rdBuf
	offset += int(sr.UsernameLen)

	// 3. Bounds check: ShellLen (2)
	if len(data) < offset+2 {
		return nil, ErrMalformedControlPacket
	}
	sr.ShellLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 4. Read Shell
	if len(data) < offset+int(sr.ShellLen) {
		return nil, ErrMalformedControlPacket
	}
	sr.Shell = cloneBytes(data[offset : offset+int(sr.ShellLen)]) // copy: detach from reused rdBuf
	offset += int(sr.ShellLen)

	// 5. Bounds check: Row (2) + Cols (2) = 4 bytes
	if len(data) < offset+4 {
		return nil, ErrMalformedControlPacket
	}
	sr.Row = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	sr.Cols = binary.BigEndian.Uint16(data[offset : offset+2])

	return sr, nil
}

func (sr *ShellRequest) Marshal() []byte {
	// Size: ID(4) + UserLen(1) + User + ShellLen(2) + Shell + Row(2) + Cols(2)
	// Total base size = 11 bytes + variable payload sizes
	totalSize := 4 + 1 + len(sr.User) + 2 + len(sr.Shell) + 2 + 2
	out := make([]byte, totalSize)
	offset := 0

	// Write RequestID (4 bytes)
	binary.BigEndian.PutUint32(out[offset:], sr.RequestID)
	offset += 4

	// Write UsernameLen (1 byte)
	out[offset] = sr.UsernameLen
	offset += 1

	// Write User bytes
	offset += copy(out[offset:], sr.User)

	// Write ShellLen (2 bytes)
	binary.BigEndian.PutUint16(out[offset:], sr.ShellLen)
	offset += 2

	// Write Shell bytes
	offset += copy(out[offset:], sr.Shell)

	// Write Row (2 bytes)
	binary.BigEndian.PutUint16(out[offset:], sr.Row)
	offset += 2

	// Write Cols (2 bytes)
	binary.BigEndian.PutUint16(out[offset:], sr.Cols)

	return out
}

func (p *ShellRequestResponse) Type() uint8 {
	return MsgServerShellReqResponse
}

func (p *ShellRequestResponse) Unmarshal(data []byte) error {
	parsed, err := ParseShellRequestResponse(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func ParseShellRequestResponse(data []byte) (*ShellRequestResponse, error) {
	// Bounds check: RequestID (4) + ChannelID (4) + Success (1) = 9 bytes
	if len(data) < 9 {
		return nil, ErrMalformedControlPacket
	}

	return &ShellRequestResponse{
		RequestID: binary.BigEndian.Uint32(data[0:4]),
		ChannelID: binary.BigEndian.Uint32(data[4:8]),
		Success:   data[8] == 1,
	}, nil
}

func (srr *ShellRequestResponse) Marshal() []byte {
	out := make([]byte, 9)

	binary.BigEndian.PutUint32(out[0:4], srr.RequestID)
	binary.BigEndian.PutUint32(out[4:8], srr.ChannelID)

	if srr.Success {
		out[8] = 1
	} else {
		out[8] = 0
	}

	return out
}

// getSysCredentials looks up the system UID, GID, and all supplementary groups
func getSysCredentials(u *user.User) (*syscall.Credential, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("bad uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("bad gid %q: %w", u.Gid, err)
	}

	gids, err := u.GroupIds()
	var groups []uint32
	if err == nil {
		for _, g := range gids {
			if id, err := strconv.ParseUint(g, 10, 32); err == nil {
				groups = append(groups, uint32(id))
			}
		}
	}

	return &syscall.Credential{
		Uid:    uint32(uid),
		Gid:    uint32(gid),
		Groups: groups,
	}, nil
}

// sanitizeEnv filters out the old parent process environment variables (like root's HOME)
// and injects the new user's environment variables.
func sanitizeEnv(env []string, overrides map[string]string) []string {
	var result []string
	for _, val := range env {
		parts := strings.SplitN(val, "=", 2)
		if len(parts) == 2 {
			// Skip old values that we want to override
			if _, exists := overrides[parts[0]]; exists {
				continue
			}
		}
		result = append(result, val)
	}
	// Append the correct new values
	for k, v := range overrides {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

func (p *WindowResize) Unmarshal(data []byte) error {
	parsed, err := ParseWindowResize(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func (p *WindowResize) Type() uint8 {
	return MsgClientPTYResize
}

func ParseWindowResize(data []byte) (*WindowResize, error) {
	if len(data) < 8 {
		return nil, ErrMalformedControlPacket
	}
	return &WindowResize{
		ChannelID: binary.BigEndian.Uint32(data[0:4]),
		Rows:      binary.BigEndian.Uint16(data[4:6]),
		Cols:      binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

func (wr *WindowResize) Marshal() []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[0:4], wr.ChannelID)
	binary.BigEndian.PutUint16(out[4:6], wr.Rows)
	binary.BigEndian.PutUint16(out[6:8], wr.Cols)
	return out
}
