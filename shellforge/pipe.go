package shellforge

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/creack/pty"
)

// pipe or Channel represents a single multiplexed stream inside our secure session.
// It implements io.ReadWritecloser.
type PipeStream struct {
	id      uint32 //== channel id
	session *Session

	mu       sync.Mutex
	notEmpty *sync.Cond // signaled when data arrives or the pipe closes
	ring     []byte     // preallocated ring storage
	r        int        // index of the next byte to read
	w        int        // index of the next byte to write
	size     int        // bytes currently buffered (0 <= size <= len(ring))
	closed   bool

	fileMu sync.Mutex
	file   *os.File
}

func NewPipe(id uint32, s *Session) *PipeStream {
	p := &PipeStream{
		id:      id,
		session: s,
		ring:    make([]byte, PIPE_RING_CAPACITY),
	}
	p.notEmpty = sync.NewCond(&p.mu)
	return p
}

func (p *PipeStream) push(data []byte) int {
	n := len(p.ring) - p.size // free space
	if n > len(data) {
		n = len(data)
	}
	if n == 0 {
		return 0
	}

	// First segment: from w up to the physical end of the ring.
	first := copy(p.ring[p.w:], data[:n])
	// Second segment (wraparound): continue at the start of the ring.
	if first < n {
		copy(p.ring, data[first:n])
	}

	p.w = (p.w + n) % len(p.ring)
	p.size += n
	return n
}

func (p *PipeStream) pop(b []byte) int {
	n := p.size
	if n > len(b) {
		n = len(b)
	}
	if n == 0 {
		return 0
	}

	// First segment: from r up to the physical end of the ring.
	first := copy(b[:n], p.ring[p.r:])
	// Second segment (wraparound): continue at the start of the ring.
	if first < n {
		copy(b[first:n], p.ring)
	}

	p.r = (p.r + n) % len(p.ring)
	p.size -= n
	return n
}

func (p *PipeStream) Read(b []byte) (int, error) {
	p.mu.Lock()
	for p.size == 0 && !p.closed {
		p.notEmpty.Wait()
	}
	if p.size == 0 {
		// Closed and fully drained.
		p.mu.Unlock()
		return 0, io.EOF
	}

	n := p.pop(b)
	p.mu.Unlock()

	// Credit the peer for the bytes we just removed from the ring. Done OUTSIDE
	// p.mu (returnRecvWindow may write a WindowAdjust to the socket) and off the
	// shared read loop, so a slow control write can never deadlock delivery.
	if n > 0 && p.session != nil {
		_ = p.session.returnRecvWindow(p.id, n)
	}
	return n, nil
}

func (p *PipeStream) Write(b []byte) (int, error) {
	mt := MsgClientChanneledData
	if p.session.isDaemon {
		mt = MsgServerChanneledData
	}
	// SendChannelData blocks HERE (in the caller's goroutine, e.g. the PTY->pipe
	// copy) when the peer's receive window is exhausted -- exactly the desired
	// backpressure, applied off the shared read loop.
	if err := p.session.SendChannelData(mt, p.id, b); err != nil {
		return 0, err
	}
	return len(b), nil

}

func (p *PipeStream) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		// Wake EVERY waiter on both conditions: blocked Feeds return
		// io.ErrClosedPipe, blocked Reads drain leftovers and then hit EOF.
		p.notEmpty.Broadcast()

	}
	p.mu.Unlock()
	return nil
}

// Feed is called by the main Event Loop when a packet arrives for this Channel ID
func (p *PipeStream) Feed(data []byte) (int, error) {

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, io.ErrClosedPipe
	}

	free := len(p.ring) - p.size
	if len(data) > free {
		// Never block the reader: report the violation instead.
		return 0, ErrFlowControlWindowOverflow
	}

	n := p.push(data)
	if n > 0 {
		p.notEmpty.Signal()
	}

	return n, nil
}

// SetPTY associates the active OS PTY file with this Pipe.
func (p *PipeStream) SetPTY(f *os.File) {
	p.fileMu.Lock()
	p.file = f
	p.fileMu.Unlock()
}

// Resize forcefully changes the window dimensions of the active PTY.
func (p *PipeStream) Resize(rows, cols uint16) error {
	p.fileMu.Lock()
	defer p.fileMu.Unlock()

	if p.file == nil {
		return errors.New("no active PTY to resize")
	}

	// This sends the SIGWINCH signal directly to the remote bash process!
	return pty.Setsize(p.file, &pty.Winsize{Rows: rows, Cols: cols})
}
