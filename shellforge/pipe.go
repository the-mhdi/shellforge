package shellforge

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/creack/pty"
)

// pipe or Channel represents a single multiplexed stream inside our secure session.
// It implements io.ReadWriter.
type PipeStream struct {
	id      uint32 //== channel id
	session *Session

	readCh chan []byte
	closed chan struct{}
	once   sync.Once

	ptyMu   sync.Mutex
	ptyFile *os.File
}

func NewPipe(id uint32, s *Session) *PipeStream {
	return &PipeStream{
		id:      id,
		session: s,
		readCh:  make(chan []byte, PIPE_BUFFER_SIZE), // Buffered to prevent blocking the event loop
		closed:  make(chan struct{}),
	}
}

func (p *PipeStream) Read(b []byte) (int, error) {
	select {
	case data, ok := <-p.readCh:
		if !ok {
			return 0, io.EOF
		}
		return copy(b, data), nil
	case <-p.closed:
		return 0, io.EOF
	}
}

func (p *PipeStream) Write(b []byte) (int, error) {
	// Wrap the raw bytes in our multiplexed ChannelData packet!
	cd := &ChannelData{
		ChannelID: p.id,
		Data:      b,
	}

	// Send it securely over our encrypted session
	// (MsgServerChanData or MsgClientChanData depending on who is writing)
	if p.session.isDaemon {

		err := p.session.WritePacket(MsgServerChanneledData, cd.Marshal())
		if err != nil {
			return 0, err
		}
	} else {
		err := p.session.WritePacket(MsgClientChanneledData, cd.Marshal())
		if err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (p *PipeStream) Close() error {
	p.once.Do(func() {
		close(p.closed)
		close(p.readCh)
	})
	return nil
}

// Feed is called by the main Event Loop when a packet arrives for this Channel ID
func (p *PipeStream) Feed(data []byte) (int, error) {
	select {
	case p.readCh <- data:

	default:
		// Drop data if the channel buffer is completely full to prevent deadlocks
	}
	return len(data), nil
}

// SetPTY associates the active OS PTY file with this Pipe.
func (p *PipeStream) SetPTY(f *os.File) {
	p.ptyMu.Lock()
	p.ptyFile = f
	p.ptyMu.Unlock()
}

// Resize forcefully changes the window dimensions of the active PTY.
func (p *PipeStream) Resize(rows, cols uint16) error {
	p.ptyMu.Lock()
	defer p.ptyMu.Unlock()

	if p.ptyFile == nil {
		return errors.New("no active PTY to resize")
	}

	// This sends the SIGWINCH signal directly to the remote bash process!
	return pty.Setsize(p.ptyFile, &pty.Winsize{Rows: rows, Cols: cols})
}
