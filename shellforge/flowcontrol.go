package shellforge

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"sync"
)

// =============================================================================
// Credit / window based flow control (SSH-style channel windows).
//
// Goal: a single slow consumer (a stalled shell, a saturated forwarded socket)
// must never wedge the shared per-session read loop. We achieve this with two
// coupled mechanisms:
//
//   1. A RECEIVE window per channel. We advertise (implicitly) that a peer may
//      send at most INITIAL_WINDOW unacknowledged bytes. Because that value
//      equals the receive ring capacity, PipeStream.Feed can be made totally
//      non-blocking: a compliant peer can never overflow the ring, so the read
//      loop dispatches every packet in O(1) and moves on.
//
//   2. A SEND window per channel. Before transmitting, a producer must acquire
//      credits; when the peer's window is exhausted the producer BLOCKS IN ITS
//      OWN GOROUTINE. That goroutine is the one reading the origin socket/PTY,
//      so blocking it applies natural backpressure to the data source instead
//      of freezing the mux.
//
// The receiver replenishes the sender by emitting WindowAdjust(chanID, n) as
// its local consumer drains bytes.
// =============================================================================

var ErrFlowControlWindowOverflow = errors.New(
	"flow-control window overflow: peer sent more than its advertised window",
)

// INITIAL_WINDOW is the number of unacknowledged bytes a peer may send on a
// freshly opened channel before it MUST block waiting for a WindowAdjust.
//
// It is deliberately equal to the receive ring capacity (PIPE_RING_CAPACITY).
// Because both binaries compile in the same constant, neither side has to
// advertise its window on the wire at channel-open time -- the value is
// implicit and symmetric. The invariant "advertised recv window == ring
// capacity" is exactly what lets PipeStream.Feed become non-blocking: a
// compliant sender can never put more bytes in flight than the ring can hold.

// WINDOW_ADJUST_THRESHOLD batches credit returns. Emitting one WindowAdjust per
// Read would flood the link with tiny control frames, so the receiver instead
// accumulates drained bytes and only sends a WindowAdjust once at least this
// many bytes are reclaimable. Half the window keeps the sender's pipe full
// while roughly halving control-frame volume.

// -----------------------------------------------------------------------------
// WindowAdjust wire message
// -----------------------------------------------------------------------------

// WindowAdjust tells the peer "you may send me Increment more bytes on
// ChannelID". Payload layout: [ChannelID uint32][Increment uint32] (8 bytes,
// big-endian), matching the framing style of the other control messages.
type WindowAdjust struct {
	ChannelID uint32
	Increment uint32
}

func (w *WindowAdjust) Type() uint8 { return MsgWindowAdjust }

func (w *WindowAdjust) Marshal() []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[0:4], w.ChannelID)
	binary.BigEndian.PutUint32(out[4:8], w.Increment)
	return out
}

func (w *WindowAdjust) Unmarshal(data []byte) error {
	parsed, err := ParseWindowAdjust(data)
	if err != nil {
		return err
	}
	*w = *parsed
	return nil
}

func ParseWindowAdjust(data []byte) (*WindowAdjust, error) {
	if len(data) < 8 {
		return nil, ErrCanNotParseMalformedPacket
	}
	return &WindowAdjust{
		ChannelID: binary.BigEndian.Uint32(data[0:4]),
		Increment: binary.BigEndian.Uint32(data[4:8]),
	}, nil
}

// -----------------------------------------------------------------------------
// Per-channel flow-control state
// -----------------------------------------------------------------------------

// chanFlow holds the credit accounting for one multiplexed channel.
//
//   - sendWindow: how many more bytes WE may transmit before we must block.
//     Decremented under mu when we send; replenished when a WindowAdjust
//     arrives. A blocked sender waits on cond.
//   - recvPending: bytes our local consumer has drained but not yet credited
//     back to the peer. Flushed as a WindowAdjust once it crosses the threshold.
type chanFlow struct {
	mu   sync.Mutex
	cond *sync.Cond

	sendWindow  int64
	recvPending uint32
	closed      bool
}

func newChanFlow() *chanFlow {
	f := &chanFlow{sendWindow: int64(INITIAL_WINDOW)}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// getFlow returns the flow state for id, creating it lazily. Lazy creation is
// safe precisely because the initial window is a shared constant: whichever
// side touches the channel first initialises identical accounting on both ends.
func (s *stream) getFlow(id uint32) *chanFlow {
	s.flowsMu.Lock()
	defer s.flowsMu.Unlock()
	if s.flows == nil {
		s.flows = make(map[uint32]*chanFlow)
	}
	f, ok := s.flows[id]
	if !ok {
		f = newChanFlow()
		s.flows[id] = f
	}
	return f
}

// closeFlow tears down flow state for a channel and wakes any sender blocked on
// a depleted window so it returns instead of hanging forever.
func (s *stream) closeFlow(id uint32) {
	s.flowsMu.Lock()
	f := s.flows[id]
	delete(s.flows, id)
	s.flowsMu.Unlock()
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

// closeAllFlows wakes and drops every channel's flow state. Called from
// Session.closeAllChannels during shutdown.
func (s *stream) closeAllFlows() {
	s.flowsMu.Lock()
	flows := s.flows
	s.flows = make(map[uint32]*chanFlow)
	s.flowsMu.Unlock()
	for _, f := range flows {
		f.mu.Lock()
		f.closed = true
		f.cond.Broadcast()
		f.mu.Unlock()
	}
}

// acquireSendWindow blocks the CALLING goroutine (never the shared read loop)
// until at least n send credits are available, then consumes them. This is the
// backpressure primitive: when the peer's window is exhausted, the sender's own
// producer goroutine parks here, which stops it reading from its source
// socket/PTY -- pushing congestion back to the origin instead of the mux.
//
// n is always <= MAX_PACKET_LEN (framing limit) which is < INITIAL_WINDOW, so a
// single chunk can always eventually be admitted; there is no self-deadlock.
func (s *stream) acquireSendWindow(id uint32, n int) error {
	if n <= 0 {
		return nil
	}
	if s.closed {
		return io.ErrClosedPipe
	}

	f := s.getFlow(id)
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.sendWindow < int64(n) && !f.closed {
		f.cond.Wait()
	}
	if f.closed {
		return io.ErrClosedPipe
	}
	f.sendWindow -= int64(n)
	return nil
}

// grantSendWindow is invoked from the read loop when a WindowAdjust arrives. It
// is intentionally trivial and non-blocking so the reader never stalls.
func (s *stream) grantSendWindow(id uint32, n uint32) {
	f := s.getFlow(id)
	f.mu.Lock()
	f.sendWindow += int64(n)
	f.cond.Broadcast()
	f.mu.Unlock()
}

// returnRecvWindow is called by a consumer AFTER it has drained n bytes out of
// the receive ring (PipeStream.Read, or a sink-drain goroutine). It batches the
// credit and, once the threshold is crossed, emits a WindowAdjust so the peer
// may resume sending. Runs in the consumer goroutine, never the read loop.
func (s *stream) returnRecvWindow(id uint32, n int) error {
	if n <= 0 {
		return nil
	}
	f := s.getFlow(id)
	f.mu.Lock()
	f.recvPending += uint32(n)
	var flush uint32
	if f.recvPending >= WINDOW_ADJUST_THRESHOLD {
		flush = f.recvPending
		f.recvPending = 0
	}
	f.mu.Unlock()

	if flush == 0 {
		return nil
	}
	wa := &WindowAdjust{ChannelID: id, Increment: flush}
	return s.session.WritePacket(MsgWindowAdjust, wa)
}

// -----------------------------------------------------------------------------
// Unified send + sink helpers
// -----------------------------------------------------------------------------

// SendChannelData is the SINGLE entry point for transmitting channel payload.
// It first blocks (in the caller's goroutine) until the peer's receive window
// has room for the whole chunk, then frames+encrypts+writes it via the existing
// zero-copy writeChannelData path. Every producer -- PipeStream.Write and the
// forward reader goroutines -- must go through here so no data path can bypass
// flow control.
//
// data MUST be <= MAX_PACKET_LEN; callers already chunk to bufferPool/io.Copy
// sizes (<= 64 KiB), well under both the framing limit and INITIAL_WINDOW.

// attachSinkChannel registers a receive buffer (a PipeStream) for a channel
// whose ultimate destination is a plain writer -- a forwarded net.Conn, or
// os.Stdout for log channels. The read loop feeds the PipeStream (non-blocking,
// flow-controlled); a private drain goroutine copies buffered bytes into the
// real sink and, through PipeStream.Read, returns receive-window credits as the
// sink accepts them.
//
// If closeSink is true the sink is closed when the channel ends (use for
// net.Conn); pass false for shared writers like os.Stdout.
//
// This is what removes head-of-line blocking for FORWARDS: the slow socket now
// backs up into the ring (and then, via withheld WindowAdjusts, onto the remote
// sender) instead of stalling the shared reader inside cc.Write.

// it assigns a channel id to a io file , now you can read from channel to the file or write to file to be written to channel

// *****************************

// closeChannel is the one-stop teardown for an active channel: it closes the
// registered object (a PipeStream, which unblocks its drain goroutine and
// closes the underlying sink), removes it from the active map, and tears down
// flow state (DeleteActiveChannel calls closeFlow).
func (s *stream) CloseActiveChannel(id uint32) {
	if c, ok := s.getActiveChannel(id); ok {

		//log.Printf("asdsad\n")
		_ = c.Close()
		if c.sessionTied {
			s.session.Close()
		}
		s.deleteActiveChannel(id)
	}
	log.Printf("[Session flow] channel %d closed\r\n", id)
}
