package shellforge

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"runtime"
	"sync"
	"time"

	"go.uber.org/atomic"
)

// connection -> pipe(channel) -> read
//write -> pipe(channel) -> connection

// pipe or Channel represents a single multiplexed stream inside our secure session.
// It implements io.ReadWritecloser.

// pipe is the a connection beteen server / client , server and client communicate through pipe using channels
// so map 1 channel -> one pipe
// pipe has two ends each end reads and writes to its respective io.readerwriterS, each have an id
type stream struct {
	session              *Session
	channelCounter       atomic.Uint32
	activeChannelsMu     sync.RWMutex
	activeChannels       map[uint32]*channel
	closed               bool
	channelOpenConfirmed map[uint32]chan bool // Tracks which channels have been confirmed open by client
	ConfirmChannelsMu    sync.RWMutex

	flows   map[uint32]*chanFlow
	flowsMu sync.Mutex

	//ring     *SpscRingBuffer
	ring     *RingBuffer
	notEmpty *sync.Cond // signaled when data arrives or the pipe closes
	mu       sync.Mutex

	idLen   [4]byte
	dataLen [4]byte
}

func NewStream(s *Session) *stream {
	p := &stream{
		session:              s,
		activeChannels:       make(map[uint32]*channel),
		flows:                make(map[uint32]*chanFlow),
		channelOpenConfirmed: make(map[uint32]chan bool, 1),
	}
	p.notEmpty = sync.NewCond(&p.mu)
	p.ring = NewRing(PIPE_RING_CAPACITY).SetBlocking(true).SetOverwrite(false)
	go p.dispatcher()

	return p
}

func (p *stream) dispatcher() {

	for {
		ch := &Channel{}
		//	= binary.BigEndian.Uint32(data[offset : offset+4])
		n, err := p.ring.Read(p.idLen[:])
		if n != 4 {
			p.ring.Reset()
			continue
		}
		if err != nil {
			log.Println(err)
			p.ring.Reset()
			continue
		}
		ch.ChannelID = binary.BigEndian.Uint32(p.idLen[:])

		n, err = p.ring.Read(p.dataLen[:])

		if n != 4 {
			p.ring.Reset()
			continue
		}
		if err != nil {
			log.Println(err)
			p.ring.Reset()
			continue
		}
		ch.DataLen = binary.BigEndian.Uint32(p.dataLen[:])

		data, err := p.ring.ReadExactly(int(ch.DataLen))
		if err != nil {
			p.ring.Reset()
			continue
		}

		if chann, ok := p.getActiveChannel(ch.ChannelID); ok {
			_, err := chann.Feed(data)
			if err != nil {
				log.Println(err)
				log.Printf("channel %d feed failed: %v; closing", chann.id, err)
				p.session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: chann.id}))
				chann.Close()

			}
		} else {
			log.Printf("Received Data with unknown Channel ID")
			continue
			//p.session.WritePacket(MsgServerChannelUnknownOrClosed, nil)
		}

		/*
				if p.closed {
					return
				}
				ch, err := p.ring.Dequeue()
				if err == ErrIsEmpty {
					runtime.Gosched()
					continue
				}
				if c, ok := ch.(*Channel); ok {
					if chann, ok := p.getActiveChannel(c.ChannelID); ok {
						_, err := chann.Feed(c.Data)
						if err != nil {
							log.Println(err)
							log.Printf("channel %d feed failed: %v; closing", chann.id, err)
							p.session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: chann.id}))
							chann.Close()

						}
					} else {
						log.Printf("Received Data with unknown Channel ID: %d", chann.id)
						//p.session.WritePacket(MsgServerChannelUnknownOrClosed, nil)
					}
				}
			}
		*/
	}
}

// Feed is called by the main Event Loop when a packet arrives for this Channel ID
func (p *stream) Feed(data []byte) error {
	if p.closed {
		return io.ErrClosedPipe
	}
	_, err := p.ring.Write(data)
	if err == nil {
		runtime.Gosched()
		//p.notEmpty.Signal()
	}
	return err
}
func (p *stream) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil // idempotent — the leaked stdin goroutine will call it again
	}
	p.closed = true
	p.notEmpty.Broadcast() // wake any Read blocked on an empty ring
	p.mu.Unlock()
	return nil
}

func (s *stream) getActiveChannel(id uint32) (*channel, bool) {
	s.activeChannelsMu.RLock()
	defer s.activeChannelsMu.RUnlock()
	ch, exists := s.activeChannels[id]
	return ch, exists
}

func (s *stream) addActiveChannel(id uint32, c *channel) {
	s.activeChannelsMu.Lock()
	defer s.activeChannelsMu.Unlock()
	if s.activeChannels == nil {
		s.activeChannels = make(map[uint32]*channel)
	}
	s.activeChannels[id] = c
}
func (s *stream) addActiveChannelWithConfirmation(id uint32, c *channel) bool {

	s.ConfirmChannelsMu.Lock()
	if s.channelOpenConfirmed == nil {
		s.channelOpenConfirmed = make(map[uint32]chan bool, 1)
	}
	s.channelOpenConfirmed[id] = make(chan bool, 1)
	s.ConfirmChannelsMu.Unlock()

	log.Printf("LogStream created and added to active channel %d", id)
	co := &ChannelOpen{
		ChannelID: id,
	}

	err := s.session.WritePacket(MsgServerOpenLogChannel, co)
	if err != nil {
		return false
	}
	//wait for confirmation msg :MsgClientChannelOpenConfirm or time out
	select {
	case open := <-s.channelOpenConfirmed[id]:
		if open {
			s.activeChannelsMu.Lock()
			if s.activeChannels == nil {
				s.activeChannels = make(map[uint32]*channel)
			}
			s.activeChannels[id] = c
			s.activeChannelsMu.Unlock()
			log.Printf("client confirmed channel opne ID: %d", id)
			return true
		} else {
			log.Printf("client couldnt open channel ID: %d", id)
			return false
		}

	case <-time.After(MAX_WAIT_FOR_CHAN_CONFIRM):
		log.Printf("channel Confirmation Timeout,  ID : %d\n", id)
		return false
	}

}
func (s *stream) addActiveChannelIfAbsent(id uint32, c *channel) bool {
	s.activeChannelsMu.Lock()
	defer s.activeChannelsMu.Unlock()
	if s.activeChannels == nil {
		s.activeChannels = make(map[uint32]*channel)
	}
	if _, exists := s.activeChannels[id]; exists {
		return false
	}
	s.activeChannels[id] = c
	return true
}
func (s *stream) deleteActiveChannel(id uint32) {
	s.activeChannelsMu.Lock()
	delete(s.activeChannels, id)
	s.activeChannelsMu.Unlock()
	s.closeFlow(id) // wake any blocked sender; drop credit state
}

func (s *stream) IncrementChannelID() uint32 {
	return s.channelCounter.Add(1) &^ ClientChannelIDBit
}

// IncrementClientChannelID allocates a client-initiated channel ID (top bit
// set). Only the peer that opens a channel -- the client, for `-L` local
// forwards -- calls this.
func (s *stream) IncrementClientChannelID() uint32 {
	return s.channelCounter.Add(1) | ClientChannelIDBit
}

func (s *stream) OpenComfirmed(id uint32) {
	s.ConfirmChannelsMu.RLock()
	op, ok := s.channelOpenConfirmed[id]
	s.ConfirmChannelsMu.RUnlock()
	if ok {
		select {
		case op <- true:
		default:
		} // never block the reader
	}

}

type channel struct {
	id uint32 //== channel id
	//session     *Session
	stream      *stream
	sessionTied bool

	mu       sync.Mutex
	notEmpty *sync.Cond // signaled when data arrives or the pipe closes
	ring     []byte     // preallocated ring storage
	r        int        // index of the next byte to read
	w        int        // index of the next byte to write
	size     int        // bytes currently buffered (0 <= size <= len(ring))
	closed   bool

	W io.Writer
	R io.Reader
	C io.Closer
}

func (st *stream) NewChannel(sessionTie bool) (uint32, *channel) {
	p := &channel{
		id:          st.IncrementChannelID(),
		stream:      st,
		sessionTied: sessionTie,
		ring:        make([]byte, PIPE_RING_CAPACITY),
	}
	p.notEmpty = sync.NewCond(&p.mu)
	st.addActiveChannel(p.id, p)
	return p.id, p
}

func (st *stream) NewChannelWithID(id uint32, sessionTie bool) (*channel, bool) {
	p := &channel{
		id:          id,
		stream:      st,
		sessionTied: sessionTie,
		ring:        make([]byte, PIPE_RING_CAPACITY),
	}
	p.notEmpty = sync.NewCond(&p.mu)
	ok := st.addActiveChannelIfAbsent(p.id, p)
	if ok {
		return p, true
	}
	return nil, false
}
func (ch *channel) WaitForComfirmation() bool {
	if ch.stream.session.isDaemon {
		return ch.WaitForComfirmationWithMsgType(MsgServerOpenChannel)
	}

	return ch.WaitForComfirmationWithMsgType(MsgClientOpenChannel)

}

func (ch *channel) WaitForComfirmationWithMsgType(msgType uint8) bool {
	ch.stream.ConfirmChannelsMu.Lock()
	if ch.stream.channelOpenConfirmed == nil {
		ch.stream.channelOpenConfirmed = make(map[uint32]chan bool, 1)
	}
	ch.stream.channelOpenConfirmed[ch.id] = make(chan bool, 1)
	ch.stream.ConfirmChannelsMu.Unlock()

	log.Printf("awiting channel open confirmation from peer id: %d", ch.id)
	co := &ChannelOpen{
		ChannelID: ch.id,
	}

	err := ch.stream.session.WritePacket(msgType, co)
	if err != nil {
		return false
	}
	//wait for confirmation msg :MsgClientChannelOpenConfirm or time out
	select {
	case open := <-ch.stream.channelOpenConfirmed[ch.id]:
		if open {
			log.Printf("client confirmed channel opne ID: %d", ch.id)
			return true
		} else {
			log.Printf("client couldnt open channel ID: %d", ch.id)
			ch.Close()
			return false
		}

	case <-time.After(MAX_WAIT_FOR_CHAN_CONFIRM):
		log.Printf("channel Confirmation Timeout,  ID : %d\n", ch.id)
		ch.Close()
		return false
	}

}

func (p *channel) push(data []byte) int {
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

func (p *channel) pop(b []byte) int {
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

func (p *channel) Read(b []byte) (int, error) {
	p.mu.Lock()

	if p.closed && p.size == 0 {
		// Closed and fully drained.
		p.mu.Unlock()
		return 0, io.EOF
	}

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
	if n > 0 && p.stream.session != nil {
		if err := p.stream.session.Stream.returnRecvWindow(p.id, n); err != nil {
			// A lost WindowAdjust means the peer's send window shrinks
			// PERMANENTLY -- the channel slowly strangles itself and eventually
			// stalls forever. Don't hide it; the session is almost certainly
			// dying anyway, so surface it.
			log.Printf("[flow] channel %d: failed to return %d bytes of recv window: %v", p.id, n, err)
		}
	}
	return n, nil
}

func (p *channel) Write(b []byte) (int, error) {
	mt := MsgClientChanneledData
	if p.stream.session.isDaemon {
		mt = MsgServerChanneledData
	}
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	// SendChannelData blocks HERE (in the caller's goroutine, e.g. the PTY->pipe
	// copy) when the peer's receive window is exhausted -- exactly the desired
	// backpressure, applied off the shared read loop.
	if err := p.stream.session.SendChannelData(mt, p.id, b); err != nil {
		return 0, err
	}
	return len(b), nil

}

func (p *channel) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}

	p.closed = true
	p.notEmpty.Broadcast()
	p.mu.Unlock()

	p.stream.deleteActiveChannel(p.id)

	if p.sessionTied {
		p.stream.session.Close()
	}
	return nil
}

// Feed is called by the main Event Loop when a packet arrives for this Channel ID
func (p *channel) Feed(data []byte) (int, error) {

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
func (ch *channel) AddIO(IO io.ReadWriteCloser) error {

	if ch.W != nil {
		return errors.New("Chnnel already attached to an IO device")
	}
	ch.W = IO

	if ch.R != nil {
		return errors.New("Chnnel already attached to an IO device")
	}
	ch.C = IO
	if ch.R != nil {
		return errors.New("Chnnel already attached to an IO device")
	}
	ch.C = IO

	return nil
}

func (ch *channel) AttachIO(IO io.ReadWriteCloser) error {

	if ch.W != nil {
		return errors.New("Chnnel already attached to an IO device")
	}
	ch.W = IO

	if ch.R != nil {
		return errors.New("Chnnel already attached to an IO device")
	}
	ch.C = IO
	if ch.R != nil {
		return errors.New("Chnnel already attached to an IO device")
	}
	ch.C = IO
	//for write only channels :
	go func() {
		_, _ = io.Copy(IO, ch) // p.Read drains the ring and returns credits

		if ch.sessionTied {
			ch.Close()
			ch.stream.session.Close() //!!!!!!!!!
		}
	}()

	go func() {
		_, _ = io.Copy(ch, IO) // p.Read drains the ring and returns credits
		if ch.sessionTied {
			IO.Close()
			ch.stream.session.Close() //!!!!!!!!!
		}
	}()
	return nil
}

func (ch *channel) AttachWriter(w io.Writer) error {
	if ch.W != nil {
		return errors.New("Chnnel already attached to an IO witer device")
	}
	ch.W = w
	go func() {
		_, _ = io.Copy(w, ch) // p.Read drains the ring and returns credits

		if ch.sessionTied {
			ch.Close()
			ch.stream.session.Close() //!!!!!!!!!
		}
	}()
	return nil
}

func (ch *channel) AttachReader(r io.Reader) error {
	if ch.R != nil {
		return errors.New("Chnnel already attached to an IO device")
	}
	ch.R = r
	go func() {
		_, _ = io.Copy(ch, r) // p.Read drains the ring and returns credits

		if ch.sessionTied {
			ch.Close()
			ch.stream.session.Close() //!!!!!!!!!
		}
	}()
	return nil
}

func IsClientChannelID(id uint32) bool {
	return id&ClientChannelIDBit != 0
}
