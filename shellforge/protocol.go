package shellforge

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/the-mhdi/wireforge/tcp"
)

var ErrCanNotParseMalformedPacket = errors.New("ErrCanNotParseMalformedPacket")

const MAX_PAYLOAD_LEN uint32 = 64 * 1024                       //defu 64kb
const MAX_PACKET_LEN uint32 = (MAX_PAYLOAD_LEN + 5 + 512 + 64) //64 * 1024 + 4+1+...+max255 + max 64byte
const MIN_PACKET_LEN uint32 = 4                                // Minimum packet size to prevent abuse (e.g., empty packets)
const MAX_AUTH_RETRY uint8 = 5

// PIPE_BUFFER_SIZE uint32        = (4 * 1024) //4kb

// We partition the 32-bit ID space using the top bit, and both peers agree on
// the full 32-bit ID (namespace bit included) on the wire:
//   - server-initiated IDs: high bit CLEAR (0x0000_0001 .. 0x7FFF_FFFF)
//   - client-initiated IDs: high bit SET   (0x8000_0001 .. 0xFFFF_FFFF)
const ClientChannelIDBit uint32 = 1 << 31

const MAX_WAIT_FOR_CHAN_CONFIRM = 5 * time.Second
const SESSION_DEADLINE_DEDAULT = 15 * time.Minute
const SESSION_HANDSHAKE_DEADLINE_DEDAULT = 1 * time.Minute

const CHANNEL_RING_CAPACITY = 5 * 1024 * 1024 // 2 MB
const INITIAL_WINDOW uint32 = CHANNEL_RING_CAPACITY
const WINDOW_ADJUST_THRESHOLD uint32 = INITIAL_WINDOW / 8
const MAX_CHANNEL_DATA_LEN = MAX_PAYLOAD_LEN - (4 + 4)
const WINDOW_IDLE_FLUSH_MIN uint32 = MAX_CHANNEL_DATA_LEN

const (
	AuthMethodPassword  uint8 = 0x01 // 1 << 0 (0000 0001) - Password/PAM
	AuthMethodPublicKey uint8 = 0x02 // 1 << 1 (0000 0010) - Raw Ed25519
	AuthMethodPKI       uint8 = 0x04 // 1 << 2 (0000 0100) - X.509 Certificate
)

const (
	// Encryption Ciphers
	CipherChaCha20Poly1305 uint16 = 0x0001 //16byte auth tag
	CipherAES256GCM        uint16 = 0x0002 //16byte gcm tag
	CipherAES128GCM        uint16 = 0x0003 //16byte gcm tag

	//supported Key Exchange (KEX) Algorithms
	KexX25519               uint16 = 0x1000
	KexHybridX25519MLKEM768 uint16 = 0x2000
)

// Message Types
// format: Msg + source + type
const (
	MsgNilPacket                = 0
	MsgClientInit               = 10
	MsgServerInit               = 11 // if MsgClientInit accepted // server sends a MsgServerInit String then client can starts handshake prosses by sending client hello
	MsgServerClientInitRejected = 12 //server closes the connection imediately while sends a WireforgePacket with MessageType 12 to the client
	MsgServerClientInitInvalid  = 13

	MsgServerClientHelloMalformed       = 14
	MsgServerClientHelloRejected        = 15
	MsgClientHello                uint8 = 1
	MsgServerHello                uint8 = 2
	MsgServerPublicInvalidLen           = 3

	MsgServerPublicInvalid                   = 4
	MsgServerKeyGenProblem                   = 5
	MsgServerSharedSecertGenError            = 6
	MsgServerExpectedClientHello             = 7
	MsgServerEncryptionHandShakeFailed       = 16
	MsgServerUnsupportedKEX                  = 17
	MsgServerUnsupportedCipher               = 18
	MsgClientListenRequest             uint8 = 100 //== MsgClientListenAndForward
	MsgServerListenResponse            uint8 = 101
	MsgServerListernerInUse            uint8 = 154
	MsgServerInvalidSignature                = 155

	MsgClientForwardRequest  uint8 = 110
	MsgServerForwardResponse uint8 = 111
	MsgServerFailedToDial    uint8 = 112

	MsgClientOpenChannel uint8 = 50

	MsgServerNewChannelOpened uint8 = 51
	MsgClientNewChannelOpened uint8 = 52

	MsgServerForwardReqMalformed    uint8 = 166
	MsgServerChannelUnknownOrClosed uint8 = 219

	MsgServerChanneledData      uint8 = 200
	MsgClientChanneledData      uint8 = 201
	MsgServerChannelClosed      uint8 = 202
	MsgClientChannelClosed      uint8 = 203
	MsgChanneledData                  = 204
	MsgClientChannelOpenConfirm       = 205
	MsgServerChannelOpenConfirm       = 206
	MsgClientChanDataMalformed  uint8 = 207
	MsgServerChanDataMalformed  uint8 = 208
	MsgChannelClosed                  = 209
	MsgServerOpenChannel              = 210
	MsgServerOpenLogChannel           = 211

	MsgClientShellRequest              uint8 = 20
	MsgServerShellReqResponse          uint8 = 21
	MsgServerFailedToOpenShell               = 22
	MsgClientENVCreate                 uint8 = 26
	MsgServerENVCreateNotAllowed             = 27
	MsgServerFailedToOpenTempShell           = 28
	MsgServerFailedToCreateTempSysUser       = 29
	MsgServerENVRequestResponse              = 23
	MsgServerFailedToCreateContainer         = 38
	MsgClientConnectContainer                = 39
	MsgClientGetContainerShell               = 44
	MsgClientContainerCommandExec            = 48
	MsgClientContainerLog                    = 49
	MsgClientContainerOpRequest              = 47
	MsgServerContainersListResponse          = 40
	MsgServerENVCreated                      = 41
	MsgServerInvalidEnvType                  = 42
	MsgServerNoContainer                     = 43
	MsgServerRequestMalformed          uint8 = 151

	MsgServerError uint8 = 60
	MsgClientError uint8 = 61

	MsgClientKeepAlive uint8 = 255

	MsgClientResumeProof uint8 = 45

	MsgChanIDRenegotiationRequest uint8 = 46

	MsgserverUnsupportedKexCipher = 123

	MsgClientSessionClosed uint8 = 249
	MsgServerSessionClosed uint8 = 250

	MsgClientPTYResize = 25

	/////////////////////////////////////////
	MsgServerAuthResponse           uint8 = 30
	MsgServerAuthSuccess            uint8 = 31
	MsgServerAuthFailed             uint8 = 32
	MsgServerAuthFailedTooManyRetry       = 37
	MsgClientAuthPassword           uint8 = 34 // Password / PAM
	MsgClientAuthPKI                uint8 = 33 // PKI (X.509 Cert)
	MsgClientAuthPub                uint8 = 35
	MsgServerPassAuthFaild          uint8 = 36

	MsgServer = 8
	MsgClient = 9

	MsgServerOpenReadChannel = 212
	MsgWindowAdjust          = 24
)

// 4+1+...+max255 + max 64byte so max packet len is = payload + all this so payload is max packet len
type PacketFrame struct {
	PacketLength uint32

	PaddingLength uint8
	Payload       []byte
	Padding       []byte
	MAC           []byte //not used just for beauty
}

type Payload struct {
	MessageType uint8
	Data        []byte //clienthello, etc ..
}

// represents an acctive connection between a client and server,and server and client
type Session struct {
	ID   []byte
	User string // Stores the validated username // session.AuthorizedUser

	isDaemon bool     // 1=daemon , 0 = client
	conn     net.Conn //connection between server <-> client

	//streamIDCounter atomic.Uint32
	//activeStreamMu  sync.RWMutex
	Stream  *stream
	shells  map[uint32]*Shell //map if channels to their shells on one session
	shellMu sync.Mutex
	// Multiplexing
	//flows   map[uint32]*chanFlow
	//flowsMu sync.Mutex

	//channelCounter       atomic.Uint32
	//activeChannelsMu     sync.RWMutex
	//activeChannels       map[uint32]*channel  //map[chanID]*pipe map[chanID]net.conn  //connection between server/client and their users/io devices
	//channelOpenConfirmed map[uint32]chan bool // Tracks which channels have been confirmed open by client
	//ConfirmChannelsMu    sync.RWMutex
	// Cryptography
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	writeSeq atomic.Uint64 // Tracks packets sent
	readSeq  atomic.Uint64 // Tracks packets received

	rdLen       [4]byte // stack-ish, no heap alloc
	rdNonce     []byte  // allocated once == decrypter.NonceSize()
	rdBuf       []byte  // reused, cap == MAX_PACKET_LEN
	readerOwner atomic.Int32

	writeMu sync.Mutex // Serializes seq++ -> Seal -> conn.Write so concurrent writers can't reuse a nonce or interleave frames
	wrNonce []byte
	wrPlain []byte
	wrOut   []byte

	authMethod uint8  //publicKey, Password, PKI
	PublicKey  []byte // 32 bytes (Ed25519) //used for session resume proof]

	forwardMap map[string]string // Maps Remote Requested Port -> Local Target Port
	forwardMu  sync.RWMutex
	listeners  []*tcp.Listener

	mu        sync.Mutex // Protects the TCP connection swap for session resume and close
	closeOnce sync.Once
	stopping  atomic.Bool
	IsAlive   bool
	Closed    chan struct{} // Signals when the session is closed (used by Dialer to unblock)

	deadlineMu    sync.Mutex  // guards the session-wide deadline timer below
	deadlineTimer *time.Timer // fires s.Close() when the deadline expires
	deadlineGen   uint64      // invalidates stale timers on re-arm/clear

}

func NewSession(conn net.Conn) *Session {
	s := &Session{
		conn: conn,
		//	activeChannels:       make(map[uint32]io.ReadWriteCloser),
		//flows:                make(map[uint32]*chanFlow),
		//channelOpenConfirmed: make(map[uint32]chan bool, 1),
		shells:     make(map[uint32]*Shell),
		forwardMap: make(map[string]string),
		Closed:     make(chan struct{}),
		IsAlive:    true,
	}

	s.Stream = NewStream(s)
	return s
}

func (s *Session) NewShell(channelid uint32) *Shell {
	s.shellMu.Lock()
	defer s.shellMu.Unlock()
	sh := newShell(channelid)
	s.shells[channelid] = sh
	return sh

}

func (s *Session) GetShell(channelid uint32) *Shell {
	s.shellMu.Lock()
	defer s.shellMu.Unlock()
	if shell, ok := s.shells[channelid]; ok {
		return shell
	}
	return nil
}

func (s *Session) DeleteShell(channelid uint32) {
	s.shellMu.Lock()
	defer s.shellMu.Unlock()
	delete(s.shells, channelid)

}
func (s *Session) ReadPacket() (*PacketFrame, error) {

	if !s.readerOwner.CompareAndSwap(0, 1) {
		return nil, errors.New("[READ ERROR] concurrent ReadPacket — one-reader invariant violated")
	}
	defer s.readerOwner.Store(0)

	conn := s.getConn()
	if conn == nil {
		return nil, errors.New("session has no active connection")
	}

	if _, err := io.ReadFull(conn, s.rdLen[:]); err != nil {
		return nil, err
	}
	pktLen := binary.BigEndian.Uint32(s.rdLen[:])
	if pktLen > MAX_PACKET_LEN {
		return nil, fmt.Errorf("packet too large: %d", pktLen)
	}
	if pktLen < MIN_PACKET_LEN {
		return nil, errors.New("packet too short")
	}

	if cap(s.rdBuf) < int(pktLen) {
		s.rdBuf = make([]byte, MAX_PACKET_LEN) // one-time, then reused
	}
	dataBuf := s.rdBuf[:pktLen]
	if _, err := io.ReadFull(conn, dataBuf); err != nil {
		return nil, err
	}

	var plaintext []byte
	if s.decrypter != nil {
		if s.rdNonce == nil {
			s.rdNonce = make([]byte, s.decrypter.NonceSize())
		}
		binary.BigEndian.PutUint64(s.rdNonce[len(s.rdNonce)-8:], s.readSeq.Load())
		s.readSeq.Add(1)
		var err error
		plaintext, err = s.decrypter.Open(dataBuf[:0], s.rdNonce, dataBuf, s.rdLen[:])
		if err != nil {
			return nil, fmt.Errorf("decryption/MAC failure (tampered packet): %w", err)
		}
	} else {
		plaintext = dataBuf
	}

	// 4. Parse the unencrypted block
	if len(plaintext) < 1 {
		return nil, errors.New("packet too short, missing padding length")
	}

	padLen := plaintext[0]
	if int(padLen)+1 > len(plaintext) {
		return nil, errors.New("invalid padding length: exceeds packet size")
	}

	payload := plaintext[1 : len(plaintext)-int(padLen)]
	padding := plaintext[len(plaintext)-int(padLen):]

	// A well-formed packet always carries at least the 1-byte message type as
	// the first payload byte. Reject empty payloads here at the framing layer so
	// every downstream handler can safely read pkt.Payload[0] without an
	// index-out-of-range panic. This path is reachable pre-authentication (the
	// Phase 1 init read), and an unrecovered panic in a per-connection goroutine
	// would otherwise crash the ENTIRE daemon process (remote DoS).
	if len(payload) < 1 {
		return nil, errors.New("packet too short, missing message type byte")
	}

	return &PacketFrame{
		PacketLength:  pktLen,
		PaddingLength: padLen,
		Payload:       payload,
		Padding:       padding,
		MAC:           nil, // AEAD handled the MAC internally!
	}, nil
}

// WritePacket frames the payload, encrypts it, and sends it over the TCP socket.
func (s *Session) WritePacket(msgType uint8, packet Packet) error {

	if packet == nil {
		return s.WritePacketRaw(msgType, nil)
	}

	if p, ok := packet.(*Channel); ok {
		if msgType == MsgServerChanneledData {
			return s.SendChannelData(MsgServerChanneledData, p.ChannelID, p.Data)
		}

		if msgType == MsgClientChanneledData {
			return s.SendChannelData(MsgClientChanneledData, p.ChannelID, p.Data)
		}
	}

	return s.WritePacketRaw(msgType, packet.Marshal())
}

func (s *Session) WritePacketRaw(msgType uint8, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	payload := append([]byte{msgType}, data...)

	// 1. Calculate padding (Pad out to nearest 8-byte boundary to hide traffic signatures)
	padLen := uint8(8 - ((len(payload) + 1) % 8))

	// 2. Build the Plaintext block: [PadLen] + [Payload] + [Padding]
	plaintextLen := 1 + len(payload) + int(padLen)
	plaintext := make([]byte, plaintextLen)

	plaintext[0] = padLen
	copy(plaintext[1:], payload)

	// Fill the padding section with secure random bytes
	if padLen > 0 {
		_, err := rand.Read(plaintext[1+len(payload):])
		if err != nil {
			return err
		}
	}

	var out []byte

	// 3. Encrypt if active
	if s.encrypter != nil {
		// Create the Nonce using the Write Sequence Number
		nonce := make([]byte, s.encrypter.NonceSize())
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], s.writeSeq.Load())
		s.writeSeq.Add(1)

		// AEAD adds a 16-byte MAC tag to the end of the ciphertext.
		// Our total wire length is plaintext length + 16 overhead bytes.
		pktLen := uint32(len(plaintext) + s.encrypter.Overhead())

		out = make([]byte, 4, 4+pktLen)
		binary.BigEndian.PutUint32(out[0:4], pktLen)

		// Seal encrypts the plaintext and appends the MAC tag.
		// Again, we pass out[0:4] (The Length Header) as AAD to protect it from tampering.
		encrypted := s.encrypter.Seal(nil, nonce, plaintext, out[0:4])

		out = append(out, encrypted...)
	} else {
		// Unencrypted output
		pktLen := uint32(len(plaintext))
		out = make([]byte, 4+pktLen)
		binary.BigEndian.PutUint32(out[0:4], pktLen)
		copy(out[4:], plaintext)
	}

	// 4. Send to the OS socket
	currentConn := s.getConn()
	if currentConn == nil {
		return errors.New("session has no active connection")
	}

	// Write to whatever the CURRENT active socket is
	_, err := currentConn.Write(out)
	return err
}

func (s *Session) writeChannelData(msgType uint8, channelID uint32, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// payload = [msgType(1)][channelID(4)][dataLen(4)][data]
	payloadLen := 1 + 8 + len(data)
	padLen := uint8(8 - ((payloadLen + 1) % 8))
	plainLen := 1 + payloadLen + int(padLen) // [padLen] + payload + padding

	if cap(s.wrPlain) < plainLen {
		s.wrPlain = make([]byte, plainLen)
	}
	p := s.wrPlain[:plainLen]
	p[0] = padLen
	p[1] = msgType
	binary.BigEndian.PutUint32(p[2:6], channelID)
	binary.BigEndian.PutUint32(p[6:10], uint32(len(data)))
	copy(p[10:10+len(data)], data) // the ONLY data copy
	if padLen > 0 {
		// Zero padding, NOT crypto/rand. This function is only ever called on the
		// encrypted channel-data hot path (s.encrypter != nil below): the padding
		// bytes are covered by the AEAD, so the ciphertext hides their content --
		// random padding adds no security here. crypto/rand.Read is a getrandom(2)
		// syscall PER PACKET; at shell/forward packet rates that syscall shows up
		// as measurable latency jitter. (The buffer is reused, so explicitly clear
		// stale bytes from previous packets.)
		clear(p[plainLen-int(padLen):])
	}

	pktLen := plainLen + s.encrypter.Overhead()
	if cap(s.wrOut) < 4+pktLen {
		s.wrOut = make([]byte, 4+pktLen)
	}
	out := s.wrOut[:4]
	binary.BigEndian.PutUint32(out[0:4], uint32(pktLen))

	if s.wrNonce == nil {
		s.wrNonce = make([]byte, s.encrypter.NonceSize())
	}
	binary.BigEndian.PutUint64(s.wrNonce[len(s.wrNonce)-8:], s.writeSeq.Load())
	s.writeSeq.Add(1)

	// Seal appends ciphertext+tag right after the 4-byte header; AAD = header.
	// dst (out[4:]) and plaintext (p) don't overlap -> valid.
	out = s.encrypter.Seal(out, s.wrNonce, p, out[0:4])
	s.wrOut = out // preserve grown backing array

	conn := s.getConn()
	if conn == nil {
		return errors.New("session has no active connection")
	}
	_, err := conn.Write(out)
	return err
}

func (s *Session) SendChannelData(msgType uint8, channelID uint32, data []byte) error {
	for len(data) > 0 {
		want := len(data)
		if want > int(MAX_CHANNEL_DATA_LEN) {
			want = int(MAX_CHANNEL_DATA_LEN) // finally enforces the frame cap too
		}
		g, err := s.Stream.acquireSendWindowUpTo(channelID, want)
		if err != nil {
			return err
		}
		if err := s.writeChannelData(msgType, channelID, data[:g]); err != nil {
			return err
		}
		data = data[g:]
	}
	return nil
}

func (s *Session) AttachNewSocket(newConn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If the old connection is still lingering in memory, forcefully close it.
	// This ensures any background goroutines stuck in conn.Write() immediately
	// get a "use of closed network connection" error and unblock!
	if s.conn != nil {
		s.conn.Close()
	}

	// Attach the fresh, newly resumed socket
	s.conn = newConn
}
func (s *Session) closeConn() {
	if c := s.getConn(); c != nil {
		c.Close()
	}
}

// getConn is a thread-safe helper to grab the current active socket.
func (s *Session) getConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *Session) CloseWithSignal(timeout time.Duration) error {
	msgType := uint8(MsgClientSessionClosed)
	if s.isDaemon {
		msgType = MsgServerSessionClosed
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.WritePacket(msgType, nil)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			if s.isDaemon {
				log.Printf("[Log] Failed to send session-close signal to client: %v\r\n", err)
			} else {
				log.Printf("[Log] Failed to send session-close signal to server: %v\r\n", err)
			}
		}
	case <-time.After(timeout):
		log.Printf("[Log] Session-close signal timed out after %s\r\n", timeout)
	}

	log.Printf("[Log] user [%s] Session closing gracefully, sent close signal: %x\r\n", s.User, s.ID)
	return s.shutdown()
}

func (s *Session) Close() error {

	return s.shutdown()

	//return errors.New("[SESSION NOTICE] Session is being stopped, can't call close twice")
}

func (s *Session) shutdown() error {

	var closeErr error
	s.closeOnce.Do(func() {
		s.stopping.Store(true)
		s.IsAlive = false
		close(s.Closed)
		// Kill any armed deadline timer so it can't fire on a dead session.
		s.deadlineMu.Lock()
		s.deadlineGen++
		if s.deadlineTimer != nil {
			s.deadlineTimer.Stop()
			s.deadlineTimer = nil
		}
		s.deadlineMu.Unlock()
		s.closeAllChannels()
		s.mu.Lock()
		conn := s.conn
		s.mu.Unlock()
		if s.User == "" {
			if s.ID != nil {
				log.Printf("[Log] Session [%x] closed With No User\r\n", s.ID[:10])
			}
		} else {
			if s.ID != nil {
				log.Printf("[Log] user [%s] Session [%x] closed \r\n", s.User, s.ID[:10])
			}
		}
		s.Stream.Close()
		if len(s.listeners) > 0 {
			for _, ln := range s.listeners {
				ln.Close()
			}
		}

		if conn != nil {
			closeErr = conn.Close()
		}
	})
	return closeErr
}

func (s *Session) closeAllChannels() {
	s.Stream.activeChannelsMu.Lock()
	chans := make([]*channel, 0, len(s.Stream.activeChannels))
	for _, ch := range s.Stream.activeChannels {
		chans = append(chans, ch)
	}
	s.Stream.activeChannels = make(map[uint32]*channel)
	s.Stream.activeChannelsMu.Unlock()

	for _, ch := range chans {

		ch.Close()
	}
	s.Stream.closeAllFlows()
}

func (s *Session) NewChannel(sessionTie bool) (uint32, *channel) {
	return s.Stream.NewChannel(sessionTie)
}

func (s *Session) NewChannelWithID(id uint32, sessionTie bool) (*channel, bool) {
	return s.Stream.NewChannelWithID(id, sessionTie)
}
func (s *Session) GetActiveChannel(channelID uint32) (*channel, bool) {
	return s.Stream.getActiveChannel(channelID)
}

func (s *Session) SetDeadline(t time.Time) error {
	s.armDeadlineTimer(t)

	c := s.getConn()
	if c == nil {
		return net.ErrClosed
	}
	return c.SetDeadline(t)

}

// armDeadlineTimer (re)arms or clears the timer that closes the session
// when the deadline is reached. Each call supersedes the previous one:
// the generation counter guarantees a stale timer that already started
// firing becomes a no-op instead of killing a session that was granted
// more time.
func (s *Session) armDeadlineTimer(t time.Time) {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()

	s.deadlineGen++
	gen := s.deadlineGen

	if s.deadlineTimer != nil {
		s.deadlineTimer.Stop()
		s.deadlineTimer = nil
	}
	if t.IsZero() {
		return // zero time = deadline cleared
	}

	d := time.Until(t)
	if d < 0 {
		d = 0
	}
	s.deadlineTimer = time.AfterFunc(d, func() {
		s.deadlineMu.Lock()
		stale := gen != s.deadlineGen
		s.deadlineMu.Unlock()
		if stale {
			return // re-armed or cleared after this timer was scheduled
		}
		log.Printf("[Log] Session [%x] deadline reached, closing session (user=%q)\r\n", s.ID, s.User)
		s.CloseWithSignal(5 * time.Second)
	})
}
