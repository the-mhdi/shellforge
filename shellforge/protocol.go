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
)

var ErrCanNotParseMalformedPacket = errors.New("ErrCanNotParseMalformedPacket")

const (
	AuthMethodPassword  uint8 = 0x01 // 1 << 0 (0000 0001) - Password/PAM
	AuthMethodPublicKey uint8 = 0x02 // 1 << 1 (0000 0010) - Raw Ed25519
	AuthMethodPKI       uint8 = 0x04 // 1 << 2 (0000 0100) - X.509 Certificate
)

const (
	// Encryption Ciphers
	CipherChaCha20Poly1305 uint16 = 0x0001
	CipherAES256GCM        uint16 = 0x0002
	CipherAES128GCM        uint16 = 0x0003

	//supported Key Exchange (KEX) Algorithms
	KexX25519               uint16 = 0x1000
	KexHybridX25519MLKEM768 uint16 = 0x2000
)

const (
	MAX_PACKET_LEN               uint32        = 64 * 1024 //defu 64kb
	MIN_PACKET_LEN               uint32        = 4         // Minimum packet size to prevent abuse (e.g., empty packets)
	MAX_AUTH_RETRY               uint8         = 5
	TEMPSHELL_SESSION_HEADER_KEY string        = "tempSession" //included in client hello headers
	TEMPSHELL_USER_PREFIX        string        = "wf_tmp_"
	PIPE_BUFFER_SIZE             uint32        = (4 * 1024)
	CLEANUP_INTERVAL             time.Duration = 5 * time.Minute
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
	MsgServerChannelUnknownOrClosed uint8 = 205

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
	MsgClientGetContainer                    = 39
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

	MsgserverUnsupportedKexCipher = 111

	MsgClientSessionClosed uint8 = 249
	MsgServerSessionClosed uint8 = 250

	MsgClientWindowResize = 25

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
)

type WireforgePacket struct {
	PacketLength uint32

	PaddingLength uint8
	Payload       []byte
	Padding       []byte
	MAC           []byte
}

type Payload struct {
	MessageType uint8
	Data        []byte //clienthello, etc ..
}

// represents an acctive connection between a client and server,and server and client
type Session struct {
	ID       []byte
	User     string // Stores the validated username // session.AuthorizedUser
	isDaemon bool   // 1=daemon , 0 = client

	conn net.Conn //connection between server <-> client

	// Multiplexing
	channelCounter   atomic.Uint32
	activeChannelsMu sync.RWMutex
	activeChannels   map[uint32]io.ReadWriteCloser //map[chanID]*pipe map[chanID]net.conn  //connection between server/client and their users/io devices

	// Cryptography
	writeSeq  uint64 // Tracks packets sent
	readSeq   uint64 // Tracks packets received
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	authMethod uint8 //publicKey, Password, PKI
	PublicKey  string
	forwardMap map[string]string // Maps Remote Requested Port -> Local Target Port
	shells     []*Shell
	mu         sync.Mutex // Protects the TCP connection swap for session resume and close
	closeOnce  sync.Once

	Closed chan struct{} // Signals when the session is closed (used by Dialer to unblock)
}

func NewSession(conn net.Conn) *Session {
	return &Session{
		conn:           conn,
		activeChannels: make(map[uint32]io.ReadWriteCloser),
		forwardMap:     make(map[string]string),
		Closed:         make(chan struct{}),
	}
}

func (s *Session) ReadPacket() (*WireforgePacket, error) {

	currentConn := s.getConn()

	if currentConn == nil {
		return nil, errors.New("session has no active connection")
	}
	// 1. Read the 4-byte Length Header
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(currentConn, lenBuf); err != nil {
		return nil, err
	}
	pktLen := binary.BigEndian.Uint32(lenBuf)

	// Protect against massive malicious packets
	if pktLen > MAX_PACKET_LEN {
		return nil, fmt.Errorf("packet too large: %d", pktLen)
	}

	if pktLen < MIN_PACKET_LEN {
		return nil, errors.New("packet too short, missing padding length")
	}

	// 2. Read the rest of the packet (Ciphertext + MAC)
	dataBuf := make([]byte, pktLen)
	if _, err := io.ReadFull(s.conn, dataBuf); err != nil {
		return nil, err
	}

	var plaintext []byte

	// 3. Decrypt the block if we have an active cipher
	if s.decrypter != nil {
		// Create the 12-byte Nonce using the Read Sequence Number
		nonce := make([]byte, s.decrypter.NonceSize())
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], s.readSeq)
		s.readSeq++

		// Open automatically decrypts the data AND verifies the MAC signature.
		// We pass lenBuf as 'AAD' (Associated Data). If a hacker alters the 4-byte
		// length header in transit, Open() will instantly fail and drop the packet!
		var err error
		plaintext, err = s.decrypter.Open(nil, nonce, dataBuf, lenBuf)
		if err != nil {
			return nil, fmt.Errorf("decryption/MAC failure (tampered packet): %w", err)
		}
	} else {
		plaintext = dataBuf // Unencrypted phase (e.g. ClientHello)
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

	return &WireforgePacket{
		PacketLength:  pktLen,
		PaddingLength: padLen,
		Payload:       payload,
		Padding:       padding,
		MAC:           nil, // AEAD handled the MAC internally!
	}, nil
}

// WritePacket frames the payload, encrypts it, and sends it over the TCP socket.
func (s *Session) WritePacket(msgType uint8, data []byte) error {
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
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], s.writeSeq)
		s.writeSeq++

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

func (s *Session) IncrementChannelID() uint32 {
	return s.channelCounter.Add(1)
}

func (s *Session) AddActiveChannel(id uint32, conn io.ReadWriteCloser) {
	s.activeChannelsMu.Lock()
	defer s.activeChannelsMu.Unlock()
	if s.activeChannels == nil {
		s.activeChannels = make(map[uint32]io.ReadWriteCloser)
	}
	s.activeChannels[id] = conn
}

func (s *Session) GetActiveChannel(id uint32) (io.ReadWriteCloser, bool) {
	s.activeChannelsMu.RLock()
	defer s.activeChannelsMu.RUnlock()
	conn, exists := s.activeChannels[id]
	return conn, exists
}

func (s *Session) DeleteActiveChannel(id uint32) {
	s.activeChannelsMu.Lock()
	defer s.activeChannelsMu.Unlock()
	delete(s.activeChannels, id)
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

// getConn is a thread-safe helper to grab the current active socket.
func (s *Session) getConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close the channel exactly once, no matter how many times Close() is called
	s.closeOnce.Do(func() {
		close(s.Closed)
	})

	for _, ch := range s.activeChannels {
		ch.Close() // forcefully closes all active channels on the session
	}
	log.Printf("[Log] user [%s] Session closed: %x\r\n", s.User, s.ID)
	return s.conn.Close()
}

func (s *Session) CloseWithSignal(timeout time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	errCh := make(chan error)

	go func() {
		if s.isDaemon {
			errCh <- s.WritePacket(MsgServerSessionClosed, nil)
		} else {
			errCh <- s.WritePacket(MsgClientSessionClosed, nil)
		}

	}()

	select {
	case err := <-errCh:
		if err != nil {
			if s.isDaemon {
				log.Printf("[Log] Failed to Send Session Close Msg to Server: %v\r\n", err)
			} else {
				log.Printf("[Log] Failed to Send Session Close Msg to Client: %v\r\n", err)
			}
		}

	case <-time.After(timeout):
	}

	close(errCh)

	// Close the channel exactly once
	s.closeOnce.Do(func() {
		close(s.Closed)
	})

	for _, ch := range s.activeChannels {
		ch.Close() // forcefully closes all active channels on the session
	}
	log.Printf("[Log] user [%s] Session closed gracefully, sent close signal to the other side: %x\r\n", s.User, s.ID)
	return s.conn.Close() //close the underlying TCP connection
}
