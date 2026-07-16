package shellforge

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/the-mhdi/wireforge/tcp" // Go's official chacha package
)

const CLIENT_VERSION_STRING string = "SHELLFORGE-CLIENT-v0.1.0"

var ErrUnexpectedMsgType = errors.New("unexpected message type from server")

// To-do : if connection drops while shell is active, the client shell freezes because the server never got the chance to send the "Channel Closed" message. We should add a timeout and cleanup logic on the client side to handle this edge case.
// To-do: Add a "ping" message type that the client sends every 30 seconds to detect dead connections faster and trigger cleanup of pending shell requests and active channels.
// to-do: add error handling and malformed packet handling to the client event loop to prevent crashes from unexpected input
// to-do: add a max packet corruption handled to server
// todo : one Authentication failure user gets disconnected from the daemon, add retry logic on the client and daemon
// to-do: after secure chanel gets terminated, the tcp stil stays oopen , sovle it.
// to-do:add Timeout, server not responding.
// handler client close session and client close
const (
	SHELL_REQUEST_TIMEOUT = 60 * time.Second
)

type ClientConfig struct {
	PreferedKeyExAlgo       string // e.g. "x25519" or "hybrid-x25519-mlkem768" if non specified client sends both and let the server choose
	PreferedEncyptionCipher string // e.g. "aes-256-gcm" , "aes-128-gcm"or "chacha20-poly1305"
	ClientInitMessage       string

	ClientDir string //default ~/.shellforge //keys and clint config file here
	//pki auth
	ClientCert  []byte          // DER-encoded client certificate
	PrivateKeys []crypto.Signer // e.g. *ecdsa.PrivateKey or ed25519.PrivateKey

	KnownHostsPath string //defaults to <ClientDir>/known_hosts

	InsecureSkipHostKeyVerify bool // for testing only!!!!

}

// Client represents a connection to a Wireforge daemon.
// It manages the secure session, multiplexed channels, and the event loop.
type Client struct {
	conf *ClientConfig

	session *Session

	// Configuration
	DaemonAddr  string
	DaemonAuths uint8

	dialer *tcp.Dialer

	InitMsg []byte // Custom init message to send to daemon
	//ServerInitHandler func([]byte) bool
	pendingShells         map[uint32]chan *ShellRequestResponse // Tracks pending shell requests by RequestID
	pendingContainerLists map[uint32]chan *ContainersListResponse
	PendingAuthResponse   chan *AuthResponse
	AuthResCh             chan struct{}
	PendingResponse       chan PacketFrame
	// State
	mu      sync.RWMutex
	context context.Context
	cancel  context.CancelFunc
	//forwardMap map[string]string // Maps Remote Requested Port -> Local Target Port

}

func NewClientWithInitMsg(ctx context.Context, daemonAddr string, conf *ClientConfig, InitMsg string) *Client {
	// Create a robust dialer with Keep-Alives and Fast Open

	dOpts := &tcp.DialOptions{
		Verbose:              true,
		KeepAlive:            true,
		Timeout:              30 * time.Second,
		KeepAliveFirstProbe:  10 * time.Second,
		KeepAliveInterval:    10 * time.Second,
		MaxKeepAliveAttempts: 6,
		NoDelay:              true,
	}

	ctx, cancel := context.WithCancel(ctx)

	if conf == nil {
		home := os.Getenv("HOME")

		conf = &ClientConfig{
			PreferedKeyExAlgo:       "hybrid-x25519-mlkem768", // Default to high-security PQC
			PreferedEncyptionCipher: "chacha20-poly1305",
			ClientInitMessage:       CLIENT_VERSION_STRING,
			ClientDir:               filepath.Join(home, ".shellforge"),
		}
	}

	if conf.ClientDir == "" {
		home := os.Getenv("HOME")
		conf.ClientDir = filepath.Join(home, ".shellforge")
	}

	if conf.PreferedKeyExAlgo == "" {
		conf.PreferedKeyExAlgo = "hybrid-x25519-mlkem768"
	}

	if conf.PreferedEncyptionCipher == "" {
		conf.PreferedEncyptionCipher = "chacha20-poly1305"
	}

	if conf.ClientInitMessage == "" {
		conf.ClientInitMessage = CLIENT_VERSION_STRING
	}

	if InitMsg != "" {
		conf.ClientInitMessage = InitMsg
	}

	return &Client{
		DaemonAddr:            daemonAddr,
		conf:                  conf,
		InitMsg:               []byte(conf.ClientInitMessage),
		dialer:                dOpts.NewDialer(),
		pendingShells:         make(map[uint32]chan *ShellRequestResponse),
		pendingContainerLists: make(map[uint32]chan *ContainersListResponse),
		PendingAuthResponse:   make(chan *AuthResponse),
		AuthResCh:             make(chan struct{}),
		PendingResponse:       make(chan PacketFrame),
		context:               ctx,
		cancel:                cancel,
	}
}

func NewClient(ctx context.Context, daemonAddr string, conf *ClientConfig) *Client {
	return NewClientWithInitMsg(ctx, daemonAddr, conf, "")
}

func (c *Client) ConnectWithNoAuth(ctx context.Context) error {
	conn, err := c.dialer.DialWithContext(ctx, c.DaemonAddr)

	if err != nil {
		return fmt.Errorf("Failed To Connect To Server [%s]: %w", c.DaemonAddr, err)
	}

	log.Printf("TCP Connection Established With The Server [ %s ]", c.DaemonAddr)

	tempSession := NewSession(conn)
	tempSession.isDaemon = false // We are the client

	// ==========================================
	// PHASE 1: INIT EXCHANGE
	// ==========================================
	if err := tempSession.WritePacketRaw(MsgClientInit, []byte(c.conf.ClientInitMessage)); err != nil {
		return err
	}

	log.Printf("[Log] Client Init Sent: %s", string(c.InitMsg))

	initRes, err := tempSession.ReadPacket()
	if err != nil {
		return err
	}
	if initRes.Payload[0] != MsgServerInit {
		log.Printf("Unexpected Msg Type From Server expected: %d, received: %d: Not A Server INIT Msg", MsgServerInit, initRes.Payload[0])
		//tempSession.Close()
		return ErrUnexpectedMsgType

	}

	log.Printf("[Log] Server Init Received: %s", string(initRes.Payload[1:]))

	// Determine if this is a fresh connection or a resumption attempt
	c.mu.RLock()
	isResume := c.session != nil && len(c.session.ID) > 0
	c.mu.RUnlock()

	var clientPrivKey *ecdh.PrivateKey
	var pqDecapsulationKey *mlkem.DecapsulationKey768 // Our Post-Quantum private key

	// Generate 32-bytes of randomness for the HKDF salt & ResumeProof
	clientRandom := make([]byte, 32)
	rand.Read(clientRandom)

	// ==========================================
	// PHASE 2: HELLO & KEY EXCHANGE PREP
	// ==========================================

	cHello := &ClientHello{
		EncryptionSupport: true,
		ClientRandom:      clientRandom,
	}

	var KEX uint16
	var Cipher uint16

	if !isResume {
		log.Printf("[Log] New Client Session, Trying to Crafting Client Hello")
		// --- NEW CONNECTION ---
		cHello.SessLen = 0

		// 1. Map client configurations to explicit protocol choices (no negotiation) [1]
		switch strings.ToLower(c.conf.PreferedKeyExAlgo) {
		case "x25519":
			KEX = KexX25519
		default: // Default to Hybrid Post-Quantum
			KEX = KexHybridX25519MLKEM768
		}

		switch strings.ToLower(c.conf.PreferedEncyptionCipher) {
		case "aes-128-gcm":
			Cipher = CipherAES128GCM
		case "aes-256-gcm":
			Cipher = CipherAES256GCM
		default: // Default to ChaCha20
			Cipher = CipherChaCha20Poly1305
		}

		// 2. Generate key materials based on chosen KEX
		var shareKey []byte //==pubkey

		if KEX == KexHybridX25519MLKEM768 {
			// Classical part
			clientPrivKey, err = ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			x25519Pub := clientPrivKey.PublicKey().Bytes()

			// Post-Quantum part
			pqDecapsulationKey, err = mlkem.GenerateKey768()
			if err != nil {
				return fmt.Errorf("failed to generate ML-KEM key: %w", err)
			}
			pqPub := pqDecapsulationKey.EncapsulationKey().Bytes() // 1184 bytes

			// Concatenate them into a single Share Key (1216 bytes total)
			shareKey = append(x25519Pub, pqPub...)
		} else {
			// Classical X25519 Only
			clientPrivKey, err = ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			shareKey = clientPrivKey.PublicKey().Bytes() // 32 bytes
		}

		cHello.Encryption = ClientHelloEncryptionFields{
			CLIENT_KEX_ALGO:   KEX,
			CLIENT_CIPHER:     Cipher,
			ClientSharekeyLen: uint16(len(shareKey)),
			Client_Share_key:  shareKey,
		}

	} /*else {
		// --- RESUMING CONNECTION ---
		log.Printf("[Log] Resuming Client Session With ID: %x, Trying to Craft a New Client Hello Resume and RESUMPTION PROOF", c.session.ID)
		c.mu.RLock()
		cHello.SessLen = uint16(len(c.session.ID))
		cHello.SessionID = c.session.ID
		c.mu.RUnlock()

		cHello.EncryptionSupport = true

	}*/

	if err := tempSession.WritePacket(MsgClientHello, cHello); err != nil {
		return err
	}

	log.Printf("[Log] Client Hello Sent to Server [%s]", c.DaemonAddr)

	// ==========================================
	// PHASE 2.5: RESUMPTION PROOF (If resuming)
	// ==========================================
	/*if isResume {

		log.Printf("[Log] Session %x Being Resumed", c.session.ID)

		c.mu.Lock()
		// Attach the fresh TCP socket to our existing, fully-encrypted session state
		c.session.AttachNewSocket(conn)
		c.mu.Unlock()

		log.Printf("[Log] Generating Resumption Proof, Server Address : [%s]", c.DaemonAddr)

		proof := &ResumeProof{
			ClientRandom: clientRandom,
		}

		// Because we use c.session, this WritePacket is AUTOMATICALLY ENCRYPTED
		// using our existing AES-GCM keys. The server will verify the MAC!
		if err := c.session.WritePacket(MsgClientResumeProof, proof); err != nil {
			return fmt.Errorf("failed to send resume proof: %w", err)
		}

		// Switch to using the established session for Phase 3
		tempSession = c.session
	}*/

	// ==========================================
	// PHASE 3: SERVER HELLO & VALIDATION
	// ==========================================
	serverHelloPkt, err := tempSession.ReadPacket()

	log.Printf("[Log] Server Hello Received From [%s]", c.DaemonAddr)

	if err != nil {
		return fmt.Errorf("[Error] failed to read server hello: %w", err)
	}

	if serverHelloPkt.Payload[0] == MsgserverUnsupportedKexCipher {
		return fmt.Errorf("[Error] Server Doesnt support provided key exchange and cipher suite by client")
	}

	if serverHelloPkt.Payload[0] != MsgServerHello {
		return fmt.Errorf("[Error] %q expected ServerHello, got %d", ErrUnexpectedMsgType, serverHelloPkt.Payload[0])
	}

	sHello, err := ParseServerHello(serverHelloPkt.Payload[1:])

	if err != nil {
		return fmt.Errorf("[Error] failed to parse ServerHello: %w", err)
	}

	if !isResume {
		// --- NEW CONNECTION KEY DERIVATION ---
		if sHello.SessionResumed {
			return errors.New("[Error] server incorrectly claimed session was resumed")
		}

		if !sHello.EncryptionSupport {
			return errors.New("server rejected encryption support")
		}

		if err := c.verifyServerIdentity(sHello, clientRandom, KEX, Cipher); err != nil {
			return fmt.Errorf("[Error] server identity verification failed: %w", err)
		}

		// Split the server's share key depending on the chosen KEX
		var serverPubKeyBytes []byte
		var pqCiphertext []byte

		if KEX == KexHybridX25519MLKEM768 {
			if len(sHello.Encryption.Server_Share_key) != 1120 { // 32 (X25519) + 1088 (ML-KEM ciphertext)
				return errors.New("invalid server share key length for hybrid KEX")
			}
			serverPubKeyBytes = sHello.Encryption.Server_Share_key[:32]
			pqCiphertext = sHello.Encryption.Server_Share_key[32:]
		} else {
			if len(sHello.Encryption.Server_Share_key) != 32 {
				return errors.New("invalid server share key length for classical KEX")
			}
			serverPubKeyBytes = sHello.Encryption.Server_Share_key
		}

		serverPubKey, err := ecdh.X25519().NewPublicKey(serverPubKeyBytes)
		if err != nil {
			return err
		}

		x25519Secret, err := clientPrivKey.ECDH(serverPubKey)

		if err != nil {
			return err
		}

		// 2. Post-Quantum Secret (If chosen) [5]
		var sharedSecret []byte
		if KEX == KexHybridX25519MLKEM768 {
			pqSecret, err := pqDecapsulationKey.Decapsulate(pqCiphertext)
			if err != nil {
				return fmt.Errorf("failed to decapsulate PQ key: %w", err)
			}

			// Blend the classical and quantum secrets!
			hybridSecretHash := sha256.Sum256(append(x25519Secret, pqSecret...))
			sharedSecret = hybridSecretHash[:]
		} else {
			sharedSecret = x25519Secret
		}

		keySize := 32
		if Cipher == CipherAES128GCM {
			keySize = 16
		}

		log.Printf("[Log] Shared Secret Computed, Length: %d bytes", len(sharedSecret))

		salt := append(clientRandom, sHello.SessionID...)
		clientWriteKey, _ := hkdf.Key(sha256.New, sharedSecret, salt, "wireforge-client-to-server", keySize)
		serverWriteKey, _ := hkdf.Key(sha256.New, sharedSecret, salt, "wireforge-server-to-client", 32) // Server read key is 32

		// 4. Initialize cipher
		var enc, dec cipher.AEAD
		switch Cipher {
		case CipherAES256GCM, CipherAES128GCM:
			cBlock, _ := aes.NewCipher(clientWriteKey)
			sBlock, _ := aes.NewCipher(serverWriteKey)
			enc, _ = cipher.NewGCM(cBlock)
			dec, _ = cipher.NewGCM(sBlock)
		case CipherChaCha20Poly1305:
			enc, _ = chacha20poly1305.New(clientWriteKey)
			dec, _ = chacha20poly1305.New(serverWriteKey)
		default:
			return errors.New("[Error] unsupported negotiated cipher")
		}

		tempSession.encrypter = enc
		tempSession.decrypter = dec
		tempSession.ID = sHello.SessionID

		c.mu.Lock()
		c.session = tempSession
		c.DaemonAuths = sHello.SupportedAuths
		c.mu.Unlock()

		log.Printf("[Log] Secure Session Established! Cipher: %x, KEX: %x", Cipher, KEX)
	}

	go c.eventLoop()

	log.Printf("[Log] Client Event Loop Started, Server Address: [%s]", c.DaemonAddr)

	return nil
}

// Connect dials the daemon and executes the 3-Phase Cryptographic Handshake.
func (c *Client) Connect(ctx context.Context, username string) error {
	conn, err := c.dialer.DialWithContext(ctx, c.DaemonAddr)

	if err != nil {
		return fmt.Errorf("Failed To Connect To Server [%s]: %w", c.DaemonAddr, err)
	}

	log.Printf("TCP Connection Established With The Server [ %s ]", c.DaemonAddr)

	tempSession := NewSession(conn)
	tempSession.isDaemon = false // We are the client
	//c.session = tempSession
	// ==========================================
	// PHASE 1: INIT EXCHANGE
	// ==========================================
	if err := tempSession.WritePacketRaw(MsgClientInit, c.InitMsg); err != nil {
		return err
	}
	log.Printf("[Log] Client Init Sent: %s", string(c.InitMsg))

	initRes, err := tempSession.ReadPacket()
	if err != nil {
		return err
	}
	if initRes.Payload[0] != MsgServerInit {
		log.Printf("Unexpected Msg Type From Server expected: %d, received: %d: Not A Server INIT Msg", MsgServerInit, initRes.Payload[0])
		return ErrUnexpectedMsgType

	}

	log.Printf("[Log] Server Init Received: %s", string(initRes.Payload[1:]))

	// Determine if this is a fresh connection or a resumption attempt
	c.mu.RLock()
	isResume := c.session != nil && len(c.session.ID) > 0
	c.mu.RUnlock()

	var clientPrivKey *ecdh.PrivateKey
	var pqDecapsulationKey *mlkem.DecapsulationKey768 // Our Post-Quantum private key

	// Generate 32-bytes of randomness for the HKDF salt & ResumeProof
	clientRandom := make([]byte, 32)
	rand.Read(clientRandom)

	// ==========================================
	// PHASE 2: HELLO & KEY EXCHANGE PREP
	// ==========================================

	cHello := &ClientHello{
		EncryptionSupport: true,
		ClientRandom:      clientRandom,
	}

	var KEX uint16
	var Cipher uint16

	if !isResume {
		log.Printf("[Log] New Client Session, Trying to Crafting Client Hello")
		// --- NEW CONNECTION ---
		cHello.SessLen = 0

		// 1. Map client configurations to explicit protocol choices (no negotiation) [1]
		switch strings.ToLower(c.conf.PreferedKeyExAlgo) {
		case "x25519":
			KEX = KexX25519
		default: // Default to Hybrid Post-Quantum
			KEX = KexHybridX25519MLKEM768
		}

		switch strings.ToLower(c.conf.PreferedEncyptionCipher) {
		case "aes-128-gcm":
			Cipher = CipherAES128GCM
		case "aes-256-gcm":
			Cipher = CipherAES256GCM
		default: // Default to ChaCha20
			Cipher = CipherChaCha20Poly1305
		}

		// 2. Generate key materials based on chosen KEX
		var shareKey []byte //==pubkey

		if KEX == KexHybridX25519MLKEM768 {
			// Classical part
			clientPrivKey, err = ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			x25519Pub := clientPrivKey.PublicKey().Bytes()

			// Post-Quantum part
			pqDecapsulationKey, err = mlkem.GenerateKey768()
			if err != nil {
				return fmt.Errorf("failed to generate ML-KEM key: %w", err)
			}
			pqPub := pqDecapsulationKey.EncapsulationKey().Bytes() // 1184 bytes

			// Concatenate them into a single Share Key (1216 bytes total)
			shareKey = append(x25519Pub, pqPub...)
		} else {
			// Classical X25519 Only
			clientPrivKey, err = ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			shareKey = clientPrivKey.PublicKey().Bytes() // 32 bytes
		}

		cHello.Encryption = ClientHelloEncryptionFields{
			CLIENT_KEX_ALGO:   KEX,
			CLIENT_CIPHER:     Cipher,
			ClientSharekeyLen: uint16(len(shareKey)),
			Client_Share_key:  shareKey,
		}

	} /*else {
		// --- RESUMING CONNECTION ---
		log.Printf("[Log] Resuming Client Session With ID: %x, Trying to Craft a New Client Hello Resume and RESUMPTION PROOF", c.session.ID)
		c.mu.RLock()
		cHello.SessLen = uint16(len(c.session.ID))
		cHello.SessionID = c.session.ID
		c.mu.RUnlock()

		cHello.EncryptionSupport = true

	}*/

	if err := tempSession.WritePacket(MsgClientHello, cHello); err != nil {
		return err
	}

	log.Printf("[Log] Client Hello Sent to Server [%s]", c.DaemonAddr)

	// ==========================================
	// PHASE 2.5: RESUMPTION PROOF (If resuming)
	// ==========================================
	/*if isResume {

		log.Printf("[Log] Session %x Being Resumed", c.session.ID)

		c.mu.Lock()
		// Attach the fresh TCP socket to our existing, fully-encrypted session state
		c.session.AttachNewSocket(conn)
		c.mu.Unlock()

		log.Printf("[Log] Generating Resumption Proof, Server Address : [%s]", c.DaemonAddr)

		proof := &ResumeProof{
			ClientRandom: clientRandom,
		}

		// Because we use c.session, this WritePacket is AUTOMATICALLY ENCRYPTED
		// using our existing AES-GCM keys. The server will verify the MAC!
		if err := c.session.WritePacket(MsgClientResumeProof, proof); err != nil {
			return fmt.Errorf("failed to send resume proof: %w", err)
		}

		// Switch to using the established session for Phase 3
		tempSession = c.session
	}
	*/
	// ==========================================
	// PHASE 3: SERVER HELLO & VALIDATION
	// ==========================================
	serverHelloPkt, err := tempSession.ReadPacket()

	log.Printf("[Log] Server Hello Received From [%s]", c.DaemonAddr)

	if err != nil {
		return fmt.Errorf("[Error] failed to read server hello: %w", err)
	}

	if serverHelloPkt.Payload[0] == MsgserverUnsupportedKexCipher {
		return fmt.Errorf("[Error] Server Doesnt support provided key exchange and cipher suite by client")
	}

	if serverHelloPkt.Payload[0] != MsgServerHello {
		return fmt.Errorf("[Error] %q expected ServerHello, got %d", ErrUnexpectedMsgType, serverHelloPkt.Payload[0])
	}

	sHello, err := ParseServerHello(serverHelloPkt.Payload[1:])

	if err != nil {
		return fmt.Errorf("[Error] failed to parse ServerHello: %w", err)
	}

	if !isResume {
		// --- NEW CONNECTION KEY DERIVATION ---
		if sHello.SessionResumed {
			return errors.New("[Error] server incorrectly claimed session was resumed")
		}

		if !sHello.EncryptionSupport {
			return errors.New("server rejected encryption support")
		}

		if err := c.verifyServerIdentity(sHello, clientRandom, KEX, Cipher); err != nil {
			return fmt.Errorf("[Error] server identity verification failed: %w", err)
		}

		// Split the server's share key depending on the chosen KEX
		var serverPubKeyBytes []byte
		var pqCiphertext []byte

		if KEX == KexHybridX25519MLKEM768 {
			if len(sHello.Encryption.Server_Share_key) != 1120 { // 32 (X25519) + 1088 (ML-KEM ciphertext)
				return errors.New("invalid server share key length for hybrid KEX")
			}
			serverPubKeyBytes = sHello.Encryption.Server_Share_key[:32]
			pqCiphertext = sHello.Encryption.Server_Share_key[32:]
		} else {
			if len(sHello.Encryption.Server_Share_key) != 32 {
				return errors.New("invalid server share key length for classical KEX")
			}
			serverPubKeyBytes = sHello.Encryption.Server_Share_key
		}

		serverPubKey, err := ecdh.X25519().NewPublicKey(serverPubKeyBytes)
		if err != nil {
			return err
		}

		x25519Secret, err := clientPrivKey.ECDH(serverPubKey)

		if err != nil {
			return err
		}

		// 2. Post-Quantum Secret (If chosen) [5]
		var sharedSecret []byte
		if KEX == KexHybridX25519MLKEM768 {
			pqSecret, err := pqDecapsulationKey.Decapsulate(pqCiphertext)
			if err != nil {
				return fmt.Errorf("failed to decapsulate PQ key: %w", err)
			}

			// Blend the classical and quantum secrets!
			hybridSecretHash := sha256.Sum256(append(x25519Secret, pqSecret...))
			sharedSecret = hybridSecretHash[:]
		} else {
			sharedSecret = x25519Secret
		}

		keySize := 32
		if Cipher == CipherAES128GCM {
			keySize = 16
		}

		log.Printf("[Log] Shared Secret Computed, Length: %d bytes", len(sharedSecret))

		salt := append(clientRandom, sHello.SessionID...)
		clientWriteKey, _ := hkdf.Key(sha256.New, sharedSecret, salt, "wireforge-client-to-server", keySize)
		serverWriteKey, _ := hkdf.Key(sha256.New, sharedSecret, salt, "wireforge-server-to-client", 32) // Server read key is 32

		// 4. Initialize cipher
		var enc, dec cipher.AEAD
		switch Cipher {
		case CipherAES256GCM, CipherAES128GCM:
			cBlock, _ := aes.NewCipher(clientWriteKey)
			sBlock, _ := aes.NewCipher(serverWriteKey)
			enc, _ = cipher.NewGCM(cBlock)
			dec, _ = cipher.NewGCM(sBlock)
		case CipherChaCha20Poly1305:
			enc, _ = chacha20poly1305.New(clientWriteKey)
			dec, _ = chacha20poly1305.New(serverWriteKey)
		default:
			return errors.New("[Error] unsupported negotiated cipher")
		}

		tempSession.encrypter = enc
		tempSession.decrypter = dec
		tempSession.ID = sHello.SessionID

		c.mu.Lock()
		c.session = tempSession
		c.DaemonAuths = sHello.SupportedAuths
		c.mu.Unlock()

		log.Printf("[Log] Secure Session Established! Cipher: %x, KEX: %x", Cipher, KEX)

		// ==========================================
		// PHASE 3.5: CLIENT AUTHENTICATION
		// ==========================================
		if c.DaemonAuths&AuthMethodPublicKey != 0 {
			log.Println("[AUTH] Server supports public key authentication")
		}

		if c.DaemonAuths&AuthMethodPassword != 0 {
			log.Println("[AUTH] Server supports password authentication")
		}

		if c.DaemonAuths&AuthMethodPKI != 0 {
			log.Println("[AUTH] Server supports PKI authentication")
		}

		serverAuths := c.DaemonAuths
		//var aRes *AuthResponse
		var authsuccess bool
		authsuccess = false
		pkCheck := false
		pkiCheck := false
	authLoop:
		for {
			if serverAuths&AuthMethodPublicKey != 0 && pkCheck == false {
				pkCheck = true
				if len(c.conf.PrivateKeys) == 0 {
					c.conf.PrivateKeys, err = loadKeys(c.conf.ClientDir, true)
					if err != nil {
						log.Println(err)
						continue
					}
				}

				for _, key := range c.conf.PrivateKeys {
					if _, ok := key.(ed25519.PrivateKey); ok {
						log.Println("[Log] Executing Cryptographic Public Key Authentication...")
						publicKey := key.Public().(ed25519.PublicKey)
						if err != nil {
							return err
						}

						signature := ed25519.Sign(key.(ed25519.PrivateKey), c.session.ID)

						PubAuthReq := &PubAuthRequest{
							Username:  username,
							PublicKey: publicKey,
							Signature: signature,
						}

						c.session.WritePacket(MsgClientAuthPub, PubAuthReq)
						log.Printf("Client sent public key authentication request for user: %s", username)

						pkt, err := c.session.ReadPacket()
						if err != nil {
							return fmt.Errorf("failed to read authentication response: %w", err)
						}

						if pkt.Payload[0] == MsgServerAuthFailed {
							return fmt.Errorf("[AUTH] Authentication failed, disconnecting...")
						}

						if pkt.Payload[0] != MsgServerAuthResponse {
							return fmt.Errorf("unexpected message type from server during authentication expected: %d, got %d", MsgServerAuthResponse, pkt.Payload[0])
						}

						ar, err := ParseAuthResponse(pkt.Payload[1:])
						if err != nil {
							return fmt.Errorf("failed to parse authentication response: %w", err)
						}

						if ar.Success && ar.AuthType == AuthMethodPublicKey && ar.Username == username {
							log.Println("[Success] pubkey login succeeded!")
							authsuccess = true
							break authLoop
						}

					}
					log.Println("pubkey auth login failed, trying other methods if available...")
				}
			}

			if serverAuths&AuthMethodPKI != 0 && pkiCheck == false {
				pkiCheck = true
				log.Println("[Log] Executing PKI Certificate Handshake...")
				for _, key := range c.conf.PrivateKeys {
					var signature []byte
					if edKey, ok := key.(ed25519.PrivateKey); ok {
						signature = ed25519.Sign(edKey, c.session.ID)
					} else {
						// For ECDSA
						hash := sha256.Sum256(c.session.ID)
						sig, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
						signature = sig
						if err != nil {

							return fmt.Errorf("failed to sign session ID: %w", err)
						}
					}

					pkiReq := &PKIAuthRequest{
						Certificate: c.conf.ClientCert,
						Signature:   signature,
					}

					c.session.WritePacket(MsgClientAuthPKI, pkiReq)

					pkt, err := c.session.ReadPacket()
					if pkt.Payload[0] != MsgServerAuthResponse {
						return fmt.Errorf("unexpected message type from server during authentication expected: %d, got %d", MsgServerAuthResponse, pkt.Payload[0])
					}

					if err != nil {
						return fmt.Errorf("failed to read authentication response: %w", err)
					}

					ar, err := ParseAuthResponse(pkt.Payload[1:])
					if err != nil {
						return fmt.Errorf("failed to parse authentication response: %w", err)
					}

					if ar.Success && ar.AuthType == AuthMethodPKI && ar.Username == username {
						log.Println("[Success] PKI Certificate login succeeded!")
						authsuccess = true
						break authLoop
					}
				}

				log.Println("PKI Certificate auth login failed, trying other methods if available...")

			}

			if serverAuths&AuthMethodPassword != 0 {

			passloop:
				for {
					log.Println("[Log] Executing Password Authentication...")

					fmt.Printf("Password for %s@%s: ", username, c.DaemonAddr)

					passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return fmt.Errorf("failed to read password: %w", err)
					}

					PassAuthReq := &PasswordAuthRequest{
						Username: username,
						Password: string(passBytes),
					}

					if err := c.session.WritePacket(MsgClientAuthPassword, PassAuthReq); err != nil {
						return err
					}
					pkt, err := c.session.ReadPacket()

					log.Printf("auth response received")
					if err != nil {
						return fmt.Errorf("failed to read authentication response: %w", err)
					}
					if pkt.Payload[0] == MsgServerAuthFailed {
						authsuccess = false
						return errors.New("authentication failed, disconnecting...")
					}

					if pkt.Payload[0] == MsgServerPassAuthFaild {
						log.Printf("Password Authentication Failed for user %s, try again!", username)
						continue passloop

					}
					if pkt.Payload[0] != MsgServerAuthResponse && pkt.Payload[0] != MsgServerPassAuthFaild {

						log.Printf("unexpected message type from server during authentication expected: %d, got %d", MsgServerAuthResponse, pkt.Payload[0])
						return errors.New("unexpected message type from server during authentication")

					}

					ar, err := ParseAuthResponse(pkt.Payload[1:])
					if err != nil {
						return fmt.Errorf("failed to parse authentication response: %w", err)
					}

					if ar.Success && ar.AuthType == AuthMethodPassword && ar.Username == username {
						log.Println("[Success] passwd login succeeded!")
						authsuccess = true
						break authLoop
					}

				}
			}

		}

		if !authsuccess {
			return errors.New("AUTH FAILED!")
		}

	} /*else {
		// --- RESUMING SUCCESS ---
		if !sHello.SessionResumed {
			c.mu.Lock()
			c.session = nil
			c.mu.Unlock()
			return errors.New("[Error] server rejected session resumption, session expired")
		}
		log.Printf("[Log] Session %x Successfully Resumed!", c.session.ID)
	}*/

	c.session.User = username

	go c.eventLoop()

	return nil
}

// eventLoop runs in the background and handles all incoming encrypted messages.
func (c *Client) eventLoop() {
	log.Printf("[Log] Client Event Loop Started, Server Address: [%s]", c.DaemonAddr)
	defer log.Printf("Client Event Loop Exited\r\n")
	defer c.Close()
	defer c.cancel()

	for {
		pkt, err := c.session.ReadPacket()
		if err != nil {
			log.Printf("Disconnected From Server: %v\r\n", err)
			break
		}

		switch pkt.Payload[0] {
		case MsgServerListenResponse:
			// Daemon confirmed it started listening on our requested remote port
			res, err := ParseListenResponse(pkt.Payload[1:])
			if err == nil {
				if res.Success {
					log.Printf("[Success] Server is now listening on public port: %s", res.Address)
				} else {
					log.Printf("[Error] Server failed to open public port: %s", res.Address)
					return
				}
			}
		case MsgServerOpenLogChannel, MsgServerOpenReadChannel:
			ch, err := ParseChannelOpen(pkt.Payload[1:])
			if err != nil {
				log.Printf("[Error] failed to open log channel: %v", err)
				continue
			}
			// Buffer server logs in a ring, drained to stdout with the "[Server LOG]: "
			// prefix. false => never close os.Stdout when the channel ends.
			Channel, k := c.session.NewChannelWithID(ch.ChannelID, false)
			if k {
				err := Channel.AttachWriter(os.Stdout)
				if err != nil {
					log.Printf("[Error] failed to open log channel: %v", err)
					continue
				}
			} else {
				log.Printf("[Error] failed to open log channel")
				continue
			}
			log.Printf("Server Log channel Opened, %d", ch.ChannelID)

			confirm := &ClientChannelOpenConfirm{ChannelID: ch.ChannelID, Success: true}
			c.session.WritePacket(MsgClientChannelOpenConfirm, confirm)
			defer Channel.Close()

		case MsgServerNewChannelOpened:
			// A public web user connected to the Daemon! We must dial our local target.
			sco, err := ParseServerChannelOpen(pkt.Payload[1:])
			if err != nil {
				continue
			}

			c.session.forwardMu.RLock()
			localTarget, exists := c.session.forwardMap[sco.RemoteAddr]
			c.session.forwardMu.RUnlock()

			if !exists {
				log.Printf("Security alert: Daemon requested unknown port %s", sco.RemoteAddr)
				continue
			}

			// Dial the local server in the background (e.g. 127.0.0.1:8080)
			go c.handleIncomingTrafiic(sco.ChannelID, localTarget)

		case MsgServerChanneledData:
			// Data arriving from the Daemon destined for our local server or shell
			ch, err := ParseChannelData(pkt.Payload[1:])
			if err != nil {
				log.Println("Malformed Channel Data from client")
				go c.session.WritePacket(MsgServerChanDataMalformed, nil)
				continue
			}
			if chann, ok := c.session.Stream.getActiveChannel(ch.ChannelID); ok {
				_, err := chann.Feed(ch.Data)
				if err != nil {
					log.Println(err)
					log.Printf("channel %d feed failed: %v; closing", chann.id, err)
					c.session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: chann.id}))
					chann.Close()

				}
			} else {
				log.Printf("Received Data with unknown Channel ID")
				continue
				//p.session.WritePacket(MsgServerChannelUnknownOrClosed, nil)
			}
			//log.Printf("Data received on Channel %d", ch.ChannelID)
			// Look up the session and ch id and write the data
			//log.Printf("Data received on Channel %d", ch.ChannelID)
		////	err = c.session.Stream.Feed(pkt.Payload[1:])
		//	if err != nil {

		// Flow-control violation or closed pipe: drop the channel,
		// never block the shared reader.
		//log.Printf("channel %d feed failed: %v; closing", ch.ChannelID, err)
		//		//		session.CloseActiveChannel(ch.ChannelID)
		//		c.session.WritePacket(MsgClientChannelClosed, (&ChannelClosed{ChannelID: ch.ChannelID}))
		//	}

		case MsgServerChannelClosed:
			// The remote user disconnected
			if ccl, err := ParseChannelClosed(pkt.Payload[1:]); err == nil {
				c.session.Stream.CloseActiveChannel(ccl.ChannelID)
			}

		case MsgServerShellReqResponse:
			res, err := ParseShellRequestResponse(pkt.Payload[1:])
			log.Printf("Shell request response received: %v\r\n", res.RequestID)

			if err != nil {
				log.Printf("Shell request responses couldn't be parsed: %v", err)
				continue
			}

			// Find the pending request and send the response!
			c.mu.Lock()
			if waitCh, exists := c.pendingShells[res.RequestID]; exists {
				log.Printf("Shell request responded by the server - reqID: %v", res.RequestID)
				waitCh <- res
				delete(c.pendingShells, res.RequestID)
			}
			c.mu.Unlock()
		case MsgServerChannelUnknownOrClosed:
			if id, err := ParseChannelClosed(pkt.Payload[1:]); err == nil {
				c.session.Stream.CloseActiveChannel(id.ChannelID)
			}

		case MsgServerAuthSuccess:

			log.Println("[Success] Logged in successfully!")
		case MsgServerENVCreated:
			ec, err := ParseEnvCreated(pkt.Payload[1:])
			if err != nil {
				log.Printf(" EnvCreated couldn't be parsed: %v", err)
				continue
			}
			if !ec.Success {
				log.Printf(" [EnvCreate] not successful")
				continue
			}
			fmt.Printf(
				"\n\nEnvCreated{\n"+
					"  RequestID: %d\n"+
					"  PublicKey: %x\n"+
					"  AccessType: %s\n"+
					"  UserRequestedName: %s\n"+
					"  Name: %s\n"+
					"  Success: %v\n"+
					"}\n\n",
				ec.RequestID,
				ec.PublicKey,
				string(ec.AccessType),
				string(ec.UserRequestedName),
				string(ec.Name),
				ec.Success,
			)
			return
		case MsgServerContainersListResponse:
			res, err := ParseContainersListResponse(pkt.Payload[1:])
			if err == nil {
				c.mu.Lock()
				if waitCh, exists := c.pendingContainerLists[res.RequestID]; exists {
					waitCh <- res
					delete(c.pendingContainerLists, res.RequestID)
				}
				c.mu.Unlock()
			}
		case MsgServerENVCreateNotAllowed:
			log.Printf("evm create not allowed!")
		case MsgServerNoContainer:
			log.Printf("MsgServerNoContainer!")
			return

		case MsgWindowAdjust:
			if wa, err := ParseWindowAdjust(pkt.Payload[1:]); err == nil {
				c.session.Stream.grantSendWindow(wa.ChannelID, wa.Increment)
			}

		default:
			log.Printf("Unknown message from Daemon: %d", pkt.Payload[0])
		}
	}

}

// handleIncomingTunnel is called when the daemon tells us a web user connected.
func (c *Client) handleIncomingTrafiic(channelID uint32, localTarget string) {
	localConn, err := c.dialer.Dial(localTarget)
	if err != nil {
		log.Printf("Failed to dial local target %s: %v", localTarget, err)
		return
	}

	channelID, Channel := c.session.NewChannel(false) // inbound ring -> localConn
	Channel.AttachWriter(localConn)
	defer Channel.Close()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	for {
		n, err := localConn.Read(buf)
		if n > 0 {
			if werr := c.session.SendChannelData(MsgClientChanneledData, channelID, buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

func (c *Client) verifyServerIdentity(sHello *ServerHello, clientRandom []byte, kexAlgo, cipher uint16) error {
	if c.conf != nil && c.conf.InsecureSkipHostKeyVerify {
		log.Printf("[Security][WARNING] Host key verification DISABLED ... vulnerable to active MITM!")
		return nil
	}

	hostPub, err := VerifyServerHelloSignature(sHello, clientRandom, kexAlgo, cipher)
	if err != nil {
		return err
	}
	knownHostsPath := c.knownHostsPath() // config override
	pinned, err := CheckOrPinHostKey(knownHostsPath, c.DaemonAddr, hostPub)
	if err != nil {
		return fmt.Errorf("host key check for %s: %w", c.DaemonAddr, err)
	}

	if pinned {
		log.Printf("[Security] Pinned NEW host key for %s: %x (trust-on-first-use) -- verify this fingerprint out-of-band!", c.DaemonAddr, []byte(hostPub))
	} else {
		log.Printf("[Security] Server host key for %s verified against known_hosts.", c.DaemonAddr)
	}
	return nil
}

// knownHostsPath resolves the known_hosts location: explicit config override
// first, then <ClientDir>/known_hosts, then the package default
// (~/.shellforge/known_hosts).
func (c *Client) knownHostsPath() string {
	if c.conf != nil {
		if c.conf.KnownHostsPath != "" {
			return c.conf.KnownHostsPath
		}
		if c.conf.ClientDir != "" {
			return filepath.Join(c.conf.ClientDir, "known_hosts")
		}
	}
	return DefaultKnownHostsPath()
}

// ForwardRemoteToLocal (`ssh -R`) tells the Daemon to listen on `remotePort` and route to `localTarget`.
func (c *Client) ForwardRemoteToLocal(remotePort string, localTarget string) error {
	c.mu.Lock()
	c.session.forwardMap[remotePort] = localTarget
	c.mu.Unlock()

	req := &ListenRequest{
		AddrLen: uint16(len(remotePort)),
		Address: remotePort,
	}

	return c.session.WritePacket(MsgClientListenRequest, req)
}

// ForwardLocalToRemote (`ssh -L`) opens a port on this laptop and pushes it to a target via the Daemon.
func (c *Client) ForwardLocalToRemote(ctx context.Context, localListenAddr string, remoteTarget string) error {

	handler := func(ctx context.Context, localConn net.Conn) {
		chanID := c.session.Stream.IncrementClientChannelID()
		Channel, ok := c.session.NewChannelWithID(chanID, false) // inbound ring -> localConn
		if !ok {
			log.Println("bluhhhhhhh")
			return
		}
		if werr := Channel.AttachWriter(localConn); werr != nil {
			log.Println("wwbluhhhhhhh")
			return
		}
		defer Channel.Close()
		//	c.session.AttachChannelwi(chanID, localConn, true)
		//	defer c.session.CloseActiveChannel(chanID)

		req := &ClientChannelOpen{
			ChannelID:  chanID,
			AddrLen:    uint16(len(remoteTarget)),
			RemoteAddr: remoteTarget,
		}
		c.session.WritePacket(MsgClientNewChannelOpened, req)

		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		for {
			n, err := localConn.Read(buf)
			if n > 0 {
				if werr := c.session.SendChannelData(MsgClientChanneledData, chanID, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		c.session.WritePacket(MsgClientChannelClosed, (&ChannelClosed{ChannelID: chanID}))
	}

	ln := tcp.DefaultListenOptions().WithVerbose(true)
	go ln.ListenWithContext(ctx, localListenAddr, handler)
	return nil
}

func (c *Client) Close() error {
	if c.session != nil {
		return c.session.Close()
	}
	return nil
}

// RequestShell asks the daemon for an interactive shell and links os.Stdin/Stdout to it!
// SENDS TWO PACKETS SHELL REQ + WINDOW RESIZE
// escapeByte is the local escape key (Ctrl+]). Pressing it in a raw-mode
// shell tears the session down locally without waiting for the daemon.
const escapeByte = 0x1D

// RequestShell asks the daemon for an interactive shell and links os.Stdin/Stdout to it.
// SENDS TWO PACKETS: SHELL REQ + WINDOW RESIZE
func (c *Client) RequestShell(shellPath, username string) error {
	// 1. Generate a random RequestID (4 bytes for Uint32)
	reqID := binary.BigEndian.Uint32(randomBytes(4))

	cols, rows, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		log.Printf("failed to get initial window size")
		cols, rows = 80, 24 // Default size
	}

	req := &ShellRequest{
		RequestID:   reqID,
		UsernameLen: uint8(len(username)),
		User:        []byte(username),
		ShellLen:    uint16(len(shellPath)),
		Shell:       []byte(shellPath),
		Row:         uint16(rows),
		Cols:        uint16(cols),
	}

	// 2. Create a channel to wait for the Daemon's response
	responseCh := make(chan *ShellRequestResponse, 1)
	c.mu.Lock()
	c.pendingShells[reqID] = responseCh
	c.mu.Unlock()

	// 3. Send the request to the Daemon
	if err := c.session.WritePacket(MsgClientShellRequest, req); err != nil {
		c.mu.Lock()
		delete(c.pendingShells, reqID)
		c.mu.Unlock()
		return err
	}
	log.Printf("Requested shell (%s). Waiting for Server approval...", shellPath)

	// ========================================================
	// SET UP SYSTEM SIGNAL CATCHER EARLY
	// NOTE: once raw mode is on, Ctrl+C no longer generates SIGINT
	// (raw mode disables ISIG). This only catches external kills.
	// ========================================================
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)

	// 4. Wait for the Daemon's response, a Timeout, or a Ctrl+C
	var res *ShellRequestResponse
	select {
	case res = <-responseCh:
		if !res.Success {
			return fmt.Errorf("server failed to start the shell")
		}
		log.Printf("Shell approved! Assigned ChannelID: %d. Hooking up terminal...", res.ChannelID)
	case <-time.After(SHELL_REQUEST_TIMEOUT):
		c.mu.Lock()
		delete(c.pendingShells, reqID)
		c.mu.Unlock()
		return fmt.Errorf("timed out waiting for shell approval")
	case <-quit:
		// User pressed Ctrl+C BEFORE the shell was approved!
		log.Printf("\r\n[wireforge] Cancelled by user. Aborting shell request.\r\n")
		c.mu.Lock()
		delete(c.pendingShells, reqID)
		c.mu.Unlock() // FIX: was missing — deadlocked the client on any later c.mu.Lock()
		return nil
	}

	stdinFd := int(os.Stdin.Fd())

	Channel, ok := c.session.NewChannelWithID(res.ChannelID, true)
	if !ok {
		return fmt.Errorf("client failed to start the shell")
	}
	defer Channel.Close()
	log.Printf("Client Shell Pipe Created, With Channel ID %d \r\n", res.ChannelID)

	// notifyDaemonClosed tells the daemon to kill the remote PTY when WE
	// initiate the exit. Fire-and-forget; we do not wait for a reply.
	notifyDaemonClosed := func() {
		c.session.WritePacket(MsgClientChannelClosed,
			&ChannelClosed{ChannelID: res.ChannelID})
	}

	// ========================================================
	// TERMINAL RAW MODE
	// ========================================================
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("failed to set raw terminal mode: %v", err)
	}
	log.Printf("Client Old Shell Preserved, Starting the Raw Shell\r\n")
	defer term.Restore(stdinFd, oldState)

	shellDone := make(chan struct{}) // remote side ended (daemon close / conn drop)
	localQuit := make(chan struct{}) // local escape key or stdin EOF

	// ========================================================
	// WINDOW RESIZE WATCHER (SIGWINCH)
	// ========================================================
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.Signal(28)) // SIGWINCH
	defer signal.Stop(sigwinch)

	go func() {
		for {
			select {
			case <-sigwinch:
				cols, rows, err := term.GetSize(stdinFd)
				if err == nil {
					resizeReq := &WindowResize{
						ChannelID: res.ChannelID,
						Rows:      uint16(rows),
						Cols:      uint16(cols),
					}
					c.session.WritePacket(MsgClientPTYResize, resizeReq)
				}
			case <-shellDone:
				return
			case <-localQuit:
				return
			}
		}
	}()

	// 7. Pipe local terminal input to the daemon, scanning for the escape key.
	//    NOTE: in raw mode Ctrl+D is just byte 0x04 forwarded to the remote
	//    shell — it never produces a local EOF, so io.Copy could never exit
	//    here. Ctrl+] (0x1D) is our reserved local escape instead.
	go func() {
		buf := make([]byte, MAX_PAYLOAD_LEN)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if i := bytes.IndexByte(buf[:n], escapeByte); i >= 0 {
					// Forward anything typed before the escape, then bail.
					if i > 0 {
						Channel.Write(buf[:i])
					}
					close(localQuit)
					return
				}
				if _, werr := Channel.Write(buf[:n]); werr != nil {
					// Channel closed (remote exit already in progress).
					// shellDone path handles cleanup; just stop reading.
					return
				}
			}
			if err != nil {
				// Genuine stdin EOF (piped input / terminal closed).
				close(localQuit)
				return
			}
		}
	}()

	// 8. Pipe daemon output to local terminal.
	//    Returns when the daemon sends MsgServerChannelClosed (or the
	//    connection drops) and PipeStream.Read yields io.EOF.
	go func() {
		io.Copy(os.Stdout, Channel)
		close(shellDone)
	}()

	// 9. The Main Wait Block
	select {
	case <-shellDone:
		// Remote-initiated: shell exited (Ctrl+D/exit) or connection dropped.
		// Daemon already knows; nothing to send.
		log.Printf("[wireforge] Remote shell exited or connection dropped.\r\n")
		Channel.Close()
	case <-localQuit:
		// Local-initiated: escape key or stdin EOF. Tell the daemon so it
		// kills the remote PTY, then exit immediately without waiting.
		log.Printf("[wireforge] Escape pressed. Closing shell locally.\r\n")
		notifyDaemonClosed()
		Channel.Close()
	case <-quit:
		// External SIGTERM/SIGINT (e.g. docker stop) while in raw mode.
		log.Printf("SIGTERM CAUGHT: Client Shell is being stopped\r\n")
		notifyDaemonClosed()
		Channel.Close()
	}

	return nil
	// Deferred on the way out (LIFO): signal.Stop(sigwinch),
	// term.Restore (terminal back to normal), Channel.Close()
	// (local teardown — wakes the stdout copier if it's still blocked),
	// signal.Stop(quit).
}

func (c *Client) CreateENV(envType, RequestedName string, prvKey crypto.Signer) error {
	if envType != "container" && envType != "system-user" && envType != "hostsharednamespace" {
		return errors.New("not a supported envType")
	}

	reqID := binary.BigEndian.Uint32(randomBytes(4))

	// FIXED: Corrected type assertion from *ed25519.PrivateKey to ed25519.PrivateKey [1]
	if edKey, ok := prvKey.(ed25519.PrivateKey); ok {
		//edKey := *edKeyPtr
		log.Println("[Log] Executing Cryptographic Public Key Authentication...")
		publicKey := edKey.Public().(ed25519.PublicKey)

		// Sign the unique Session ID!
		signature := ed25519.Sign(edKey, c.session.ID)
		req := &EnvRequest{
			RequestID:            reqID,
			PublicKey:            publicKey,
			Signature:            signature,
			AccessTypeLen:        uint16(len(envType)),
			AccessType:           []byte(envType),
			UserRequestedNameLen: uint8(len(RequestedName)),
			UserRequestedName:    []byte(RequestedName),
		}

		c.session.WritePacket(MsgClientENVCreate, req)

		log.Printf("[Log] env request sent for public key : %s ", hex.EncodeToString(publicKey))
		return nil
	} else {
		return errors.New("unsupported private key type (must be ed25519)")
	}

}

// GetAndRunContainer checks if a container exists, boots it, or cleanly prints
// a list of alternative valid active containers if it is missing [1, 3].
func (c *Client) GetAndRunContainer(containerName string, signer crypto.Signer) error {
	reqID := binary.BigEndian.Uint32(randomBytes(4))
	stdinFd := int(os.Stdin.Fd())

	// FIXED: Corrected type assertion [1]
	if edKey, ok := signer.(ed25519.PrivateKey); ok {
		log.Println("[Log] Executing Cryptographic Public Key Authentication...")
		publicKey := edKey.Public().(ed25519.PublicKey)

		// Sign the unique Session ID
		signature := ed25519.Sign(edKey, c.session.ID)
		req := &EnvRequest{
			RequestID:            reqID,
			PublicKey:            publicKey,
			Signature:            signature,
			AccessTypeLen:        uint16(len("container")),
			AccessType:           []byte("container"),
			UserRequestedNameLen: uint8(len(containerName)),
			UserRequestedName:    []byte(containerName),
		}

		if err := c.session.WritePacket(MsgClientConnectContainer, req); err != nil {
			return err
		}
		cols, rows, _ := term.GetSize(stdinFd)

		shellreq := &ContainerOpRequest{
			OpType:    1,
			RequestID: reqID,
			PublicKey: publicKey,
			NameLen:   uint8(len(containerName)),
			Name:      []byte(containerName),
			Row:       uint16(rows),
			Cols:      uint16(cols),
		}

		if err := c.session.WritePacket(MsgClientGetContainerShell, shellreq); err != nil {
			return err
		}

		log.Println("[Log] env request sent")

		responseCh := make(chan *ShellRequestResponse, 1)
		listCh := make(chan *ContainersListResponse, 1)

		// FIXED: Register BOTH channels in your Client map so the eventLoop can find them! [2]
		c.mu.Lock()
		c.pendingShells[reqID] = responseCh
		c.pendingContainerLists[reqID] = listCh // CRITICAL FIX!
		c.mu.Unlock()

		// Defers ensure we cleanly wipe both channels from memory on exit
		defer func() {
			c.mu.Lock()
			delete(c.pendingShells, reqID)
			delete(c.pendingContainerLists, reqID)
			c.mu.Unlock()
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(quit)

		// 4. Wait for the Daemon's response, a lists-fallback response, or a timeout
		select {
		case res := <-responseCh:
			if !res.Success {
				return fmt.Errorf("server failed to start the shell")
			}
			log.Printf("Container approved! Assigned ChannelID: %d. Hooking up terminal...", res.ChannelID)
			return c.startInteractivePTY(res.ChannelID, stdinFd)

		case listRes := <-listCh:
			//fmt.Printf("\r\n[Error] Container %q not found on server.\r\n", containerName)
			fmt.Println()
			fmt.Println("Available active containers for your key:")
			for _, name := range listRes.ContainersList {
				fmt.Printf("  - %s\r\n", name)
			}
			fmt.Println()
			return errors.New("container not found")

		case <-time.After(SHELL_REQUEST_TIMEOUT):
			return fmt.Errorf("timed out waiting for container approval")
		case <-quit:
			log.Printf("\r\n[wireforge] Cancelled by user. Aborting shell request.\r\n")
			return nil
		}

	}
	return errors.New("unsupported private key type (must be ed25519)")
}

// startInteractivePTY consolidates the raw terminal setting and stream copying
func (c *Client) startInteractivePTY(channelID uint32, stdinFd int) error {

	Channel, ok := c.session.NewChannelWithID(channelID, true) // inbound ring -> localConn
	if !ok {
		log.Println("bluhhhhhhh")
		return fmt.Errorf("client failed to start the shell")
	}

	//defer c.session.CloseActiveChannel(channelID)
	defer Channel.Close()

	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("failed to set raw terminal mode: %v", err)
	}
	defer term.Restore(stdinFd, oldState)

	shellDone := make(chan struct{})
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.Signal(28))
	defer signal.Stop(sigwinch)

	go func() {
		for {
			select {
			case <-sigwinch:
				cols, rows, err := term.GetSize(stdinFd)
				if err == nil {
					resizeReq := &WindowResize{
						ChannelID: channelID,
						Rows:      uint16(rows),
						Cols:      uint16(cols),
					}
					c.session.WritePacket(MsgClientPTYResize, resizeReq)
				}
			case <-shellDone:
				return
			}
		}
	}()

	go func() {
		io.Copy(Channel, os.Stdin)
		Channel.Close()
	}()

	io.Copy(os.Stdout, Channel)
	close(shellDone)

	return nil
}

// code MsgClientContainerLog
func (c *Client) GetContainerLogs(ctx context.Context, name string, signer crypto.Signer) error {

	reqID := binary.BigEndian.Uint32(randomBytes(4))

	// FIXED: Corrected type assertion [1]
	if _, ok := signer.(ed25519.PrivateKey); ok {
		log.Println("[Log] Executing Cryptographic Public Key Authentication...")

	}
	// Sign the unique Session ID
	signature := ed25519.Sign(signer.(ed25519.PrivateKey), c.session.ID)
	req := &EnvRequest{
		RequestID:            reqID,
		PublicKey:            signer.Public().(ed25519.PublicKey),
		Signature:            signature,
		AccessTypeLen:        uint16(len("container")),
		AccessType:           []byte("container"),
		UserRequestedNameLen: uint8(len(name)),
		UserRequestedName:    []byte(name),
	}

	if err := c.session.WritePacket(MsgClientConnectContainer, req); err != nil {
		return err
	}

	conR := &ContainerOpRequest{
		OpType:    2,
		RequestID: reqID,
		PublicKey: signer.Public().(ed25519.PublicKey),
		NameLen:   uint8(len(name)),
		Name:      []byte(name),
	}

	return c.session.WritePacket(MsgClientContainerLog, conR)
}

// //func (c *Client) GetContainerInspect(ctx context.Context, name string, signer crypto.Signer) error{}
// func (c *Client) GetContainerStats(ctx context.Context, name string, signer crypto.Signer) error{}
// func (c *Client) GetContainerTop(ctx context.Context, name string, signer crypto.Signer) error{}

// msg code : MsgClientContainerCommandExec
func (c *Client) ContainerExec(ctx context.Context, name, command string, signer crypto.Signer) error {
	reqID := binary.BigEndian.Uint32(randomBytes(4))

	if _, ok := signer.(ed25519.PrivateKey); !ok {
		log.Println("[Log] Executing Cryptographic Public Key Authentication...")
		return errors.New("unsupported private key type (must be ed25519)")
	}

	signature := ed25519.Sign(signer.(ed25519.PrivateKey), c.session.ID)
	req := &EnvRequest{
		RequestID:            reqID,
		PublicKey:            signer.Public().(ed25519.PublicKey),
		Signature:            signature,
		AccessTypeLen:        uint16(len("container")),
		AccessType:           []byte("container"),
		UserRequestedNameLen: uint8(len(name)),
		UserRequestedName:    []byte(name),
	}

	if err := c.session.WritePacket(MsgClientConnectContainer, req); err != nil {
		return err
	}
	conR := &ContainerOpRequest{
		OpType:     3,
		RequestID:  reqID,
		PublicKey:  signer.Public().(ed25519.PublicKey),
		NameLen:    uint8(len(name)),
		Name:       []byte(name),
		CommandLen: uint16(len(command)),
		Command:    []byte(command),
	}

	return c.session.WritePacket(MsgClientContainerCommandExec, conR)
}

// loadKeys scans configDir for all usable private key files (any filename,
// skipping *.pub and config.json), parses each one, and returns them
// sorted by filename (so the result is deterministic and the "primary"
// key, signers[0], can be controlled by renaming files). If configDir
// wasn't explicitly given via -c and has no usable keys (or doesn't
// exist), falls back to scanning ~/.ssh for the standard key filenames.
// If -c WAS given explicitly and no usable key is found there, that's a
// hard error rather than a silent fallback.
func LoadKeys(keyDir string, fallback bool) ([]crypto.Signer, error) {
	return loadKeys(keyDir, fallback)
}

func loadKeys(keyDir string, fallback bool) ([]crypto.Signer, error) {
	signers, err := loadKeysFromDir(keyDir)
	if err != nil {
		log.Printf("cannot read key directory %s: %v", keyDir, err)
	}

	if len(signers) > 0 {
		return signers, nil
	}

	if !fallback {
		return nil, fmt.Errorf("load key failed")
	}

	log.Printf("Fall back to the standard ~/.ssh key filenames")

	home := os.Getenv("HOME")
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		path := filepath.Join(home, ".ssh", name)
		if _, statErr := os.Stat(path); statErr != nil {
			continue
		}
		signer, loadErr := loadPrivateKeyPEM(path, name)
		if loadErr != nil {
			log.Printf("[CLI] skipping %s: %v", path, loadErr)
			continue
		}
		log.Printf("[CLI] Loaded private key: %s", path)
		signers = append(signers, signer)
	}
	if len(signers) == 0 {
		return nil, errors.New("no usable private keys found in ~/.shellforge or ~/.ssh")
	}
	return signers, nil
}

// loadKeysFromDir parses every plausible key file directly inside dir.
func loadKeysFromDir(dir string) ([]crypto.Signer, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".pub") || n == "config.json" || strings.HasPrefix(n, ".") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)

	var signers []crypto.Signer
	for _, n := range names {
		path := filepath.Join(dir, n)
		signer, err := loadPrivateKeyPEM(path, n)
		if err != nil {
			log.Printf("[CLI] skipping %s: %v", path, err)
			continue
		}
		log.Printf("[CLI] Loaded private key: %s", path)
		signers = append(signers, signer)
	}
	return signers, nil
}

// loadPrivateKeyPEM handles OpenSSH-format, PKCS#1, and PKCS#8 PEM keys,
// prompting for a passphrase if the key is encrypted.
func loadPrivateKeyPEM(path string, name string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {

			fmt.Fprint(os.Stderr, "Enter passphrase for key(", name, "):")

			passBytes, readErr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if readErr != nil {
				return nil, fmt.Errorf("failed to read passphrase: %w", readErr)
			}
			key, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, passBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	// x/crypto/ssh returns ed25519 keys as *ed25519.PrivateKey; normalize
	// to the value type so downstream code can use a single, consistent
	// type assertion against ed25519.PrivateKey.
	if edPtr, ok := key.(*ed25519.PrivateKey); ok {
		key = *edPtr
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not support signing")
	}
	return signer, nil
}

///////////////helpers

type prefixWriter struct {
	w      io.Writer
	prefix []byte
}

func (p prefixWriter) Write(b []byte) (int, error) {
	if _, err := p.w.Write(p.prefix); err != nil {
		return 0, err
	}
	return p.w.Write(b)
}

func (p prefixWriter) Read([]byte) (int, error) {
	return 0, nil
}

func (p prefixWriter) Close() error {
	return nil
}
