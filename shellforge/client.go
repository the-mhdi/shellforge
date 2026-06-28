package shellforge

import (
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
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"

	"github.com/the-mhdi/wireforge/tcp" // Go's official chacha package
)

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
	ClientCert []byte          // DER-encoded client certificate
	PrivateKey []crypto.Signer // e.g. *ecdsa.PrivateKey or ed25519.PrivateKey

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
	PendingResponse       chan Packet
	// State
	mu      sync.RWMutex
	context context.Context
	cancel  context.CancelFunc
	//forwardMap map[string]string // Maps Remote Requested Port -> Local Target Port

}

func NewClient(ctx context.Context, daemonAddr string, conf *ClientConfig) *Client {
	// Create a robust dialer with Keep-Alives and Fast Open

	dOpts := &tcp.DialOptions{
		Verbose:              true,
		KeepAlive:            true,
		KeepAliveFirstProbe:  10 * time.Second,
		KeepAliveInterval:    10 * time.Second,
		MaxKeepAliveAttempts: 6,
	}

	ctx, cancel := context.WithCancel(ctx)

	return &Client{
		DaemonAddr:            daemonAddr,
		conf:                  conf,
		InitMsg:               []byte(conf.ClientInitMessage),
		dialer:                dOpts.NewDialer(),
		pendingShells:         make(map[uint32]chan *ShellRequestResponse),
		pendingContainerLists: make(map[uint32]chan *ContainersListResponse),
		PendingAuthResponse:   make(chan *AuthResponse),
		AuthResCh:             make(chan struct{}),
		PendingResponse:       make(chan Packet),
		context:               ctx,
		cancel:                cancel,
	}
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
	if err := tempSession.WritePacket(MsgClientInit, []byte(c.conf.ClientInitMessage)); err != nil {
		return err
	}
	log.Printf("[Log] Client Init Sent: %s", string(c.InitMsg))

	initRes, err := tempSession.ReadPacket()
	if err != nil {
		return err
	}
	if initRes.Payload[0] != MsgServerInit {
		log.Printf("Unexpected Msg Type From Server expected: %d, received: %d: Not A Server INIT Msg", MsgServerInit, initRes.Payload[0])
		tempSession.Close()
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

	} else {
		// --- RESUMING CONNECTION ---
		log.Printf("[Log] Resuming Client Session With ID: %x, Trying to Craft a New Client Hello Resume and RESUMPTION PROOF", c.session.ID)
		c.mu.RLock()
		cHello.SessLen = uint16(len(c.session.ID))
		cHello.SessionID = c.session.ID
		c.mu.RUnlock()

		cHello.EncryptionSupport = true

	}

	if err := tempSession.WritePacket(MsgClientHello, cHello.Marshal()); err != nil {
		return err
	}

	log.Printf("[Log] Client Hello Sent to Server [%s]", c.DaemonAddr)

	// ==========================================
	// PHASE 2.5: RESUMPTION PROOF (If resuming)
	// ==========================================
	if isResume {

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
		if err := c.session.WritePacket(MsgClientResumeProof, proof.Marshal()); err != nil {
			return fmt.Errorf("failed to send resume proof: %w", err)
		}

		// Switch to using the established session for Phase 3
		tempSession = c.session
	}

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

	// ==========================================
	// PHASE 1: INIT EXCHANGE
	// ==========================================
	if err := tempSession.WritePacket(MsgClientInit, c.InitMsg); err != nil {
		return err
	}
	log.Printf("[Log] Client Init Sent: %s", string(c.InitMsg))

	initRes, err := tempSession.ReadPacket()
	if err != nil {
		return err
	}
	if initRes.Payload[0] != MsgServerInit {
		log.Printf("Unexpected Msg Type From Server expected: %d, received: %d: Not A Server INIT Msg", MsgServerInit, initRes.Payload[0])
		tempSession.Close()
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

	} else {
		// --- RESUMING CONNECTION ---
		log.Printf("[Log] Resuming Client Session With ID: %x, Trying to Craft a New Client Hello Resume and RESUMPTION PROOF", c.session.ID)
		c.mu.RLock()
		cHello.SessLen = uint16(len(c.session.ID))
		cHello.SessionID = c.session.ID
		c.mu.RUnlock()

		cHello.EncryptionSupport = true

	}

	if err := tempSession.WritePacket(MsgClientHello, cHello.Marshal()); err != nil {
		return err
	}

	log.Printf("[Log] Client Hello Sent to Server [%s]", c.DaemonAddr)

	// ==========================================
	// PHASE 2.5: RESUMPTION PROOF (If resuming)
	// ==========================================
	if isResume {

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
		if err := c.session.WritePacket(MsgClientResumeProof, proof.Marshal()); err != nil {
			return fmt.Errorf("failed to send resume proof: %w", err)
		}

		// Switch to using the established session for Phase 3
		tempSession = c.session
	}

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

		serverAuths := c.DaemonAuths
		//var aRes *AuthResponse
		var authsuccess bool
		authsuccess = false

	authLoop:
		for {
			if serverAuths&AuthMethodPublicKey != 0 {
				for _, key := range c.conf.PrivateKey {
					if _, ok := key.(*ed25519.PrivateKey); ok {
						log.Println("[Log] Executing Cryptographic Public Key Authentication...")
						publicKey := key.Public().(ed25519.PublicKey)

						// Sign the unique Session ID!
						signature := ed25519.Sign(key.(ed25519.PrivateKey), c.session.ID)

						PubAuthReq := &PubAuthRequest{
							Username:  username,
							PublicKey: publicKey,
							Signature: signature,
						}

						c.session.WritePacket(MsgClientAuthPub, PubAuthReq.Marshal())
						log.Printf("Client sent public key authentication request for user: %s", username)

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

						if ar.Success && ar.Type == AuthMethodPublicKey && ar.Username == username {
							log.Println("[Success] pubkey login succeeded!")
							authsuccess = true
							break authLoop
						}

					}
					log.Println("pubkey auth login failed, trying other methods if available...")
				}
			}

			if serverAuths&AuthMethodPKI != 0 {
				log.Println("[Log] Executing PKI Certificate Handshake...")
				for _, key := range c.conf.PrivateKey {
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

					c.session.WritePacket(MsgClientAuthPKI, pkiReq.Marshal())

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

					if ar.Success && ar.Type == AuthMethodPKI && ar.Username == username {
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

					if err := c.session.WritePacket(MsgClientAuthPassword, PassAuthReq.Marshal()); err != nil {
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

					if ar.Success && ar.Type == AuthMethodPassword && ar.Username == username {
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

	} else {
		// --- RESUMING SUCCESS ---
		if !sHello.SessionResumed {
			c.mu.Lock()
			c.session = nil
			c.mu.Unlock()
			return errors.New("[Error] server rejected session resumption, session expired")
		}
		log.Printf("[Log] Session %x Successfully Resumed!", c.session.ID)
	}

	c.session.User = username

	go c.eventLoop()

	log.Printf("[Log] Client Event Loop Started, Server Address: [%s]", c.DaemonAddr)

	return nil
}

// eventLoop runs in the background and handles all incoming encrypted messages.
func (c *Client) eventLoop() {
	defer log.Printf("Client Event Loop Exited\r\n")
	defer c.session.Close()
	defer c.cancel()

	for {
		pkt, err := c.session.ReadPacket()
		if err != nil {
			log.Printf("Disconnected From Server: %v\r\n", err)
			c.session.conn.Close()
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
					c.session.Close()
					return
				}
			}
		case MsgServerOpenLogChannel:
			ch, err := ParseChannelOpen(pkt.Payload[1:])
			if err != nil {
				log.Printf("[Error] failed to open log channel: %v", err)
				continue
			}

			c.session.AddActiveChannel(ch.ChannelID, os.Stdout)
			log.Printf("Server Log channel Opened, %d", ch.ChannelID)

			defer c.session.DeleteActiveChannel(ch.ChannelID)

		case MsgServerNewChannelOpened:
			// A public web user connected to the Daemon! We must dial our local target.
			sco, err := ParseServerChannelOpen(pkt.Payload[1:])
			if err != nil {
				continue
			}

			c.mu.RLock()
			localTarget, exists := c.session.forwardMap[sco.RemoteAddr]
			c.mu.RUnlock()

			if !exists {
				log.Printf("Security alert: Daemon requested unknown port %s", sco.RemoteAddr)
				continue
			}

			// Dial the local server in the background (e.g. 127.0.0.1:8080)
			go c.handleIncomingTrafiic(sco.ChannelID, localTarget)

		case MsgServerChanneledData:
			// Data arriving from the Daemon destined for our local server or shell
			cd, err := ParseChannelData(pkt.Payload[1:])
			if err != nil {
				continue
			}

			if ac, exists := c.session.GetActiveChannel(cd.ChannelID); exists {
				switch ch := ac.(type) {
				case net.Conn:
					ch.Write(cd.Data)
				case *PipeStream:
					ch.Feed(cd.Data)
				case *os.File:
					s := []byte("[Server LOG]: ")
					cd.Data = append(s, cd.Data...)
					ch.Write(cd.Data)
				}
			}

		case MsgServerChannelClosed:
			// The remote user disconnected
			ccl, err := ParseChannelClosed(pkt.Payload[1:])
			if err == nil {
				if channelObj, exists := c.session.GetActiveChannel(ccl.ChannelID); exists {
					switch ch := channelObj.(type) {
					case net.Conn:
						ch.Close()
					case *PipeStream:
						ch.Close()
					}
					c.session.DeleteActiveChannel(ccl.ChannelID)
				}
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
			c.session.conn.Close()
		case MsgServerAuthSuccess:

			log.Println("[Success] Logged in successfully!")
		case MsgServerENVCreated:
			ec, err := ParseEnvCreated(pkt.Payload[1:])
			if err != nil {
				log.Printf(" EnvCreated couldn't be parsed: %v", err)
				continue
			}
			if !ec.Success {
				log.Printf(" EnvCreate not successful")
				continue
			}
			log.Printf(" EnvCreated : %v", err)
			fmt.Printf(
				"EnvCreated{\n"+
					"  RequestID: %d\n"+
					"  PublicKey: %x\n"+
					"  AccessType: %s\n"+
					"  UserRequestedName: %s\n"+
					"  Name: %s\n"+
					"  Success: %v\n"+
					"}",
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

	c.session.AddActiveChannel(channelID, localConn)
	defer c.session.DeleteActiveChannel(channelID)
	defer localConn.Close()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	for {
		n, err := localConn.Read(buf)
		if n > 0 {
			cd := &ChannelData{
				ChannelID: channelID,
				Data:      buf[:n],
			}
			c.session.WritePacket(MsgClientChanneledData, cd.Marshal())
		}
		if err != nil {
			break
		}
	}

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

	return c.session.WritePacket(MsgClientListenRequest, req.Marshal())
}

// ForwardLocalToRemote (`ssh -L`) opens a port on this laptop and pushes it to a target via the Daemon.
func (c *Client) ForwardLocalToRemote(ctx context.Context, localListenAddr string, remoteTarget string) error {

	handler := func(ctx context.Context, localConn net.Conn) {
		chanID := c.session.IncrementChannelID()
		c.session.AddActiveChannel(chanID, localConn)
		defer c.session.DeleteActiveChannel(chanID)
		defer localConn.Close()

		// 1. Tell Daemon to dial the remote target
		// (Note: You need to add `MsgClientOpenChannel` to your daemon event loop to handle this!)
		req := &ClientChannelOpen{
			ChannelID:  chanID,
			AddrLen:    uint16(len(remoteTarget)),
			RemoteAddr: remoteTarget,
		}

		c.session.WritePacket(MsgClientNewChannelOpened, req.Marshal())

		// 2. Read from local connection, send to daemon
		pool := tcp.BufferPool(MAX_PACKET_LEN)
		buf := pool.Get().([]byte)
		defer pool.Put(buf)

		for {
			n, err := localConn.Read(buf)
			if n > 0 {
				cd := &ChannelData{
					ChannelID: chanID,
					Data:      buf[:n],
				}
				c.session.WritePacket(MsgClientChanneledData, cd.Marshal())
			}
			if err != nil {
				break
			}
		}

		ccl := &ChannelClosed{ChannelID: chanID}
		c.session.WritePacket(MsgClientChannelClosed, ccl.Marshal())
	}

	ln := tcp.DefaultListenOptions().WithVerbose(true)
	go ln.ListenWithContext(ctx, localListenAddr, handler)
	return nil
}

func (c *Client) Close() error {
	return nil
}

// RequestShell asks the daemon for an interactive shell and links os.Stdin/Stdout to it!
// SENDS TWO PACKETS SHELL REQ + WINDOW RESIZE
func (c *Client) RequestShell(shellPath, username string) error {
	// 1. Generate a random RequestID (4 bytes for Uint32)
	reqID := binary.BigEndian.Uint32(randomBytes(4))
	// Get the file descriptor for Stdin
	cols, row, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		log.Printf("failed to get initial window size")
		cols, row = 80, 24 // Default size
	}

	req := &ShellRequest{
		RequestID:   reqID,
		UsernameLen: uint8(len(username)),
		User:        []byte(username),
		ShellLen:    uint16(len(shellPath)),
		Shell:       []byte(shellPath),
		Row:         uint16(row), // Default size, will be updated by the client later
		Cols:        uint16(cols),
	}

	// 2. Create a channel to wait for the Daemon's response
	responseCh := make(chan *ShellRequestResponse, 1)
	c.mu.Lock()
	c.pendingShells[reqID] = responseCh
	c.mu.Unlock()

	// 3. Send the request to the Daemon
	if err := c.session.WritePacket(MsgClientShellRequest, req.Marshal()); err != nil {
		c.mu.Lock()
		delete(c.pendingShells, reqID)
		c.mu.Unlock()
		return err
	}

	log.Printf("Requested shell (%s). Waiting for Server approval...", shellPath)

	// ========================================================
	// SET UP SYSTEM SIGNAL CATCHER EARLY
	// ========================================================
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit) // Clean up the signal listener when this function exits!

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
		delete(c.pendingShells, reqID) // Clean up map
		c.mu.Unlock()
		return fmt.Errorf("timed out waiting for shell approval")
	case <-quit:
		// User pressed Ctrl+C BEFORE the shell was approved!
		log.Printf("\r\n[wireforge] Cancelled by user. Aborting shell request.\r\n")
		c.mu.Lock()
		delete(c.pendingShells, reqID) // Clean up map so event loop ignores late replies

		return nil
	}
	stdinFd := int(os.Stdin.Fd())

	stream := NewPipe(res.ChannelID, c.session)
	c.session.AddActiveChannel(res.ChannelID, stream)

	log.Printf("Client Shell Pipe Created, With Channel ID %d \r\n", res.ChannelID)

	defer c.session.DeleteActiveChannel(res.ChannelID)
	defer stream.Close()

	// ========================================================
	// TERMINAL RAW MODE
	// ========================================================
	//stdinFd := int(os.Stdin.Fd())

	// Put the local terminal into Raw Mode so every keystroke (like Tab and Arrows)
	// is sent immediately to the remote PTY.

	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("failed to set raw terminal mode: %v", err)
	}

	log.Printf("Client Old Shell Preserved, Starting the Raw Shell\r\n")

	// Guarantee the terminal goes back to normal when we disconnect!
	defer term.Restore(stdinFd, oldState)

	shellDone := make(chan struct{})
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.Signal(28))
	defer signal.Stop(sigwinch)

	go func() {
		for {
			select {
			case <-sigwinch:
				// Read your laptop terminal's new dimensions
				cols, rows, err := term.GetSize(stdinFd)
				if err == nil {
					resizeReq := &WindowResize{
						ChannelID: res.ChannelID,
						Rows:      uint16(rows),
						Cols:      uint16(cols),
					}
					// Send the new size to the daemon!
					c.session.WritePacket(MsgClientWindowResize, resizeReq.Marshal())
				}

			case <-shellDone:
				return // Stop monitoring when the shell closes
			}
		}
	}()

	// 7. Pipe local terminal input to the daemon
	go func() {
		io.Copy(stream, os.Stdin)
		// If the user types 'exit' or presses Ctrl+D, close the stream
		stream.Close()
	}()

	// 8. Pipe daemon output to local terminal

	go func() {
		io.Copy(os.Stdout, stream)
		close(shellDone) // Trigger the select block below when the server hangs up
	}()

	// 9. The Main Wait Block
	select {
	case <-shellDone:
		log.Printf("\r\n[wireforge] Remote shell exited or connection dropped.\r\n")
	case <-quit:
		// Catches OS kills (like Docker stop) while in Raw mode
		log.Printf("\r\nSIGTERM CAUGHT: Client Shell is being stopped\r\n")

	}

	return nil

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

		c.session.WritePacket(MsgClientENVCreate, req.Marshal())

		log.Printf("[Log] env request sent for public key : %s ", hex.EncodeToString(publicKey))
		return nil
	} else {
		return errors.New("unsupported private key type (must be ed25519)")
	}

}

// GetAndRunContainer checks if a container exists, boots it, or cleanly prints
// a list of alternative valid active containers if it is missing [1, 3].
func (c *Client) GetAndRunContainer(containerName string, prvKey crypto.Signer) error {
	reqID := binary.BigEndian.Uint32(randomBytes(4))
	stdinFd := int(os.Stdin.Fd())

	// FIXED: Corrected type assertion [1]
	if edKey, ok := prvKey.(ed25519.PrivateKey); ok {
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

		if err := c.session.WritePacket(MsgClientGetContainer, req.Marshal()); err != nil {
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

		case listRes := <-listCh: // FIXED: Now this case is 100% reachable and will unblock!
			fmt.Printf("\r\n[Error] Container %q not found on server.\r\n", containerName)
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
	stream := NewPipe(channelID, c.session)
	c.session.AddActiveChannel(channelID, stream)
	defer c.session.DeleteActiveChannel(channelID)
	defer stream.Close()

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
					c.session.WritePacket(MsgClientWindowResize, resizeReq.Marshal())
				}
			case <-shellDone:
				return
			}
		}
	}()

	go func() {
		io.Copy(stream, os.Stdin)
		stream.Close()
	}()

	io.Copy(os.Stdout, stream)
	close(shellDone)

	return nil
}
