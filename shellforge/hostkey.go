package shellforge

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Header keys used to carry the server's host-key identity proof inside the
// ServerHello header/extension block. Reusing the existing header mechanism
// means the ServerHello wire struct does not change, and any parser that does
// not understand these headers simply ignores them.
const (
	HostKeyHeaderKey = "host-key" // Ed25519 public key (32 bytes)
	HostSigHeaderKey = "host-sig" // Ed25519 signature over the handshake transcript (64 bytes)
)

// transcriptLabel is a domain-separation prefix so a host-key signature can
// never be confused with a signature produced for any other purpose.
const transcriptLabel = "shellforge-handshake-v1"

const hostKeyPEMType = "SHELLFORGE HOST KEY"

// LoadOrCreateHostKey loads the daemon's long-term Ed25519 host identity from
// disk, generating and persisting a fresh one on first run. The private key is
// written 0600 so only the daemon user can read it. This key is the root of
// trust that lets clients authenticate the server and detect an active MITM.
func LoadOrCreateHostKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("host key path is empty")
	}

	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != hostKeyPEMType {
			return nil, fmt.Errorf("host key file %q is not a valid PEM %q block", path, hostKeyPEMType)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key %q: %w", path, err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("host key %q is not an Ed25519 key", path)
		}
		return edKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to read host key %q: %w", path, err)
	}

	// First run: generate and persist a new host key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal host key: %w", err)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create host key dir %q: %w", dir, err)
		}
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: hostKeyPEMType, Bytes: pkcs8})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write host key %q: %w", path, err)
	}

	return priv, nil
}

// BuildHandshakeTranscript produces the exact byte string that the server signs
// with its host key and that the client verifies. It binds:
//   - ClientRandom  (the client's contributed randomness),
//   - SessionID     (the server's contributed randomness),
//   - kexAlgo       (negotiated key exchange, for downgrade protection),
//   - cipher        (negotiated symmetric cipher, for downgrade protection),
//   - serverShareKey (the server's ephemeral KEX share).
//
// Every variable-length field is length-prefixed so the concatenation is
// unambiguous and cannot be re-partitioned by an attacker. BOTH sides MUST
// build this identically or verification will (correctly) fail.
func BuildHandshakeTranscript(clientRandom, sessionID []byte, kexAlgo, cipher uint16, serverShareKey []byte) []byte {
	buf := make([]byte, 0, len(transcriptLabel)+len(clientRandom)+len(sessionID)+len(serverShareKey)+16)
	buf = append(buf, []byte(transcriptLabel)...)
	buf = appendLenPrefixed(buf, clientRandom)
	buf = appendLenPrefixed(buf, sessionID)

	var algoBuf [2]byte
	binary.BigEndian.PutUint16(algoBuf[:], kexAlgo)
	buf = append(buf, algoBuf[:]...)
	binary.BigEndian.PutUint16(algoBuf[:], cipher)
	buf = append(buf, algoBuf[:]...)

	buf = appendLenPrefixed(buf, serverShareKey)
	return buf
}

func appendLenPrefixed(dst, field []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, field...)
	return dst
}

// ---------------------------------------------------------------------------
// Client-side server authentication (host-key verification + TOFU pinning)
// ---------------------------------------------------------------------------

var (
	ErrNoHostKey = errors.New("server did not present a host key/signature (server authentication unavailable)")

	ErrHostKeyBadLength = errors.New("server host key or signature has an invalid length")

	ErrHostSigInvalid = errors.New("server host key signature verification failed (possible MITM or wrong key)")

	ErrHostKeyMismatch = errors.New("server host key does NOT match the pinned key in known_hosts (possible MITM!)")
)

func VerifyServerHelloSignature(sHello *ServerHello, clientRandom []byte, kexAlgo, cipher uint16) (ed25519.PublicKey, error) {
	hostPub, ok := sHello.GetHeader([]byte(HostKeyHeaderKey))
	if !ok {
		return nil, ErrNoHostKey
	}
	hostSig, ok := sHello.GetHeader([]byte(HostSigHeaderKey))
	if !ok {
		return nil, ErrNoHostKey
	}
	if len(hostPub) != ed25519.PublicKeySize || len(hostSig) != ed25519.SignatureSize {
		return nil, ErrHostKeyBadLength
	}

	transcript := BuildHandshakeTranscript(clientRandom, sHello.SessionID, kexAlgo, cipher, sHello.Encryption.Server_Share_key)
	if !ed25519.Verify(ed25519.PublicKey(hostPub), transcript, hostSig) {
		return nil, ErrHostSigInvalid
	}
	return ed25519.PublicKey(hostPub), nil
}

func CheckOrPinHostKey(knownHostsPath, addr string, hostPub ed25519.PublicKey) (pinned bool, err error) {
	existing, err := lookupKnownHost(knownHostsPath, addr)
	if err != nil {
		return false, err
	}

	hexKey := hex.EncodeToString(hostPub)
	if existing == "" {
		if err := appendKnownHost(knownHostsPath, addr, hexKey); err != nil {
			return false, err
		}
		return true, nil
	}

	// Constant-time compare; returns 0 on length mismatch too, which we treat
	// as a mismatch.
	if subtle.ConstantTimeCompare([]byte(existing), []byte(hexKey)) != 1 {
		return false, ErrHostKeyMismatch
	}
	return false, nil
}

// DefaultKnownHostsPath returns ~/.shellforge/known_hosts, falling back to a
// relative path if the home directory cannot be determined.
func DefaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".shellforge", "known_hosts")
	}
	return filepath.Join(home, ".shellforge", "known_hosts")
}

func lookupKnownHost(path, addr string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == addr {
			return fields[1], nil
		}
	}
	return "", sc.Err()
}

func appendKnownHost(path, addr, hexKey string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", addr, hexKey)
	return err
}
