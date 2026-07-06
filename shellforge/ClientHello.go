package shellforge

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var ErrMalformedPacket = errors.New("malformed ClientHello packet: out of bounds")
var ErrLargePacket = errors.New("packet claims to be larger than provided data, connection DROPED")
var ErrInvalidProofSize = errors.New("malformed ResumeProof: must be exactly 32 bytes")

type ClientHello struct {
	Length uint32 // 4 bytes (Length of this specific message)

	SessLen   uint16 //if 0 -> new session , if non-zero server can accept or reject based on this configuration
	SessionID []byte // 1-16 bytes

	EncryptionSupport bool //based on the server configuration server can only accept encyrpted sessions and reject if client doesnt support encryption
	Encryption        ClientHelloEncryptionFields

	HeaderLen uint32
	Header    []ClientHelloHeader //Extensions etc,, used for key exchange

	ClientRandom []byte // 256bit/32byte random number
}

type ClientHelloEncryptionFields struct {
	CLIENT_KEX_ALGO uint16 // 2 bytes: The chosen Key Exchange (e.g., KexHybridX25519MLKEM768)
	CLIENT_CIPHER   uint16 // 2 bytes: The chosen Symmetric Cipher (e.g., CipherChaCha20Poly1305)

	//daemon will use the client's prefered key exchange method and cipher suite to respond with the server hello
	// if the client hello does not support encryption or the client's prefered key exchange and cipher suite are
	// not supported by the server configuration, the server can choose to reject the session or
	// fall back to an unencrypted session based on its configuration, this allows for flexible security policies
	//  while still enabling compatibility with clients that may have limited capabilities.
	ClientSharekeyLen uint16
	Client_Share_key  []byte // Client's X25519 public key or ML-KEM ciphertext (1088 bytes)
}

type ClientHelloHeader struct {
	KeyLen uint16
	Key    []byte

	ValueLen uint16
	Value    []byte
}

func (p *ClientHello) Type() uint8 {
	return MsgClientHello
}

func (p *ClientHello) Unmarshal(data []byte) error {
	parsed, err := parseClientHello(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func parseClientHello(data []byte) (*ClientHello, error) {
	h := &ClientHello{}
	offset := 0

	// 1. Read Length (4 bytes)
	if len(data) < offset+4 {
		return nil, ErrMalformedPacket
	}
	h.Length = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Length is the size of everything after these 4 bytes
	if int(h.Length) > len(data)-4 {
		return nil, ErrLargePacket
	}

	// 2. Read Session ID
	if len(data) < offset+2 {
		return nil, ErrMalformedPacket
	}
	h.SessLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(h.SessLen) {
		return nil, ErrMalformedPacket
	}
	h.SessionID = cloneBytes(data[offset : offset+int(h.SessLen)]) // copy: detach from reused rdBuf
	offset += int(h.SessLen)

	// 3. Read EncryptionSupport (1 byte)
	if len(data) < offset+1 {
		return nil, ErrMalformedPacket
	}
	h.EncryptionSupport = data[offset] == 1
	offset += 1

	// 4. Read Encryption Fields ONLY if EncryptionSupport is true
	if h.EncryptionSupport {
		// Read CLIENT_KEX(2) + CLIENT_CIPHER(2) + ClientSharekeyLen(2)
		if len(data) < offset+6 {
			return nil, ErrMalformedPacket
		}
		h.Encryption.CLIENT_KEX_ALGO = binary.BigEndian.Uint16(data[offset : offset+2])
		h.Encryption.CLIENT_CIPHER = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		h.Encryption.ClientSharekeyLen = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		offset += 6

		if len(data) < offset+int(h.Encryption.ClientSharekeyLen) {
			return nil, ErrMalformedPacket
		}
		h.Encryption.Client_Share_key = cloneBytes(data[offset : offset+int(h.Encryption.ClientSharekeyLen)]) // copy: detach from reused rdBuf
		offset += int(h.Encryption.ClientSharekeyLen)
	}

	// 5. Read Header block length (4 bytes)
	if len(data) < offset+4 {
		return nil, ErrMalformedPacket
	}
	h.HeaderLen = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// 6. Read Headers
	if h.HeaderLen > 0 {
		var headOffset uint32 = 0

		for headOffset < h.HeaderLen {
			var currentHeader ClientHelloHeader

			// Read KeyLen (2 bytes)
			if len(data) < offset+2 {
				return nil, ErrMalformedPacket
			}
			currentHeader.KeyLen = binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2
			headOffset += 2

			// Read Key
			if len(data) < offset+int(currentHeader.KeyLen) {
				return nil, ErrMalformedPacket
			}
			currentHeader.Key = cloneBytes(data[offset : offset+int(currentHeader.KeyLen)]) // copy: detach from reused rdBuf
			offset += int(currentHeader.KeyLen)
			headOffset += uint32(currentHeader.KeyLen)

			// Read ValueLen (2 bytes)
			if len(data) < offset+2 {
				return nil, ErrMalformedPacket
			}
			currentHeader.ValueLen = binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2
			headOffset += 2

			// Read Value
			if len(data) < offset+int(currentHeader.ValueLen) {
				return nil, ErrMalformedPacket
			}
			currentHeader.Value = cloneBytes(data[offset : offset+int(currentHeader.ValueLen)]) // copy: detach from reused rdBuf
			offset += int(currentHeader.ValueLen)
			headOffset += uint32(currentHeader.ValueLen)

			// Security boundary check
			if headOffset > h.HeaderLen {
				return nil, ErrMalformedPacket
			}

			h.Header = append(h.Header, currentHeader)
		}
	}

	// 7. Read ClientRandom (32 bytes) at the outer struct level
	if len(data) < offset+32 {
		return nil, ErrMalformedPacket
	}
	h.ClientRandom = cloneBytes(data[offset : offset+32]) // copy: detach from reused rdBuf
	offset += 32

	return h, nil
}

// Marshal converts the ClientHello struct into a binary byte slice ready for the network
func (ch *ClientHello) Marshal() []byte {
	// 1. Calculate the exact size needed
	// Base size: Length(4) + SessLen(2) + SessionID + EncSupport(1) + HeaderLen(4) + ClientRandom(32)
	totalSize := 4 + 2 + len(ch.SessionID) + 1 + 4 + 32

	if ch.EncryptionSupport {
		// CLIENT_KEX(2) + CLIENT_CIPHER(2) + ClientSharekeyLen(2) + Client_Share_key
		totalSize += 2 + 2 + 2 + len(ch.Encryption.Client_Share_key)
	}

	headerBlockSize := 0
	for _, h := range ch.Header {
		// KeyLen(2) + Key + ValLen(2) + Value
		headerBlockSize += 2 + len(h.Key) + 2 + len(h.Value)
	}
	totalSize += headerBlockSize

	// 2. Allocate the exact buffer size
	out := make([]byte, totalSize)
	offset := 0

	// Length field (excluding the 4 length bytes themselves)
	binary.BigEndian.PutUint32(out[offset:], uint32(totalSize-4))
	offset += 4

	binary.BigEndian.PutUint16(out[offset:], uint16(len(ch.SessionID)))
	offset += 2

	offset += copy(out[offset:], ch.SessionID)

	if ch.EncryptionSupport {
		out[offset] = 1
		offset += 1

		binary.BigEndian.PutUint16(out[offset:], ch.Encryption.CLIENT_KEX_ALGO)
		offset += 2

		binary.BigEndian.PutUint16(out[offset:], ch.Encryption.CLIENT_CIPHER)
		offset += 2

		binary.BigEndian.PutUint16(out[offset:], uint16(len(ch.Encryption.Client_Share_key)))
		offset += 2

		offset += copy(out[offset:], ch.Encryption.Client_Share_key)
	} else {
		out[offset] = 0
		offset += 1
	}

	// Write Headers length prefix
	binary.BigEndian.PutUint32(out[offset:], uint32(headerBlockSize))
	offset += 4

	// Write Headers
	for _, h := range ch.Header {
		binary.BigEndian.PutUint16(out[offset:], uint16(len(h.Key)))
		offset += 2
		offset += copy(out[offset:], h.Key)

		binary.BigEndian.PutUint16(out[offset:], uint16(len(h.Value)))
		offset += 2
		offset += copy(out[offset:], h.Value)
	}

	// Write ClientRandom (Must be exactly 32 bytes)
	if len(ch.ClientRandom) != 32 {
		panic("wireforge: ClientRandom must be exactly 32 bytes")
	}
	copy(out[offset:], ch.ClientRandom)

	return out
}

func (ch *ClientHello) AddHeader(key, value []byte) {
	newhead := ClientHelloHeader{
		Key:   key,
		Value: value,
	}
	ch.Header = append(ch.Header, newhead)
}

func (ch *ClientHello) HasHeader(name string) bool {
	_, ok := ch.GetHeaderString(name)
	return ok
}

// GetHeader searches the parsed headers for a specific key
func (ch *ClientHello) GetHeader(key []byte) ([]byte, bool) {

	for _, h := range ch.Header {
		// bytes.Equal is fast and safe
		if len(h.Key) == len(key) && bytes.Equal(h.Key, key) {
			return h.Value, true
		}
	}
	return nil, false
}

func (ch *ClientHello) GetHeaderString(key string) (string, bool) {
	keyBytes := []byte(key)

	val, ok := ch.GetHeader(keyBytes)

	return string(val), ok
}

// ResumeProof is sent by the client over the newly attached TCP socket.
// It is encrypted using the existing AES-GCM keys of the resumed session.
type ResumeProof struct {
	ClientRandom []byte // Must be exactly 32 bytes
}

func (p *ResumeProof) Type() uint8 {
	return MsgClientResumeProof
}

func (p *ResumeProof) Unmarshal(data []byte) error {
	parsed, err := ParseResumeProof(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

// ParseResumeProof extracts the proof payload.
// It expects the data slice to exclude the 1-byte Message Type prefix.
func ParseResumeProof(data []byte) (*ResumeProof, error) {
	// Strict bounds checking: Cryptographic proofs must be exact.
	// If it is not exactly 32 bytes, a hacker is tampering with the packet.
	if len(data) != 32 {
		return nil, ErrInvalidProofSize
	}

	return &ResumeProof{
		ClientRandom: cloneBytes(data[:32]), // copy: detach from reused rdBuf
	}, nil
}

// Marshal converts the proof into a byte slice.
func (rp *ResumeProof) Marshal() []byte {
	// Allocate exactly 32 bytes
	out := make([]byte, 32)

	// Safety check to prevent panics during copy
	if len(rp.ClientRandom) != 32 {
		panic("wireforge: ResumeProof ClientRandom must be exactly 32 bytes")
	}

	copy(out, rp.ClientRandom)
	return out
}
