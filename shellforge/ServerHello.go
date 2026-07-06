package shellforge

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var ErrMalformedServerHello = errors.New("malformed ServerHello packet: out of bounds")

type ServerHello struct {
	Length uint32 // 4 bytes (Length of everything after this field)

	SessionResumed bool // 1 byte (0x01 = true, 0x00 = false)

	SessLen   uint16 // 2 bytes
	SessionID []byte // 32 bytes

	EncryptionSupport bool // 1 byte
	Encryption        ServerHelloEncryptionFields

	SupportedAuths uint8 // 1 byte

	HeaderLen uint32
	Header    []ServerHelloHeader //capability ad

}

type ServerHelloEncryptionFields struct {
	ServerSharekeyLen uint16
	Server_Share_key  []byte // Server's X25519 public key or ML-KEM ciphertext (1088 bytes)
}

type ServerHelloHeader struct {
	KeyLen uint16
	Key    []byte

	ValueLen uint16
	Value    []byte
}

func (p *ServerHello) Unmarshal(data []byte) error {
	parsed, err := ParseServerHello(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func (p *ServerHello) Type() uint8 {
	return MsgServerHello
}

func ParseServerHello(data []byte) (*ServerHello, error) {
	sh := &ServerHello{}
	offset := 0

	// 1. Read Length (4 bytes)
	if len(data) < offset+4 {
		return nil, ErrMalformedServerHello
	}
	sh.Length = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if int(sh.Length) > len(data)-4 {
		return nil, ErrLargePacket
	}

	// 2. Read SessionResumed flag (1 byte)
	if len(data) < offset+1 {
		return nil, ErrMalformedServerHello
	}
	sh.SessionResumed = data[offset] == 1
	offset += 1

	// 3. Read Session ID
	if len(data) < offset+2 {
		return nil, ErrMalformedServerHello
	}
	sh.SessLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(sh.SessLen) {
		return nil, ErrMalformedServerHello
	}
	sh.SessionID = cloneBytes(data[offset : offset+int(sh.SessLen)]) // copy: detach from reused rdBuf
	offset += int(sh.SessLen)

	// 4. Read EncryptionSupport flag (1 byte)
	if len(data) < offset+1 {
		return nil, ErrMalformedServerHello
	}
	sh.EncryptionSupport = data[offset] == 1
	offset += 1

	// 5. Read Encryption Fields
	if sh.EncryptionSupport {
		if len(data) < offset+2 {
			return nil, ErrMalformedServerHello
		}
		sh.Encryption.ServerSharekeyLen = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		if len(data) < offset+int(sh.Encryption.ServerSharekeyLen) {
			return nil, ErrMalformedServerHello
		}
		sh.Encryption.Server_Share_key = cloneBytes(data[offset : offset+int(sh.Encryption.ServerSharekeyLen)]) // copy: detach from reused rdBuf
		offset += int(sh.Encryption.ServerSharekeyLen)
	}

	// 6. Read SupportedAuths (1 byte)
	if len(data) < offset+1 {
		return nil, ErrMalformedServerHello
	}
	sh.SupportedAuths = data[offset]
	offset += 1

	// 7. Read HeaderLen (4 bytes)
	if len(data) < offset+4 {
		return nil, ErrMalformedServerHello
	}
	sh.HeaderLen = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// 8. Read Headers Block
	if sh.HeaderLen > 0 {
		var headOffset uint32 = 0
		for headOffset < sh.HeaderLen {
			var currentHeader ServerHelloHeader

			// Read KeyLen (2 bytes)
			if len(data) < offset+2 {
				return nil, ErrMalformedServerHello
			}
			currentHeader.KeyLen = binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2
			headOffset += 2

			// Read Key
			if len(data) < offset+int(currentHeader.KeyLen) {
				return nil, ErrMalformedServerHello
			}
			currentHeader.Key = cloneBytes(data[offset : offset+int(currentHeader.KeyLen)]) // copy: detach from reused rdBuf
			offset += int(currentHeader.KeyLen)
			headOffset += uint32(currentHeader.KeyLen)

			// Read ValueLen (2 bytes)
			if len(data) < offset+2 {
				return nil, ErrMalformedServerHello
			}
			currentHeader.ValueLen = binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2
			headOffset += 2

			// Read Value
			if len(data) < offset+int(currentHeader.ValueLen) {
				return nil, ErrMalformedServerHello
			}
			currentHeader.Value = cloneBytes(data[offset : offset+int(currentHeader.ValueLen)]) // copy: detach from reused rdBuf
			offset += int(currentHeader.ValueLen)
			headOffset += uint32(currentHeader.ValueLen)

			// Verify we didn't exceed the boundary
			if headOffset > sh.HeaderLen {
				return nil, ErrMalformedServerHello
			}

			sh.Header = append(sh.Header, currentHeader)
		}
	}

	return sh, nil
}

func (sh *ServerHello) Marshal() []byte {
	// Base size: 4 (Length) + 1 (Resumed) + 2 (SessLen) + len(SessionID) + 1 (EncSupport) + 1 (SupportedAuths) + 4 (HeaderLen)
	totalSize := 4 + 1 + 2 + len(sh.SessionID) + 1 + 1 + 4
	if sh.EncryptionSupport {
		totalSize += 2 + len(sh.Encryption.Server_Share_key)
	}

	headerBlockSize := 0
	for _, h := range sh.Header {
		// KeyLen(2) + Key + ValLen(2) + Value
		headerBlockSize += 2 + len(h.Key) + 2 + len(h.Value)
	}
	totalSize += headerBlockSize

	out := make([]byte, totalSize)
	offset := 0

	// Length (excluding the first 4 bytes)
	binary.BigEndian.PutUint32(out[offset:], uint32(totalSize-4))
	offset += 4

	// Session Resumed
	if sh.SessionResumed {
		out[offset] = 1
	} else {
		out[offset] = 0
	}
	offset += 1

	// SessLen & SessionID
	binary.BigEndian.PutUint16(out[offset:], uint16(len(sh.SessionID)))
	offset += 2
	offset += copy(out[offset:], sh.SessionID)

	// Encryption Support
	if sh.EncryptionSupport {
		out[offset] = 1
		offset += 1

		binary.BigEndian.PutUint16(out[offset:], uint16(len(sh.Encryption.Server_Share_key)))
		offset += 2
		offset += copy(out[offset:], sh.Encryption.Server_Share_key)
	} else {
		out[offset] = 0
		offset += 1
	}

	// Supported Auths
	out[offset] = sh.SupportedAuths
	offset += 1

	// HeaderLen
	binary.BigEndian.PutUint32(out[offset:], uint32(headerBlockSize))
	offset += 4

	// Headers Block
	for _, h := range sh.Header {
		binary.BigEndian.PutUint16(out[offset:], uint16(len(h.Key)))
		offset += 2
		offset += copy(out[offset:], h.Key)

		binary.BigEndian.PutUint16(out[offset:], uint16(len(h.Value)))
		offset += 2
		offset += copy(out[offset:], h.Value)
	}

	return out
}

// GetHeader searches the parsed headers for a specific key
func (ch *ServerHello) GetHeader(key []byte) ([]byte, bool) {

	for _, h := range ch.Header {
		// bytes.Equal is fast and safe
		if len(h.Key) == len(key) && bytes.Equal(h.Key, key) {
			return h.Value, true
		}
	}
	return nil, false
}

func (ch *ServerHello) GetHeaderString(key string) (string, bool) {
	keyBytes := []byte(key)

	val, ok := ch.GetHeader(keyBytes)

	return string(val), ok
}

func (ch *ServerHello) HasHeader(name string) bool {
	_, ok := ch.GetHeaderString(name)
	return ok
}

func (ch *ServerHello) AddHeader(key, value []byte) {
	newhead := ServerHelloHeader{
		Key:   key,
		Value: value,
	}
	ch.Header = append(ch.Header, newhead)
}
