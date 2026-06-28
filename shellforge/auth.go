package shellforge

import (
	"encoding/binary"
	"errors"
)

var ErrMalformedPKIPacket = errors.New("malformed PKI auth packet: out of bounds")

type PubAuthRequest struct {
	UserLen   uint16
	Username  string
	PublicKey []byte // Exactly 32 bytes (Ed25519)
	Signature []byte // Exactly 64 bytes (Ed25519 Signature over Session.ID)
}

func (p *PubAuthRequest) Type() uint8 {
	return MsgClientAuthPub
}

func (p *PubAuthRequest) Unmarshal(data []byte) error {

	parsed, err := ParsePubAuthRequest(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil

}

func ParsePubAuthRequest(data []byte) (*PubAuthRequest, error) {
	ar := &PubAuthRequest{}
	offset := 0

	if len(data) < offset+2 {
		return nil, ErrMalformedControlPacket
	}
	ar.UserLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Username + 32 (PubKey) + 64 (Signature)
	if len(data) < offset+int(ar.UserLen)+32+64 {
		return nil, ErrMalformedControlPacket
	}

	ar.Username = string(data[offset : offset+int(ar.UserLen)])
	offset += int(ar.UserLen)

	ar.PublicKey = data[offset : offset+32]
	offset += 32

	ar.Signature = data[offset : offset+64]

	return ar, nil
}

func (ar *PubAuthRequest) Marshal() []byte {
	out := make([]byte, 2+len(ar.Username)+32+64)
	offset := 0

	binary.BigEndian.PutUint16(out[offset:], uint16(len(ar.Username)))
	offset += 2

	offset += copy(out[offset:], ar.Username)
	offset += copy(out[offset:], ar.PublicKey)
	copy(out[offset:], ar.Signature)

	return out
}

// PasswordAuthRequest handles standard PAM/Password handshakes
type PasswordAuthRequest struct {
	UserLen  uint16
	Username string
	PassLen  uint16
	Password string
}

func (p *PasswordAuthRequest) Type() uint8 {
	return MsgClientAuthPassword
}

func (p *PasswordAuthRequest) Unmarshal(data []byte) error {
	parsed, err := ParsePasswordAuthRequest(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func (ar *PasswordAuthRequest) Marshal() []byte {
	out := make([]byte, 2+len(ar.Username)+2+len(ar.Password))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(ar.Username)))
	copy(out[2:], ar.Username)

	passOffset := 2 + len(ar.Username)
	binary.BigEndian.PutUint16(out[passOffset:passOffset+2], uint16(len(ar.Password)))
	copy(out[passOffset+2:], ar.Password)
	return out
}

func ParsePasswordAuthRequest(data []byte) (*PasswordAuthRequest, error) {
	ar := &PasswordAuthRequest{}
	offset := 0

	if len(data) < offset+2 {
		return nil, ErrMalformedControlPacket
	}
	ar.UserLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(ar.UserLen) {
		return nil, ErrMalformedControlPacket
	}
	ar.Username = string(data[offset : offset+int(ar.UserLen)])
	offset += int(ar.UserLen)

	if len(data) < offset+2 {
		return nil, ErrMalformedControlPacket
	}
	ar.PassLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(ar.PassLen) {
		return nil, ErrMalformedControlPacket
	}
	ar.Password = string(data[offset : offset+int(ar.PassLen)])

	return ar, nil
}

type PKIAuthRequest struct {
	CertLen     uint32 // 4 bytes
	Certificate []byte // Raw DER-encoded X.509 certificate

	SigLen    uint16 // 2 bytes
	Signature []byte // Cryptographic signature over Session.ID
}

func (p *PKIAuthRequest) Type() uint8 {
	return MsgClientAuthPKI
}

func (p *PKIAuthRequest) Unmarshal(data []byte) error {
	parsed, err := ParsePKIAuthRequest(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func ParsePKIAuthRequest(data []byte) (*PKIAuthRequest, error) {
	req := &PKIAuthRequest{}
	offset := 0

	// 1. Read CertLen (4 bytes) + SigLen (2 bytes)
	if len(data) < offset+6 {
		return nil, ErrMalformedPKIPacket
	}
	req.CertLen = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// 2. Read Certificate bytes
	if len(data) < offset+int(req.CertLen) {
		return nil, ErrMalformedPKIPacket
	}
	req.Certificate = data[offset : offset+int(req.CertLen)]
	offset += int(req.CertLen)

	// 3. Read SigLen (2 bytes)
	if len(data) < offset+2 {
		return nil, ErrMalformedPKIPacket
	}
	req.SigLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 4. Read Signature bytes
	if len(data) < offset+int(req.SigLen) {
		return nil, ErrMalformedPKIPacket
	}
	req.Signature = data[offset : offset+int(req.SigLen)]

	return req, nil
}

func (r *PKIAuthRequest) Marshal() []byte {
	totalSize := 4 + len(r.Certificate) + 2 + len(r.Signature)
	out := make([]byte, totalSize)
	offset := 0

	binary.BigEndian.PutUint32(out[offset:], uint32(len(r.Certificate)))
	offset += 4
	offset += copy(out[offset:], r.Certificate)

	binary.BigEndian.PutUint16(out[offset:], uint16(len(r.Signature)))
	offset += 2
	copy(out[offset:], r.Signature)

	return out
}

type AuthResponse struct {
	UserLen  uint16
	Username string
	Type     uint8
	Success  bool
}

// ParseAuthResponse is a lightweight helper that instantiates an AuthResponse
// and unmarshals the raw binary data into it.
func ParseAuthResponse(data []byte) (*AuthResponse, error) {
	ar := &AuthResponse{}
	if err := ar.Unmarshal(data); err != nil {
		return nil, err
	}
	return ar, nil
}

// Unmarshal parses the binary payload and populates the receiver struct in-place.
func (ar *AuthResponse) Unmarshal(data []byte) error {
	offset := 0

	// 1. Bounds check: Minimum 4 bytes (UserLen(2) + Type(1) + Success(1))
	if len(data) < offset+4 {
		return ErrMalformedControlPacket
	}

	ar.UserLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Bounds check: Ensure remaining buffer can hold the Username, Type, and Success flag
	if len(data) < offset+int(ar.UserLen)+2 {
		return ErrMalformedControlPacket
	}

	ar.Username = string(data[offset : offset+int(ar.UserLen)]) // Zero-Copy conversion
	offset += int(ar.UserLen)

	// 3. Read Type (1 byte)
	ar.Type = data[offset]
	offset += 1

	// 4. Read Success (1 byte boolean)
	ar.Success = data[offset] == 1

	return nil
}

// Marshal converts the AuthResponse struct into a binary network payload.
func (ar *AuthResponse) Marshal() []byte {
	// Size: UserLen(2) + len(Username) + Type(1) + Success(1) = 4 + len(Username)
	totalSize := 4 + len(ar.Username)
	out := make([]byte, totalSize)

	// Write UserLen
	binary.BigEndian.PutUint16(out[0:2], uint16(len(ar.Username)))

	// Write Username string
	copy(out[2:], ar.Username)

	// Write Type (placed immediately after the variable string)
	typeOffset := 2 + len(ar.Username)
	out[typeOffset] = ar.Type

	// Write Success flag (at the very last byte)
	successOffset := 3 + len(ar.Username)
	if ar.Success {
		out[successOffset] = 1
	} else {
		out[successOffset] = 0
	}

	return out
}
