package shellforge

import (
	"encoding/binary"
	"errors"
)

var ErrMalformedControlPacket = errors.New("malformed control packet: out of bounds")

// 1. LISTEN REQUEST (Client -> Server)
// ListenRequest = MsgClientListenAndForward == 	100
type ListenRequest struct {
	AddrLen uint16
	Address string // e.g., "0.0.0.0:8080"
}

// 2. LISTEN RESPONSE (Server -> Client)

type ListenResponse struct {
	AddrLen uint16
	Address string // e.g., "0.0.0.0:8080"
	Success bool
}

type ForwardRequest struct {
	AddrLen uint16
	Address string // e.g., "0.0.0.0:8080"
}

type ForwardResponse struct {
	AddrLen uint16
	Address string // e.g., "0.0.0.0:8080"
	Success bool
}

func (p *ListenRequest) Type() uint8 {
	return MsgClientListenRequest
}

func (p *ListenRequest) Unmarshal(data []byte) error {
	parsed, err := ParseListenRequest(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func ParseListenRequest(data []byte) (*ListenRequest, error) {
	req := &ListenRequest{}
	offset := 0

	if len(data) < offset+2 {
		return nil, ErrMalformedControlPacket
	}
	req.AddrLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(req.AddrLen) {
		return nil, ErrMalformedControlPacket
	}
	// Zero-copy string conversion
	req.Address = string(data[offset : offset+int(req.AddrLen)])

	return req, nil
}

func (req *ListenRequest) Marshal() []byte {
	out := make([]byte, 2+len(req.Address))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(req.Address)))
	copy(out[2:], req.Address)
	return out
}

func (p *ListenResponse) Type() uint8 {
	return MsgServerListenResponse
}

func (p *ListenResponse) Unmarshal(data []byte) error {
	parsed, err := ParseListenResponse(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func ParseListenResponse(data []byte) (*ListenResponse, error) {
	res := &ListenResponse{}
	offset := 0

	// 1. Bounds check: We need at least 2 bytes (AddrLen) + 1 byte (Success)
	if len(data) < offset+3 {
		return nil, ErrMalformedControlPacket
	}

	res.AddrLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Bounds check: Ensure the remaining data matches the string length + the 1-byte Success flag
	if len(data) < offset+int(res.AddrLen)+1 {
		return nil, ErrMalformedControlPacket
	}
	res.Address = string(data[offset : offset+int(res.AddrLen)]) // Zero-Copy conversion
	offset += int(res.AddrLen)

	// 3. Read the Success boolean (0x01 = true, 0x00 = false)
	res.Success = data[offset] == 1

	return res, nil
}

func (lo *ListenResponse) Marshal() []byte {
	// Allocate exact buffer size needed: 2 (AddrLen) + len(Address) + 1 (Success)
	out := make([]byte, 2+len(lo.Address)+1)

	binary.BigEndian.PutUint16(out[0:2], uint16(len(lo.Address)))
	copy(out[2:], lo.Address)

	// Write Success to the very last byte
	successOffset := 2 + len(lo.Address)
	if lo.Success {
		out[successOffset] = 1
	} else {
		out[successOffset] = 0
	}

	return out
}

func (p *ForwardRequest) Type() uint8 {
	return MsgClientForwardRequest
}

func (p *ForwardRequest) Unmarshal(data []byte) error {
	parsed, err := ParseForwardRequest(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func ParseForwardRequest(data []byte) (*ForwardRequest, error) {
	req := &ForwardRequest{}
	offset := 0

	if len(data) < offset+2 {
		return nil, ErrMalformedControlPacket
	}
	req.AddrLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(req.AddrLen) {
		return nil, ErrMalformedControlPacket
	}
	// Zero-copy string conversion
	req.Address = string(data[offset : offset+int(req.AddrLen)])

	return req, nil
}

func (req *ForwardRequest) Marshal() []byte {
	out := make([]byte, 2+len(req.Address))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(req.Address)))
	copy(out[2:], req.Address)
	return out
}

func (p *ForwardResponse) Type() uint8 {
	return MsgServerForwardResponse
}

func (p *ForwardResponse) Unmarshal(data []byte) error {
	parsed, err := ParseForwardResponse(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}

func ParseForwardResponse(data []byte) (*ForwardResponse, error) {
	res := &ForwardResponse{}
	offset := 0

	// 1. Bounds check: We need at least 2 bytes (AddrLen) + 1 byte (Success)
	if len(data) < offset+3 {
		return nil, ErrMalformedControlPacket
	}

	res.AddrLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Bounds check: Ensure the remaining data matches the string length + the 1-byte Success flag
	if len(data) < offset+int(res.AddrLen)+1 {
		return nil, ErrMalformedControlPacket
	}
	res.Address = string(data[offset : offset+int(res.AddrLen)]) // Zero-Copy conversion
	offset += int(res.AddrLen)

	// 3. Read the Success boolean (0x01 = true, 0x00 = false)
	res.Success = data[offset] == 1

	return res, nil
}

func (lo *ForwardResponse) Marshal() []byte {
	// Allocate exact buffer size needed: 2 (AddrLen) + len(Address) + 1 (Success)
	out := make([]byte, 2+len(lo.Address)+1)

	binary.BigEndian.PutUint16(out[0:2], uint16(len(lo.Address)))
	copy(out[2:], lo.Address)

	// Write Success to the very last byte
	successOffset := 2 + len(lo.Address)
	if lo.Success {
		out[successOffset] = 1
	} else {
		out[successOffset] = 0
	}

	return out
}
