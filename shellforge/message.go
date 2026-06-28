package shellforge

import (
	"encoding/binary"
)

type Message struct {
	KLen uint16
	Key  []byte

	Value []byte // Leftover bytes in the packet are implicitly the value [1]
}

// Unmarshal parses the binary payload and populates the receiver struct in-place.
func (m *Message) Unmarshal(data []byte) error {
	offset := 0

	// 1. Bounds check: Minimum 2 bytes (KLen)
	if len(data) < offset+2 {
		return ErrMalformedControlPacket
	}

	m.KLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Bounds check: Ensure remaining buffer can hold the Key payload [3]
	if len(data) < offset+int(m.KLen) {
		return ErrMalformedControlPacket
	}

	m.Key = data[offset : offset+int(m.KLen)] // Zero-Copy conversion [3]
	offset += int(m.KLen)

	// 3. The Value is simply everything remaining in the packet [1]
	// No bounds check is required here because we already verified offset <= len(data).
	m.Value = data[offset:] // Zero-Copy conversion [3]

	return nil
}

// Marshal converts the Message struct into a binary network payload.
func (m *Message) Marshal() []byte {
	// Size: KLen(2) + len(Key) + len(Value) = 2 + len(Key) + len(Value) [1]
	totalSize := 2 + len(m.Key) + len(m.Value)
	out := make([]byte, totalSize)
	offset := 0

	// Write KLen (2 bytes)
	binary.BigEndian.PutUint16(out[offset:], uint16(len(m.Key)))
	offset += 2

	// Write Key bytes
	offset += copy(out[offset:], m.Key)

	// Write Value bytes (takes up the rest of the pre-allocated slice) [1]
	copy(out[offset:], m.Value)

	return out
}

func (m *Message) ParseMessage(data []byte) error {
	return m.Unmarshal(data)
}

func (m *Message) Type() uint8 {
	return MsgServer
}
