package shellforge

import "encoding/binary"

type EnvRequest struct {
	RequestID            uint32
	PublicKey            []byte // 32 bytes (Ed25519)
	Signature            []byte // 64 bytes (Signature over Session.ID)
	AccessTypeLen        uint16
	AccessType           []byte
	UserRequestedNameLen uint8
	UserRequestedName    []byte //string, max 32 char //used for container name alias, sys_username alias, etc
}

type EnvCreated struct {
	RequestID     uint32
	PublicKey     []byte
	AccessTypeLen uint16
	AccessType    []byte

	UserRequestedNameLen uint8
	UserRequestedName    []byte //string, max 32 char //used for container name alias, sys_username alias, etc

	NameLen uint8
	Name    []byte

	Success bool
}

// Type satisfies your Packet interface
func (ts *EnvRequest) Type() uint8 {
	return MsgClientENVCreate
}

// Unmarshal parses the binary payload and populates the receiver struct in-place
func (ts *EnvRequest) Unmarshal(data []byte) error {
	parsed, err := ParseENVRequest(data)
	if err != nil {
		return err
	}

	// Copy the parsed values into the receiver [2]
	*ts = *parsed
	return nil
}

// ParseTempShellCreateRequest extracts the payload securely with strict bounds checking [3]
func ParseENVRequest(data []byte) (*EnvRequest, error) {
	ts := &EnvRequest{}
	offset := 0

	// 1. Base Bounds check: RequestID(4) + PublicKey(32) + Signature(64) + AccessTypeLen(2) = 102 bytes
	if len(data) < offset+102 {
		return nil, ErrCanNotParseMalformedPacket
	}

	ts.RequestID = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	ts.PublicKey = cloneBytes(data[offset : offset+32]) // copy: detach from reused rdBuf
	offset += 32

	ts.Signature = cloneBytes(data[offset : offset+64]) // copy: detach from reused rdBuf
	offset += 64

	ts.AccessTypeLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Bounds check: Ensure remaining buffer can hold the AccessType payload + at least the 1-byte UserRequestedNameLen
	if len(data) < offset+int(ts.AccessTypeLen)+1 {
		return nil, ErrCanNotParseMalformedPacket
	}
	ts.AccessType = cloneBytes(data[offset : offset+int(ts.AccessTypeLen)]) // copy: detach from reused rdBuf
	offset += int(ts.AccessTypeLen)

	// 3. Read UserRequestedNameLen (1 byte)
	ts.UserRequestedNameLen = data[offset]
	offset += 1

	// 4. Bounds check: Ensure remaining buffer can hold the UserRequestedName payload
	if len(data) < offset+int(ts.UserRequestedNameLen) {
		return nil, ErrCanNotParseMalformedPacket
	}
	ts.UserRequestedName = cloneBytes(data[offset : offset+int(ts.UserRequestedNameLen)]) // copy: detach from reused rdBuf

	return ts, nil
}

// Marshal converts the TempShellRequest struct into a binary network payload
func (ts *EnvRequest) Marshal() []byte {

	// Base size: RequestID(4) + PublicKey(32) + Signature(64) + AccessTypeLen(2) + UserRequestedNameLen(1) = 103 bytes
	totalSize := 103 + len(ts.AccessType) + len(ts.UserRequestedName)
	out := make([]byte, totalSize)
	offset := 0

	// Write RequestID (4 bytes)
	binary.BigEndian.PutUint32(out[offset:], ts.RequestID)
	offset += 4

	// Write PublicKey (Exactly 32 bytes)
	if len(ts.PublicKey) != 32 {
		panic(" envreq PublicKey must be exactly 32 bytes")
	}
	offset += copy(out[offset:], ts.PublicKey)

	// Write Signature (Exactly 64 bytes)
	// Write Signature (Exactly 64 bytes)
	if len(ts.Signature) != 64 {
		panic(" envreq Signature must be exactly 64 bytes")
	}
	offset += copy(out[offset:], ts.Signature)

	// Write AccessTypeLen (2 bytes) - Automatically derived from actual slice length
	binary.BigEndian.PutUint16(out[offset:], uint16(len(ts.AccessType)))
	offset += 2

	// Write AccessType
	offset += copy(out[offset:offset+len(ts.AccessType)], ts.AccessType)

	// Write UserRequestedNameLen (1 byte) - Automatically derived from actual slice length
	if len(ts.UserRequestedName) > 32 {
		panic(" envreq Signature must be exactly 64 bytes")
	}
	out[offset] = uint8(len(ts.UserRequestedName))
	offset += 1

	// Write UserRequestedName
	copy(out[offset:], ts.UserRequestedName)

	return out
}

// Type satisfies your Packet interface
func (ec *EnvCreated) Type() uint8 {
	// Assumed message type, ensure you map this in your protocol.go if different!
	return MsgServerENVRequestResponse
}

// Unmarshal parses the binary payload and populates the receiver struct in-place [1].
func (ec *EnvCreated) Unmarshal(data []byte) error {
	parsed, err := ParseEnvCreated(data)
	if err != nil {
		return err
	}

	*ec = *parsed
	return nil
}

// ParseEnvCreated extracts the payload securely with strict sequential bounds checking [2, 3].
func ParseEnvCreated(data []byte) (*EnvCreated, error) {
	ec := &EnvCreated{}
	offset := 0

	// 1. Base Bounds check: RequestID(4) + PublicKey(32) + AccessTypeLen(2) = 38 bytes minimum
	if len(data) < offset+38 {
		return nil, ErrMalformedControlPacket
	}

	ec.RequestID = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	ec.PublicKey = cloneBytes(data[offset : offset+32]) // copy: detach from reused rdBuf
	offset += 32

	ec.AccessTypeLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Bounds check: AccessType payload + 1-byte UserRequestedNameLen
	if len(data) < offset+int(ec.AccessTypeLen)+1 {
		return nil, ErrMalformedControlPacket
	}
	ec.AccessType = cloneBytes(data[offset : offset+int(ec.AccessTypeLen)]) // copy: detach from reused rdBuf
	offset += int(ec.AccessTypeLen)

	// Read UserRequestedNameLen (1 byte)
	ec.UserRequestedNameLen = data[offset]
	offset += 1

	// 3. Bounds check: UserRequestedName payload + 1-byte NameLen
	if len(data) < offset+int(ec.UserRequestedNameLen)+1 {
		return nil, ErrMalformedControlPacket
	}
	ec.UserRequestedName = cloneBytes(data[offset : offset+int(ec.UserRequestedNameLen)]) // copy: detach from reused rdBuf
	offset += int(ec.UserRequestedNameLen)

	// Read NameLen (1 byte)
	ec.NameLen = data[offset]
	offset += 1

	// 4. Bounds check: Name payload + 1-byte Success flag
	if len(data) < offset+int(ec.NameLen)+1 {
		return nil, ErrMalformedControlPacket
	}
	ec.Name = cloneBytes(data[offset : offset+int(ec.NameLen)]) // copy: detach from reused rdBuf
	offset += int(ec.NameLen)

	// 5. Read Success flag (1 byte: 0x01 = true, 0x00 = false)
	ec.Success = data[offset] == 1

	return ec, nil
}

// Marshal converts the EnvCreated struct into a binary network payload
func (ec *EnvCreated) Marshal() []byte {
	// Base size: RequestID(4) + PublicKey(32) + AccessTypeLen(2) + UserRequestedNameLen(1) + NameLen(1) + Success(1) = 41 bytes
	totalSize := 41 + len(ec.AccessType) + len(ec.UserRequestedName) + len(ec.Name)
	out := make([]byte, totalSize)
	offset := 0

	// Write RequestID (4 bytes)
	binary.BigEndian.PutUint32(out[offset:], ec.RequestID)
	offset += 4

	// Write PublicKey (Exactly 32 bytes)
	if len(ec.PublicKey) != 32 {
		panic("wireforge: EnvCreated PublicKey must be exactly 32 bytes")
	}
	offset += copy(out[offset:], ec.PublicKey)

	// Write AccessTypeLen (2 bytes)
	binary.BigEndian.PutUint16(out[offset:], uint16(len(ec.AccessType)))
	offset += 2
	offset += copy(out[offset:], ec.AccessType)

	// Write UserRequestedNameLen (1 byte)
	out[offset] = uint8(len(ec.UserRequestedName))
	offset += 1
	offset += copy(out[offset:], ec.UserRequestedName)

	// Write NameLen (1 byte)
	out[offset] = uint8(len(ec.Name))
	offset += 1
	offset += copy(out[offset:], ec.Name)

	// Write Success flag (1 byte)
	if ec.Success {
		out[offset] = 1
	} else {
		out[offset] = 0
	}

	return out
}
