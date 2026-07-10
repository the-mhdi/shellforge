package shellforge

import "encoding/binary"

//every connection from/to the daemon gets a chanID() + every connection from/to the Client gets a chanID()
//daemon and client has to be aware of the all active channels

// if data > maxpacketlen, we chunk data into (maxpacklen-[1][4][4])
type Channel struct {
	ChannelID uint32
	DataLen   uint32
	Data      []byte
}

type ChannelClosed struct {
	ChannelID uint32
}

type ChannelOpen struct { // submissively tells the client to open a channel
	ChannelID uint32
}

// Sent by the Daemon to the Client when a public web user connects
type ServerChannelOpen struct {
	ChannelID  uint32
	AddrLen    uint16
	RemoteAddr string // e.g., "0.0.0.0:8080" //server lintens on this address
}

// Sent by the Client back to the Daemon if the dial succeeded or failed
type ClientChannelOpenConfirm struct {
	ChannelID uint32
	Success   bool
}

// Sent by the Client to the Daemon when a public web user connects
type ClientChannelOpen struct {
	ChannelID  uint32
	AddrLen    uint16
	RemoteAddr string // e.g., "0.0.0.0:8080" //client lintens on this address
}

// Sent by the Daemon back to the Client if the dial succeeded or failed
type ServerChannelOpenConfirm struct {
	ChannelID uint32
	Success   bool
}

func (p *Channel) Unmarshal(data []byte) error {
	parsed, err := ParseChannelData(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func (p *Channel) Type() uint8 {
	return MsgChanneledData
}

func ParseChannelData(data []byte) (*Channel, error) {
	cd := &Channel{}
	offset := 0

	if len(data) < offset+4 {
		return nil, ErrCanNotParseMalformedPacket
	}
	cd.ChannelID = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data) < offset+4 {
		return nil, ErrCanNotParseMalformedPacket
	}
	cd.DataLen = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data) < offset+int(cd.DataLen) {
		return nil, ErrCanNotParseMalformedPacket
	}
	cd.Data = data[offset : offset+int(cd.DataLen)] // Zero-Copy!

	return cd, nil
}

func (cd *Channel) Marshal() []byte {
	out := make([]byte, 8+len(cd.Data)) //4 Id + 4 len + data len
	binary.BigEndian.PutUint32(out[0:4], cd.ChannelID)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(cd.Data)))
	copy(out[8:], cd.Data)
	return out
}

func (p *ServerChannelOpen) Unmarshal(data []byte) error {
	parsed, err := ParseServerChannelOpen(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func (p *ServerChannelOpen) Type() uint8 {
	return MsgServerNewChannelOpened
}

func ParseServerChannelOpen(data []byte) (*ServerChannelOpen, error) {
	sco := &ServerChannelOpen{}
	offset := 0

	// 1. Bounds check: We need at least 4 bytes (ChannelID) + 2 bytes (AddrLen)
	if len(data) < offset+6 {
		return nil, ErrCanNotParseMalformedPacket
	}

	sco.ChannelID = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	sco.AddrLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Bounds check: Ensure the remaining data matches the string length
	if len(data) < offset+int(sco.AddrLen) {
		return nil, ErrCanNotParseMalformedPacket
	}
	sco.RemoteAddr = string(data[offset : offset+int(sco.AddrLen)]) // Zero-Copy conversion

	return sco, nil
}

func (s *ServerChannelOpen) Marshal() []byte {
	// Allocate exact buffer size needed
	out := make([]byte, 6+len(s.RemoteAddr))

	binary.BigEndian.PutUint32(out[0:4], s.ChannelID)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(s.RemoteAddr)))
	copy(out[6:], s.RemoteAddr)

	return out
}

func (p *ClientChannelOpenConfirm) Unmarshal(data []byte) error {
	parsed, err := ParseClientChannelOpenConfirm(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func (p *ClientChannelOpenConfirm) Type() uint8 {
	return MsgClientChannelOpenConfirm
}

func ParseClientChannelOpenConfirm(data []byte) (*ClientChannelOpenConfirm, error) {
	// Bounds check: Must be exactly 5 bytes
	if len(data) < 5 {
		return nil, ErrCanNotParseMalformedPacket
	}

	return &ClientChannelOpenConfirm{
		ChannelID: binary.BigEndian.Uint32(data[0:4]),
		Success:   data[4] == 1, // 0x01 = true, 0x00 = false
	}, nil
}

func (c *ClientChannelOpenConfirm) Marshal() []byte {
	out := make([]byte, 5)

	binary.BigEndian.PutUint32(out[0:4], c.ChannelID)
	if c.Success {
		out[4] = 1
	} else {
		out[4] = 0
	}

	return out
}

func (p *ClientChannelOpen) Unmarshal(data []byte) error {
	parsed, err := ParseClientChannelOpen(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func (p *ClientChannelOpen) Type() uint8 {
	return MsgClientOpenChannel
}

func ParseClientChannelOpen(data []byte) (*ClientChannelOpen, error) {
	sco := &ClientChannelOpen{}
	offset := 0

	// 1. Bounds check: We need at least 4 bytes (ChannelID) + 2 bytes (AddrLen)
	if len(data) < offset+6 {
		return nil, ErrCanNotParseMalformedPacket
	}

	sco.ChannelID = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	sco.AddrLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 2. Bounds check: Ensure the remaining data matches the string length
	if len(data) < offset+int(sco.AddrLen) {
		return nil, ErrCanNotParseMalformedPacket
	}
	sco.RemoteAddr = string(data[offset : offset+int(sco.AddrLen)]) // Zero-Copy conversion

	return sco, nil
}

func (s *ClientChannelOpen) Marshal() []byte {
	// Allocate exact buffer size needed
	out := make([]byte, 6+len(s.RemoteAddr))

	binary.BigEndian.PutUint32(out[0:4], s.ChannelID)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(s.RemoteAddr)))
	copy(out[6:], s.RemoteAddr)

	return out
}

func (p *ServerChannelOpenConfirm) Unmarshal(data []byte) error {
	parsed, err := ParseServerChannelOpenConfirm(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func (p *ServerChannelOpenConfirm) Type() uint8 {
	return MsgServerChannelOpenConfirm
}

func ParseServerChannelOpenConfirm(data []byte) (*ServerChannelOpenConfirm, error) {
	// Bounds check: Must be exactly 5 bytes
	if len(data) < 5 {
		return nil, ErrCanNotParseMalformedPacket
	}

	return &ServerChannelOpenConfirm{
		ChannelID: binary.BigEndian.Uint32(data[0:4]),
		Success:   data[4] == 1, // 0x01 = true, 0x00 = false
	}, nil
}

func (c *ServerChannelOpenConfirm) Marshal() []byte {
	out := make([]byte, 5)

	binary.BigEndian.PutUint32(out[0:4], c.ChannelID)
	if c.Success {
		out[4] = 1
	} else {
		out[4] = 0
	}

	return out
}

func (p *ChannelClosed) Unmarshal(data []byte) error {
	parsed, err := ParseChannelClosed(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func (p *ChannelClosed) Type() uint8 {
	return MsgChannelClosed
}

func ParseChannelClosed(data []byte) (*ChannelClosed, error) {
	// Bounds check: Must be at least 4 bytes
	if len(data) < 4 {
		return nil, ErrCanNotParseMalformedPacket
	}

	return &ChannelClosed{
		ChannelID: binary.BigEndian.Uint32(data[0:4]),
	}, nil
}

func (cc *ChannelClosed) Marshal() []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out[0:4], cc.ChannelID)
	return out
}

func (p *ChannelOpen) Unmarshal(data []byte) error {
	parsed, err := ParseChannelOpen(data)
	if err != nil {
		return err
	}

	*p = *parsed

	return nil
}
func (p *ChannelOpen) Type() uint8 {
	return MsgServerOpenChannel
}

func ParseChannelOpen(data []byte) (*ChannelOpen, error) {
	// Bounds check: Must be at least 4 bytes
	if len(data) < 4 {
		return nil, ErrCanNotParseMalformedPacket
	}

	return &ChannelOpen{
		ChannelID: binary.BigEndian.Uint32(data[0:4]),
	}, nil
}

func (cc *ChannelOpen) Marshal() []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out[0:4], cc.ChannelID)
	return out
}
