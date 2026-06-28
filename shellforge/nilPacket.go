package shellforge

// for packets with no payload
type nilPacket struct {
	Code uint8 // ==type
}

func (p *nilPacket) Unmarshal(data []byte) error {

	*p = *new(nilPacket)

	return nil
}

func (p *nilPacket) Type() uint8 {
	return p.Code
}

func (p *nilPacket) Marshal() []byte {
	return nil
}
