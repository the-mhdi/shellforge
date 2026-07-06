package shellforge

import "fmt"

type Packet interface {
	Type() uint8
	Marshal() []byte
	Unmarshal(data []byte) error
}

// instantiates the correct Go struct, and parses the binary payload.
func UnmarshalPacket(msgType uint8, data []byte) (Packet, error) {
	var msg Packet

	switch msgType {
	case MsgClientHello:
		msg = &ClientHello{}
	case MsgServerHello:
		msg = &ServerHello{}
	case MsgClientListenRequest:
		msg = &ListenRequest{}
	case MsgServerListenResponse:
		msg = &ListenResponse{}
	case MsgServerNewChannelOpened:
		msg = &ServerChannelOpen{}
	case MsgClientChanneledData, MsgServerChanneledData:
		msg = &Channel{}
	case MsgClientChannelClosed, MsgServerChannelClosed:
		msg = &ChannelClosed{}
	case MsgClientShellRequest:
		msg = &ShellRequest{}
	case MsgServerShellReqResponse:
		msg = &ShellRequestResponse{}
	case MsgClientResumeProof:
		msg = &ResumeProof{}
	// nil packets
	case MsgNilPacket:
		msg = &nilPacket{Code: MsgNilPacket}
	case MsgServerAuthSuccess:
		msg = &nilPacket{Code: MsgServerAuthSuccess}
	default:
		return nil, fmt.Errorf("unknown protocol message type: %d", msgType)
	}

	// Execute the polymorphic Unmarshal method
	if err := msg.Unmarshal(data); err != nil {
		return nil, err
	}

	return msg, nil
}
