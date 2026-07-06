package shellforge

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"runtime"
	"sync/atomic"
	"testing"
)

// TestControlParsersDetachFromReusableReadBuffer is a regression test for the
// bug class:
//
//	ReadPacket returns Payload as a subslice of Session.rdBuf, parsers retain
//	zero-copy []byte fields, handlers pass parsed structs to goroutines, and
//	the next ReadPacket overwrites rdBuf.
//
// Each subtest parses a CONTROL packet from a mutable buffer, then reads the
// parsed []byte fields in a goroutine while the original parse buffer is
// overwritten many times. With the old zero-copy parsers, `go test -race` should
// report a data race here. With fixed parsers that clone their []byte fields,
// the goroutine reads detached memory and the race detector remains quiet.
//
// Run with:
//
//	go test -race ./shellforge -run TestControlParsersDetachFromReusableReadBuffer -count=1
func TestControlParsersDetachFromReusableReadBuffer(t *testing.T) {
	pub := bytes.Repeat([]byte{0xA1}, ed25519.PublicKeySize)
	sig := bytes.Repeat([]byte{0xB2}, ed25519.SignatureSize)
	cert := bytes.Repeat([]byte{0xC3}, 96)

	tests := []struct {
		name   string
		packet []byte
		parse  func([]byte) ([][]byte, error)
	}{
		{
			name: "ShellRequest_User_Shell",
			packet: (&ShellRequest{
				RequestID:   0x01020304,
				UsernameLen: uint8(len("mahdi")),
				User:        []byte("mahdi"),
				ShellLen:    uint16(len("/bin/bash")),
				Shell:       []byte("/bin/bash"),
				Row:         24,
				Cols:        80,
			}).Marshal(),
			parse: func(b []byte) ([][]byte, error) {
				sr, err := ParseShellRequest(b)
				if err != nil {
					return nil, err
				}
				return [][]byte{sr.User, sr.Shell}, nil
			},
		},
		{
			name: "ContainerOpRequest_PublicKey_Name_Command",
			packet: (&ContainerOpRequest{
				RequestID: 0x11121314,
				PublicKey: pub,
				NameLen:   uint8(len("demo-container")),
				Name:      []byte("demo-container"),
				OpType:    ContainerOpCommand,
				Command:   []byte("id && uname -a"),
				Row:       30,
				Cols:      120,
			}).Marshal(),
			parse: func(b []byte) ([][]byte, error) {
				cop, err := ParseContainerOpRequest(b)
				if err != nil {
					return nil, err
				}
				return [][]byte{cop.PublicKey, cop.Name, cop.Command}, nil
			},
		},
		{
			name: "EnvRequest_PublicKey_Signature_AccessType_Name",
			packet: (&EnvRequest{
				RequestID:            0x21222324,
				PublicKey:            pub,
				Signature:            sig,
				AccessType:           []byte("container"),
				UserRequestedNameLen: uint8(len("demo")),
				UserRequestedName:    []byte("demo"),
			}).Marshal(),
			parse: func(b []byte) ([][]byte, error) {
				er, err := ParseENVRequest(b)
				if err != nil {
					return nil, err
				}
				return [][]byte{er.PublicKey, er.Signature, er.AccessType, er.UserRequestedName}, nil
			},
		},
		{
			name: "PubAuthRequest_PublicKey_Signature",
			packet: (&PubAuthRequest{
				Username:  "mahdi",
				PublicKey: pub,
				Signature: sig,
			}).Marshal(),
			parse: func(b []byte) ([][]byte, error) {
				ar, err := ParsePubAuthRequest(b)
				if err != nil {
					return nil, err
				}
				return [][]byte{ar.PublicKey, ar.Signature}, nil
			},
		},
		{
			name: "PKIAuthRequest_Certificate_Signature",
			packet: (&PKIAuthRequest{
				Certificate: cert,
				Signature:   sig,
			}).Marshal(),
			parse: func(b []byte) ([][]byte, error) {
				pr, err := ParsePKIAuthRequest(b)
				if err != nil {
					return nil, err
				}
				return [][]byte{pr.Certificate, pr.Signature}, nil
			},
		},
		{
			name: "Message_Key_Value",
			packet: (&Message{
				Key:   []byte("control-key"),
				Value: []byte("control-value"),
			}).Marshal(),
			parse: func(b []byte) ([][]byte, error) {
				var msg Message
				if err := msg.Unmarshal(b); err != nil {
					return nil, err
				}
				return [][]byte{msg.Key, msg.Value}, nil
			},
		},
		{
			name:   "ResumeProof_ClientRandom",
			packet: bytes.Repeat([]byte{0x5A}, 32),
			parse: func(b []byte) ([][]byte, error) {
				rp, err := ParseResumeProof(b)
				if err != nil {
					return nil, err
				}
				return [][]byte{rp.ClientRandom}, nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate Session.rdBuf / PacketFrame.Payload: one mutable backing
			// buffer whose contents are overwritten by later ReadPacket calls.
			rdBuf := append([]byte(nil), tc.packet...)

			fields, err := tc.parse(rdBuf)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if len(fields) == 0 {
				t.Fatal("test bug: no parsed byte fields returned")
			}

			// Snapshot the parsed values. Even without -race, this catches aliasing:
			// after rdBuf is overwritten, detached fields must still equal before.
			before := cloneFieldSetForTest(fields)

			var stop atomic.Bool
			var checksum atomic.Uint64
			done := make(chan struct{})

			go func() {
				defer close(done)
				var local uint64
				for !stop.Load() {
					for _, f := range fields {
						for _, c := range f {
							local += uint64(c)
						}
					}
					runtime.Gosched()
				}
				checksum.Store(local)
			}()

			// Overwrite the parse buffer repeatedly, matching the real bug trigger:
			// the event loop immediately calls ReadPacket again, which reuses rdBuf.
			for i := 0; i < 20000; i++ {
				fill := byte(i)
				for j := range rdBuf {
					rdBuf[j] = fill
				}
				runtime.Gosched()
			}
			stop.Store(true)
			<-done
			_ = checksum.Load() // keep the goroutine's reads observable

			for i := range fields {
				if !bytes.Equal(fields[i], before[i]) {
					t.Fatalf("parsed field %d changed after rdBuf reuse: before=%q after=%q", i, before[i], fields[i])
				}
			}
		})
	}
}

// TestChannelDataIsTheOnlyIntentionalZeroCopyParser documents the one exception:
// channel bulk data may alias the input buffer for speed. Its current handlers
// must consume/copy synchronously and must not pass Channel.Data to goroutines.
func TestChannelDataIsTheOnlyIntentionalZeroCopyParser(t *testing.T) {
	wire := (&Channel{ChannelID: 7, Data: []byte("bulk-data")}).Marshal()
	ch, err := ParseChannelData(wire)
	if err != nil {
		t.Fatalf("ParseChannelData failed: %v", err)
	}

	// Locate the Data payload inside the channel frame: 4-byte channel id,
	// 4-byte data length, then payload.
	if got := binary.BigEndian.Uint32(wire[4:8]); got != uint32(len("bulk-data")) {
		t.Fatalf("test bug: unexpected encoded data length %d", got)
	}
	wire[8] ^= 0xFF
	if ch.Data[0] != wire[8] {
		t.Fatal("Channel.Data no longer aliases input; update the zero-copy contract/test")
	}
}

func cloneFieldSetForTest(fields [][]byte) [][]byte {
	out := make([][]byte, len(fields))
	for i := range fields {
		out[i] = append([]byte(nil), fields[i]...)
	}
	return out
}

func TestSessionPublicKeyDoesNotAliasReadBuffer(t *testing.T) {
	originalKey := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	attackerKey := bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize)

	envReq := &EnvRequest{
		RequestID:         1,
		PublicKey:         originalKey,
		Signature:         bytes.Repeat([]byte{0x33}, ed25519.SignatureSize),
		AccessType:        []byte("container"),
		UserRequestedName: []byte("demo"),
	}

	rdBuf := envReq.Marshal()

	parsed, err := ParseENVRequest(rdBuf)
	if err != nil {
		t.Fatal(err)
	}

	s := NewSession(nil)
	s.PublicKey = parsed.PublicKey

	before := append([]byte(nil), s.PublicKey...)

	cop := &ContainerOpRequest{
		RequestID: 2,
		PublicKey: attackerKey,
		Name:      []byte("target"),
		OpType:    ContainerOpShell,
		Row:       24,
		Cols:      80,
	}

	next := cop.Marshal()

	// Simulate ReadPacket reusing the same rdBuf backing array.
	copy(rdBuf, next)

	if !bytes.Equal(s.PublicKey, before) {
		t.Fatalf("session.PublicKey mutated after rdBuf reuse: before=%x after=%x", before, s.PublicKey)
	}

	if bytes.Equal(s.PublicKey, attackerKey) {
		t.Fatal("session.PublicKey was overwritten with attacker-controlled key")
	}
}
