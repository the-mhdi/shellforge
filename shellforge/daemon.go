package shellforge

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/atomic"

	"github.com/creack/pty"
	"github.com/the-mhdi/wireforge/tcp"
	"golang.org/x/crypto/chacha20poly1305"
)

const CLEANUP_INTERVAL time.Duration = 5 * time.Minute

// to-do: add error handling and malformed packet handling to the server event loop to handle bad network speed and packet losts
// to-do: add a max packet corruption handled to server
// to-do: add a max packet corruption handled to server, if a session exceeds this threshold we can terminate it to prevent abuse or potential
// to-do : closer and free the listener port on deamon when the client disconnects, and also close the active channels and connections related to that client session, we can track these using the session struct and its active channels map, when a disconnect is detected we can loop through the active channels and close them gracefully, then we can also close any listeners that were spawned for that client, this will help free up resources and prevent potential issues with orphaned listeners or channels consuming resources on the daemon after a client disconnects.
var bufferPool = sync.Pool{
	New: func() any {
		return make([]byte, MAX_PACKET_LEN)
	},
}

type DaemonConfig struct {
	AcceptedInitMsgs []string //// List of acceptable init messages from clients. If empty, accepts all.
	DaemonInitMsg    string   // the one we send to client

	ListenAddr string
	Port       string //default 77

	PasswordAuth  bool
	PublicKeyAuth bool

	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration //drops idle sessions after this period , if 0 no time out
	//a definitive key directory, by default its "" and for root its root/.shellforge/authorized_keys and other users  home/$username/.shellforge/authorized_keys
	AuthorizedKeysPath              string // e.g. "home/$username/.shellforge/authorized_keys", for root "root/.shellforge/authorized_keys" "/etc/wireforge/authorized_keys"
	AllowLoginAsRoot                bool
	MaxConnectionsAllowed           uint32
	MaxContainersConnectionsAllowed uint32

	//EnvironmentsJsonConfig string
	DatabaseDir       string
	ClientInitHandler func(ctx context.Context, msg []byte) bool

	HostKeyPath string // defaults to /etc/shellforge/host_ed25519 if empty
}

type Daemon struct {
	Conf           *DaemonConfig
	Names          []string
	Versions       []uint8
	supportedAuths uint8

	ListenAddr string
	Port       string

	CAPool *x509.CertPool // Loaded on startup

	DB *DB // Database for tracking allowed keys and active temp users

	AllowedKeys map[string]AccessKeyRecord
	State       *DaemonState

	HostKey ed25519.PrivateKey

	idleTimeout      time.Duration //drops idle sessions after this period
	handshakeTimeout time.Duration

	ctx    context.Context
	Cancel context.CancelFunc
}

type DaemonState struct {
	mu             sync.RWMutex
	connections    atomic.Uint32
	ContainerConns atomic.Uint32
	sessions       map[string]*Session //map of  sessionID to Session struct
	UserSessions   map[string][]string //map of a user to hex sessionIDs, used to track how many sessions a user has
	UserSessCount  map[string]uint8    //map of a user to number of active sessions, used to enforce max session per user limits
	UserShellCount map[string]uint8    //map of a user to number of active shells, used to enforce max shell per user limits
}

// main loop
func (d *Daemon) listen() {

	// 2. Run an initial active purge immediately on startup
	d.DB.RunStartupSweeper()

	// 3. Start the Active Background Reaper (The Janitor)
	// It runs asynchronously in the background for the lifetime of the Daemon.

	go func(ctx context.Context) {
		// Checks the database every 10 minutes. You can adjust this to 1 hour, etc.
		ticker := time.NewTicker(CLEANUP_INTERVAL)
		defer ticker.Stop()

		for range ticker.C {
			select {
			case <-ctx.Done():
				log.Println("[wireforge] Background database reaper gracefully stopped.")
				return // CLEANLY EXITS THE LOOP & GOROUTINE!
			case <-ticker.C:
				d.DB.PurgeExpired()
			}

		}
	}(d.ctx)

	handler := func(parentCtx context.Context, fd net.Conn) {
		defer fd.Close()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] recovered in connection handler for %v: %v", fd.RemoteAddr(), r)
			}
		}()

		if d.State.connections.Load() >= d.Conf.MaxConnectionsAllowed && d.Conf.MaxConnectionsAllowed != 0 {
			log.Printf("max connections reached, no other client conns allowed")
			return
		}

		d.State.connections.Add(1)
		defer d.State.connections.Sub(1)
		// Create a connection-specific cancelable context
		connCtx, cancel := context.WithCancel(parentCtx)
		defer cancel() // Automatically fires when this handler exits!

		session := NewSession(fd)
		newSessionID := generateSessionID(32)
		log.Printf("session id generated, %x", newSessionID)
		session.ID = newSessionID
		d.State.SaveSession(newSessionID, session)
		defer d.State.DeleteSession(session.ID)

		session.isDaemon = true

		defer session.Close()

		// ==========================================
		// PHASE 1: THE INIT EXCHANGE (Cleartext)
		// ==========================================
		if d.handshakeTimeout != 0 {
			session.SetDeadline(time.Now().Add(d.handshakeTimeout))
		}

		initPkt, err := session.ReadPacket()
		if err != nil {
			return
		}

		if initPkt.Payload[0] != MsgClientInit {
			log.Println("Expected ClientInit, dropping connection.")
			session.WritePacket(MsgServerClientInitInvalid, nil)
			return
		}

		log.Printf("[CLI] Received Client Init Message: %s", string(initPkt.Payload[1:]))
		// Let the user dictate if this client is allowed based on their Init string
		//if d.Conf.ClientInitHandler == nil {
		//	d.Conf.ClientInitHandler = d.DefaultClientInitHandler(connCtx, initPkt.Payload[1:])
		//}

		if d.Conf.ClientInitHandler != nil && !d.Conf.ClientInitHandler(connCtx, initPkt.Payload[1:]) {
			log.Println("ClientInit rejected by handler.")
			session.WritePacket(MsgServerClientInitRejected, nil)
			return
		}

		// Success! Send ServerInit back to the client
		err = session.WritePacketRaw(MsgServerInit, []byte(d.Conf.DaemonInitMsg))
		if err != nil {

			return
		}

		// ==========================================
		// PHASE 2: CLIENT HELLO (unEncrypted)
		// ==========================================
		cHelloPkt, err := session.ReadPacket()
		if err != nil {
			log.Println(err)
			return
		}

		if cHelloPkt.Payload[0] != MsgClientHello {
			session.WritePacket(MsgServerExpectedClientHello, nil)
			return
		}

		cHello, err := parseClientHello(cHelloPkt.Payload[1:])
		if err != nil {
			log.Printf("Malformed ClientHello: %v", err)
			session.WritePacket(MsgServerClientHelloMalformed, nil)

			return
		}

		enc, dec, serverHello, err := d.HandShake(session, cHello)
		if err != nil {
			log.Printf("handshake failed: %v", err)
			session.WritePacket(MsgServerEncryptionHandShakeFailed, nil)
			return
		}

		err = session.WritePacket(MsgServerHello, serverHello)
		if err != nil {
			log.Printf("failed to send ServerHello: %v", err)
			return
		}
		log.Printf("Server Hello Packet Created and sent, with session ID: %x", session.ID)
		// 9. Setup the Encrypter/Decrypter based on client's selected cipher

		// messages are encrypted from now on //session encrypted
		session.encrypter = enc
		session.decrypter = dec

		log.Printf("Secure Session Established! session ID: %x", session.ID)

		//temp shell connection hijack //temp sessions dont follow regular auth steps
		//if cHello.HasHeader(TEMPSHELL_SESSION_HEADER_KEY) {
		//	log.Printf("client asked for temporary session")

		//	d.tempSessionHandler(ctx, session) //blocking call
		//	d.State.DeleteSession(session.ID)
		//	return
		//}

		// ==========================================
		// PHASE 3.5: authenticate access//shell
		// ==========================================
		pkt, err := session.ReadPacket()
		if err != nil {
			log.Printf("%v", err)
			return
		}

		if d.handshakeTimeout != 0 {
			session.SetDeadline(time.Now().Add(d.handshakeTimeout))
		}

		switch pkt.Payload[0] {

		case MsgClientENVCreate:
			log.Printf("got MsgClientENVCreate")
			// Parse the temporary shell request
			eReq, err := ParseENVRequest(pkt.Payload[1:])
			if err != nil {
				return
			}

			//chanID := session.IncrementChannelID()
			//pipe := NewPipe(chanID, session)
			//pipeStream := session.AttachChannel(chanID, pipe, false)
			chanID, Channel := session.NewChannel(true)

			log.Printf("LogStream created and added to active channel %d", chanID)
			co := &ChannelOpen{
				ChannelID: chanID,
			}

			session.WritePacket(MsgServerOpenLogChannel, co)

			if d.handshakeTimeout != 0 {
				session.SetDeadline(time.Now().Add(d.handshakeTimeout))
			}

			env, err := d.CreateEnvironment(connCtx, Channel, string(session.ID), eReq)

			if err != nil {
				session.WritePacket(MsgServerENVCreateNotAllowed, nil)
				log.Printf("Faild to create the requested ENV, %v", err)
				return
			}

			envr := &EnvCreated{
				RequestID:            eReq.RequestID,
				PublicKey:            eReq.PublicKey,
				AccessType:           eReq.AccessType,
				UserRequestedNameLen: uint8(len(eReq.UserRequestedName)),
				UserRequestedName:    eReq.UserRequestedName,
				NameLen:              uint8(len(env.Name)),
				Name:                 []byte(env.Name),
				Success:              true,
			}
			session.WritePacket(MsgServerENVCreated, envr)
			return

		case MsgClientAuthPub, MsgClientAuthPassword, MsgClientAuthPKI:

			ar := &AuthResponse{Success: false}
			isAuthenticated := false
			var i uint8

			for i = 0; i < MAX_AUTH_RETRY; i++ {

				if i != 0 {
					authPkt, err := session.ReadPacket()
					if err != nil {
						return
					}
					pkt = authPkt
				}

				log.Println("auth packet received")
				AuthRes, err := d.shellAuth(session, pkt)
				if err != nil && i < MAX_AUTH_RETRY {
					session.WritePacket(MsgServerAuthFailed, nil)
					continue
				}

				if AuthRes.Success == false {
					if i < MAX_AUTH_RETRY {
						log.Printf("auth failed attempt %d", i)
						session.WritePacket(MsgServerAuthResponse, AuthRes)
						continue
					}
					if i >= MAX_AUTH_RETRY {
						session.WritePacket(MsgServerAuthFailedTooManyRetry, nil)
						log.Printf("too many auth retry by the client")
						break
					}
					continue
				} else { //success
					session.User = AuthRes.Username
					*ar = *AuthRes
					isAuthenticated = true
					break
				}

			}

			//if isAuthenticated
			if !isAuthenticated || !ar.Success {
				return
			}

			err := d.State.UpdateUserState(session.User, session.ID)
			if err != nil {
				log.Printf("Error updating user state: %v", err)
				session.WritePacket(MsgServerAuthFailed, nil)
				return
			}
			// Success!
			log.Printf("User Authenticated Sending Auth response for username: %s", session.User)
			session.WritePacket(MsgServerAuthResponse, ar)
			log.Printf("User [%s] authenticated successfully!", session.User)
			// PHASE 4: THE SECURE EVENT LOOP (Multiplexing)

			d.shellLoop(connCtx, session)
			return
		case MsgClientConnectContainer:

			eReq, err := ParseENVRequest(pkt.Payload[1:])
			if err != nil {
				return
			}

			if !ed25519.Verify(eReq.PublicKey, session.ID, eReq.Signature) {
				log.Printf("cant verify the sig")
				session.WritePacket(MsgServerInvalidSignature, nil)
				return
			}

			if strings.ToLower(string(eReq.AccessType)) != "container" {
				log.Printf("conflict")
				session.WritePacket(MsgServerInvalidEnvType, nil)
				return
			}

			//pubKeyHex := hex.EncodeToString(eReq.PublicKey)

			if !d.DB.HasActiveEnv(eReq.PublicKey, "container") || !d.DB.IsEligibleKey(eReq.PublicKey) {
				log.Printf("no container fot this key %s", hex.EncodeToString(eReq.PublicKey))
				session.WritePacket(MsgServerNoContainer, nil)
				return
			}

			if eReq.UserRequestedName == nil || eReq.UserRequestedNameLen == 0 {
				envs, err := d.DB.GetEnvsByType(eReq.PublicKey, "container")
				if err != nil {
					log.Printf("cant get container list, %v", err)
					session.WritePacket(MsgServerNoContainer, nil)
					return
				}

				var conList []string

				for _, env := range envs {
					conList = append(conList, env.UserRequestedName)
				}

				clist := &ContainersListResponse{
					RequestID:      eReq.RequestID,
					PublicKey:      eReq.PublicKey,
					ContainersList: conList,
				}

				//send ContainersListResponse if no name specified
				err = session.WritePacket(MsgServerContainersListResponse, clist)
				if err != nil {
					log.Println(err)
					return
				}
				return
			}

			if string(eReq.AccessType) == "container" {
				if d.State.ContainerConns.Load() >= d.Conf.MaxConnectionsAllowed && d.Conf.MaxConnectionsAllowed != 0 {
					log.Printf("max container connections reached, no other client conns allowed")
					return
				}

				session.PublicKey = eReq.PublicKey
				d.ContainerLoop(connCtx, session)
			}

		default:
			log.Printf("invalid request")
			return
		}

	}

	opts := &tcp.ListenOptions{
		Verbose: true,

		ReuseAddr:           true,
		ReusePort:           false,
		TCPFastOpen:         false,
		MultipathTCP:        true,
		OnConnect:           nil,
		OnConnectTimeout:    0,
		OnDisconnect:        nil,
		OnDisconnectTimeout: 0,
		ShutdownTimeout:     5 * time.Second,

		Inbounds: tcp.InboundConnOptions{
			NoDelay:                true,
			WriteBuffer:            0,
			ReadBuffer:             0,
			Deadline:               0,
			DrainConnectionOnClose: 0,

			KeepAlive: true,

			KeepAliveFirstProbe:  0,
			KeepAliveInterval:    0,
			MaxKeepAliveAttempts: 0,
		},
	}
	//opts := tcp.DefaultListenOptions().WithVerbose(true)

	var address string

	if d.Conf.ListenAddr == "" && d.Conf.Port == "" {
		address = "0.0.0.0:77"
	}

	if d.Conf.ListenAddr == "" && d.Conf.Port != "" {
		address = fmt.Sprintf("0.0.0.0:%s", d.Conf.Port)
	}

	if d.Conf.ListenAddr != "" && d.Conf.Port == "" {
		address = fmt.Sprintf("%s:77", d.Conf.ListenAddr)
	}

	if d.Conf.ListenAddr != "" && d.Conf.Port != "" {

		address = fmt.Sprintf("%s:%s", d.Conf.ListenAddr, d.Conf.Port)

	}
	//blocking call that handles the life cycle of the listener and incoming connections
	opts.Listen(address, handler)
	d.Cancel()

}

func (d *Daemon) HandShake(session *Session, cHello *ClientHello) (encrypter, decrypter cipher.AEAD, serverHello *ServerHello, err error) {

	// ==========================================
	// PHASE 3: KEY EXCHANGE & ENCRYPTION
	// ==========================================
	if cHello.SessLen != 0 {
		// used for sess resume -- not allowed for now
		log.Printf("Client attempting to resume Session: %x", cHello.SessionID)
		log.Println("Session expired or invalid. Forcing full reconnect.")
		//session.WritePacket(MsgServerClientHelloRejected, nil)
		return nil, nil, nil, errors.New("session expired or invalid")
	}

	// Generate 32-byte Session ID
	//newSessionID := generateSessionID(32)
	//log.Printf("session id generated, %x", newSessionID)

	//encrypt the session
	enc, dec, serverShareKey, err := encryptSession(cHello, session, session.ID)
	if err != nil {
		log.Printf("Faild to encrypt the session, %v", err)
		return nil, nil, nil, err
	}

	// 7. Save session state
	//session.ID = newSessionID
	//d.State.SaveSession(newSessionID, session)
	//defer d.State.DeleteSession(session.ID)

	sh := &ServerHello{
		SessionResumed:    false,
		SessLen:           uint16(len(session.ID)),
		SessionID:         session.ID,
		EncryptionSupport: true,
		Encryption: ServerHelloEncryptionFields{
			ServerSharekeyLen: uint16(len(serverShareKey)),
			Server_Share_key:  serverShareKey, //pub key if KexX25519 | Public Key + ML-KEM Ciphertext if KexHybridX25519MLKEM768
		},
		SupportedAuths: d.supportedAuths, // <--- ADVERTISE

	}

	transcript := BuildHandshakeTranscript(
		cHello.ClientRandom,
		session.ID,
		cHello.Encryption.CLIENT_KEX_ALGO,
		cHello.Encryption.CLIENT_CIPHER,
		serverShareKey,
	)

	hostPub := d.HostKey.Public().(ed25519.PublicKey)
	hostSig := ed25519.Sign(d.HostKey, transcript)
	sh.AddHeader([]byte(HostKeyHeaderKey), []byte(hostPub))
	sh.AddHeader([]byte(HostSigHeaderKey), hostSig)

	// 9. Setup the Encrypter/Decrypter based on client's selected cipher

	// messages are encrypted from now on
	//session.encrypter = enc
	//session.decrypter = dec

	return enc, dec, sh, nil
}

func (d *Daemon) ContainerLoop(ctx context.Context, session *Session) {
	if d.idleTimeout != 0 {
		session.SetDeadline(time.Now().Add(d.idleTimeout))
	} else {
		//clear hanbdsjake time out if idel time out is 0 , session no longer has a deadline
		session.SetDeadline(time.Time{})
	}

	log.Printf("container loop running")
	d.State.ContainerConns.Add(1)
	defer d.State.ContainerConns.Sub(1)

	for {

		pkt, err := session.ReadPacket()
		//log.Printf("pkt %x...", session.ID[0:3])
		if err != nil {
			log.Printf("[] Error reading packet from Session %x...: %v", session.ID[0:3], err)
			log.Printf("Ending The Session %x... : %v", session.ID[0:3], err)
			break
		}

		switch pkt.Payload[0] {
		case MsgClientChanneledData:
			// CLIENT WRITING DATA BACK TO PUBLIC USER
			ch, err := ParseChannelData(pkt.Payload[1:])
			if err != nil {
				log.Println("Malformed Channel Data from client")
				go session.WritePacket(MsgServerChanDataMalformed, nil)
				continue
			}

			//log.Printf("Data received on Channel %d", ch.ChannelID)
			if chann, ok := session.Stream.getActiveChannel(ch.ChannelID); ok {
				_, err := chann.Feed(ch.Data)
				if err != nil {
					log.Println(err)
					log.Printf("channel %d feed failed: %v; closing", chann.id, err)
					session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: chann.id}))
					chann.Close()

				}
			} else {
				session.WritePacket(MsgServerChannelUnknownOrClosed,
					&ChannelClosed{ChannelID: ch.ChannelID})
				//return nil
				log.Printf("Received Data with unknown Channel ID")
				continue
				//p.session.WritePacket(MsgServerChannelUnknownOrClosed, nil)
			}

		case MsgWindowAdjust:
			wa, err := ParseWindowAdjust(pkt.Payload[1:])
			if err != nil {
				log.Printf("malformed WindowAdjust")
				continue
			}
			session.Stream.grantSendWindow(wa.ChannelID, wa.Increment)
		case MsgClientChannelOpenConfirm:

			confirm, err := ParseClientChannelOpenConfirm(pkt.Payload[1:])

			if err != nil {
				log.Printf("Malformed Channel Open Confirmation from client")
				continue
			}

			if confirm.Success {
				session.Stream.OpenComfirmed(confirm.ChannelID)
			}
		case MsgClientGetContainerShell:
			cop, err := ParseContainerOpRequest(pkt.Payload[1:])
			if err != nil {
				session.WritePacket(MsgServerFailedToOpenShell, nil)
				continue
			}
			if cop.OpType != ContainerOpShell {
				return
			}

			log.Printf("Received [container] Shell Request for container [%s] by [%s]- Req id %v", string(cop.Name), string(cop.PublicKey), cop.RequestID)

			if !bytes.Equal(cop.PublicKey, session.PublicKey) {
				session.WritePacket(MsgServerInvalidSignature, nil)
				return
			}
			//pubKeyHex := hex.EncodeToString(cop.PublicKey)
			// 2. Daemon is authoritative! It assigns the Channel ID safely.
			chanID, Channel := session.NewChannel(true)

			log.Printf("New Channel Created by the Daemon - Chan ID = %v", hex.EncodeToString([]byte{byte(chanID)}))

			env, err := d.DB.GetENVByUserReqestedName(string(cop.Name), cop.PublicKey)

			if err != nil {
				log.Println(err)
				Channel.Close()
				return
			}

			if env == nil {
				log.Printf("%s doesn't exist or belong to this key", string(cop.Name))
				session.WritePacket(MsgServerNoContainer, nil)
				Channel.Close()
				return
			}

			if env != nil {
				//pipe := NewPipe(chanID, session)
				//pipeStream := session.AttachChannel(chanID, pipe, false)
				she := session.NewShell(chanID)
				runCh := make(chan struct{}, 1)
				go func() {
					defer Channel.Close()
					//defer pipeStream.Close()

					err := d.RunContainer(ctx, she, runCh, env, 24, 80, Channel)
					if err != nil {
						log.Printf("[ERROR RunContainer] %v\n for container %s", err, env.Name)
						return
					}
				}()

				<-runCh

				srr := &ShellRequestResponse{
					RequestID: cop.RequestID, // Matches the client's request
					ChannelID: chanID,        // ASSIGNED BY THE SERVER!
					Success:   true,
				}

				err = session.WritePacket(MsgServerShellReqResponse, srr)
				if err != nil {
					continue
				}
			}

		case MsgClientContainerLog:
			cop, err := ParseContainerOpRequest(pkt.Payload[1:])
			if err != nil {
				session.WritePacket(MsgServerFailedToOpenShell, nil)
				continue
			}
			if cop.OpType != ContainerOpLogs {
				log.Printf("invaild containerOp code")
				continue
			}
			if !bytes.Equal(cop.PublicKey, session.PublicKey) {
				session.WritePacket(MsgServerInvalidSignature, nil)
				return
			}
			//pubKeyHex := hex.EncodeToString(cop.PublicKey)
			log.Printf("[container] log Request for container [%s] by [%s]- Req id %v", string(cop.Name), hex.EncodeToString(cop.PublicKey), cop.RequestID)

			chanID, Channel := session.NewChannel(true)

			log.Printf("New Channel Created by the Daemon - Chan ID = %v", hex.EncodeToString([]byte{byte(chanID)}))
			env, err := d.DB.GetENVByUserReqestedName(string(cop.Name), cop.PublicKey)
			if err != nil {
				log.Println(err)
				continue
			}

			if env == nil {
				log.Printf("%s doesn't exist or belong to this key", string(cop.Name))
				session.WritePacket(MsgServerNoContainer, nil)
				continue
			}

			co := &ChannelOpen{
				ChannelID: chanID,
			}

			werr := session.WritePacket(MsgServerOpenLogChannel, co)
			if werr != nil {
				return
			}

			//client needs to send MsgClientChannelOpenConfirm
			/*if !session.WaitForClientChannelOpenConfirmed(chanID) {
				return
			}*/
			//	log.Printf("client Confirmed channel opened %d", chanID)
			//<-time.After(10 * time.Second)
			//log.Println("fire")
			go func() {
				//pipe := NewPipe(chanID, session)
				//pipeStream, ok := session.AttachChannelWithConfirmation(chanID, pipe, false)
				//if !ok {
				//	return
				//	}
				//	defer session.CloseActiveChannel(chanID)
				defer Channel.Close()
				defer session.WritePacket(MsgServerChannelClosed, co)
				err = d.GetContainerLogs(ctx, env.Name, Channel)

				if err != nil {
					log.Println(err)
					return
				}
				//log.Println("fire", err)
			}()
		case MsgClientContainerCommandExec:
			cop, err := ParseContainerOpRequest(pkt.Payload[1:])
			if err != nil {
				session.WritePacket(MsgServerFailedToOpenShell, nil)
				continue
			}
			if cop.OpType != ContainerOpCommand {
				return
			}

			if !bytes.Equal(cop.PublicKey, session.PublicKey) {
				session.WritePacket(MsgServerInvalidSignature, nil)
				return
			}

			if cop.Command == nil || cop.CommandLen == 0 || len(cop.Command) != int(cop.CommandLen) {
				log.Printf("bad op packet")
				return
			}

			//pubKeyHex :=
			log.Printf("[container] command exec Request for container [%s] by [%s]- Req id %v", string(cop.Name), hex.EncodeToString(cop.PublicKey), cop.RequestID)

			// 2. Daemon is authoritative! It assigns the Channel ID safely.

			env, err := d.DB.GetENVByUserReqestedName(string(cop.Name), cop.PublicKey)

			if err != nil {
				log.Println(err)
				return
			}

			if env == nil {
				log.Printf("%s doesn't exist or belong to this key", string(cop.Name))
				session.WritePacket(MsgServerNoContainer, nil)
				return
			}

			//pipe := NewPipe(chanID, session)
			//pipeStream := session.AttachChannel(chanID, pipe, false)

			//co := &ChannelClosed{
			//	ChannelID: chanID,
			//	}
			//session.WritePacket(MsgServerOpenReadChannel, co)

			//client needs to send MsgClientChannelOpenConfirm
			//	if !session.WaitForClientChannelOpenConfirmed(chanID) {
			//		return
			//	}

			//log.Printf("client Confirmed channel opened %d", chanID)
			chanID, Channel := session.NewChannel(true)
			log.Printf("New Channel Created by the Daemon - Chan ID = %v", hex.EncodeToString([]byte{byte(chanID)}))

			go func() {
				//pipe := NewPipe(chanID, session)
				//pipeStream, ok := session.AttachChannelWithConfirmation(chanID, pipe, false)
				//if !ok {
				//	return
				//}
				defer Channel.Close()
				defer session.WritePacket(MsgServerChannelClosed, &ChannelClosed{ChannelID: chanID})
				if ok := Channel.WaitForComfirmationWithMsgType(MsgServerOpenReadChannel); !ok {
					return
				}

				command := string(cop.Command)
				err = d.ContainerExec(ctx, env.Name, command, Channel)
				if err != nil {
					log.Println(err)
				}
			}()

		case MsgClientSessionClosed:
			log.Printf("MsgClientSessionClosed")
			return
		case MsgClientPTYResize:
			ws, err := ParseWindowResize(pkt.Payload[1:])
			if err != nil {
				log.Printf("Packet window resize couldn't be parsed!")
			}

			log.Printf("Packet window resize, Channel %d", ws.ChannelID)

			Channel, ok := session.GetActiveChannel(ws.ChannelID)

			if !ok {
				continue
			}
			shell := session.GetShell(Channel.id)
			if shell == nil {
				log.Printf("window resize on unknown shell!")
				continue
			}
			//if  != Channel.id {
			//
			//}

			//chanID := session.IncrementChannelID()
			//session.AddActiveChannel(chanID, p)
			err = shell.ResizePTY(ws.Rows, ws.Cols)

			if err != nil {
				log.Printf("initial window resize failed %v ", err)
			}
		case MsgClientKeepAlive:
			if d.idleTimeout != 0 {
				session.SetDeadline(time.Now().Add(d.idleTimeout))
			}
		default:
			log.Printf("Unknown or corrupted message type: %d", pkt.Payload[0])
			log.Printf("packet code %d cant be handle", pkt)
		}
	}
}
func (d *Daemon) shellLoop(ctx context.Context, session *Session) {
	if d.idleTimeout != 0 {
		session.SetDeadline(time.Now().Add(d.idleTimeout))
	} else {
		//clear hanbdsjake time out if idel time out is 0 , session no longer has a deadline
		session.SetDeadline(time.Time{})
	}

	for {

		pkt, err := session.ReadPacket()
		if err != nil {
			log.Printf("[] Error reading packet from Session %x...: %v", session.ID[0:3], err)

			log.Printf("Ending The Session %x... : %v", session.ID[0:3], err)
			break
		}

		switch pkt.Payload[0] {
		case MsgClientChanneledData:
			// CLIENT WRITING DATA BACK TO PUBLIC USER

			ch, err := ParseChannelData(pkt.Payload[1:])
			if err != nil {
				log.Println("Malformed Channel Data from client")
				go session.WritePacket(MsgServerChanDataMalformed, nil)
				continue

			}
			if chann, ok := session.Stream.getActiveChannel(ch.ChannelID); ok {
				_, err := chann.Feed(ch.Data)
				if err != nil {
					log.Println(err)
					log.Printf("channel %d feed failed: %v; closing", chann.id, err)
					session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: chann.id}))
					chann.Close()

				}
			} else {
				log.Printf("Received Data with unknown Channel ID")
				continue
				//p.session.WritePacket(MsgServerChannelUnknownOrClosed, nil)
			}

			//log.Printf("Data received on Channel %d", ch.ChannelID)
			// Look up the session and ch id and write the data
			//log.Printf("Data received on Channel %d", ch.ChannelID)
			//err = session.Stream.Feed(pkt.Payload[1:])
			//log.Println("feedinggg")
			//if err != nil {

			// Flow-control violation or closed pipe: drop the channel,
			// never block the shared reader.
			//log.Printf("channel %d feed failed: %v; closing", ch.ChannelID, err)
			//		session.CloseActiveChannel(ch.ChannelID)
			//	session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: ch.ChannelID}))
			//}
		case MsgWindowAdjust:
			wa, err := ParseWindowAdjust(pkt.Payload[1:])
			if err != nil {
				log.Printf("malformed WindowAdjust")
				continue
			}
			//log.Printf("packet WindowAdjust recieved on channel %d", wa.ChannelID)
			session.Stream.grantSendWindow(wa.ChannelID, wa.Increment)

			//go log.Println(session.Stream.getFlow(wa.ChannelID).sendWindow)
		case MsgClientListenRequest:
			// Handle client's request to listen on a local port and forward to a destination
			// This will involve parsing the payload for the requested local port and target destination,
			//the server listens on the port and forwards all the incoming traffic back to the client
			//client then parses the recvied data and handles the routing to the specified

			// 1. Parse the request
			req, err := ParseListenRequest(pkt.Payload[1:])
			if err != nil {
				log.Println("Malformed Listen Request")
				session.WritePacket(MsgServerRequestMalformed, nil)
				continue
			}

			log.Printf("Client requested remote port forward for: %s", req.Address)

			// 2. Start the public listener!
			// We create a handler that fires every time an internet user connects to this port
			forwardHandler := func(ctx context.Context, uConn net.Conn) {

				// Assign a unique ID to this (connection) user
				chanID, Chann := session.NewChannel(false)
				// Save the connection so we can write back to it later!
				//session.AttachChannel(chanID, uConn, true) // inbound ring -> uConn
				err := Chann.AttachWriter(uConn)
				if err != nil {
					log.Println(err)
					return
				}
				defer Chann.Close() // closes pipe (=> drain closes uConn)
				//defer uConn.Close()

				// A. Tell the Client a new user connected!
				sch := &ServerChannelOpen{
					ChannelID:  chanID,
					RemoteAddr: req.Address,
				}

				session.WritePacket(MsgServerNewChannelOpened, sch)

				// B. Read from the user, wrap it in a ChannelData packet, and send to Client
				//buf := make([]byte, MAX_PACKET_LEN)

				buf := bufferPool.Get().([]byte)
				defer bufferPool.Put(buf)
				for {
					n, err := uConn.Read(buf)
					if n > 0 {

						cd := &Channel{
							ChannelID: chanID,
							Data:      buf[:n],
						}
						if werr := session.WritePacket(MsgServerChanneledData, cd); werr != nil {
							break
						}
					}

					if err != nil {
						break
					}
				}
				// C. Tell client the web user disconnected
				ccl := &ChannelClosed{ChannelID: chanID}
				session.WritePacket(MsgServerChannelClosed, ccl)
			}

			// Run the listener in the background!
			ln := tcp.NewListenerWithContext(ctx, tcp.DefaultListenOptions())
			err = ln.Initialize(req.Address, forwardHandler)

			// 3. Reply to the Client
			res := &ListenResponse{Address: req.Address, Success: err == nil}
			session.WritePacket(MsgServerListenResponse, res)

			if err != nil {
				log.Printf("Failed to start listener for client on %s: %v", req.Address, err)
				continue
			}

			go ln.Run()
			session.listeners = append(session.listeners, ln)
			//ln.Close()
			log.Printf("Spawned listener for client on %s", ln.Address)

		case MsgClientShellRequest:
			// 1. Parse the specific shell request
			sr, err := ParseShellRequest(pkt.Payload[1:])
			if err != nil {
				session.WritePacket(MsgServerFailedToOpenShell, nil)
				continue
			}
			log.Printf("Received Shell Request for user [%s] and shell [%s]- Req id %v", string(sr.User), string(sr.Shell), sr.RequestID)

			// 2. Daemon is authoritative! It assigns the Channel ID safely.
			//chanID := session.IncrementChannelID()

			//shell := string(sr.Shell)
			//username := string(sr.User)

			if session.User != string(sr.User) {
				log.Printf("Authentication failed: missmatched users!")
				continue
			}

			chanID, Channel := session.NewChannel(false)
			log.Printf("New Channel Created by the Daemon - Chan ID = %v", hex.EncodeToString([]byte{byte(chanID)}))

			// 5. Reply to Client: "Your RequestID is approved, here is your official ChannelID"
			res := &ShellRequestResponse{
				RequestID: sr.RequestID,
				ChannelID: chanID,
				Success:   err == nil,
			}

			err = session.WritePacket(MsgServerShellReqResponse, res)
			if err != nil {
				log.Printf("init Shell failed: %v", err)
				Channel.Close()
				continue
			}
			log.Printf("Shell request response sent for reqID %v: %v", res.RequestID, hex.EncodeToString([]byte{byte(res.ChannelID)}))

			var shell *ShellRequest

			shell = sr

			if !SysUserExists(string(shell.User)) {
				log.Printf("not a sys user")
				Channel.Close()
				continue
			}
			sh := session.NewShell(chanID)

			//pipe := NewPipe(chanID, session)
			//pipeStream := session.AttachChannel(chanID, pipe, true)

			// 4. Spawn the interactive shell in the background
			go func(shellrq *ShellRequest, pipe *channel) {

				//defer session.DeleteActiveChannel(chanID)
				defer session.WritePacket(MsgServerChannelClosed, &ChannelClosed{ChannelID: chanID})
				defer Channel.Close()
				log.Printf("interactive shell running in the background, ChanID %d", chanID)
				// Spawn the PTY

				if err := sh.RunInteractiveShell(ctx, shellrq, Channel, shellrq.Row, shellrq.Cols); err != nil {
					log.Printf(" interactive shell failed or exited with error: %v", err)
					return
				}
			}(shell, Channel)

		case MsgClientForwardRequest:
			fr, err := ParseForwardRequest(pkt.Payload[1:])
			if err != nil {
				log.Println("Malformed Forward Request from client")
				go session.WritePacket(MsgServerForwardReqMalformed, nil)
				continue
			}

			log.Printf("Client requested forward to %s", fr.Address)
			session.forwardMu.Lock()
			session.forwardMap[fr.Address] = fr.Address
			session.forwardMu.Unlock()

		case MsgClientNewChannelOpened:
			// A public web user connected to the Daemon! We must dial our local target.
			cco, err := ParseClientChannelOpen(pkt.Payload[1:])
			if err != nil {
				continue
			}

			//reject server-namespace IDs from clients
			if !IsClientChannelID(cco.ChannelID) {
				log.Printf("Security alert: client tried to open channel with server-namespace ID %d; rejecting", cco.ChannelID)
				session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: cco.ChannelID}))
				continue
			}

			session.forwardMu.Lock()
			localTarget, exists := session.forwardMap[cco.RemoteAddr]
			session.forwardMu.Unlock()

			if !exists {
				log.Printf("Security alert: Client requested unknown port %s", cco.RemoteAddr)
				continue
			}

			// Dial the local server in the background (e.g. 127.0.0.1:8080)
			go func(channelID uint32, localTarget string) {
				dl := tcp.DefaultDialOptions().NewDialer()
				c, err := dl.Dial(localTarget)

				if err != nil {
					log.Printf("Failed to connect to remote target for forwarding: %v", err)
					session.WritePacket(MsgServerFailedToDial, nil)
					return
				}

				Chann, ok := session.NewChannelWithID(channelID, false)
				if !ok || Chann == nil {
					log.Printf("Security alert: client requested channel ID %d that is already in use; refusing (possible channel hijack attempt)", channelID)
					c.Close()
					session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: channelID}))
					return
				}
				if !IsClientChannelID(channelID) {
					log.Printf("Security alert: client tried to close channel with server-namespace ID %d; rejecting", channelID)
					session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: channelID}))
					return
				}
				//if !session.AddActiveChannelIfAbsent(channelID, c) {
				//	log.Printf("Security alert: client requested channel ID %d that is already in use; refusing (possible channel hijack attempt)", channelID)
				//	c.Close()
				//	session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: channelID}))
				//	return
				//}
				Chann.AttachWriter(c)
				defer Chann.Close()

				// read the data from the target and send it back to the client!
				buf := bufferPool.Get().([]byte)
				defer bufferPool.Put(buf)

				for {
					n, err := c.Read(buf)
					if n > 0 {
						cd := &Channel{
							ChannelID: channelID, // Use the client's ID
							Data:      buf[:n],
						}
						if werr := session.WritePacket(MsgServerChanneledData, cd); werr != nil {
							break
						}
					}
					if err != nil {
						break
					}
				}

				session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: channelID}))

			}(cco.ChannelID, localTarget)

		case MsgClientKeepAlive:
			if d.idleTimeout != 0 {
				session.SetDeadline(time.Now().Add(d.idleTimeout))
			}
		//case MsgChanIDRenegotiationRequest:
		case MsgClientChannelClosed:
			ccl, err := ParseChannelClosed(pkt.Payload[1:])
			if err != nil {
				continue
			}

			//reject server-namespace IDs from clients
			if !IsClientChannelID(ccl.ChannelID) {
				log.Printf("Security alert: client tried to close channel with server-namespace ID %d; rejecting", ccl.ChannelID)
				session.WritePacket(MsgServerChannelClosed, (&ChannelClosed{ChannelID: ccl.ChannelID}))
				continue
			}

			// Find the active connection and terminate it
			if ch, ok := session.GetActiveChannel(ccl.ChannelID); ok {
				ch.Close()
			}
			//return
		case MsgClientSessionClosed:
			log.Printf("[signal] received MsgClientSessionClosed")
			return

		case MsgClientPTYResize:
			ws, err := ParseWindowResize(pkt.Payload[1:])
			if err != nil {
				log.Printf("Packet PTY window resize couldn't be parsed!")
			}

			log.Printf("Packet PTY window resize, Channel %d", ws.ChannelID)

			Channel, ok := session.GetActiveChannel(ws.ChannelID)

			if !ok {
				continue
			}
			shell := session.GetShell(Channel.id)
			if shell == nil {
				log.Printf("PTY window resize on unknown shell!")
				continue
			}
			//if  != Channel.id {
			//
			//}

			//chanID := session.IncrementChannelID()
			//session.AddActiveChannel(chanID, p)
			err = shell.ResizePTY(ws.Rows, ws.Cols)

			if err != nil {
				log.Printf("initial window resize failed %v ", err)
			}

		default:
			log.Printf("Unknown or corrupted message type: %d", pkt.Payload[0])
			log.Printf("packet code %d cant be handle", pkt)
		}
	}
}

// returns enc AEAD cipher, dec, serverShareKey and error
func encryptSession(cHello *ClientHello, session *Session, ID []byte) (cipher.AEAD, cipher.AEAD, []byte, error) {
	// 1. Strict Enforcement: Verify we support the client's chosen KEX and Cipher [1]
	if cHello.Encryption.CLIENT_KEX_ALGO != KexX25519 && cHello.Encryption.CLIENT_KEX_ALGO != KexHybridX25519MLKEM768 {
		log.Printf("Unsupported Key Exchange requested: %d. Rejecting.", cHello.Encryption.CLIENT_KEX_ALGO)
		session.WritePacket(MsgServerUnsupportedKEX, nil)

		return nil, nil, nil, ErrUnsupportedKEX
	}

	if cHello.Encryption.CLIENT_CIPHER != CipherAES256GCM &&
		cHello.Encryption.CLIENT_CIPHER != CipherAES128GCM &&
		cHello.Encryption.CLIENT_CIPHER != CipherChaCha20Poly1305 {
		log.Printf("Unsupported Cipher requested: %d. Rejecting.", cHello.Encryption.CLIENT_CIPHER)
		session.WritePacket(MsgServerUnsupportedCipher, nil)
		return nil, nil, nil, ErrUnsupportedCipher
	}

	if cHello.Encryption.CLIENT_KEX_ALGO == KexX25519 {
		log.Printf("Client Asked for X25519  KEX Algorithm")
	}
	if cHello.Encryption.CLIENT_KEX_ALGO == KexHybridX25519MLKEM768 {
		log.Printf("Client Asked for HybridX25519MLKEM768  KEX Algorithm")
	}

	// 2. Parse client keys depending on the chosen KEX
	var clientPubKeyBytes []byte
	var clientMLKEMPubKeyBytes []byte

	if cHello.Encryption.CLIENT_KEX_ALGO == KexHybridX25519MLKEM768 {
		if len(cHello.Encryption.Client_Share_key) != 1216 { // 32 (X25519) + 1184 (ML-KEM-768)
			session.WritePacket(MsgServerPublicInvalidLen, nil)

			return nil, nil, nil, ErrClientPublicInvalidLen
		}
		clientPubKeyBytes = cHello.Encryption.Client_Share_key[:32]
		clientMLKEMPubKeyBytes = cHello.Encryption.Client_Share_key[32:]
	} else {
		if len(cHello.Encryption.Client_Share_key) != 32 {
			session.WritePacket(MsgServerPublicInvalidLen, nil)

			return nil, nil, nil, ErrClientPublicInvalidLen
		}
		clientPubKeyBytes = cHello.Encryption.Client_Share_key
	}

	// Classical X25519 public key conversion
	clientPubKey, err := ecdh.X25519().NewPublicKey(clientPubKeyBytes)
	if err != nil {
		session.WritePacket(MsgServerPublicInvalid, nil)

		return nil, nil, nil, ErrClientPubKeyInvalid
	}

	// 3. Generate Server's Ephemeral Key
	serverPrivKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		session.WritePacket(MsgServerKeyGenProblem, nil)

		return nil, nil, nil, ErrServerKeyGenProblem
	}
	serverPubKeyBytes := serverPrivKey.PublicKey().Bytes()

	// 4. Compute Classical Shared Secret (Diffie-Hellman)
	x25519Secret, err := serverPrivKey.ECDH(clientPubKey)
	if err != nil {
		session.WritePacket(MsgServerSharedSecertGenError, nil)

		return nil, nil, nil, ErrServerSharedSecertGen
	}

	// 5. Compute Post-Quantum Secret & Ciphertext if Hybrid [5]
	var sharedSecret []byte
	var serverShareKey []byte

	if cHello.Encryption.CLIENT_KEX_ALGO == KexHybridX25519MLKEM768 {
		ek, err := mlkem.NewEncapsulationKey768(clientMLKEMPubKeyBytes)
		if err != nil {
			session.WritePacket(MsgServerPublicInvalid, nil)

			return nil, nil, nil, ErrClientPubKeyInvalid
		}
		pqSecret, pqCiphertext := ek.Encapsulate() // pqCiphertext is 1088 bytes

		// Blend the classical and quantum secrets together!
		hybridSecretHash := sha256.Sum256(append(x25519Secret, pqSecret...))
		sharedSecret = hybridSecretHash[:]

		// Package our X25519 Public Key + ML-KEM Ciphertext into a single Share Key (1120 bytes)
		serverShareKey = append(serverPubKeyBytes, pqCiphertext...)
	} else {
		sharedSecret = x25519Secret
		serverShareKey = serverPubKeyBytes // 32 bytes
	}

	// 6. Derive AES-GCM or ChaCha Keys using HKDF (Go 1.24+) [1]
	keySize := 32
	if cHello.Encryption.CLIENT_CIPHER == CipherAES128GCM {
		keySize = 16
	}

	salt := append(cHello.ClientRandom, ID...)
	clientWriteKey, err := hkdf.Key(sha256.New, sharedSecret, salt, "wireforge-client-to-server", keySize)

	if err != nil {
		session.WritePacket(MsgServerEncryptionHandShakeFailed, nil)

		return nil, nil, nil, ErrClientWriteKeyGen
	}

	serverWriteKey, err := hkdf.Key(sha256.New, sharedSecret, salt, "wireforge-server-to-client", 32)

	if err != nil {
		session.WritePacket(MsgServerEncryptionHandShakeFailed, nil)

		return nil, nil, nil, ErrServertWriteKeyGen
	}

	var enc, dec cipher.AEAD
	switch cHello.Encryption.CLIENT_CIPHER {
	case CipherAES256GCM, CipherAES128GCM:
		cBlock, _ := aes.NewCipher(clientWriteKey)
		sBlock, _ := aes.NewCipher(serverWriteKey)
		dec, _ = cipher.NewGCM(cBlock) // We decrypt what client writes
		enc, _ = cipher.NewGCM(sBlock) // We encrypt what we write
	case CipherChaCha20Poly1305:
		dec, _ = chacha20poly1305.New(clientWriteKey)
		enc, _ = chacha20poly1305.New(serverWriteKey)
	}

	return enc, dec, serverShareKey, nil
}

func (d *Daemon) shellAuth(session *Session, aPkt *PacketFrame) (*AuthResponse, error) {
	var authUsername string
	var user string
	ar := &AuthResponse{Success: false}

	switch aPkt.Payload[0] {

	case MsgClientAuthPub:
		log.Println("PUB key auth packet received ")
		// --- PUBLIC KEY AUTHENTICATION ---
		authReq, err := ParsePubAuthRequest(aPkt.Payload[1:])
		if err != nil {
			return nil, err
		}

		if !SysUserExists(authReq.Username) {
			return nil, ErrUserDoesNotExist
		}

		if authReq.Username == "root" && !d.Conf.AllowLoginAsRoot {
			log.Printf("root login no allowed")
			return nil, ErrRootLoginNotAllowed
		}

		user = authReq.Username
		var AuthorizedKeysPath string

		if user == "root" {
			AuthorizedKeysPath = "/root/.shellforge/authorized_keys"
		}

		if user != "root" {
			p, perr := AuthorizedKeysPathForUser(authReq.Username)
			if perr != nil {
				log.Printf("PublicKey auth failed for user %s: %v", authReq.Username, perr)
				return nil, perr
			}
			AuthorizedKeysPath = p
		}

		log.Printf("authorized key dir for user %s is %s", user, AuthorizedKeysPath)
		ok, err := VerifyClientSignature(AuthorizedKeysPath, session.ID, authReq.Signature, authReq.PublicKey)
		if err != nil {
			log.Printf("PublicKey auth failed for user %s: %v", authReq.Username, err)

			return nil, err

		}
		if !ok {
			log.Printf("PublicKey auth failed for user %s: signature not accepted", authReq.Username)
			return nil, errors.New("public key authentication failed: signature verification rejected")
		}

		log.Printf("User [%s] successfully authenticated via Public key!", authReq.Username)

		authUsername = user
		ar.Username = authUsername
		ar.AuthType = AuthMethodPublicKey
		ar.Success = true

		session.authMethod = AuthMethodPublicKey
		session.PublicKey = authReq.PublicKey
		return ar, nil

	case MsgClientAuthPassword:
		// --- PASSWORD / PAM AUTHENTICATION ---
		authReq, err := ParsePasswordAuthRequest(aPkt.Payload[1:])
		if err != nil {

			return nil, err
		}
		if !SysUserExists(authReq.Username) {
			return nil, ErrUserDoesNotExist
		}
		if authReq.Username == "root" && !d.Conf.AllowLoginAsRoot {
			log.Printf("root login no allowed")
			return nil, ErrRootLoginNotAllowed
		}

		err = AuthenticatePAM(authReq.Username, authReq.Password)
		if err != nil {
			log.Printf("PAM auth failed for user %s: %v", authReq.Username, err)
			session.WritePacket(MsgServerPassAuthFaild, nil)
			return nil, err

		}

		log.Printf("User [%s] successfully authenticated via password!", authReq.Username)

		authUsername = authReq.Username
		ar.Username = authUsername
		ar.AuthType = AuthMethodPassword
		ar.Success = true

		session.authMethod = AuthMethodPassword
		return ar, nil

	case MsgClientAuthPKI:
		authReq, err := ParsePKIAuthRequest(aPkt.Payload[1:])
		if err != nil {
			log.Printf("Malformed PKI request: %v", err)

			return nil, err
		}

		// Validate the certificate chain and verify key ownership
		username, err := VerifyPKIChain(authReq.Certificate, authReq.Signature, session.ID, d.CAPool)

		if err != nil {
			log.Printf("PKI Authentication failed: %v", err)
			return nil, err
		}
		if !SysUserExists(username) {
			return nil, ErrUserDoesNotExist
		}
		if username == "root" && !d.Conf.AllowLoginAsRoot {
			log.Printf("root login no allowed")
			return nil, ErrRootLoginNotAllowed
		}

		log.Printf("User [%s] successfully authenticated via PKI!", username)

		authUsername = username
		ar.Username = authUsername
		ar.AuthType = AuthMethodPKI
		ar.Success = true
		session.authMethod = AuthMethodPKI
		return ar, nil

	default:
		log.Printf("Unexpected packet type [%d] in Auth Phase. Dropping.", aPkt.Payload[0])
		return nil, ErrMalformedPacket

	}

}

func (d *Daemon) CreateEnvironment(ctx context.Context, p *channel, sessionID string, eReq *EnvRequest) (*ENVs, error) {

	// Look up the public key in our database
	//pubKeyHex := hex.EncodeToString(eReq.PublicKey)
	//pubk := ed25519.PublicKey(eReq.PublicKey)
	publicKeyString := base64.URLEncoding.EncodeToString(eReq.PublicKey)

	log.Printf("%s asking for a %s", publicKeyString, string(eReq.AccessType))
	//base64.RawStdEncoding.Decode()

	record, envConfig, err := d.ValidateENVRequest(eReq, sessionID)

	if err != nil {
		log.Printf("NOT A VALID ENV REQ: %v", err)
		return nil, err
	}

	if d.DB.UserRequestedNameExists(string(eReq.UserRequestedName), eReq.PublicKey) {
		return nil, ErrDuplicateEnvName
	}
	requestedType := strings.ToLower(strings.TrimSpace(string(eReq.AccessType)))

	switch requestedType {
	/*case "system-user":

	//IM_TO_DO: sever should have a type of message that when is recieved by client the client is
	// asked to type a string(passwd) or sth and that would be sent to the server
	if SysUserExists(string(eReq.UserRequestedName)) {
		return nil, errors.New("user already exists. Skipping creation.")
	}
	tempUser := GenerateTempUsername()
	err = CreateSystemUser(tempUser, envConfig.Setting.GroupName, envConfig.Setting.Shell)
	if err != nil {
		log.Printf("Failed to create Ephemeral system user: %v", err)
		//session.WritePacket(MsgServerFailedToCreateTempSysUser, nil)
		return nil, err
	}
	log.Printf("Successfully created Ephemeral system User: %s", tempUser)
	var expiresAt time.Time
	duration, err := parseDurationWithDays(envConfig.LifeSpan)

	if err != nil {
		DeleteSystemUser(tempUser)
		return nil, err
	}

	if duration > 0 {
		expiresAt = time.Now().Add(duration)
	}

	// ====================================================
	// WRITE TO DB: Track the active container environment! [1, 3]
	// ====================================================
	activeEnv := &ENVs{
		PubKey:            pubKeyHex,
		EnvType:           "system-user",
		Name:              tempUser,
		ImageName:         "",
		UserRequestedName: string(eReq.UserRequestedName),
		Setting:           envConfig.Setting, // COPY THE SETTINGS DIRECTLY! [1]
		ExpiresAt:         expiresAt,
		CreatedAt:         time.Now(),
		SurviveReboot:     envConfig.Setting.SurviveReboot,
	}

	err = d.DB.AddENV(activeEnv) // Track in SQLite [1]
	if err != nil {
		DeleteSystemUser(tempUser)
		return nil, err
	}

	return activeEnv, nil
	//session.WritePacket(MsgServerTempShellResponse)
	*/
	case "container": //use libcontainer, https://github.com/opencontainers/runc/tree/main/libcontainer

		var imageName string
		var containerName string
		if envConfig.Setting.DockerfilePath != "" {

			imageName, err = BuildDockerfileOnDemand(ctx, p, envConfig.Setting.DockerfilePath, publicKeyString)
			if err != nil {
				log.Printf("Failed to compile custom Dockerfile: %v", err)
				return nil, err
			}
		}

		log.Printf("image built: %s", imageName)

		containerName, err = CreateContainer(ctx, p, publicKeyString, imageName, envConfig.Setting.MemoryLimit, envConfig.Setting.CPULimit, envConfig.Setting.GPULimit)
		if err != nil {
			if containerName != "" {
				KillAndRemoveContainer(ctx, containerName)
			}

			DeleteContainerImage(ctx, imageName)

			return nil, err
		}

		log.Printf("container created: %s", containerName)

		// Calculate absolute expiration time
		var expiresAt time.Time
		duration, err := parseDurationWithDays(record.ContainersExpireAfter)

		if err != nil {
			KillAndRemoveContainer(ctx, containerName)
			DeleteContainerImage(ctx, imageName)
			return nil, err
		}

		if duration > 0 {
			expiresAt = time.Now().Add(duration)
		}

		// ====================================================
		// WRITE TO DB: Track the active container environment! [1, 3]
		// ====================================================
		activeEnv := &ENVs{
			PubKey:            record.PubKey,
			EnvType:           "container",
			Name:              containerName,
			ImageName:         imageName,
			UserRequestedName: string(eReq.UserRequestedName),
			Setting:           envConfig.Setting, // COPY THE SETTINGS DIRECTLY! [1]
			ExpiresAt:         expiresAt,
			CreatedAt:         time.Now(),
			SurviveReboot:     envConfig.Setting.SurviveReboot,
		}

		fmt.Printf(
			"container Created{\n"+
				"  PubKey: %s\n"+
				"  EnvType: container\n"+
				"  Name: %s\n"+
				"  ImageName: %s\n"+
				"  UserRequestedName: %s\n"+
				"  Setting: %v\n"+
				"  ExpiresAt:%s"+
				"  SurviveReboot: %t\n"+
				"}\n",
			record.PubKey,
			containerName,
			imageName,
			string(eReq.UserRequestedName),
			envConfig.Setting,
			expiresAt,
			envConfig.Setting.SurviveReboot,
		)

		err = d.DB.AddENV(activeEnv)
		if err != nil {
			if err == ErrDuplicateEnvName {
				return nil, err
			}
			KillAndRemoveContainer(ctx, containerName)
			DeleteContainerImage(ctx, imageName)
			return nil, err
		}
		return activeEnv, nil

	//case "hostsharednamespace", "jailed", "namespace", "host-shared":
	default:
		return nil, errors.New("invaild env type ")
	}
	//d.DB.updateField("allowed_keys", string(tsReq.PublicKey), "created_users", record.CreatedUsers+1)

	//return nil, nil
}

// ValidateTempShellRequest performs cryptographic, stateful, and resource-limit
// validations on the incoming Client request against the SQLite database [1, 2].
func (d *Daemon) ValidateENVRequest(eReq *EnvRequest, sessionID string) (*AccessKeyRecord, *EnvConfig, error) {
	if eReq == nil {
		return nil, nil, fmt.Errorf("nil temporary shell request")
	}
	if !d.DB.IsEligibleKey(eReq.PublicKey) {
		return nil, nil, ErrNonEligibleKey
	}

	// Cryptographically verify ownership of the private key
	if !ed25519.Verify(eReq.PublicKey, []byte(sessionID), eReq.Signature) {
		return nil, nil, ErrInvalidSignature
	}

	record, err := d.DB.GetRecord(eReq.PublicKey)
	if err != nil {
		log.Printf("Database error retrieving key: %v", err)
		return nil, nil, ErrDBKeyRetrival
	}
	if record == nil {
		log.Printf("Database error retrieving key, nil record: %v", err)
		return nil, nil, ErrDBKeyRetrival
	}

	// 3. Verify overall key expiration (survives reboots!) [2]
	if record.IsExpired(time.Now()) {
		return nil, nil, fmt.Errorf("access key expired on %s", record.KeyExpiresAt)
	}

	if len(eReq.UserRequestedName) > 32 {
		return nil, nil, fmt.Errorf("requested name is longer than 32 char")
	}

	// 4. Normalize the requested AccessType (case-insensitive, trimmed)
	requestedType := strings.ToLower(strings.TrimSpace(string(eReq.AccessType)))

	// 5. Only containers are supported; build the env profile straight
	// from the flat access key record [1, 2]
	if requestedType != "container" {
		return nil, nil, fmt.Errorf("environment type %q is not authorized for this key (only \"container\" is supported)", string(eReq.AccessType))
	}
	matchedEnv := &EnvConfig{
		Type:    "container",
		Setting: record.ContainerSetting(),
	}

	// 7. Enforce dynamic resource limit thresholds [2]
	if record.KeyMaxContainers > 0 {
		active := d.DB.CountEnvsByType(eReq.PublicKey, "container")
		if active >= record.KeyMaxContainers {
			return nil, nil, fmt.Errorf("maximum active containers limit reached (%d/%d)",
				active, record.KeyMaxContainers)
		}
	}

	return record, matchedEnv, nil
}

func Start(conf DaemonConfig) {
	log.Printf("[CLI] Starting shellforge Daemon")
	// Open the SQLite database
	dbdir := "/etc/shellforge/"
	if conf.DatabaseDir != "" {
		dbdir = conf.DatabaseDir
	}
	db, err := OpenDB(dbdir)

	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	log.Printf("database Loaded (access keys: %s)", AccessKeysPath)

	ctx, cancel := context.WithCancel(context.Background())
	s := &DaemonState{
		sessions:       make(map[string]*Session),
		UserSessions:   make(map[string][]string),
		UserSessCount:  make(map[string]uint8),
		UserShellCount: make(map[string]uint8),
	}
	d := &Daemon{
		Conf:             &conf,
		ctx:              ctx,
		Cancel:           cancel,
		DB:               db,
		State:            s,
		idleTimeout:      0,
		handshakeTimeout: 0,
	}

	if conf.IdleTimeout != 0 {
		d.handshakeTimeout = conf.IdleTimeout
	}

	if conf.HandshakeTimeout != 0 {
		d.handshakeTimeout = conf.HandshakeTimeout
	}

	hostKeyPath := conf.HostKeyPath
	if hostKeyPath == "" {
		hostKeyPath = "/etc/shellforge/host_ed25519"
	}
	// Let the user dictate if this client is allowed based on their Init string
	if d.Conf.ClientInitHandler == nil {
		d.Conf.ClientInitHandler = d.DefaultClientInitHandler()
	}
	hostKey, err := LoadOrCreateHostKey(hostKeyPath)

	if err != nil {
		log.Fatalf("Failed to load/create host key: %v", err)
	}
	d.HostKey = hostKey

	log.Printf("[Daemon] Host key loaded from %s; public key: %x", hostKeyPath, hostKey.Public().(ed25519.PublicKey))

	// Calculate supported auth bitmask dynamically
	var supportedAuths uint8 = 0

	if d.Conf.PublicKeyAuth {

		supportedAuths |= AuthMethodPublicKey
	}

	if d.Conf.PasswordAuth { // Assuming PAM fallback configured
		supportedAuths |= AuthMethodPassword
	}

	if d.CAPool != nil {
		supportedAuths |= AuthMethodPKI
	}

	d.supportedAuths = supportedAuths

	// This blocks and automatically handles SIGTERM OS graceful shutdowns
	d.listen()
}

func (ds *DaemonState) GetSession(ID []byte) (*Session, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	// Convert []byte to string for map lookup
	s, exists := ds.sessions[string(ID)]
	return s, exists
}

func (ds *DaemonState) SaveSession(ID []byte, s *Session) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	// Initialize map if nil
	if ds.sessions == nil {
		ds.sessions = make(map[string]*Session)
	}
	ds.sessions[string(ID)] = s

}

func (ds *DaemonState) DeleteSession(ID []byte) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	sess, ok := ds.sessions[string(ID)]
	if !ok {
		log.Printf("[ERROR] Attempted to delete non-existent session: %x", ID)
		return
	}

	us, exi := ds.UserSessions[sess.User]
	if exi {
		for i, s := range us {
			if s == string(ID) {
				ds.UserSessions[sess.User] = append(us[:i], us[i+1:]...)
				ds.UserSessCount[sess.User]--
				break
			}
		}
	}

	delete(ds.sessions, string(ID))
}

func (ds *DaemonState) UpdateUserState(user string, ID []byte) error {

	s, e := ds.GetSession(ID)
	if !e {
		return errors.New("can't update user session state, session doesnt exists")
	}
	if s.User != user {
		return errors.New("can't update user session state, session user mismatch")
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	stateIDs, ok := ds.UserSessions[user]

	if !ok {
		stateIDs = []string{}
	}

	stateIDs = append(stateIDs, string(ID))

	ds.UserSessions[user] = stateIDs
	ds.UserSessCount[user]++

	return nil
}

func generateSessionID(length int) []byte {
	return randomBytes(length)
}

func randomBytes(length int) []byte {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic("PANIC! crypto/rand failed, FATAL FLAW") // If the OS crypto fails, the server MUST panic.
	}
	return b
}

// RunPodmanContainer dynamically starts a fresh container or resumes an existing stopped one [1, 2, 3].
func (d *Daemon) RunContainer(ctx context.Context, shell *Shell, run chan struct{}, env *ENVs, rows, cols uint16, ch io.ReadWriter) error {
	log.Printf("[Container] as uid=%d, XDG_RUNTIME_DIR=%s", os.Getuid(), os.Getenv("XDG_RUNTIME_DIR"))
	state := getContainerState(env.Name)
	log.Printf("[Container] Current state of %s: %q", env.Name, state)

	leaveRunning := !env.Setting.StopAfterExit && !env.Setting.KillAfterExit

	var cmd *exec.Cmd

	switch state {
	case "running":
		// Already running — attach to it with exec instead of start,
		// so we don't conflict with whatever started it.
		log.Printf("[Container] Container %s is already running, attaching via exec...", env.Name)
		args := []string{"exec", "-it", env.Name, "/bin/bash"}
		cmd = exec.CommandContext(ctx, "podman", args...)

	case "stopped", "exited", "created":
		// Normal resume path — container exists but isn't running.
		log.Printf("[Container] Resuming stopped container: %s", env.Name)
		args := []string{"start", "-a", "-i", env.Name}
		cmd = exec.CommandContext(ctx, "podman", args...)

	case "paused":
		log.Printf("[Container] Unpausing container: %s", env.Name)
		if err := exec.CommandContext(ctx, "podman", "unpause", env.Name).Run(); err != nil {
			return fmt.Errorf("failed to unpause container %s: %w", env.Name, err)
		}
		args := []string{"exec", "-it", env.Name, "/bin/bash"}
		cmd = exec.CommandContext(ctx, "podman", args...)
	case "dead":
		// Container is wedged — remove it and let the "" branch recreate it
		log.Printf("[Container] Container %s is dead, removing and recreating...", env.Name)
		if err := exec.CommandContext(ctx, "podman", "rm", "--force", env.Name).Run(); err != nil {
			return fmt.Errorf("failed to remove dead container %s: %w", env.Name, err)
		}
		// Fall through to fresh creation by recursing or inlining the run args
		state = ""
		fallthrough
	case "": // doesn't exist at all
		// First-time login — create a fresh persistent container.
		log.Printf("[Container] Creating fresh persistent container: %s", env.Name)
		args := []string{
			"run", "-it",
			"--name", env.Name,
			"--pull=never",
		}
		if env.Setting.MemoryLimit != "" {
			args = append(args, fmt.Sprintf("--memory=%s", env.Setting.MemoryLimit))
		}
		if env.Setting.CPULimit > 0 {
			args = append(args, fmt.Sprintf("--cpus=%f", env.Setting.CPULimit))
		}

		//if gpuLimit != "" {
		//	args = append(args, "--device", fmt.Sprintf("nvidia.com/gpu=%s", gpuLimit))
		//}

		args = append(args, fmt.Sprintf("localhost/%s", env.ImageName))
		cmd = exec.CommandContext(ctx, "podman", args...)

	case "stopping":
		log.Printf("[Container] Container %s is stopping, waiting up for clean exit...", env.Name)
		err := waitForContainerState(ctx, env.Name, "exited", 10*time.Second)
		if err != nil {
			// Didn't exit cleanly in time — force kill it
			log.Printf("[Container] Container %s did not exit cleanly, sending SIGKILL...", env.Name)
			killCmd := exec.CommandContext(ctx, "podman", "kill", "--signal", "SIGKILL", env.Name)

			var stderr bytes.Buffer
			killCmd.Stderr = &stderr
			if killErr := killCmd.Run(); killErr != nil {
				return fmt.Errorf("failed to SIGKILL container %s: %w (stderr: %s)", env.Name, killErr, stderr.String())
			}
			// Wait for it to actually reach exited after SIGKILL
			if waitErr := waitForContainerState(ctx, env.Name, "exited", 5*time.Second); waitErr != nil {
				return fmt.Errorf("container %s did not exit after SIGKILL: %w", env.Name, waitErr)
			}
		}
		log.Printf("[Container] Container %s exited, resuming...", env.Name)
		args := []string{"start", "-a", "-i", env.Name}
		cmd = exec.CommandContext(ctx, "podman", args...)
	default:
		return fmt.Errorf("container %s is in unexpected state %q, manual intervention required", env.Name, state)
	}

	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second

	// 2. Spawn the container inside the PTY [3]
	ptyFd, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		close(run) //close on err
		return err
	}

	defer ptyFd.Close()

	shell.SetPTY(ptyFd)
	defer shell.SetPTY(nil)

	// Wait until the runtime actually reports "running" before signaling
	// readiness — pty start only means the podman *process* spawned.
	if err := waitForContainerState(ctx, env.Name, "running", 10*time.Second); err != nil {
		close(run)
		return fmt.Errorf("container %s failed to reach running state: %w", env.Name, err)
	}

	log.Printf("[Container] pty started: %s", env.Name)
	close(run) //signal run

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(ptyFd, ch)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(ch, ptyFd)
		errCh <- err
	}()

	applyExitPolicy := func() {
		switch {
		case env.Setting.KillAfterExit:
			log.Printf("[Container] killing container on exit %s...", env.Name)
			_ = exec.Command("podman", "kill", "--signal", "SIGKILL", env.Name).Run()
		case env.Setting.StopAfterExit:
			log.Printf("[Container] Gracefully stopping container %s...", env.Name)
			_ = exec.Command("podman", "stop", "-t", "5", env.Name).Run()
		case leaveRunning:
			log.Printf("[Container] container %s stays running in the background", env.Name)
		}
	}

	select {
	case <-ctx.Done():
		// Client disconnected or daemon is shutting down. Tear down OUR side:
		// CommandContext already signaled the podman attach client (see
		// cmd.Cancel above), the deferred ptyFd.Close() unblocks both io.Copy
		// goroutines, and cmd.Wait() reaps the child so nothing accumulates.
		applyExitPolicy()
		_ = cmd.Wait()
		log.Printf("[Container] loop exit for %s...", env.Name)
		return ctx.Err()
	case err := <-errCh:
		// The PTY or the client pipe ended on its own (e.g. user typed "exit").
		log.Printf("[Container] %v\n", err)
		applyExitPolicy()
	}

	return cmd.Wait()
}

// =====================================================================
// CONTAINER OBSERVATION FUNCTIONS
// =====================================================================

// PodmanStats is the struct podman emits per-container from
// `podman stats --no-stream --format json`.
type PodmanStats struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	CPUPerc  string `json:"cpu_percent"`
	MemUsage string `json:"mem_usage"`
	MemPerc  string `json:"mem_percent"`
	NetIO    string `json:"net_io"`
	BlockIO  string `json:"block_io"`
	PIDs     uint64 `json:"pids"`
}

// PodmanInspectResult is a subset of the rich JSON podman inspect returns.
// Extend the fields here if you need more detail surfaced to the client.
type PodmanInspectResult struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	State   struct {
		Status     string    `json:"Status"`
		Running    bool      `json:"Running"`
		Paused     bool      `json:"Paused"`
		StartedAt  time.Time `json:"StartedAt"`
		FinishedAt time.Time `json:"FinishedAt"`
		ExitCode   int       `json:"ExitCode"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Env    []string          `json:"Env"`
		Labels map[string]string `json:"Labels"`
		Cmd    []string          `json:"Cmd"`
	} `json:"Config"`
	HostConfig struct {
		Memory   int64 `json:"Memory"`
		NanoCPUs int64 `json:"NanoCpus"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		IPAddress string `json:"IPAddress"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Mode        string `json:"Mode"`
	} `json:"Mounts"`
}

// GetContainerLogs streams the stdout+stderr of the named container back into w.
// Equivalent to: podman logs --timestamps <containerName>
func (d *Daemon) GetContainerLogs(ctx context.Context, containerName string, w io.Writer) error {
	state := getContainerState(containerName)
	if state == "" {
		return fmt.Errorf("container %q does not exist", containerName)
	}

	cmd := exec.CommandContext(ctx, "podman", "logs", "--timestamps", "-f", containerName)
	cmd.Stdout = w
	cmd.Stderr = w

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("podman logs failed: %w", err)
	}
	return nil
}

// GetStats returns a single point-in-time snapshot of resource usage for
// the named container. The container must be running.
// Equivalent to: podman stats --no-stream --format json <containerName>
func (d *Daemon) GetContainerStats(ctx context.Context, containerName string) (*PodmanStats, error) {
	state := getContainerState(containerName)
	if state == "" {
		return nil, fmt.Errorf("container %q does not exist", containerName)
	}
	if state != "running" {
		return nil, fmt.Errorf("container %q is not running (state: %s): stats require a running container", containerName, state)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "podman", "stats",
		"--no-stream",
		"--format", "json",
		containerName,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("podman stats failed: %w (stderr: %s)", err, stderr.String())
	}

	// podman stats --format json wraps results in an array even for one container.
	var results []PodmanStats
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		return nil, fmt.Errorf("failed to parse podman stats output: %w (raw: %s)", err, stdout.String())
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("podman stats returned empty result for %q", containerName)
	}
	return &results[0], nil
}

// GetInspect returns detailed metadata about a container (running or stopped).
// Equivalent to: podman inspect <containerName>
func (d *Daemon) GetContainerInspect(ctx context.Context, containerName string) (*PodmanInspectResult, error) {
	state := getContainerState(containerName)
	if state == "" {
		return nil, fmt.Errorf("container %q does not exist", containerName)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "podman", "inspect", containerName)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("podman inspect failed: %w (stderr: %s)", err, stderr.String())
	}

	// podman inspect always returns a JSON array.
	var results []PodmanInspectResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		return nil, fmt.Errorf("failed to parse podman inspect output: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("podman inspect returned empty result for %q", containerName)
	}
	return &results[0], nil
}

// GetTop returns the process list inside the container, formatted as a
// human-readable table, streamed into w.
// Equivalent to: podman top <containerName>
func (d *Daemon) GetContainerTop(ctx context.Context, containerName string, w io.Writer) error {
	state := getContainerState(containerName)
	if state == "" {
		return fmt.Errorf("container %q does not exist", containerName)
	}
	if state != "running" {
		return fmt.Errorf("container %q is not running (state: %s): top requires a running container", containerName, state)
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "podman", "top", containerName,
		// Extra ps columns for more useful output than the default.
		"pid", "ppid", "user", "pcpu", "pmem", "etime", "args",
	)
	cmd.Stdout = w
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("podman top failed: %w (stderr: %s)", err, stderr.String())
	}
	return nil
}

// ContainerExec runs a single non-interactive command inside a running
// container and streams its combined stdout+stderr back into w.
// Equivalent to: podman exec <containerName> <command...>
// The commandStr is split on spaces — if you need shell features like pipes
// or redirects, wrap in sh -c: ContainerExec(ctx, name, "sh -c 'cat /a | grep b'", w)
func (d *Daemon) ContainerExec(ctx context.Context, containerName, commandStr string, w io.Writer) error {
	if strings.TrimSpace(commandStr) == "" {
		fmt.Fprintf(w, "command string must not be empty")
		return fmt.Errorf("command string must not be empty")
	}

	state := getContainerState(containerName)
	if state == "" {
		fmt.Fprintf(w, "container %q does not exist", containerName)
		return fmt.Errorf("container %q does not exist", containerName)
	}

	// Ensure the container is actually accepting exec sessions.
	// NOTE: even if inspect says "running", a start may still be settling,
	// so we always wait rather than trusting a single snapshot.
	if state != "running" {
		// Idempotent: if a concurrent resume (RunContainer) already started
		// it, this is a no-op / harmless error we can ignore.
		startCmd := exec.CommandContext(ctx, "podman", "start", containerName)
		var startErr bytes.Buffer
		startCmd.Stderr = &startErr
		if err := startCmd.Run(); err != nil {
			log.Printf("[exec] podman start %s: %v (stderr: %s) — waiting anyway, a concurrent start may be in flight",
				containerName, err, strings.TrimSpace(startErr.String()))
		}
	}
	if err := waitForContainerState(ctx, containerName, "running", 10*time.Second); err != nil {
		fmt.Fprintf(w, "container %q did not reach running state: %v", containerName, err)
		return err
	}

	parts := strings.Fields(commandStr)
	args := append([]string{"exec", "-t", containerName}, parts...)

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "podman", args...)
	//cmd.Stdin = w
	cmd.Stdout = w
	cmd.Stderr = &stderr // capture separately; merge into w after run

	if err := cmd.Run(); err != nil {
		podmanErr := strings.TrimSpace(stderr.String())
		// Non-zero exit from the *command inside the container* is normal —
		// surface it with stderr so the client sees the actual error output.
		_, _ = fmt.Fprintf(w, "\n[exec error] %v\n", err)
		if podmanErr != "" {
			_, _ = fmt.Fprintf(w, "[stderr] %s\n", podmanErr)
		}
		return fmt.Errorf("exec %q in %s exited non-zero: %w", commandStr, containerName, err)
	}

	// Flush any stderr the command wrote (e.g. warnings from the program itself).
	if stderr.Len() > 0 {
		_, _ = w.Write(stderr.Bytes())
	}
	return nil
}
