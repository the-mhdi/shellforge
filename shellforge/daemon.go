package shellforge

import (
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
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/atomic"

	"github.com/the-mhdi/wireforge/tcp"
	"golang.org/x/crypto/chacha20poly1305"
)

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

	//a definitive key directory, by default its "" and for root its root/.shellforge/authorized_keys and other users  home/$username/.shellforge/authorized_keys
	AuthorizedKeysPath              string // e.g. "home/$username/.shellforge/authorized_keys", for root "root/.shellforge/authorized_keys" "/etc/wireforge/authorized_keys"
	AllowLoginAsRoot                bool
	MaxConnectionsAllowed           uint32
	MaxContainersConnectionsAllowed uint32

	EnvironmentsJsonConfig string
	DatabaseDir            string
	ClientInitHandler      func(ctx context.Context, msg []byte) bool
}

type Daemon struct {
	Conf           *DaemonConfig
	Names          []string
	Versions       []uint8
	supportedAuths uint8

	ListenAddr string
	Port       string

	CAPool *x509.CertPool // Loaded on startup

	State *DaemonState

	DB *DB // Database for tracking allowed keys and active temp users

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

// listen loop
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
		session.isDaemon = true

		defer session.Close()

		// ==========================================
		// PHASE 1: THE INIT EXCHANGE (Cleartext)
		// ==========================================
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
		if d.Conf.ClientInitHandler == nil {
			d.Conf.ClientInitHandler = d.DefaultClientInitHandler(connCtx, initPkt.Payload[1:])
		}

		if d.Conf.ClientInitHandler != nil && !d.Conf.ClientInitHandler(connCtx, initPkt.Payload[1:]) {
			log.Println("ClientInit rejected by handler.")
			session.WritePacket(MsgServerClientInitRejected, nil)

			return
		}

		// Success! Send ServerInit back to the client
		err = session.WritePacket(MsgServerInit, []byte(d.Conf.DaemonInitMsg))
		if err != nil {

			return
		}

		// ==========================================
		// PHASE 2: CLIENT HELLO (unEncrypted)
		// ==========================================
		cHelloPkt, err := session.ReadPacket()
		if err != nil {

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

		// ==========================================
		// PHASE 3: KEY EXCHANGE & ENCRYPTION
		// ==========================================
		if cHello.SessLen != 0 {
			// used for sess resume -- not allowed for now
			log.Printf("Client attempting to resume Session: %x", cHello.SessionID)
			log.Println("Session expired or invalid. Forcing full reconnect.")
			session.WritePacket(MsgServerClientHelloRejected, nil)
			return
		}

		// Generate 32-byte Session ID
		newSessionID := generateSessionID(32)
		log.Printf("session id generated, %x", newSessionID)

		//encrypt the session
		enc, dec, serverShareKey, err := d.encryptSession(cHello, session, newSessionID)
		if err != nil {
			log.Printf("Faild to encrypt the session, %v", err)
			return
		}

		// 7. Save session state
		session.ID = newSessionID
		d.State.SaveSession(newSessionID, session)
		defer d.State.DeleteSession(session.ID)

		sh := &ServerHello{
			SessionResumed:    false,
			SessLen:           uint16(len(newSessionID)),
			SessionID:         newSessionID,
			EncryptionSupport: true,
			Encryption: ServerHelloEncryptionFields{
				ServerSharekeyLen: uint16(len(serverShareKey)),
				Server_Share_key:  serverShareKey, //pub key if KexX25519 | Public Key + ML-KEM Ciphertext if KexHybridX25519MLKEM768
			},
			SupportedAuths: d.supportedAuths, // <--- ADVERTISE

		}

		log.Printf("Server Hello Packet Created and sent, %x", newSessionID)

		err = session.WritePacket(MsgServerHello, sh.Marshal())
		if err != nil {
			log.Printf("failed to send ServerHello: %v", err)
			return
		}

		// 9. Setup the Encrypter/Decrypter based on client's selected cipher

		// messages are encrypted from now on
		session.encrypter = enc
		session.decrypter = dec

		log.Printf("Secure Session Established! ID: %x", newSessionID)

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
		switch pkt.Payload[0] {

		case MsgClientENVCreate:
			log.Printf("got MsgClientENVCreate")
			// Parse the temporary shell request
			eReq, err := ParseENVRequest(pkt.Payload[1:])
			if err != nil {
				return
			}

			chanID := session.IncrementChannelID()
			pipeStream := NewPipe(chanID, session)
			session.AddActiveChannel(chanID, pipeStream)

			log.Printf("LogStream created and added to active channel %d", chanID)
			co := &ChannelOpen{
				ChannelID: chanID,
			}

			session.WritePacket(MsgServerOpenLogChannel, co.Marshal())

			env, err := d.CreateEnvironment(connCtx, pipeStream, string(session.ID), eReq)

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
			session.WritePacket(MsgServerENVCreated, envr.Marshal())
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
					continue
				}

				if AuthRes.Success == false {
					if i < MAX_AUTH_RETRY {
						log.Printf("auth failed attempt %d", i)
						session.WritePacket(MsgServerAuthResponse, AuthRes.Marshal())
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
			session.WritePacket(MsgServerAuthResponse, ar.Marshal())
			log.Printf("User [%s] authenticated successfully!", session.User)
			// PHASE 4: THE SECURE EVENT LOOP (Multiplexing)

			d.shellLoop(connCtx, session)
			return
		case MsgClientGetContainer:

			eReq, err := ParseENVRequest(pkt.Payload[1:])
			if err != nil {
				return
			}
			if !ed25519.Verify(eReq.PublicKey, session.ID, eReq.Signature) {
				log.Printf("cant verify sig")
				session.WritePacket(MsgServerInvalidSignature, nil)
				return
			}

			if strings.ToLower(string(eReq.AccessType)) != "container" {
				log.Printf("conflict")
				session.WritePacket(MsgServerInvalidEnvType, nil)
				return
			}

			if !d.DB.HasActiveEnv(string(eReq.PublicKey), "container") || !d.DB.IsEligibleKey(string(eReq.PublicKey)) {
				log.Printf("no container fot this key ")
				session.WritePacket(MsgServerNoContainer, nil)
				return
			}

			if eReq.UserRequestedName == nil || eReq.UserRequestedNameLen == 0 {
				envs, err := d.DB.GetEnvsByType(string(eReq.PublicKey), "container")
				if err != nil {
					log.Printf("cant get container list, %v", err)
					session.WritePacket(MsgServerNoContainer, nil)
					return
				}

				var conList []string

				for _, env := range envs {
					conList = append(conList, env.Name)
				}

				clist := &ContainersListResponse{
					RequestID:      eReq.RequestID,
					PublicKey:      eReq.PublicKey,
					ContainersList: conList,
				}

				//send ContainersListResponse if no name specified
				session.WritePacket(MsgServerContainersListResponse, clist.Marshal())
				return

			}

			if string(eReq.AccessType) == "container" {
				if d.State.ContainerConns.Load() >= d.Conf.MaxConnectionsAllowed && d.Conf.MaxConnectionsAllowed != 0 {
					log.Printf("max container connections reached, no other client conns allowed")
					return
				}

			}
			env, err := d.DB.GetENVByUserReqestedName(string(eReq.UserRequestedName), string(eReq.PublicKey))

			if err == nil && env != nil {
				chanID := session.IncrementChannelID()

				log.Printf("New Channel for container Created by the Daemon - Chan ID = %v", hex.EncodeToString([]byte{byte(chanID)}))

				pipeStream := NewPipe(chanID, session)

				go func() {
					defer session.DeleteActiveChannel(chanID)
					defer pipeStream.Close()
					err := d.RunContainer(connCtx, env.Name, env.ImageName, env.Setting.MemoryLimit, env.Setting.CPULimit, env.Setting.GPULimit, 24, 80, pipeStream)
					if err != nil {
						return
					}
					srr := &ShellRequestResponse{
						RequestID: eReq.RequestID, // Matches the client's request
						ChannelID: chanID,         // ASSIGNED BY THE SERVER!
						Success:   true,
					}

					err = session.WritePacket(MsgServerShellReqResponse, srr.Marshal())
					if err != nil {
						return
					}
					log.Printf("container running")
				}()

				d.ContainerLoop(connCtx, session)
			}
		default:
			log.Printf("invalid request")
			return
		}

	}
	opts := tcp.DefaultListenOptions().WithVerbose(true)
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

}
func (d *Daemon) ContainerLoop(ctx context.Context, session *Session) {
	d.State.ContainerConns.Add(1)
	defer d.State.ContainerConns.Sub(1)

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

			log.Printf("Data received on Channel %d", ch.ChannelID)
			// Look up the session and ch id and write the data
			if c, exists := session.GetActiveChannel(ch.ChannelID); exists {

				switch cc := c.(type) {

				case net.Conn:
					_, err = cc.Write(ch.Data)
					if err != nil {
						log.Printf("Failed to write back to io dev: %v", err)
					}
				case *PipeStream:
					// Feed the decrypted data directly into the Channel's read queue!
					cc.Feed(ch.Data)
				default:
					log.Println("Unknown channel type in memory!")
				}
			} else {
				log.Printf("Received Data with unknown Channel ID: %d", ch.ChannelID)
				go session.WritePacket(MsgServerChannelUnknownOrClosed, nil)
			}
		case MsgClientSessionClosed:
			session.Close()
			log.Printf("MsgClientSessionClosed")
		case MsgClientWindowResize:
			ws, err := ParseWindowResize(pkt.Payload[1:])
			if err != nil {
				log.Printf("Packet window resize couldn't be parsed!")
			}
			pipe, ok := session.GetActiveChannel(ws.ChannelID)

			if !ok {
				continue
			}

			if p, ok := pipe.(*PipeStream); ok {
				//chanID := session.IncrementChannelID()
				//session.AddActiveChannel(chanID, p)
				err := p.Resize(ws.Rows, ws.Cols)
				log.Printf("Packet window resize, Channel %d", ws.ChannelID)
				if err != nil {
					log.Printf("initial window resize failed %v ", err)
				}
			}

		default:
			log.Printf("Unknown or corrupted message type: %d", pkt.Payload[0])
			log.Printf("packet code %d cant be handle", pkt)
		}
	}
}
func (d *Daemon) shellLoop(ctx context.Context, session *Session) {
	for {

		pkt, err := session.ReadPacket()
		if err != nil {
			log.Printf("[] Error reading packet from Session %x...: %v", session.ID[0:3], err)

			log.Printf("Ending The Session %x... : %v", session.ID[0:3], err)
			break
		}

		switch pkt.Payload[0] {

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
				chanID := session.IncrementChannelID()
				// Save the connection so we can write back to it later!
				session.AddActiveChannel(chanID, uConn)
				defer session.DeleteActiveChannel(chanID)
				defer uConn.Close()

				// A. Tell the Client a new user connected!
				sch := &ServerChannelOpen{
					ChannelID:  chanID,
					RemoteAddr: req.Address,
				}

				session.WritePacket(MsgServerNewChannelOpened, sch.Marshal())

				// B. Read from the user, wrap it in a ChannelData packet, and send to Client
				//buf := make([]byte, MAX_PACKET_LEN)

				buf := bufferPool.Get().([]byte)
				defer bufferPool.Put(buf)
				for {
					n, err := uConn.Read(buf)
					if n > 0 {

						cd := &ChannelData{
							ChannelID: chanID,
							Data:      buf[:n],
						}
						session.WritePacket(MsgServerChanneledData, cd.Marshal())
					}

					if err != nil {
						break
					}
				}
				// C. Tell client the web user disconnected
				ccl := &ChannelClosed{ChannelID: chanID}
				session.WritePacket(MsgServerChannelClosed, ccl.Marshal())
			}

			// Run the listener in the background!
			ln := tcp.NewListenerWithContext(ctx, tcp.DefaultListenOptions())
			err = ln.Initialize(req.Address, forwardHandler)

			// 3. Reply to the Client
			res := &ListenResponse{Address: req.Address, Success: err == nil}
			session.WritePacket(MsgServerListenResponse, res.Marshal())

			if err != nil {
				log.Printf("Failed to start listener for client on %s: %v", req.Address, err)
				continue
			}

			go ln.Run()

			log.Printf("Spawned listener for client on %s", ln.Address)

		case MsgClientChanneledData:
			// CLIENT WRITING DATA BACK TO PUBLIC USER
			ch, err := ParseChannelData(pkt.Payload[1:])
			if err != nil {
				log.Println("Malformed Channel Data from client")
				go session.WritePacket(MsgServerChanDataMalformed, nil)
				continue
			}

			log.Printf("Data received on Channel %d", ch.ChannelID)
			// Look up the session and ch id and write the data
			if c, exists := session.GetActiveChannel(ch.ChannelID); exists {

				switch cc := c.(type) {

				case net.Conn:
					_, err = cc.Write(ch.Data)
					if err != nil {
						log.Printf("Failed to write back to io dev: %v", err)
					}
				case *PipeStream:
					// Feed the decrypted data directly into the Channel's read queue!
					cc.Feed(ch.Data)
				default:
					log.Println("Unknown channel type in memory!")
				}
			} else {
				log.Printf("Received Data with unknown Channel ID: %d", ch.ChannelID)
				go session.WritePacket(MsgServerChannelUnknownOrClosed, nil)
			}

		case MsgClientShellRequest:
			// 1. Parse the specific shell request
			sr, err := ParseShellRequest(pkt.Payload[1:])
			log.Printf("Received Shell Request for user [%s] and shell [%s]- Req id %v", string(sr.User), string(sr.Shell), sr.RequestID)
			if err != nil {
				session.WritePacket(MsgServerFailedToOpenShell, nil)
				continue
			}

			// 2. Daemon is authoritative! It assigns the Channel ID safely.
			chanID := session.IncrementChannelID()
			log.Printf("New Channel Created by the Daemon - Chan ID = %v", hex.EncodeToString([]byte{byte(chanID)}))

			//shell := string(sr.Shell)
			//username := string(sr.User)

			if session.User != string(sr.User) {
				log.Printf("Authentication failed: missmatched users!")
				continue
			}

			// 5. Reply to Client: "Your RequestID is approved, here is your official ChannelID"
			res := &ShellRequestResponse{
				RequestID: sr.RequestID,
				ChannelID: chanID,
				Success:   err == nil,
			}

			err = session.WritePacket(MsgServerShellReqResponse, res.Marshal())

			log.Printf("Shell request response sent for reqID %v: %v", res.RequestID, hex.EncodeToString([]byte{byte(res.ChannelID)}))

			if err != nil {
				log.Printf("init Shell failed: %v", err)
				continue
			}

			if string(sr.User) != session.User {
				log.Printf("sth wrong! shel req user: %s session user %s", string(sr.User), session.User)
				continue

			}

			pipeStream := NewPipe(chanID, session)
			session.AddActiveChannel(chanID, pipeStream)
			log.Printf("PipeStream created and added to active channel %d", chanID)

			var shell *ShellRequest

			shell = sr

			log.Printf("db search")

			if isTempUser(string(sr.User)) && d.DB.HasActiveEnv(session.PublicKey, "system-user") {
				env, err := d.DB.GetENVByname(string(sr.User), session.PublicKey)
				if err == nil && env == nil {
					log.Printf("cant get user")
					continue

				}

				if err == ErrFailedToQueryByReqNmae { //temp user but falid to query
					log.Printf("cant get user")
					continue
				}

				shell = &ShellRequest{
					RequestID: sr.RequestID,
					User:      []byte(env.Name),
					Shell:     []byte(env.Setting.Shell),
					Row:       sr.Row,
					Cols:      sr.Cols,
				}
			}

			env, err := d.DB.GetENVByUserReqestedName(string(sr.User), session.PublicKey)

			if err == ErrFailedToQueryByReqNmae { //temp user but falid to query
				log.Printf("cant get user")
				continue
			}
			if err != nil {
				log.Printf("cant get user")
				continue
			}

			if err == nil && env != nil { //is tempuser
				shell = &ShellRequest{
					RequestID: sr.RequestID,
					User:      []byte(env.Name),
					Shell:     []byte(env.Setting.Shell),
					Row:       sr.Row,
					Cols:      sr.Cols,
				}
			}

			if !SysUserExists(string(shell.User)) {
				log.Printf("not a sys user")
				continue
			}
			// 4. Spawn the interactive shell in the background
			go func(shellrq *ShellRequest, pipe *PipeStream) {

				defer session.DeleteActiveChannel(chanID)
				defer pipe.Close()
				log.Printf("interactive shell running in the background, ChanID %d", chanID)
				// Spawn the PTY

				err = RunInteractiveShell(ctx, shellrq, pipeStream, shellrq.Row, shellrq.Cols)
				if err != nil {
					log.Printf(" interactive shell failed: %v", err)
				}
			}(shell, pipeStream)

		case MsgClientForwardRequest:
			fr, err := ParseForwardRequest(pkt.Payload[1:])
			if err != nil {
				log.Println("Malformed Forward Request from client")
				go session.WritePacket(MsgServerForwardReqMalformed, nil)
				continue
			}

			log.Printf("Client requested forward to %s", fr.Address)
			d.State.mu.Lock()
			session.forwardMap[fr.Address] = fr.Address
			d.State.mu.Unlock()

		case MsgClientNewChannelOpened:
			// A public web user connected to the Daemon! We must dial our local target.
			cco, err := ParseClientChannelOpen(pkt.Payload[1:])
			if err != nil {
				continue
			}
			session.mu.Lock()
			localTarget, exists := session.forwardMap[cco.RemoteAddr]
			session.mu.Unlock()

			if !exists {
				log.Printf("Security alert: Client requested unknown port %s", cco.RemoteAddr)

				continue
			}

			// Dial the local server in the background (e.g. 127.0.0.1:8080)
			go func(channelID uint32, localTarget string) {
				d := tcp.DefaultDialOptions().NewDialer()
				c, err := d.Dial(localTarget)

				if err != nil {
					log.Printf("Failed to connect to remote target for forwarding: %v", err)
					session.WritePacket(MsgServerFailedToDial, nil)
					return
				}

				session.AddActiveChannel(channelID, c)
				defer session.DeleteActiveChannel(channelID)
				defer c.Close()

				// read the data from the target and send it back to the client!
				buf := bufferPool.Get().([]byte)
				defer bufferPool.Put(buf)

				for {
					n, err := c.Read(buf)
					if n > 0 {
						cd := &ChannelData{
							ChannelID: channelID, // Use the client's ID
							Data:      buf[:n],
						}
						session.WritePacket(MsgServerChanneledData, cd.Marshal())
					}
					if err != nil {
						break
					}
				}

				// Tell client the connection closed
				ccl := &ChannelClosed{ChannelID: channelID}
				session.WritePacket(MsgServerChannelClosed, ccl.Marshal())

			}(cco.ChannelID, localTarget)

		case MsgClientKeepAlive:
			// Handle keep-alive messages
		//case MsgChanIDRenegotiationRequest:
		case MsgClientChannelClosed:
			ccl, err := ParseChannelClosed(pkt.Payload[1:])
			if err != nil {
				continue
			}

			// Find the active connection and terminate it
			if channelObj, exists := session.GetActiveChannel(ccl.ChannelID); exists {
				switch c := channelObj.(type) {
				case net.Conn:
					c.Close()
				case *PipeStream:
					c.Close()
				}
				session.DeleteActiveChannel(ccl.ChannelID)
			}
		case MsgClientSessionClosed:
			session.Close()
			log.Printf("MsgClientSessionClosed")
		case MsgClientWindowResize:
			ws, err := ParseWindowResize(pkt.Payload[1:])
			if err != nil {
				log.Printf("Packet window resize couldn't be parsed!")
			}
			pipe, ok := session.GetActiveChannel(ws.ChannelID)

			if !ok {
				continue
			}

			if p, ok := pipe.(*PipeStream); ok {
				//chanID := session.IncrementChannelID()
				//session.AddActiveChannel(chanID, p)
				err := p.Resize(ws.Rows, ws.Cols)
				log.Printf("Packet window resize, Channel %d", ws.ChannelID)
				if err != nil {
					log.Printf("initial window resize failed %v ", err)
				}
			}

		default:
			log.Printf("Unknown or corrupted message type: %d", pkt.Payload[0])
			log.Printf("packet code %d cant be handle", pkt)
		}
	}
}

// returns enc AEAD cipher, dec, serverShareKey and error
func (d *Daemon) encryptSession(cHello *ClientHello, session *Session, ID []byte) (cipher.AEAD, cipher.AEAD, []byte, error) {
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

func (d *Daemon) shellAuth(session *Session, aPkt *WireforgePacket) (*AuthResponse, error) {
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
		if isTempUser(authReq.Username) && d.DB.HasActiveEnv(string(authReq.PublicKey), "system-user") {
			user = authReq.Username
			//env, err := d.DB.GetENVByname(user, string(authReq.PublicKey))
			//return nil, errors.New("temp user dosent exists. Skipping.")
			AuthorizedKeysPath = "/etc/shellforge/authorized_env_keys"
		}

		env, err := d.DB.GetENVByUserReqestedName(authReq.Username, string(authReq.PublicKey))
		if err == nil && env != nil { //a temp user but using user requeted name - alais
			if d.DB.HasActiveEnv(string(authReq.PublicKey), "system-user") {
				user = env.Name
				AuthorizedKeysPath = "/etc/shellforge/authorized_env_keys"
			} else {
				return nil, errors.New(" user has no active envs ")
			}
		}

		if err == ErrFailedToQueryByReqNmae { //temp user but falid to query
			return nil, err
		}

		if user == "root" {
			AuthorizedKeysPath = "/root/.shellforge/authorized_keys"
		}

		if user != "root" && !isTempUser(user) {
			AuthorizedKeysPath = fmt.Sprintf("home/%s/.shellforge/authorized_keys", authReq.Username)
		}

		if d.Conf.AuthorizedKeysPath != "" {
			AuthorizedKeysPath = d.Conf.AuthorizedKeysPath
		}

		log.Printf("authorized key dir for user %s is %s", user, AuthorizedKeysPath)
		ok, err := VerifyClientSignature(AuthorizedKeysPath, session.ID, authReq.Signature, authReq.PublicKey)
		if err != nil || !ok {
			log.Printf("PublicKey auth failed for user %s: %v", authReq.Username, err)
			if err != nil {
				return nil, err
			}
		}

		log.Printf("User [%s] successfully authenticated via Public key!", authReq.Username)

		authUsername = user
		ar.Username = authUsername
		ar.Type = AuthMethodPublicKey
		ar.Success = true

		session.authMethod = AuthMethodPublicKey
		session.PublicKey = string(authReq.PublicKey)
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
		ar.Type = AuthMethodPassword
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
		ar.Type = AuthMethodPKI
		ar.Success = true
		session.authMethod = AuthMethodPKI
		return ar, nil

	default:
		log.Printf("Unexpected packet type [%d] in Auth Phase. Dropping.", aPkt.Payload[0])
		return nil, ErrMalformedPacket

	}

}

func (d *Daemon) CreateEnvironment(ctx context.Context, p *PipeStream, sessionID string, eReq *EnvRequest) (*ENVs, error) {

	// Look up the public key in our database
	pubKeyHex := hex.EncodeToString(eReq.PublicKey)

	log.Printf("%s asking for a %s", pubKeyHex, string(eReq.AccessType))

	if !d.DB.IsEligibleKey(pubKeyHex) {
		return nil, ErrNonEligibleKey
	}

	// Cryptographically verify ownership of the private key
	if !ed25519.Verify(eReq.PublicKey, []byte(sessionID), eReq.Signature) {
		return nil, ErrInvalidSignature
	}

	record, err := d.DB.GetRecord(pubKeyHex)
	if err != nil {
		log.Printf("Database error retrieving key: %v", err)
		return nil, ErrDBKeyRetrival
	}
	if record == nil {
		log.Printf("Database error retrieving key, nil record: %v", err)
		return nil, ErrDBKeyRetrival
	}

	envConfig, err := d.ValidateENVRequest(eReq, record)

	if err != nil {
		log.Printf("NOT A VALID ENV REQ: %v", err)
		return nil, err
	}

	if (record.SysUsersCount+record.ContaintersCount+record.NamespacesCount) >= record.MaxSessions && record.MaxSessions != 0 {
		log.Printf("Key has reached maximum active sessions: %s", pubKeyHex)
		return nil, ErrMaxActiveSessions
	}

	requestedType := strings.ToLower(strings.TrimSpace(string(eReq.AccessType)))

	switch requestedType {
	case "system-user":
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

	case "container": //use libcontainer, https://github.com/opencontainers/runc/tree/main/libcontainer

		if record.MaxContainers > 0 && record.ContaintersCount >= record.MaxContainers {
			log.Printf("Key has reached maximum container creations: %s", pubKeyHex)

			return nil, errors.New("maximum container creations reached")
		}
		var imageName string
		var containerName string
		if envConfig.Setting.DockerfilePath != "" {

			imageName, err = BuildDockerfileOnDemand(ctx, p, envConfig.Setting.DockerfilePath, pubKeyHex)
			if err != nil {
				log.Printf("Failed to compile custom Dockerfile: %v", err)

				return nil, err
			}
		}

		log.Printf("image built: %s", imageName)

		containerName, err = CreateContainer(ctx, pubKeyHex, imageName, envConfig.Setting.MemoryLimit, envConfig.Setting.CPULimit, envConfig.Setting.GPULimit)
		if err != nil {
			return nil, err
		}
		log.Printf("container created: %s", containerName)

		// Calculate absolute expiration time
		var expiresAt time.Time
		duration, err := parseDurationWithDays(envConfig.LifeSpan)

		if err != nil {
			KillAndRemoveContainer(ctx, containerName)
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
			EnvType:           "container",
			Name:              containerName,
			ImageName:         imageName,
			UserRequestedName: string(eReq.UserRequestedName),
			Setting:           envConfig.Setting, // COPY THE SETTINGS DIRECTLY! [1]
			ExpiresAt:         expiresAt,
			CreatedAt:         time.Now(),
			SurviveReboot:     envConfig.Setting.SurviveReboot,
		}
		err = d.DB.AddENV(activeEnv) // Track in SQLite [1]
		if err != nil {
			KillAndRemoveContainer(ctx, containerName)
			return nil, err
		}
		return activeEnv, nil

	case "hostsharednamespace", "jailed", "namespace", "host-shared":
	default:
		return nil, errors.New("invaild env type ")
	}
	//d.DB.updateField("allowed_keys", string(tsReq.PublicKey), "created_users", record.CreatedUsers+1)

	return nil, nil
}

// ValidateTempShellRequest performs cryptographic, stateful, and resource-limit
// validations on the incoming Client request against the SQLite database [1, 2].
func (d *Daemon) ValidateENVRequest(eReq *EnvRequest, record *AccessKeyRecord) (*EnvConfig, error) {
	if eReq == nil {
		return nil, fmt.Errorf("nil temporary shell request")
	}

	// 3. Verify overall key expiration (survives reboots!) [2]
	if record.KeyExpiresAfter > 0 {
		if time.Since(record.CreatedAt) > record.KeyExpiresAfter {
			return nil, fmt.Errorf("access key has expired (validity period was %v)", record.KeyExpiresAfter)
		}
	}

	if len(eReq.UserRequestedName) > 32 {
		return nil, fmt.Errorf("requested name is longer than 32 char")
	}

	// 4. Normalize the requested AccessType (case-insensitive, trimmed)
	requestedType := strings.ToLower(strings.TrimSpace(string(eReq.AccessType)))

	// 5. Search the environment config slice for the matching allowed profile [1, 2]
	var matchedEnv *EnvConfig
	for _, env := range record.Environment {
		if strings.ToLower(strings.TrimSpace(env.Type)) == requestedType {
			matchedEnv = &env
			break
		}
	}

	if matchedEnv == nil {
		return nil, fmt.Errorf("environment type %q is not authorized for this key", string(eReq.AccessType))
	}

	// 6. Verify login limits for this specific environment type [2]
	// (Note: MaxLogins <= 0 or -1 is treated as unlimited)
	if matchedEnv.MaxLogins > 0 && record.LoginsUsed >= matchedEnv.MaxLogins {
		return nil, fmt.Errorf("login limit reached for environment %s (%d/%d used)",
			matchedEnv.Type, record.LoginsUsed, matchedEnv.MaxLogins)
	}

	// 7. Enforce dynamic resource limit thresholds [2]
	switch requestedType {
	case "system-user":
		if record.MaxUsers > 0 && record.SysUsersCount >= record.MaxUsers {
			return nil, fmt.Errorf("maximum active system users limit reached (%d/%d)",
				record.SysUsersCount, record.MaxUsers)
		}
	case "container":
		// Preserves your exact "ContaintersCount" struct spelling to prevent compilation errors
		if record.MaxContainers > 0 && record.ContaintersCount >= record.MaxContainers {
			return nil, fmt.Errorf("maximum active containers limit reached (%d/%d)",
				record.ContaintersCount, record.MaxContainers)
		}
	case "hostsharednamespace", "jailed":
		if record.MaxNamespaces > 0 && record.NamespacesCount >= record.MaxNamespaces {
			return nil, fmt.Errorf("maximum active jailed environments limit reached (%d/%d)",
				record.NamespacesCount, record.MaxNamespaces)
		}
	}

	return matchedEnv, nil
}

func Start(conf DaemonConfig) {
	log.Printf("[CLI] Starting shellforge Daemon")
	// Open the SQLite database
	dbdir := "/etc/shellforge/shf.db"
	if conf.DatabaseDir != "" {
		dbdir = conf.DatabaseDir
	}
	db, err := OpenDB(dbdir)

	if err != nil {
		log.Fatalf("Failed to open SQLite database: %v", err)
	}
	if conf.EnvironmentsJsonConfig != "" {
		_, err := db.LoadAccessKeysConf(conf.EnvironmentsJsonConfig)
		if err != nil {
			log.Fatalf("Failed to open parse EnvironmentsJsonConfig: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &DaemonState{
		sessions:       make(map[string]*Session),
		UserSessions:   make(map[string][]string),
		UserSessCount:  make(map[string]uint8),
		UserShellCount: make(map[string]uint8),
	}
	d := &Daemon{
		Conf:   &conf,
		ctx:    ctx,
		Cancel: cancel,
		DB:     db,
		State:  s,
	}

	// Calculate supported auth bitmask dynamically
	var supportedAuths uint8 = 0

	if d.Conf.PublicKeyAuth {

		supportedAuths |= AuthMethodPublicKey
	}

	if d.Conf.AuthorizedKeysPath == "" && d.Conf.PublicKeyAuth {
		d.Conf.AuthorizedKeysPath = "root/.shellforge/authorized_keys"
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
