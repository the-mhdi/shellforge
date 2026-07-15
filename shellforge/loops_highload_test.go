package shellforge

// =============================================================================
// High-load integration tests for the three main loops and the multiplexed
// channel data plane:
//
//     Daemon.shellLoop      daemon.go   shell / port-forward session read loop
//     Daemon.ContainerLoop  daemon.go   container session read loop
//     Client.eventLoop      client.go   client-side read loop
//
// The harness builds a REAL daemon-side Session and a REAL client-side Session
// joined by a real localhost TCP socket, encrypted with real ChaCha20-Poly1305
// AEADs -- exactly the state a finished handshake leaves both peers in -- and
// then runs the actual loops against each other. No PAM, podman, or key
// exchange is required, so these tests run anywhere `go test` runs.
//
// What gets exercised end to end:
//
//   - SendChannelData chunking: single channel.Write calls far larger than
//     MAX_CHANNEL_DATA_LEN (256 KiB and 1 MiB) must arrive intact. This is
//     the regression class from "Fix #1: chunked + streamed container logs"
//     (a single oversized frame used to kill ReadPacket and the session).
//
//   - Credit flow control: every stream is much larger than INITIAL_WINDOW
//     (2 MiB), so completing AT ALL requires a healthy WindowAdjust pipeline
//     (channel.Read -> returnRecvWindow -> peer loop -> grantSendWindow).
//     A missing/lost adjust deadlocks acquireSendWindowUpTo, and the watchdog
//     turns that into a bounded-time test failure instead of a silent hang.
//
//   - Channel demux under concurrency: several channels, both directions,
//     interleaved on one socket, verified byte-for-byte with SHA-256.
//
//   - Loop robustness: oversized / truncated / unknown-channel / unknown-type
//     frames must be answered and survived, never allowed to tear down the
//     session.
//
// Usage:
//
//     go test ./shellforge -run 'HighLoad|Survives' -v
//     go test ./shellforge -race -run 'HighLoad|Survives' -v   (use small load)
//     SHELLFORGE_LOAD_MB=512 go test ./shellforge -run HighLoad -v -timeout 30m
//     SHELLFORGE_SOAK=1 SHELLFORGE_SOAK_GB=2 \
//         go test ./shellforge -run Soak -v -timeout 60m
//     SHELLFORGE_TEST_VERBOSE=1 ...    keep loop log output (very noisy)
// =============================================================================

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestMain(m *testing.M) {
	// The loops log per event; at gigabyte loads that is millions of lines.
	if os.Getenv("SHELLFORGE_TEST_VERBOSE") == "" {
		log.SetOutput(io.Discard)
	}
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const testMiB int64 = 1024 * 1024

// loadMBTotal is the number of MiB streamed PER DIRECTION by the high-load
// tests. Override with SHELLFORGE_LOAD_MB.
func loadMBTotal() int64 {
	if v := os.Getenv("SHELLFORGE_LOAD_MB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return int64(n)
		}
	}
	return 64
}

// loadTimeout converts a byte budget into a stall watchdog: a generous floor
// so slow CI boxes pass, but a flow-control deadlock still fails in bounded
// time instead of hanging until `go test -timeout` kills the binary.
func loadTimeout(totalBytes int64) time.Duration {
	return 60*time.Second + time.Duration(totalBytes/testMiB)*250*time.Millisecond
}

// newTestSessionPair returns a daemon-side and a client-side Session joined
// by a real localhost TCP connection, encrypted with the same AEAD layout
// encryptSession produces: one ChaCha20-Poly1305 key per direction, sequence
// numbers starting at zero on both ends.
func newTestSessionPair(t testing.TB) (daemonSess, clientSess *Session) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- acceptResult{conn, err}
	}()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}
	ar := <-acceptCh
	ln.Close()
	if ar.err != nil {
		t.Fatalf("accept: %v", ar.err)
	}

	clientWriteKey := bytes.Repeat([]byte{0x11}, chacha20poly1305.KeySize)
	serverWriteKey := bytes.Repeat([]byte{0x22}, chacha20poly1305.KeySize)

	dEnc, err := chacha20poly1305.New(serverWriteKey)
	if err != nil {
		t.Fatal(err)
	}
	dDec, err := chacha20poly1305.New(clientWriteKey)
	if err != nil {
		t.Fatal(err)
	}
	cEnc, err := chacha20poly1305.New(clientWriteKey)
	if err != nil {
		t.Fatal(err)
	}
	cDec, err := chacha20poly1305.New(serverWriteKey)
	if err != nil {
		t.Fatal(err)
	}

	daemonSess = NewSession(ar.conn)
	daemonSess.ID = bytes.Repeat([]byte{0xD1}, 32)
	daemonSess.isDaemon = true
	daemonSess.encrypter = dEnc
	daemonSess.decrypter = dDec

	clientSess = NewSession(clientConn)
	clientSess.ID = bytes.Repeat([]byte{0xC1}, 32)
	clientSess.isDaemon = false
	clientSess.encrypter = cEnc
	clientSess.decrypter = cDec

	t.Cleanup(func() {
		clientSess.Close()
		daemonSess.Close()
	})
	return daemonSess, clientSess
}

// newTestDaemon builds the minimal Daemon the loops touch on the data plane:
// State for the container-connection counter, idleTimeout == 0 so the loops
// never call SetDeadline.
func newTestDaemon() *Daemon {
	return &Daemon{State: &DaemonState{}}
}

// newTestClient builds the minimal Client that eventLoop needs.
func newTestClient(t testing.TB, sess *Session) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Client{
		session:               sess,
		context:               ctx,
		cancel:                cancel,
		pendingShells:         make(map[uint32]chan *ShellRequestResponse),
		pendingContainerLists: make(map[uint32]chan *ContainersListResponse),
	}
}

// ---------------------------------------------------------------------------
// Load generation / verification
// ---------------------------------------------------------------------------

// xorshiftPRNG is a fast deterministic byte stream so gigabyte loads never
// need gigabytes of RAM: sender and verifier both hash on the fly.
type xorshiftPRNG struct{ state uint64 }

func (p *xorshiftPRNG) fill(b []byte) {
	s := p.state
	for i := range b {
		s ^= s << 13
		s ^= s >> 7
		s ^= s << 17
		b[i] = byte(s)
	}
	p.state = s
}

// hashSink is the receiving end of a load stream. It is fed by exactly one
// goroutine (the channel's AttachWriter drain), hashes and counts everything,
// and closes done once want bytes have arrived.
type hashSink struct {
	h    hash.Hash
	n    atomic.Int64
	want int64
	done chan struct{}
	once sync.Once
}

func newHashSink(want int64) *hashSink {
	return &hashSink{h: sha256.New(), want: want, done: make(chan struct{})}
}

func (s *hashSink) Write(b []byte) (int, error) {
	s.h.Write(b)
	if s.n.Add(int64(len(b))) >= s.want {
		s.once.Do(func() { close(s.done) })
	}
	return len(b), nil
}

func (s *hashSink) wait(t *testing.T, label string, timeout time.Duration) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(timeout):
		t.Fatalf("%s: stream stalled (flow-control deadlock?) after %s: got %d of %d bytes",
			label, timeout, s.n.Load(), s.want)
	}
}

// sum returns the sink's SHA-256. Only call after wait() succeeded.
func (s *hashSink) sum() [sha256.Size]byte {
	var out [sha256.Size]byte
	s.h.Sum(out[:0])
	return out
}

type blastResult struct {
	sum [sha256.Size]byte
	err error
}

// blast writes total pseudo-random bytes to ch using a rotating mix of chunk
// sizes -- including single Write calls far larger than MAX_CHANNEL_DATA_LEN
// and even larger than MAX_PACKET_LEN, so SendChannelData MUST chunk them --
// and returns the SHA-256 of everything sent.
func blast(ch *channel, total int64, seed uint64) blastResult {
	chunks := []int{
		1,                             // pathological tiny frame
		4096,                          // typical PTY burst
		int(MAX_CHANNEL_DATA_LEN),     // exactly one max-size frame
		int(MAX_CHANNEL_DATA_LEN) + 1, // forces a 1-byte tail frame
		256 * 1024,                    // > MAX_PACKET_LEN: the Fix #1 case
		1024 * 1024,                   // giant single Write, half the window
	}
	h := sha256.New()
	rng := &xorshiftPRNG{state: seed}
	buf := make([]byte, 1024*1024)
	var sent int64
	for i := 0; sent < total; i++ {
		n := chunks[i%len(chunks)]
		if int64(n) > total-sent {
			n = int(total - sent)
		}
		b := buf[:n]
		rng.fill(b)
		h.Write(b)
		if _, err := ch.Write(b); err != nil {
			return blastResult{err: fmt.Errorf("send failed after %d of %d bytes: %w", sent, total, err)}
		}
		sent += int64(n)
	}
	var res blastResult
	h.Sum(res.sum[:0])
	return res
}

// ---------------------------------------------------------------------------
// shellLoop <-> eventLoop: bidirectional high load over many channels
// ---------------------------------------------------------------------------

// runShellLoopBidirectionalLoad streams perDir bytes per direction on each of
// nChannels concurrent channels between the REAL daemon shellLoop and the
// REAL client eventLoop, and verifies every byte with SHA-256.
//
// client -> daemon exercises: channel.Write -> SendChannelData
//
//	-> shellLoop MsgClientChanneledData -> channel.Feed -> drain ->
//	returnRecvWindow -> eventLoop MsgWindowAdjust -> grantSendWindow.
//
// daemon -> client exercises the mirror path through eventLoop's
//
//	MsgServerChanneledData and shellLoop's MsgWindowAdjust.
func runShellLoopBidirectionalLoad(t *testing.T, perDir int64, nChannels int) {
	t.Helper()

	dSess, cSess := newTestSessionPair(t)
	d := newTestDaemon()
	c := newTestClient(t, cSess)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.shellLoop(ctx, dSess)
	go c.eventLoop()

	total := perDir * int64(nChannels) * 2
	timeout := loadTimeout(total)

	c2dSinks := make([]*hashSink, nChannels) // received by the daemon
	d2cSinks := make([]*hashSink, nChannels) // received by the client
	c2dRes := make([]blastResult, nChannels)
	d2cRes := make([]blastResult, nChannels)

	var wg sync.WaitGroup
	for i := 0; i < nChannels; i++ {
		i := i

		// The daemon is authoritative for channel IDs (as after a shell
		// request); the client mirrors the same ID, exactly like the
		// MsgServerShellReqResponse flow.
		id, dCh := dSess.NewChannel(false)
		cCh, ok := cSess.NewChannelWithID(id, false)
		if !ok {
			t.Fatalf("client could not mirror channel %d", id)
		}

		c2dSinks[i] = newHashSink(perDir)
		d2cSinks[i] = newHashSink(perDir)
		if err := dCh.AttachWriter(c2dSinks[i]); err != nil {
			t.Fatalf("daemon AttachWriter: %v", err)
		}
		if err := cCh.AttachWriter(d2cSinks[i]); err != nil {
			t.Fatalf("client AttachWriter: %v", err)
		}

		wg.Add(2)
		go func() { // client -> daemon producer
			defer wg.Done()
			c2dRes[i] = blast(cCh, perDir, 0x9E3779B97F4A7C15+uint64(i))
		}()
		go func() { // daemon -> client producer
			defer wg.Done()
			d2cRes[i] = blast(dCh, perDir, 0xD1B54A32D192ED03+uint64(i))
		}()
	}

	start := time.Now()

	producersDone := make(chan struct{})
	go func() { wg.Wait(); close(producersDone) }()
	select {
	case <-producersDone:
	case <-time.After(timeout):
		status := ""
		for i := 0; i < nChannels; i++ {
			status += fmt.Sprintf(" ch%d[c2d=%d/%d d2c=%d/%d]", i,
				c2dSinks[i].n.Load(), perDir, d2cSinks[i].n.Load(), perDir)
		}
		t.Fatalf("producers stalled (flow-control deadlock?) after %s:%s", timeout, status)
	}

	for i := 0; i < nChannels; i++ {
		c2dSinks[i].wait(t, fmt.Sprintf("channel %d client->daemon", i), timeout)
		d2cSinks[i].wait(t, fmt.Sprintf("channel %d daemon->client", i), timeout)
	}
	elapsed := time.Since(start)

	for i := 0; i < nChannels; i++ {
		if c2dRes[i].err != nil {
			t.Fatalf("channel %d client->daemon producer: %v", i, c2dRes[i].err)
		}
		if d2cRes[i].err != nil {
			t.Fatalf("channel %d daemon->client producer: %v", i, d2cRes[i].err)
		}
		if got := c2dSinks[i].n.Load(); got != perDir {
			t.Fatalf("channel %d client->daemon byte count: got %d, want %d", i, got, perDir)
		}
		if got := d2cSinks[i].n.Load(); got != perDir {
			t.Fatalf("channel %d daemon->client byte count: got %d, want %d", i, got, perDir)
		}
		if got := c2dSinks[i].sum(); got != c2dRes[i].sum {
			t.Fatalf("channel %d client->daemon DATA CORRUPTED: sha256 %x != %x", i, got, c2dRes[i].sum)
		}
		if got := d2cSinks[i].sum(); got != d2cRes[i].sum {
			t.Fatalf("channel %d daemon->client DATA CORRUPTED: sha256 %x != %x", i, got, d2cRes[i].sum)
		}
	}

	t.Logf("moved %d MiB total (%d channels x %d MiB x 2 directions) in %s (%.1f MiB/s aggregate)",
		total/testMiB, nChannels, perDir/testMiB, elapsed.Round(time.Millisecond),
		float64(total)/testMiBFloat()/elapsed.Seconds())
}

func testMiBFloat() float64 { return float64(testMiB) }

// TestShellLoopEventLoopBidirectionalHighLoad is the main megabyte-scale test:
// SHELLFORGE_LOAD_MB (default 64) MiB per direction, split over 4 channels.
func TestShellLoopEventLoopBidirectionalHighLoad(t *testing.T) {
	nChannels := 4
	perDir := loadMBTotal() * testMiB / int64(nChannels)
	if perDir < 4*testMiB {
		perDir = 4 * testMiB // always exceed INITIAL_WINDOW (2 MiB) per channel
	}
	runShellLoopBidirectionalLoad(t, perDir, nChannels)
}

// TestShellLoopGigabyteSoak streams gigabytes through the same harness.
// Skipped unless explicitly enabled:
//
//	SHELLFORGE_SOAK=1 SHELLFORGE_SOAK_GB=2 go test ./shellforge -run Soak -v -timeout 60m
func TestShellLoopGigabyteSoak(t *testing.T) {
	if os.Getenv("SHELLFORGE_SOAK") == "" {
		t.Skip("set SHELLFORGE_SOAK=1 (and optionally SHELLFORGE_SOAK_GB=N, -timeout 60m) to stream gigabytes")
	}
	gb := int64(1)
	if v := os.Getenv("SHELLFORGE_SOAK_GB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			gb = int64(n)
		}
	}
	nChannels := 2
	runShellLoopBidirectionalLoad(t, gb*1024*testMiB/int64(nChannels), nChannels)
}

// ---------------------------------------------------------------------------
// ContainerLoop <-> eventLoop: the container-log streaming path
// ---------------------------------------------------------------------------

// TestContainerLoopLogChannelHighLoad reproduces the exact transport used by
// GetContainerLogs (the Fix #1 scenario), end to end, at high volume:
//
//  1. daemon opens a log channel and announces it with MsgServerOpenLogChannel
//  2. client eventLoop registers the channel, attaches os.Stdout, and replies
//     MsgClientChannelOpenConfirm
//  3. daemon ContainerLoop receives the confirm and unblocks the waiter
//  4. daemon streams a huge "podman logs" byte stream through channel.Write
//     (including single Writes >> MAX_PACKET_LEN, which MUST be chunked)
//  5. client drains it through the ring; WindowAdjust credits flow back via
//     ContainerLoop, keeping the daemon's send window alive past 2 MiB
//
// Because eventLoop hardwires log channels to os.Stdout, stdout is swapped
// for a pipe feeding a hash sink for the duration of the test. Do not run
// this package's tests with t.Parallel().
func TestContainerLoopLogChannelHighLoad(t *testing.T) {
	dSess, cSess := newTestSessionPair(t)
	d := newTestDaemon()
	c := newTestClient(t, cSess)

	total := loadMBTotal() * testMiB
	if total < 8*testMiB {
		total = 8 * testMiB // must exceed INITIAL_WINDOW several times over
	}
	timeout := loadTimeout(total * 2)

	// Swap os.Stdout for a pipe so the "container logs" land in a hash sink
	// instead of the terminal. Restored on cleanup.
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = wPipe
	t.Cleanup(func() {
		os.Stdout = oldStdout
		wPipe.Close()
		rPipe.Close()
	})

	logSink := newHashSink(total)
	go func() { _, _ = io.Copy(logSink, rPipe) }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.ContainerLoop(ctx, dSess)
	go c.eventLoop()

	// --- daemon -> client: the log stream ---------------------------------
	_, logCh := dSess.NewChannel(false)
	if !logCh.WaitForComfirmationWithMsgType(MsgServerOpenLogChannel) {
		t.Fatal("client never confirmed the log channel open (ContainerLoop confirm path broken)")
	}

	start := time.Now()
	resCh := make(chan blastResult, 1)
	go func() { resCh <- blast(logCh, total, 0xA5A5A5A5DEADBEEF) }()

	var logRes blastResult
	select {
	case logRes = <-resCh:
	case <-time.After(timeout):
		t.Fatalf("log producer stalled (flow-control deadlock?): client received %d of %d bytes",
			logSink.n.Load(), total)
	}
	if logRes.err != nil {
		t.Fatalf("log stream send failed: %v", logRes.err)
	}
	logSink.wait(t, "container log stream", timeout)
	elapsed := time.Since(start)

	if got := logSink.n.Load(); got != total {
		t.Fatalf("log stream byte count: got %d, want %d (stray writes to os.Stdout?)", got, total)
	}
	if got := logSink.sum(); got != logRes.sum {
		t.Fatalf("log stream DATA CORRUPTED: sha256 %x != %x", got, logRes.sum)
	}
	t.Logf("log stream: %d MiB daemon->client in %s (%.1f MiB/s)",
		total/testMiB, elapsed.Round(time.Millisecond),
		float64(total)/testMiBFloat()/elapsed.Seconds())

	// --- client -> daemon: exec/stdin-style upstream through ContainerLoop -
	upTotal := total / 4
	if upTotal < 8*testMiB {
		upTotal = 8 * testMiB
	}
	id2, dCh := dSess.NewChannel(false)
	cCh, ok := cSess.NewChannelWithID(id2, false)
	if !ok {
		t.Fatalf("client could not mirror channel %d", id2)
	}
	upSink := newHashSink(upTotal)
	if err := dCh.AttachWriter(upSink); err != nil {
		t.Fatalf("daemon AttachWriter: %v", err)
	}

	start = time.Now()
	go func() { resCh <- blast(cCh, upTotal, 0xBEEF5EED12345678) }()
	var upRes blastResult
	select {
	case upRes = <-resCh:
	case <-time.After(timeout):
		t.Fatalf("upstream producer stalled: daemon received %d of %d bytes",
			upSink.n.Load(), upTotal)
	}
	if upRes.err != nil {
		t.Fatalf("upstream send failed: %v", upRes.err)
	}
	upSink.wait(t, "client->daemon upstream", timeout)

	if got := upSink.sum(); got != upRes.sum {
		t.Fatalf("upstream DATA CORRUPTED: sha256 %x != %x", got, upRes.sum)
	}
	t.Logf("upstream: %d MiB client->daemon in %s (%.1f MiB/s)",
		upTotal/testMiB, time.Since(start).Round(time.Millisecond),
		float64(upTotal)/testMiBFloat()/time.Since(start).Seconds())
}

// ---------------------------------------------------------------------------
// Robustness: malformed frames must not kill the loops
// ---------------------------------------------------------------------------

// TestShellLoopSurvivesMalformedFrames sends protocol garbage that used to be
// fatal -- most importantly a channel-data frame whose header declares more
// than MAX_CHANNEL_DATA_LEN (the pre-Fix-#1 oversized-frame failure) -- and
// then proves the session is still alive by pushing a real payload through.
func TestShellLoopSurvivesMalformedFrames(t *testing.T) {
	dSess, cSess := newTestSessionPair(t)
	d := newTestDaemon()
	c := newTestClient(t, cSess)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.shellLoop(ctx, dSess)
	go c.eventLoop()

	id, dCh := dSess.NewChannel(false)
	cCh, ok := cSess.NewChannelWithID(id, false)
	if !ok {
		t.Fatalf("client could not mirror channel %d", id)
	}

	probe := []byte("still-alive-after-protocol-garbage")
	sink := newHashSink(int64(len(probe)))
	if err := dCh.AttachWriter(sink); err != nil {
		t.Fatal(err)
	}

	// 1. Oversized frame: header claims MAX_CHANNEL_DATA_LEN+1 bytes.
	//    ParseChannelData must reject it (ErrChannelDataTooLarge) and the loop
	//    must answer MsgServerChanDataMalformed instead of tearing down.
	over := make([]byte, 16)
	binary.BigEndian.PutUint32(over[0:4], id)
	binary.BigEndian.PutUint32(over[4:8], MAX_CHANNEL_DATA_LEN+1)
	if err := cSess.WritePacketRaw(MsgClientChanneledData, over); err != nil {
		t.Fatalf("send oversized frame: %v", err)
	}

	// 2. Truncated frame: declares 64 payload bytes, carries 2.
	trunc := make([]byte, 10)
	binary.BigEndian.PutUint32(trunc[0:4], id)
	binary.BigEndian.PutUint32(trunc[4:8], 64)
	if err := cSess.WritePacketRaw(MsgClientChanneledData, trunc); err != nil {
		t.Fatalf("send truncated frame: %v", err)
	}

	// 3. Valid frame for a channel that does not exist.
	ghost := (&Channel{ChannelID: 0x0EADBEEF &^ ClientChannelIDBit, Data: []byte("ghost")}).Marshal()
	if err := cSess.WritePacketRaw(MsgClientChanneledData, ghost); err != nil {
		t.Fatalf("send ghost-channel frame: %v", err)
	}

	// 4. Unknown message type.
	if err := cSess.WritePacketRaw(0x7E, []byte{1, 2, 3}); err != nil {
		t.Fatalf("send unknown message type: %v", err)
	}

	// The session must still be alive: a genuine payload must go through.
	if _, err := cCh.Write(probe); err != nil {
		t.Fatalf("session died after malformed frames: %v", err)
	}
	sink.wait(t, "post-garbage probe", 15*time.Second)

	want := sha256.Sum256(probe)
	if got := sink.sum(); got != want {
		t.Fatalf("probe corrupted after malformed frames: sha256 %x != %x", got, want)
	}
}
