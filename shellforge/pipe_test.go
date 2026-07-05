package shellforge

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// feedAll pushes data in fixed-size chunks, the way the event loop would.
func feedAll(t *testing.T, p *PipeStream, data []byte, chunk int) {
	t.Helper()
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		if _, err := p.Feed(data[off:end]); err != nil {
			t.Errorf("Feed failed at offset %d: %v", off, err)
			return
		}
	}
}

// TestPipeBulkTransferIntegrity streams 8 MB (32x the ring capacity)
// through the pipe with an odd chunk size (forces wraparounds at every
// possible offset) and verifies every byte arrives intact and in order.
func TestPipeBulkTransferIntegrity(t *testing.T) {
	p := NewPipe(1, nil)

	payload := make([]byte, 8*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	go func() {
		feedAll(t, p, payload, 17*1024+3) // odd size on purpose
		p.Close()
	}()

	var got bytes.Buffer
	if _, err := io.Copy(&got, p); err != nil {
		t.Fatalf("read side failed: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("data corrupted in transit: got %d bytes, want %d", got.Len(), len(payload))
	}
}

// TestPipeBackpressure verifies Feed fills the ring without blocking,
// blocks once the ring is full, and resumes as soon as the reader frees
// space - with zero drops.
func TestPipeBackpressure(t *testing.T) {
	p := NewPipe(1, nil)

	// Filling the ring exactly to capacity must not block.
	full := make([]byte, PIPE_RING_CAPACITY)
	done := make(chan struct{})
	go func() {
		p.Feed(full)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Feed blocked while the ring still had space")
	}

	// One extra byte must block...
	extra := make(chan struct{})
	go func() {
		p.Feed([]byte{0xAB})
		close(extra)
	}()
	select {
	case <-extra:
		t.Fatal("Feed should have blocked on a full ring")
	case <-time.After(100 * time.Millisecond):
	}

	// ...until the reader drains a single byte.
	buf := make([]byte, 1)
	if _, err := p.Read(buf); err != nil {
		t.Fatal(err)
	}
	select {
	case <-extra:
	case <-time.After(2 * time.Second):
		t.Fatal("Feed did not resume after space freed up")
	}
}

// TestPipeCloseDrainsThenEOF: Close must not eat buffered data - readers
// drain it first and only then get io.EOF. Feed after Close must fail
// immediately instead of blocking.
func TestPipeCloseDrainsThenEOF(t *testing.T) {
	p := NewPipe(1, nil)

	if _, err := p.Feed([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	p.Close()

	got, err := io.ReadAll(p)
	if err != nil {
		t.Fatalf("expected clean EOF, got %v", err)
	}
	if string(got) != "tail" {
		t.Fatalf("lost buffered data on close: %q", got)
	}

	if _, err := p.Feed([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe after close, got %v", err)
	}
}
