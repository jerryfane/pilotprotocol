package transport

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestTCPTransport_RoundTripSingleFrame verifies the happy path:
// server Listens, client Dials, client Sends, server receives on the
// sink channel with the expected payload and remote endpoint.
func TestTCPTransport_RoundTripSingleFrame(t *testing.T) {
	srv := NewTCPTransport()
	sink := make(chan InboundFrame, 4)
	if err := srv.Listen("127.0.0.1:0", sink); err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer srv.Close()

	addr := srv.LocalAddr()
	if addr == nil {
		t.Fatal("server LocalAddr returned nil")
	}

	cli := NewTCPTransport()
	defer cli.Close()
	ep, err := cli.ParseEndpoint(addr.String())
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dc, err := cli.Dial(ctx, ep)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	want := []byte("hello pilot over tcp")
	if err := dc.Send(want); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case got := <-sink:
		if !bytes.Equal(got.Frame, want) {
			t.Errorf("frame mismatch: got %q, want %q", got.Frame, want)
		}
		if got.From == nil || got.From.Network() != "tcp" {
			t.Errorf("expected tcp endpoint, got %v", got.From)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for frame on sink")
	}
}

// TestTCPTransport_MultiFrameStream confirms the length-prefix
// framing correctly splits adjacent frames written back-to-back onto
// the same connection.
func TestTCPTransport_MultiFrameStream(t *testing.T) {
	srv := NewTCPTransport()
	sink := make(chan InboundFrame, 16)
	if err := srv.Listen("127.0.0.1:0", sink); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	cli := NewTCPTransport()
	defer cli.Close()
	ep, _ := cli.ParseEndpoint(srv.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dc, err := cli.Dial(ctx, ep)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	frames := [][]byte{
		[]byte("a"),
		[]byte("bb"),
		[]byte("ccc"),
		make([]byte, 4096), // larger frame exercising multi-read paths
	}
	for i := range frames[3] {
		frames[3][i] = byte(i & 0xff)
	}

	for _, f := range frames {
		if err := dc.Send(f); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	for i, want := range frames {
		select {
		case got := <-sink:
			if !bytes.Equal(got.Frame, want) {
				t.Errorf("frame %d mismatch: got %d bytes, want %d", i, len(got.Frame), len(want))
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("frame %d: timeout", i)
		}
	}
}

// TestTCPTransport_DialReusesConn verifies that two Dials to the same
// endpoint return the same pooled connection.
func TestTCPTransport_DialReusesConn(t *testing.T) {
	srv := NewTCPTransport()
	sink := make(chan InboundFrame, 4)
	if err := srv.Listen("127.0.0.1:0", sink); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	cli := NewTCPTransport()
	defer cli.Close()
	ep, _ := cli.ParseEndpoint(srv.LocalAddr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dc1, err := cli.Dial(ctx, ep)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	dc2, err := cli.Dial(ctx, ep)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	if dc1 != dc2 {
		t.Errorf("expected the same pooled conn on re-dial, got distinct")
	}
}

// TestTCPTransport_DialTimeout verifies Dial honours ctx timeout on a
// non-routable address.
func TestTCPTransport_DialTimeout(t *testing.T) {
	cli := NewTCPTransport()
	cli.SetDialTimeout(100 * time.Millisecond)
	defer cli.Close()

	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), guaranteed unroutable.
	ep, err := cli.ParseEndpoint("192.0.2.1:12345")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = cli.Dial(ctx, ep)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("dial took %v, expected timeout well under a second", elapsed)
	}
}

// TestTCPTransport_PeerDisconnectMidStream confirms that when the
// peer closes mid-stream, the reader exits cleanly and the conn is
// dropped from the pool so a subsequent Dial re-opens.
func TestTCPTransport_PeerDisconnectMidStream(t *testing.T) {
	srv := NewTCPTransport()
	sink := make(chan InboundFrame, 4)
	if err := srv.Listen("127.0.0.1:0", sink); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	cli := NewTCPTransport()
	defer cli.Close()
	ep, _ := cli.ParseEndpoint(srv.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dc1, err := cli.Dial(ctx, ep)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	if err := dc1.Send([]byte("first")); err != nil {
		t.Fatalf("send: %v", err)
	}
	// Drain the frame
	<-sink

	// Close the server side to simulate peer disconnect.
	srv.Close()

	// Allow the dropped-from-pool goroutine time to observe the close.
	time.Sleep(50 * time.Millisecond)

	// Restart a fresh server on a new port; confirm a new Dial goes
	// through a freshly opened conn (not the torn-down one).
	srv2 := NewTCPTransport()
	sink2 := make(chan InboundFrame, 4)
	if err := srv2.Listen("127.0.0.1:0", sink2); err != nil {
		t.Fatalf("listen 2: %v", err)
	}
	defer srv2.Close()
	ep2, _ := cli.ParseEndpoint(srv2.LocalAddr().String())
	dc2, err := cli.Dial(ctx, ep2)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	if dc2 == nil {
		t.Fatal("expected a new DialedConn, got nil")
	}
	if err := dc2.Send([]byte("second")); err != nil {
		t.Fatalf("send 2: %v", err)
	}
	select {
	case got := <-sink2:
		if string(got.Frame) != "second" {
			t.Errorf("got %q, want %q", got.Frame, "second")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for second frame")
	}
}

// TestTCPTransport_ParallelSends verifies Send is safe to call
// concurrently — frames arrive intact (no interleaved length prefix /
// payload bytes).
func TestTCPTransport_ParallelSends(t *testing.T) {
	srv := NewTCPTransport()
	sink := make(chan InboundFrame, 64)
	if err := srv.Listen("127.0.0.1:0", sink); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	cli := NewTCPTransport()
	defer cli.Close()
	ep, _ := cli.ParseEndpoint(srv.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dc, err := cli.Dial(ctx, ep)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	const senders = 8
	const perSender = 4
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perSender; j++ {
				payload := []byte{byte(id), byte(j), 0xAA, 0xBB}
				if err := dc.Send(payload); err != nil {
					t.Errorf("send (%d,%d): %v", id, j, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	got := map[byte]int{}
	deadline := time.After(3 * time.Second)
	total := senders * perSender
	for i := 0; i < total; i++ {
		select {
		case f := <-sink:
			if len(f.Frame) != 4 || f.Frame[2] != 0xAA || f.Frame[3] != 0xBB {
				t.Errorf("malformed frame: %x", f.Frame)
				continue
			}
			got[f.Frame[0]]++
		case <-deadline:
			t.Fatalf("timeout: received %d of %d frames", i, total)
		}
	}
	for id := byte(0); id < senders; id++ {
		if got[id] != perSender {
			t.Errorf("sender %d: got %d frames, want %d", id, got[id], perSender)
		}
	}
}

// TestTCPEndpoint_RoundTrip verifies ParseEndpoint and String are
// inverses for IPv4 and IPv6 addresses.
func TestTCPEndpoint_RoundTrip(t *testing.T) {
	t.Parallel()
	trans := NewTCPTransport()
	defer trans.Close()

	cases := []string{
		"127.0.0.1:1234",
		"192.168.10.50:443",
		"[::1]:8080",
	}
	for _, want := range cases {
		ep, err := trans.ParseEndpoint(want)
		if err != nil {
			t.Errorf("parse %q: %v", want, err)
			continue
		}
		if got := ep.String(); got != want {
			t.Errorf("round-trip mismatch: parse(%q).String() = %q", want, got)
		}
		if ep.Network() != "tcp" {
			t.Errorf("network = %q, want tcp", ep.Network())
		}
	}
}

// TestTCPTransport_WrongEndpointType confirms Dial rejects a non-TCP
// endpoint.
func TestTCPTransport_WrongEndpointType(t *testing.T) {
	trans := NewTCPTransport()
	defer trans.Close()

	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
	udpEP := NewUDPEndpoint(udpAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := trans.Dial(ctx, udpEP)
	if err == nil {
		t.Fatal("expected error dialling UDP endpoint via TCP transport")
	}
}

// TestTCPTransport_CloseIdempotent verifies multiple Close calls don't
// panic or return non-nil errors.
func TestTCPTransport_CloseIdempotent(t *testing.T) {
	trans := NewTCPTransport()
	sink := make(chan InboundFrame, 1)
	if err := trans.Listen("127.0.0.1:0", sink); err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := trans.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := trans.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
