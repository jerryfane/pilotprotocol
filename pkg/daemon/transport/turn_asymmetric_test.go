package transport

import (
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
)

// TestTURNRelayDial_WithoutLocalTURN covers the asymmetric path:
// a sender with only a UDPTransport (no pion client) hands a
// frame to DialTURNRelayViaUDP + Send; the hide-ip side (full
// TURNTransport, CreatePermission'd for the sender) delivers the
// frame on its sink.
//
// Matches the jf.9 deployment where one peer opts into TURN/hide-ip
// but the rest of the mesh doesn't need to configure TURN to reach
// it. Regression guard: the sender must not require a local pion
// client, and the hide-ip peer's CreatePermission must be
// load-bearing — the negative test below confirms the second half.
func TestTURNRelayDial_WithoutLocalTURN(t *testing.T) {
	serverAddr, cleanup := turnTestServer(t, map[string]string{"hide": "pw"})
	defer cleanup()

	// Hide-ip side: full TURNTransport.
	hideProv := newRotatingProvider(&turncreds.Credentials{
		ServerAddr: serverAddr, Transport: "udp", Username: "hide", Password: "pw",
	})
	defer hideProv.Close()
	hideSink := make(chan InboundFrame, 8)
	hideT := NewTURNTransport(hideProv, hideSink)
	if err := hideT.Listen("", hideSink); err != nil {
		t.Fatalf("hideT.Listen: %v", err)
	}
	defer hideT.Close()

	relay := hideT.LocalAddr()
	if relay == nil {
		t.Fatalf("no relay addr on hide-ip side")
	}

	// Sender side: plain UDPTransport, no pion.
	udpT := NewUDPTransport()
	udpSink := make(chan InboundFrame, 8)
	if err := udpT.Listen("127.0.0.1:0", udpSink); err != nil {
		t.Fatalf("udpT.Listen: %v", err)
	}
	defer udpT.Close()

	// Hide-ip side permits the sender's ephemeral UDP addr. The
	// sender binds on 127.0.0.1, so we permit 127.0.0.1:<port>.
	senderAddr := udpT.LocalAddr().(*net.UDPAddr).String()
	if err := hideT.CreatePermission(senderAddr); err != nil {
		t.Fatalf("hideT.CreatePermission: %v", err)
	}

	// Build the asymmetric conn on the sender side.
	ep, err := NewTURNEndpoint(relay.String())
	if err != nil {
		t.Fatalf("NewTURNEndpoint: %v", err)
	}
	conn, err := DialTURNRelayViaUDP(udpT, ep)
	if err != nil {
		t.Fatalf("DialTURNRelayViaUDP: %v", err)
	}
	if conn.Name() != "turn-relay" {
		t.Fatalf("conn.Name()=%q, want turn-relay", conn.Name())
	}
	if conn.RemoteEndpoint().String() != relay.String() {
		t.Fatalf("RemoteEndpoint=%q, want %q", conn.RemoteEndpoint().String(), relay.String())
	}

	// Send until hide-ip receives (the permission pipeline may take
	// a beat on the server side).
	payload := []byte("asymmetric hello")
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := conn.Send(payload); err != nil {
			t.Fatalf("conn.Send: %v", err)
		}
		select {
		case f := <-hideSink:
			if string(f.Frame) != string(payload) {
				t.Fatalf("payload mismatch: got %q, want %q", f.Frame, payload)
			}
			return
		case <-tick.C:
		case <-deadline:
			t.Fatalf("timed out")
		}
	}
}

// TestTURNRelayDial_PermissionMissing is the inverse: skip the
// CreatePermission step on hide-ip side. Sender's Send still
// succeeds locally (UDP is best-effort) but the TURN server drops
// the unpermissioned datagram — hide-ip's sink never sees it.
//
// Regression guard: documents that CreatePermission is load-bearing
// and that the asymmetric path relies on the hide-ip peer's
// auto-permission hook firing before the sender's first datagram.
func TestTURNRelayDial_PermissionMissing(t *testing.T) {
	serverAddr, cleanup := turnTestServer(t, map[string]string{"hide": "pw"})
	defer cleanup()

	hideProv := newRotatingProvider(&turncreds.Credentials{
		ServerAddr: serverAddr, Transport: "udp", Username: "hide", Password: "pw",
	})
	defer hideProv.Close()
	hideSink := make(chan InboundFrame, 8)
	hideT := NewTURNTransport(hideProv, hideSink)
	if err := hideT.Listen("", hideSink); err != nil {
		t.Fatalf("hideT.Listen: %v", err)
	}
	defer hideT.Close()

	relay := hideT.LocalAddr()
	if relay == nil {
		t.Fatalf("no relay addr on hide-ip side")
	}

	udpT := NewUDPTransport()
	udpSink := make(chan InboundFrame, 8)
	if err := udpT.Listen("127.0.0.1:0", udpSink); err != nil {
		t.Fatalf("udpT.Listen: %v", err)
	}
	defer udpT.Close()

	ep, err := NewTURNEndpoint(relay.String())
	if err != nil {
		t.Fatalf("NewTURNEndpoint: %v", err)
	}
	conn, err := DialTURNRelayViaUDP(udpT, ep)
	if err != nil {
		t.Fatalf("DialTURNRelayViaUDP: %v", err)
	}

	payload := []byte("not permitted")
	// Send several times; each Send succeeds locally but the server
	// drops them silently.
	for i := 0; i < 5; i++ {
		if err := conn.Send(payload); err != nil {
			t.Fatalf("conn.Send: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case f := <-hideSink:
		t.Fatalf("hide-ip sink should have received nothing, got %q", f.Frame)
	case <-time.After(500 * time.Millisecond):
		// expected
	}
}

// TestTurnRelayDialedConn_CloseIdempotent locks in the atomic CAS
// on closed: repeated Close must not error, and subsequent Sends
// must return a closed error.
func TestTurnRelayDialedConn_CloseIdempotent(t *testing.T) {
	udpT := NewUDPTransport()
	if err := udpT.Listen("127.0.0.1:0", make(chan InboundFrame, 1)); err != nil {
		t.Fatalf("udpT.Listen: %v", err)
	}
	defer udpT.Close()

	ep, err := NewTURNEndpoint("127.0.0.1:1234")
	if err != nil {
		t.Fatalf("NewTURNEndpoint: %v", err)
	}
	conn, err := DialTURNRelayViaUDP(udpT, ep)
	if err != nil {
		t.Fatalf("DialTURNRelayViaUDP: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := conn.Send([]byte("x")); err == nil {
		t.Fatalf("Send after Close should error")
	}
}

// TestDialTURNRelayViaUDP_NilInputs guards against nil UDPTransport
// / endpoint passed in accidentally.
func TestDialTURNRelayViaUDP_NilInputs(t *testing.T) {
	if _, err := DialTURNRelayViaUDP(nil, nil); err == nil {
		t.Fatalf("nil udp+ep should error")
	}
	udpT := NewUDPTransport()
	if _, err := DialTURNRelayViaUDP(udpT, nil); err == nil {
		t.Fatalf("nil ep should error")
	}
	ep, _ := NewTURNEndpoint("127.0.0.1:1234")
	if _, err := DialTURNRelayViaUDP(udpT, ep); err == nil {
		t.Fatalf("un-listened udpT should error")
	}
}
