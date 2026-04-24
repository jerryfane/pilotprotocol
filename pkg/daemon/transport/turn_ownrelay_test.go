package transport

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
)

// TestSendViaOwnRelay_ReachesArbitraryPeer locks in the jf.11a.2
// semantic: a TURN-enabled client can reach any peer UDP address by
// writing through its own relay socket, without the peer having its
// own TURN allocation. The peer observes source = the TURN-assigned
// relay address, never the client's real source IP.
//
// This is the canonical WebRTC iceTransportPolicy="relay" behavior
// (RFC 8828 Mode 3): outbound traffic always traverses our TURN,
// peers can have any kind of candidate (host / srflx / relay), and
// the peer sees our relay as the packet source.
func TestSendViaOwnRelay_ReachesArbitraryPeer(t *testing.T) {
	serverAddr, cleanupSrv := turnTestServer(t, map[string]string{"u": "p"})
	defer cleanupSrv()

	// The "peer" is a plain UDP listener with no TURN. It reads an
	// inbound packet and records the source address. Under jf.11a.2,
	// the TURN-enabled client should be able to reach this peer via
	// its own TURN allocation, and the peer's observed source should
	// be the client's TURN relay address, NOT the client's local socket.
	peerConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	defer peerConn.Close()

	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	recvBuf := make([]byte, 1024)
	recvFrom := make(chan *net.UDPAddr, 1)
	go func() {
		_ = peerConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, from, err := peerConn.ReadFrom(recvBuf)
		if err != nil {
			return
		}
		if u, ok := from.(*net.UDPAddr); ok {
			recvFrom <- u
		}
	}()

	// Set up TURN-enabled client.
	sink := make(chan InboundFrame, 8)
	provider := &rotatingProvider{
		creds: &turncreds.Credentials{
			ServerAddr: serverAddr,
			Transport:  "udp",
			Username:   "u",
			Password:   "p",
		},
		subCh: make(chan *turncreds.Credentials, 1),
	}
	client := NewTURNTransport(provider, sink)
	if err := client.Listen("", sink); err != nil {
		t.Fatalf("client.Listen: %v", err)
	}
	defer client.Close()

	// Wait for the pion client's allocation to be ready.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.LocalAddr() != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if client.LocalAddr() == nil {
		t.Fatalf("client allocation never ready")
	}
	clientRelayAddr := client.LocalAddr().(*net.UDPAddr)

	// Send via own relay to the plain-UDP peer.
	if err := client.SendViaOwnRelay(peerAddr, []byte("hello-from-relay")); err != nil {
		t.Fatalf("SendViaOwnRelay: %v", err)
	}

	// Peer should receive the frame with source = relay addr.
	select {
	case observed := <-recvFrom:
		// The observed port is the allocated relay's server-assigned port,
		// which should equal clientRelayAddr.Port. The observed IP is
		// the server's external IP (127.0.0.1 in this test).
		if observed.Port != clientRelayAddr.Port {
			t.Fatalf("peer observed source port %d, want relay port %d "+
				"(packet did NOT traverse own TURN)",
				observed.Port, clientRelayAddr.Port)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("peer never received packet from relay")
	}
}

// TestSendViaOwnRelay_NilPeerAddr validates the nil-peer error path.
// Belt-and-suspenders: the writeFrame caller should never pass nil,
// but SendViaOwnRelay is a public API so an errant caller should
// get a clear error rather than a panic or silent success.
func TestSendViaOwnRelay_NilPeerAddr(t *testing.T) {
	serverAddr, cleanupSrv := turnTestServer(t, map[string]string{"u": "p"})
	defer cleanupSrv()
	sink := make(chan InboundFrame, 8)
	provider := &rotatingProvider{
		creds: &turncreds.Credentials{
			ServerAddr: serverAddr, Transport: "udp",
			Username: "u", Password: "p",
		},
		subCh: make(chan *turncreds.Credentials, 1),
	}
	client := NewTURNTransport(provider, sink)
	if err := client.Listen("", sink); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer client.Close()

	if err := client.SendViaOwnRelay(nil, []byte("x")); err == nil {
		t.Fatalf("SendViaOwnRelay(nil) succeeded; want error")
	}
}

// TestSendViaOwnRelay_NotListening validates that calling SendViaOwnRelay
// before Listen() returns a clear "not listening" error, never a nil-
// deref panic.
func TestSendViaOwnRelay_NotListening(t *testing.T) {
	sink := make(chan InboundFrame, 8)
	provider := &rotatingProvider{
		creds: &turncreds.Credentials{
			ServerAddr: "127.0.0.1:1", Transport: "udp",
			Username: "u", Password: "p",
		},
		subCh: make(chan *turncreds.Credentials, 1),
	}
	client := NewTURNTransport(provider, sink)
	// Note: NO Listen() call. Close is still safe.
	defer client.Close()

	peer, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:1234")
	if err := client.SendViaOwnRelay(peer, []byte("x")); err == nil {
		t.Fatalf("SendViaOwnRelay before Listen succeeded; want error")
	}
}

// --- writeFrame integration tests (tunnel.go outbound-turn-only branch)
// live in outbound_turn_only_test.go / tunnel_path_test.go; this file
// keeps unit tests for the SendViaOwnRelay primitive only. Integration
// tests are in the daemon package because writeFrame is a daemon method.

// Keep a reference to prevent unused-import lint from nibbling atomic
// if tests change.
var _ = atomic.LoadUint64
