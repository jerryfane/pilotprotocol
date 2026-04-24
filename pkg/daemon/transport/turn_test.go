package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
)

// turnTestServer runs a pion/turn v5 server on an ephemeral UDP port on
// 127.0.0.1. Returns the bound "host:port" and a cleanup func.
//
// The AuthHandler accepts any (username, password) pair present in the
// provided credMap. Tests drive credential rotation by registering two
// pairs up-front and then asking the TURNTransport to rotate between
// them.
func turnTestServer(t *testing.T, credMap map[string]string) (string, func()) {
	t.Helper()

	const realm = "pion.test"
	authHandler := func(ra *turn.RequestAttributes) (string, []byte, bool) {
		pw, ok := credMap[ra.Username]
		if !ok {
			return "", nil, false
		}
		return ra.Username, turn.GenerateAuthKey(ra.Username, realm, pw), true
	}

	udpListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp4: %v", err)
	}

	server, err := turn.NewServer(turn.ServerConfig{
		Realm:         realm,
		AuthHandler:   authHandler,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "0.0.0.0",
				},
			},
		},
	})
	if err != nil {
		_ = udpListener.Close()
		t.Fatalf("turn.NewServer: %v", err)
	}

	addr := udpListener.LocalAddr().(*net.UDPAddr).String()
	cleanup := func() {
		_ = server.Close()
	}
	return addr, cleanup
}

// rotatingProvider is a minimal turncreds.Provider whose current
// credentials can be swapped by the test. Subscribe returns a buffered
// channel that receives new creds when Rotate is called.
type rotatingProvider struct {
	mu    sync.Mutex
	creds *turncreds.Credentials
	subCh chan *turncreds.Credentials
}

func newRotatingProvider(c *turncreds.Credentials) *rotatingProvider {
	return &rotatingProvider{
		creds: c,
		subCh: make(chan *turncreds.Credentials, 1),
	}
}

func (p *rotatingProvider) Get(ctx context.Context) (*turncreds.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.creds, nil
}

func (p *rotatingProvider) Subscribe() <-chan *turncreds.Credentials {
	return p.subCh
}

func (p *rotatingProvider) Close() error {
	close(p.subCh)
	return nil
}

func (p *rotatingProvider) Rotate(c *turncreds.Credentials) {
	p.mu.Lock()
	p.creds = c
	p.mu.Unlock()
	select {
	case p.subCh <- c:
	default:
	}
}

func TestTURN_RoundTripInProcessServer(t *testing.T) {
	serverAddr, cleanup := turnTestServer(t, map[string]string{
		"userA": "passA",
		"userB": "passB",
	})
	defer cleanup()

	credsA := &turncreds.Credentials{
		ServerAddr: serverAddr,
		Transport:  "udp",
		Username:   "userA",
		Password:   "passA",
	}
	credsB := &turncreds.Credentials{
		ServerAddr: serverAddr,
		Transport:  "udp",
		Username:   "userB",
		Password:   "passB",
	}

	provA := newRotatingProvider(credsA)
	provB := newRotatingProvider(credsB)
	defer provA.Close()
	defer provB.Close()

	sinkA := make(chan InboundFrame, 8)
	sinkB := make(chan InboundFrame, 8)

	tA := NewTURNTransport(provA, sinkA)
	tB := NewTURNTransport(provB, sinkB)

	if err := tA.Listen("", sinkA); err != nil {
		t.Fatalf("tA.Listen: %v", err)
	}
	defer tA.Close()
	if err := tB.Listen("", sinkB); err != nil {
		t.Fatalf("tB.Listen: %v", err)
	}
	defer tB.Close()

	// Both transports should have a relay address from the server.
	relayA := tA.LocalAddr()
	relayB := tB.LocalAddr()
	if relayA == nil {
		t.Fatalf("tA.LocalAddr is nil")
	}
	if relayB == nil {
		t.Fatalf("tB.LocalAddr is nil")
	}

	// A dials B's relay (installs A→B permission). B also dials A so
	// A→B datagrams arriving on B's allocation are admitted (inbound
	// permissions live on the receiver's side, not the sender's).
	epB, err := NewTURNEndpoint(relayB.String())
	if err != nil {
		t.Fatalf("NewTURNEndpoint(B): %v", err)
	}
	connAB, err := tA.Dial(context.Background(), epB)
	if err != nil {
		t.Fatalf("tA.Dial: %v", err)
	}
	defer connAB.Close()

	epA, err := NewTURNEndpoint(relayA.String())
	if err != nil {
		t.Fatalf("NewTURNEndpoint(A): %v", err)
	}
	if _, err := tB.Dial(context.Background(), epA); err != nil {
		t.Fatalf("tB.Dial: %v", err)
	}

	// CreatePermission isn't exposed through our wrapper; pion's relay
	// auto-creates a permission as a side-effect of the first send once
	// the server receives the Send indication. The first packet may be
	// dropped while the permission propagates, so send a few.
	payload := []byte("hello over turn")
	var received []byte
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	for {
		if err := connAB.Send(payload); err != nil {
			t.Fatalf("connAB.Send: %v", err)
		}
		select {
		case f := <-sinkB:
			received = f.Frame
		case <-tick.C:
			continue
		case <-deadline:
			t.Fatalf("timed out waiting for TURN-relayed payload")
		}
		if received != nil {
			break
		}
	}

	if string(received) != string(payload) {
		t.Fatalf("payload mismatch: got %q, want %q", received, payload)
	}
}

func TestTURN_CredentialRotation(t *testing.T) {
	serverAddr, cleanup := turnTestServer(t, map[string]string{
		"alice": "old",
		"bob":   "new",
	})
	defer cleanup()

	initial := &turncreds.Credentials{
		ServerAddr: serverAddr, Transport: "udp", Username: "alice", Password: "old",
	}
	prov := newRotatingProvider(initial)
	defer prov.Close()

	sink := make(chan InboundFrame, 8)
	tr := NewTURNTransport(prov, sink)
	if err := tr.Listen("", sink); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tr.Close()

	oldRelay := tr.LocalAddr()
	if oldRelay == nil {
		t.Fatalf("no initial relay addr")
	}

	// Rotate credentials. Wait for a new allocation to show up —
	// LocalAddr changes to the new relay socket's address.
	prov.Rotate(&turncreds.Credentials{
		ServerAddr: serverAddr, Transport: "udp", Username: "bob", Password: "new",
	})

	deadline := time.After(5 * time.Second)
	var newRelay net.Addr
	for {
		select {
		case <-deadline:
			t.Fatalf("rotation did not swap relay within deadline; still %v", tr.LocalAddr())
		case <-time.After(50 * time.Millisecond):
		}
		candidate := tr.LocalAddr()
		if candidate != nil && candidate.String() != oldRelay.String() {
			newRelay = candidate
			goto rotated
		}
	}
rotated:

	// Stand up a second transport to receive from the rotated client.
	otherServer, otherCleanup := turnTestServer(t, map[string]string{"peer": "pw"})
	defer otherCleanup()
	peerProv := newRotatingProvider(&turncreds.Credentials{
		ServerAddr: otherServer, Transport: "udp", Username: "peer", Password: "pw",
	})
	defer peerProv.Close()
	peerSink := make(chan InboundFrame, 8)
	peerT := NewTURNTransport(peerProv, peerSink)
	if err := peerT.Listen("", peerSink); err != nil {
		t.Fatalf("peer.Listen: %v", err)
	}
	defer peerT.Close()

	peerRelay := peerT.LocalAddr()
	if peerRelay == nil {
		t.Fatalf("peer has no relay addr")
	}
	peerEP, err := NewTURNEndpoint(peerRelay.String())
	if err != nil {
		t.Fatalf("NewTURNEndpoint(peer): %v", err)
	}
	conn, err := tr.Dial(context.Background(), peerEP)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Reverse permission so peerT accepts inbound from tr's relay IP.
	senderEP, err := NewTURNEndpoint(newRelay.String())
	if err != nil {
		t.Fatalf("NewTURNEndpoint(sender): %v", err)
	}
	if _, err := peerT.Dial(context.Background(), senderEP); err != nil {
		t.Fatalf("peer.Dial(sender): %v", err)
	}

	payload := []byte("after rotation")
	deadline = time.After(5 * time.Second)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := conn.Send(payload); err != nil {
			t.Fatalf("Send: %v", err)
		}
		select {
		case f := <-peerSink:
			if string(f.Frame) != string(payload) {
				t.Fatalf("payload mismatch: got %q", f.Frame)
			}
			_ = newRelay
			return
		case <-tick.C:
		case <-deadline:
			t.Fatalf("timed out after rotation")
		}
	}
}

func TestTURN_CloseIdempotent(t *testing.T) {
	serverAddr, cleanup := turnTestServer(t, map[string]string{"u": "p"})
	defer cleanup()

	prov := newRotatingProvider(&turncreds.Credentials{
		ServerAddr: serverAddr, Transport: "udp", Username: "u", Password: "p",
	})
	defer prov.Close()

	tr := NewTURNTransport(prov, make(chan InboundFrame, 1))
	if err := tr.Listen("", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestTURN_DialBeforeListen(t *testing.T) {
	prov := newRotatingProvider(&turncreds.Credentials{
		ServerAddr: "127.0.0.1:1", Transport: "udp", Username: "u", Password: "p",
	})
	defer prov.Close()

	tr := NewTURNTransport(prov, make(chan InboundFrame, 1))

	ep, err := NewTURNEndpoint("127.0.0.1:9999")
	if err != nil {
		t.Fatalf("NewTURNEndpoint: %v", err)
	}
	if _, err := tr.Dial(context.Background(), ep); err == nil {
		t.Fatalf("Dial on un-listened transport should error, got nil")
	}
}

func TestTURN_EndpointParse(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	good, err := tr.ParseEndpoint("203.0.113.10:3478")
	if err != nil {
		t.Fatalf("good parse: %v", err)
	}
	if good.Network() != "turn" {
		t.Fatalf("Network()=%q, want turn", good.Network())
	}
	if _, err := tr.ParseEndpoint(""); err == nil {
		t.Fatalf("empty string should error")
	}
	if _, err := tr.ParseEndpoint("not-a-host-port"); err == nil {
		t.Fatalf("malformed addr should error")
	}
}

// Guard: the TURNEndpoint round-trips through ParseEndpoint.
func TestTURN_EndpointRoundTrip(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	orig, err := NewTURNEndpoint("198.51.100.5:49152")
	if err != nil {
		t.Fatalf("NewTURNEndpoint: %v", err)
	}
	parsed, err := tr.ParseEndpoint(orig.String())
	if err != nil {
		t.Fatalf("ParseEndpoint(orig): %v", err)
	}
	if parsed.String() != orig.String() {
		t.Fatalf("round-trip mismatch: %q vs %q", parsed.String(), orig.String())
	}
}

// Guard: name is "turn".
func TestTURN_Name(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	if n := tr.Name(); n != "turn" {
		t.Fatalf("Name=%q, want turn", n)
	}
}

// Helper to avoid an unused-import warning when running just a subset.
var _ = fmt.Sprintf
