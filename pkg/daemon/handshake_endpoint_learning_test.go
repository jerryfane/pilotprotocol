package daemon

import (
	"crypto/ed25519"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
)

// The tests below pin v1.9.0-jf.12's strict endpoint-learning
// contract for handshake replies. WireGuard rule: "the peer's
// endpoint is learned from the outer external source IP of the most
// recent correctly-authenticated packet received." Pre-jf.12, pilot
// implemented this for encrypted-data frames only — handshake
// replies (sendKeyExchangeToNode) read path.direct at send time,
// which could be a stale cache from before the peer's TURN
// allocation rotated. The chicken-and-egg deadlock that produced is
// what we're closing here.

// captureListener is a small UDP listener that drains frames into a
// channel. Used by handshake-reply tests to assert which destination
// (stale-cached vs fresh-observed) the daemon's UDP write landed at.
type captureListener struct {
	conn   *net.UDPConn
	addr   *net.UDPAddr
	frames chan []byte
}

func newCaptureListener(t *testing.T) *captureListener {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("captureListener listen: %v", err)
	}
	cl := &captureListener{
		conn:   c,
		addr:   c.LocalAddr().(*net.UDPAddr),
		frames: make(chan []byte, 16),
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			select {
			case cl.frames <- cp:
			default:
			}
		}
	}()
	return cl
}

func (cl *captureListener) Close() { _ = cl.conn.Close() }

// newKEXTestTunnel returns a TunnelManager wired up to drive
// sendKeyExchangeToNode end-to-end: real UDP socket, an Ed25519
// identity, an X25519 pubkey, encryption flagged on. Caller owns
// Close.
func newKEXTestTunnel(t *testing.T) *TunnelManager {
	t.Helper()
	tm := NewTunnelManager()
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	tm.SetNodeID(8888)
	// Identity: required for buildAuthKeyExchangeFrame to produce a
	// non-nil PILA. Without it, sendKeyExchangeToNode emits PILA-less
	// (PILT) frames which still go via the same write path; the test
	// outcome is identical.
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("crypto.GenerateIdentity: %v", err)
	}
	tm.SetIdentity(id)
	// pubKey is required by buildAuthKeyExchangeFrame too — set a
	// 32-byte placeholder X25519 pub.
	tm.pubKey = make([]byte, 32)
	tm.pubKey[0] = 0x01
	return tm
}

func newAuthKEXTestTunnel(t *testing.T, nodeID uint32) (*TunnelManager, *crypto.Identity) {
	t.Helper()
	tm := NewTunnelManager()
	tm.SetNodeID(nodeID)
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("crypto.GenerateIdentity: %v", err)
	}
	tm.SetIdentity(id)
	return tm, id
}

func expectCapturedFrame(t *testing.T, cl *captureListener, label string) []byte {
	t.Helper()
	select {
	case f := <-cl.frames:
		if len(f) < 4 {
			t.Fatalf("%s got %d-byte frame; want >= 4", label, len(f))
		}
		return f
	case <-time.After(2 * time.Second):
		t.Fatalf("%s listener never received frame", label)
	}
	return nil
}

func expectNoCapturedFrame(t *testing.T, cl *captureListener, label string) {
	t.Helper()
	select {
	case f := <-cl.frames:
		t.Fatalf("%s listener received unexpected %d-byte frame", label, len(f))
	case <-time.After(150 * time.Millisecond):
	}
}

// TestHandshakeReply_UsesObservedSourceNotCachedDirect is the
// regression guard for the live chicken-and-egg deadlock. With a
// stale path.direct cached, a sendKeyExchangeToNode call carrying
// the freshly-observed source MUST send to the fresh source, not
// the stale cache. Pre-jf.12 it sent to the stale cache.
func TestHandshakeReply_UsesObservedSourceNotCachedDirect(t *testing.T) {
	tm := newKEXTestTunnel(t)
	defer tm.Close()

	stale := newCaptureListener(t)
	defer stale.Close()
	fresh := newCaptureListener(t)
	defer fresh.Close()

	const peer uint32 = 5511
	// Seed the cache with the STALE address — the situation post-TURN-
	// rotation: peer was here before, has since moved, but our cache
	// hasn't been refreshed yet.
	tm.AddPeer(peer, stale.addr)
	// Remove the auto-KEX side-effect from AddPeer by draining
	// whatever frame it may have produced toward `stale`.
	select {
	case <-stale.frames:
	case <-time.After(150 * time.Millisecond):
	}

	// Now the test: handshake reply with FRESH observed source.
	tm.sendKeyExchangeToNode(peer, fresh.addr)

	// Fresh listener must receive the frame.
	select {
	case f := <-fresh.frames:
		if len(f) < 4 {
			t.Fatalf("fresh got %d-byte frame; want >= 4", len(f))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("FRESH listener never received the handshake reply " +
			"(pre-jf.12 the reply went to STALE, breaking the post-" +
			"rotation tunnel)")
	}

	// Stale listener must NOT receive anything.
	select {
	case f := <-stale.frames:
		t.Fatalf("STALE listener received a %d-byte frame; "+
			"jf.12 must NOT consult the cached path.direct when "+
			"observedSrc is supplied", len(f))
	case <-time.After(150 * time.Millisecond):
		// good — silent
	}
}

// TestHandshakeReply_FallsBackToCacheWhenNoObservedSource preserves
// the legacy code path: caller-initiated handshakes (startup, AddPeer
// auto-KEX, SendTo's queue-and-KEX) pass nil and MUST hit the cached
// path.direct, since they have no inbound source to react to.
func TestHandshakeReply_FallsBackToCacheWhenNoObservedSource(t *testing.T) {
	tm := newKEXTestTunnel(t)
	defer tm.Close()

	cached := newCaptureListener(t)
	defer cached.Close()

	const peer uint32 = 5512
	tm.AddPeer(peer, cached.addr)
	// Drain the AddPeer auto-KEX frame.
	select {
	case <-cached.frames:
	case <-time.After(150 * time.Millisecond):
	}

	// Caller-initiated KEX (observedSrc == nil).
	tm.sendKeyExchangeToNode(peer, nil)

	select {
	case <-cached.frames:
		// good — fell back to path.direct as expected
	case <-time.After(2 * time.Second):
		t.Fatalf("CACHED listener never received the caller-" +
			"initiated handshake; nil observedSrc must fall back to " +
			"path.direct (jf.11b behavior preserved)")
	}
}

// TestSendKeyExchangeToNode_CallerSrcOverridesPathDirect drives
// writeFrame's override condition directly. With a non-nil addr
// passed by the caller, writeFrame must NOT silently substitute
// pathDirect. Pre-jf.12 the override at tunnel.go:1105 was:
//
//	if pathDirect != nil { addr = pathDirect }   // unconditionally clobbers
//
// jf.12 narrows it to:
//
//	if addr == nil && pathDirect != nil { addr = pathDirect }
//
// Pre-jf.12 this test would fail because the caller-supplied addr
// would be silently overridden by the cached pathDirect.
func TestSendKeyExchangeToNode_CallerSrcOverridesPathDirect(t *testing.T) {
	tm := newKEXTestTunnel(t)
	defer tm.Close()

	cache := newCaptureListener(t)
	defer cache.Close()
	caller := newCaptureListener(t)
	defer caller.Close()

	const peer uint32 = 5513
	tm.AddPeer(peer, cache.addr)
	select {
	case <-cache.frames:
	case <-time.After(150 * time.Millisecond):
	}

	tm.sendKeyExchangeToNode(peer, caller.addr)

	select {
	case <-caller.frames:
	case <-time.After(2 * time.Second):
		t.Fatalf("caller-supplied addr was silently overridden by " +
			"path.direct — jf.12 writeFrame override should be " +
			"`addr == nil && pathDirect != nil`, not unconditional")
	}
	select {
	case <-cache.frames:
		t.Fatalf("cache listener received the frame; the caller's " +
			"non-nil addr should win")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestSendKeyExchangeToNode_RaceSafety: concurrent updatePathDirect
// and sendKeyExchangeToNode under -race. Just guards that the new
// observedSrc parameter doesn't introduce data races against
// path-state updates. Doesn't assert behaviour — outcome is timing-
// dependent.
func TestSendKeyExchangeToNode_RaceSafety(t *testing.T) {
	tm := newKEXTestTunnel(t)
	defer tm.Close()

	dst := newCaptureListener(t)
	defer dst.Close()

	const peer uint32 = 5514
	tm.AddPeer(peer, dst.addr)
	// Drain whatever AddPeer side-effects might write.
	go func() {
		for {
			select {
			case <-dst.frames:
			case <-time.After(100 * time.Millisecond):
				return
			}
		}
	}()

	var wg sync.WaitGroup
	var calls atomic.Int32
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tm.mu.Lock()
			tm.updatePathDirect(peer, dst.addr)
			tm.mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			tm.sendKeyExchangeToNode(peer, dst.addr)
			calls.Add(1)
		}()
	}
	wg.Wait()
	// The race detector handles the actual assertion. We just want
	// some coverage of the lock interactions.
	if calls.Load() != 50 {
		t.Fatalf("calls.Load() = %d; want 50", calls.Load())
	}
}

func TestAuthKEXTrailer_FlagsDoNotContaminateCaps(t *testing.T) {
	tm := newKEXTestTunnel(t)
	defer tm.Close()

	tm.SetLocalCaps(0x40)
	frame := tm.buildAuthKeyExchangeFrameWithFlags(authKEXFlagRequest)
	if len(frame) <= 136 {
		t.Fatalf("flagged auth KEX frame has no trailer")
	}
	caps, flags := parseAuthKEXTrailer(frame[136:])
	if caps != 0x40 {
		t.Fatalf("caps = %#x, want 0x40", caps)
	}
	if flags != authKEXFlagRequest {
		t.Fatalf("flags = %#x, want request", flags)
	}

	tm.SetLocalCaps(0)
	frame = tm.buildAuthKeyExchangeFrameWithFlags(authKEXFlagResponse)
	caps, flags = parseAuthKEXTrailer(frame[136:])
	if caps != 0 {
		t.Fatalf("caps with flags-only trailer = %#x, want 0", caps)
	}
	if flags != authKEXFlagResponse {
		t.Fatalf("flags = %#x, want response", flags)
	}
}

func TestAuthKeyExchange_TURNIngressInstallsObservedEndpoint(t *testing.T) {
	const (
		localNode = uint32(45491)
		peerNode  = uint32(45981)
		turnAddr  = "104.30.148.46:39762"
	)
	tm, _ := newAuthKEXTestTunnel(t, localNode)
	defer tm.Close()
	peer, peerID := newAuthKEXTestTunnel(t, peerNode)
	defer peer.Close()
	tm.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		if nodeID != peerNode {
			t.Fatalf("unexpected verify nodeID %d", nodeID)
		}
		return peerID.PublicKey, nil
	})

	turnEP, err := transport.NewTURNEndpoint(turnAddr)
	if err != nil {
		t.Fatalf("NewTURNEndpoint: %v", err)
	}
	frame := peer.buildAuthKeyExchangeFrameWithFlags(authKEXFlagRequest)
	tm.handleAuthKeyExchange(frame[4:], turnEP, false)

	if got := tm.PeerTURNEndpoint(peerNode); got != turnAddr {
		t.Fatalf("PeerTURNEndpoint = %q, want %q", got, turnAddr)
	}
	tm.mu.RLock()
	p := tm.paths[peerNode]
	tm.mu.RUnlock()
	if p == nil {
		t.Fatalf("path entry not created for authenticated TURN peer")
	}
	if p.direct != nil {
		t.Fatalf("TURN ingress poisoned direct path: got %v", p.direct)
	}
}

func TestAuthKeyExchange_DuplicateRecoveryRequestRepliesWithoutCryptoReset(t *testing.T) {
	const (
		localNode = uint32(45491)
		peerNode  = uint32(45981)
	)
	tm, _ := newAuthKEXTestTunnel(t, localNode)
	defer tm.Close()
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	peer, peerID := newAuthKEXTestTunnel(t, peerNode)
	defer peer.Close()
	tm.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		if nodeID != peerNode {
			t.Fatalf("unexpected verify nodeID %d", nodeID)
		}
		return peerID.PublicKey, nil
	})
	observed := newCaptureListener(t)
	defer observed.Close()
	observedEP := transport.NewUDPEndpoint(observed.addr)
	frame := peer.buildAuthKeyExchangeFrameWithFlags(authKEXFlagRequest)

	tm.handleAuthKeyExchange(frame[4:], observedEP, false)
	firstReply := expectCapturedFrame(t, observed, "initial reply")
	_, firstFlags := parseAuthKEXTrailer(firstReply[136:])
	if firstFlags != authKEXFlagResponse {
		t.Fatalf("initial reply flags = %#x, want response", firstFlags)
	}
	tm.mu.RLock()
	firstPC := tm.crypto[peerNode]
	tm.mu.RUnlock()
	if firstPC == nil {
		t.Fatalf("crypto not installed after initial auth KEX")
	}

	tm.handleAuthKeyExchange(frame[4:], observedEP, false)
	secondReply := expectCapturedFrame(t, observed, "duplicate request reply")
	_, secondFlags := parseAuthKEXTrailer(secondReply[136:])
	if secondFlags != authKEXFlagResponse {
		t.Fatalf("duplicate reply flags = %#x, want response", secondFlags)
	}
	tm.mu.RLock()
	secondPC := tm.crypto[peerNode]
	tm.mu.RUnlock()
	if secondPC != firstPC {
		t.Fatalf("same-key duplicate recovery request replaced crypto state")
	}

	tm.handleAuthKeyExchange(frame[4:], observedEP, false)
	expectNoCapturedFrame(t, observed, "cooldown duplicate request")
}

// Ensure crypto.Identity satisfies the interface ed25519 expects
// without unused import warnings if the helper changes.
var _ = ed25519.PublicKey(nil)
