package daemon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// The tests in this file cover the v1.9.0-jf.11a.3 racing-dial
// primitives: TunnelManager.SendViaBeacon (the non-mutating
// beacon-relay primitive) and Daemon.racingRelaySYN (the
// DialConnection goroutine that re-transmits SYNs through the
// beacon in parallel with direct retries).
//
// The end-to-end "relay wins when direct is stale" behavior is
// implicitly regression-guarded by the existing
// tests/nat_traversal_test.go TestRelayFallback integration test;
// the unit coverage here locks down the new primitives so that
// future refactors don't silently regress the 23× speedup this
// release buys.

// fakeBeacon spins up a UDP socket and returns its address plus a
// channel that receives every packet written to it. Used to verify
// SendViaBeacon's wire format and the racing goroutine's timing.
type fakeBeacon struct {
	conn *net.UDPConn
	addr *net.UDPAddr
	recv chan []byte
}

func newFakeBeacon(t *testing.T) *fakeBeacon {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen fake beacon: %v", err)
	}
	fb := &fakeBeacon{
		conn: c,
		addr: c.LocalAddr().(*net.UDPAddr),
		recv: make(chan []byte, 32),
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
			case fb.recv <- cp:
			default:
			}
		}
	}()
	return fb
}

func (fb *fakeBeacon) Close() { fb.conn.Close() }

// TestSendViaBeacon_EncodesRelayEnvelope locks the wire format:
// [0x05 = BeaconMsgRelay][senderID(4)][destID(4)][frame...]. Matches
// writeFrame's tier-1 encoding so the beacon server's existing
// handler accepts it.
func TestSendViaBeacon_EncodesRelayEnvelope(t *testing.T) {
	fb := newFakeBeacon(t)
	defer fb.Close()

	tm := NewTunnelManager()
	defer tm.Close()
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	tm.mu.Lock()
	tm.beaconAddr = fb.addr
	tm.SetNodeID(4242)
	tm.mu.Unlock()

	const dest uint32 = 4343
	frame := []byte("hello-relay-frame")
	if err := tm.SendViaBeacon(dest, frame); err != nil {
		t.Fatalf("SendViaBeacon: %v", err)
	}

	select {
	case got := <-fb.recv:
		if len(got) < 9 {
			t.Fatalf("short packet: %d bytes", len(got))
		}
		if got[0] != protocol.BeaconMsgRelay {
			t.Fatalf("type = 0x%02x, want 0x%02x (BeaconMsgRelay)",
				got[0], protocol.BeaconMsgRelay)
		}
		sender := binary.BigEndian.Uint32(got[1:5])
		if sender != 4242 {
			t.Fatalf("sender = %d, want 4242", sender)
		}
		dst := binary.BigEndian.Uint32(got[5:9])
		if dst != dest {
			t.Fatalf("dest = %d, want %d", dst, dest)
		}
		if string(got[9:]) != string(frame) {
			t.Fatalf("payload = %q, want %q", got[9:], frame)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("fake beacon never received the relay frame")
	}
}

// TestSendViaBeacon_DoesNotMutateViaRelay pins the Gotcha-B guard:
// SendViaBeacon must NOT flip path.viaRelay. Without this invariant,
// a losing relay-retry in DialConnection would poison the next dial
// (force it through relay forever even if direct works fine).
func TestSendViaBeacon_DoesNotMutateViaRelay(t *testing.T) {
	fb := newFakeBeacon(t)
	defer fb.Close()

	tm := NewTunnelManager()
	defer tm.Close()
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	tm.mu.Lock()
	tm.beaconAddr = fb.addr
	tm.mu.Unlock()

	const dest uint32 = 5555
	// Seed a direct path WITHOUT viaRelay.
	tm.AddPeer(dest, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1})
	if tm.IsRelayPeer(dest) {
		t.Fatalf("precondition: fresh peer must not be relay")
	}

	if err := tm.SendViaBeacon(dest, []byte("x")); err != nil {
		t.Fatalf("SendViaBeacon: %v", err)
	}

	if tm.IsRelayPeer(dest) {
		t.Fatalf("after SendViaBeacon, IsRelayPeer must remain false "+
			"(got true — viaRelay was mutated, regressing jf.11a.3's "+
			"no-poison guarantee)")
	}
}

// TestSendViaBeacon_ErrorsWhenBeaconUnset: no beacon configured means
// no usable route — SendViaBeacon returns an error so the racing
// goroutine can short-circuit instead of attempting blind sends.
func TestSendViaBeacon_ErrorsWhenBeaconUnset(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	// Do NOT set tm.beaconAddr.

	err := tm.SendViaBeacon(1, []byte("x"))
	if err == nil {
		t.Fatalf("SendViaBeacon with no beacon succeeded; want error")
	}
}

// TestSendPacketViaBeacon_Plaintext validates the marshaled-packet
// variant that DialConnection's racing goroutine actually uses.
// When tm.encrypt is false, the packet marshals straight into a PILT
// plaintext frame and ships via the beacon envelope.
func TestSendPacketViaBeacon_Plaintext(t *testing.T) {
	fb := newFakeBeacon(t)
	defer fb.Close()

	tm := NewTunnelManager()
	defer tm.Close()
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	tm.mu.Lock()
	tm.beaconAddr = fb.addr
	tm.encrypt = false
	tm.mu.Unlock()
	tm.SetNodeID(1001)

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: 1001},
		Dst:      protocol.Addr{Node: 2002},
		SrcPort:  1234,
		DstPort:  5678,
		Seq:      7,
	}
	if err := tm.SendPacketViaBeacon(2002, pkt); err != nil {
		t.Fatalf("SendPacketViaBeacon: %v", err)
	}

	select {
	case got := <-fb.recv:
		if got[0] != protocol.BeaconMsgRelay {
			t.Fatalf("envelope type wrong: 0x%02x", got[0])
		}
		if binary.BigEndian.Uint32(got[5:9]) != 2002 {
			t.Fatalf("dest node wrong in envelope")
		}
		// Inner frame should start with the PILT magic (plaintext tunnel frame).
		inner := got[9:]
		if len(inner) < 4 {
			t.Fatalf("inner frame too short: %d", len(inner))
		}
		if string(inner[:4]) != string(protocol.TunnelMagic[:]) {
			t.Fatalf("inner magic = %x, want PILT %x",
				inner[:4], protocol.TunnelMagic[:])
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("fake beacon never received the packet frame")
	}
}

// TestRacingRelaySYN_WaitsForHeadStart proves the RFC 8305 head-start
// semantic: the relay goroutine must NOT send any beacon frames
// during the first DialRelayHeadStart milliseconds. The direct
// retries get that exclusive window to win on healthy networks.
func TestRacingRelaySYN_WaitsForHeadStart(t *testing.T) {
	fb := newFakeBeacon(t)
	defer fb.Close()

	d := New(Config{
		Email:      "test@example.com",
		BeaconAddr: fb.addr.String(),
	})
	// We don't Start() the daemon — racingRelaySYN only touches
	// d.tunnels, which is allocated in New().
	if err := d.tunnels.udp.Listen("127.0.0.1:0", d.tunnels.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	d.tunnels.mu.Lock()
	d.tunnels.beaconAddr = fb.addr
	d.tunnels.encrypt = false
	d.tunnels.mu.Unlock()
	d.tunnels.SetNodeID(1111)

	syn := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: 1111},
		Dst:      protocol.Addr{Node: 2222},
		SrcPort:  9000,
		DstPort:  9001,
	}

	stop := make(chan struct{})
	defer close(stop)
	done := make(chan struct{})
	go func() {
		d.racingRelaySYN(2222, syn, stop)
		close(done)
	}()

	// During the head-start window, no frames should hit the beacon.
	// Check at 150ms (well before the 200ms head-start expires).
	select {
	case <-time.After(DialRelayHeadStart - 50*time.Millisecond):
	case got := <-fb.recv:
		t.Fatalf("beacon received a frame during head-start window "+
			"(head-start = %v); got %d-byte payload. This means the "+
			"direct path is not given its exclusive early window.",
			DialRelayHeadStart, len(got))
	}

	// After the head-start, at least one frame should arrive.
	select {
	case <-fb.recv:
		// good — relay retry fired post-head-start.
	case <-time.After(DialRelayHeadStart + 500*time.Millisecond):
		t.Fatalf("no beacon frame arrived after head-start expired; "+
			"relay goroutine appears stuck")
	}
}

// TestRacingRelaySYN_ExitsOnStop pins the cleanup contract: the
// goroutine must return promptly when the caller closes stop
// (DialConnection's defer close(raceStop)), even if it was
// mid-backoff. Prevents goroutine leaks across the 31 s
// DialRelayRetries × DialMaxRTO worst-case window.
func TestRacingRelaySYN_ExitsOnStop(t *testing.T) {
	fb := newFakeBeacon(t)
	defer fb.Close()

	d := New(Config{
		Email:      "test@example.com",
		BeaconAddr: fb.addr.String(),
	})
	if err := d.tunnels.udp.Listen("127.0.0.1:0", d.tunnels.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	d.tunnels.mu.Lock()
	d.tunnels.beaconAddr = fb.addr
	d.tunnels.encrypt = false
	d.tunnels.mu.Unlock()
	d.tunnels.SetNodeID(1111)

	syn := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: 1111},
		Dst:      protocol.Addr{Node: 2222},
		SrcPort:  9000,
		DstPort:  9001,
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		d.racingRelaySYN(2222, syn, stop)
		close(done)
	}()

	// Close stop immediately — goroutine should exit during its
	// head-start sleep without ever sending a frame.
	close(stop)
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("racingRelaySYN did not exit within 500ms of close(stop)")
	}

	// Sanity: no frames should have landed on the beacon (exited
	// during head-start, before first send).
	select {
	case got := <-fb.recv:
		t.Fatalf("beacon received a frame after close(stop); "+
			"goroutine did not short-circuit (%d bytes)", len(got))
	case <-time.After(50 * time.Millisecond):
	}
}
