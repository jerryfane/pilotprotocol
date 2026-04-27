package daemon

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func TestDuplicateInboundSYNDoesNotDuplicateAccept(t *testing.T) {
	d := New(Config{
		Email:        "stream-cleanup@example.com",
		Public:       true,
		SYNRateLimit: AcceptQueueLen * 4,
	})
	ln, err := d.ports.Bind(protocol.PortManagedScore)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	installCleanupTunnelConn(d, 2)

	pkt := inboundSYNPkt(2, 49152, 100)
	d.handleStreamPacket(pkt)
	d.handleStreamPacket(pkt)

	if got := len(ln.AcceptCh); got != 1 {
		t.Fatalf("accept queue depth = %d, want 1 after duplicate SYN", got)
	}
	if got := d.ports.TotalActiveConnections(); got != 1 {
		t.Fatalf("active connections = %d, want 1 after duplicate SYN", got)
	}

	conn := <-ln.AcceptCh
	d.ports.RemoveConnection(conn.ID)
}

func TestInboundSYNFullAcceptQueueRemovesRejectedConnection(t *testing.T) {
	d := New(Config{
		Email:                 "stream-cleanup@example.com",
		Public:                true,
		SYNRateLimit:          AcceptQueueLen * 4,
		MaxConnectionsPerPort: AcceptQueueLen + 32,
		MaxTotalConnections:   AcceptQueueLen + 32,
	})
	ln, err := d.ports.Bind(protocol.PortManagedScore)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}

	for i := 0; i < AcceptQueueLen+8; i++ {
		nodeID := uint32(1000 + i)
		installCleanupTunnelConn(d, nodeID)
		d.handleStreamPacket(inboundSYNPkt(nodeID, uint16(49152+i), uint32(100+i)))
	}

	if got := len(ln.AcceptCh); got != AcceptQueueLen {
		t.Fatalf("accept queue depth = %d, want %d", got, AcceptQueueLen)
	}
	if got := d.ports.TotalActiveConnections(); got != AcceptQueueLen {
		t.Fatalf("active connections = %d, want %d; overflow SYNs must not orphan conns", got, AcceptQueueLen)
	}
	if got := len(d.ports.AllConnections()); got != AcceptQueueLen {
		t.Fatalf("stored connections = %d, want %d", got, AcceptQueueLen)
	}

	for len(ln.AcceptCh) > 0 {
		conn := <-ln.AcceptCh
		d.ports.RemoveConnection(conn.ID)
	}
}

func TestPortManagerStaleConnectionsFINWaitAndTIMEWAIT(t *testing.T) {
	pm := NewPortManager()
	now := time.Now()

	freshFin := pm.NewConnection(4000, protocol.Addr{Node: 2}, 5000)
	setConnStateAndActivity(freshFin, StateFinWait, now)
	staleFin := pm.NewConnection(4001, protocol.Addr{Node: 3}, 5001)
	setConnStateAndActivity(staleFin, StateFinWait, now.Add(-2*time.Hour))
	freshTimeWait := pm.NewConnection(4002, protocol.Addr{Node: 4}, 5002)
	setConnStateAndActivity(freshTimeWait, StateTimeWait, now)
	staleTimeWait := pm.NewConnection(4003, protocol.Addr{Node: 5}, 5003)
	setConnStateAndActivity(staleTimeWait, StateTimeWait, now.Add(-2*time.Hour))
	closed := pm.NewConnection(4004, protocol.Addr{Node: 6}, 5004)
	setConnStateAndActivity(closed, StateClosed, now)

	stale := pm.StaleConnections(time.Hour)
	assertStaleIDs(t, stale, map[uint32]bool{
		staleFin.ID:      true,
		staleTimeWait.ID: true,
		closed.ID:        true,
	})
}

func TestDialConnectionRejectsClosingState(t *testing.T) {
	d := New(Config{Email: "stream-cleanup@example.com", Public: true})
	installCleanupTunnelConn(d, 99)

	errCh := make(chan error, 1)
	go func() {
		conn, err := d.DialConnection(protocol.Addr{Node: 99}, protocol.PortManagedScore)
		if conn != nil {
			errCh <- errors.New("DialConnection returned a connection in closing state")
			return
		}
		errCh <- err
	}()

	var conn *Connection
	deadline := time.After(time.Second)
	for conn == nil {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for DialConnection to allocate a conn")
		default:
		}
		all := d.ports.AllConnections()
		if len(all) > 0 {
			conn = all[0]
			break
		}
		time.Sleep(time.Millisecond)
	}

	conn.Mu.Lock()
	conn.State = StateTimeWait
	conn.Mu.Unlock()

	select {
	case err := <-errCh:
		if !errors.Is(err, protocol.ErrConnClosing) {
			t.Fatalf("DialConnection error = %v, want ErrConnClosing", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialConnection did not return after observing closing state")
	}
	if got := d.ports.GetConnection(conn.ID); got != nil {
		t.Fatalf("closing dial conn still registered: id=%d state=%s", got.ID, got.State)
	}
}

func TestDuplicateFINInTimeWaitIsIdempotent(t *testing.T) {
	d := New(Config{Email: "stream-cleanup@example.com", Public: true})
	rec := installRecordingTunnelConn(d, 2)
	conn := d.ports.NewConnection(4000, protocol.Addr{Node: 2}, 49152)
	conn.LocalAddr = protocol.Addr{Node: 1}
	past := time.Now().Add(-time.Minute)
	setConnStateAndActivity(conn, StateTimeWait, past)
	conn.Mu.Lock()
	conn.SendSeq = 77
	conn.Mu.Unlock()

	d.handleStreamPacket(&protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagFIN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: 2},
		Dst:      protocol.Addr{Node: 1},
		SrcPort:  49152,
		DstPort:  4000,
		Seq:      123,
		Window:   512,
	})

	conn.Mu.Lock()
	state := conn.State
	lastActivity := conn.LastActivity
	conn.Mu.Unlock()
	if state != StateTimeWait {
		t.Fatalf("state = %s, want TIME_WAIT", state)
	}
	if !lastActivity.Equal(past) {
		t.Fatalf("LastActivity changed on duplicate FIN: got %v want %v", lastActivity, past)
	}
	pkts := rec.packets(t)
	if len(pkts) != 1 {
		t.Fatalf("sent packets = %d, want 1", len(pkts))
	}
	if pkts[0].HasFlag(protocol.FlagFIN) || !pkts[0].HasFlag(protocol.FlagACK) {
		t.Fatalf("duplicate FIN response flags = 0x%x, want ACK-only", pkts[0].Flags)
	}
}

func TestFINACKInFinWaitClearsRetransmitAndDoesNotEchoFIN(t *testing.T) {
	d := New(Config{Email: "stream-cleanup@example.com", Public: true})
	rec := installRecordingTunnelConn(d, 2)
	conn := d.ports.NewConnection(4000, protocol.Addr{Node: 2}, 49152)
	conn.LocalAddr = protocol.Addr{Node: 1}
	conn.Mu.Lock()
	conn.State = StateFinWait
	conn.SendSeq = 101
	conn.Mu.Unlock()
	conn.TrackSend(100, []byte{0})

	d.handleStreamPacket(&protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagFIN | protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: 2},
		Dst:      protocol.Addr{Node: 1},
		SrcPort:  49152,
		DstPort:  4000,
		Seq:      200,
		Ack:      101,
		Window:   512,
	})

	conn.Mu.Lock()
	state := conn.State
	conn.Mu.Unlock()
	if state != StateTimeWait {
		t.Fatalf("state = %s, want TIME_WAIT", state)
	}
	conn.RetxMu.Lock()
	unacked := len(conn.Unacked)
	conn.RetxMu.Unlock()
	if unacked != 0 {
		t.Fatalf("unacked segments = %d, want 0 after FIN-ACK", unacked)
	}
	pkts := rec.packets(t)
	if len(pkts) != 1 {
		t.Fatalf("sent packets = %d, want 1", len(pkts))
	}
	if pkts[0].HasFlag(protocol.FlagFIN) || !pkts[0].HasFlag(protocol.FlagACK) {
		t.Fatalf("FIN_WAIT FIN response flags = 0x%x, want ACK-only", pkts[0].Flags)
	}
}

func TestIPCClientDisconnectCleansOwnedPortAndConnection(t *testing.T) {
	d := New(Config{Email: "ipc-cleanup@example.com"})
	installCleanupTunnelConn(d, 99)
	s := NewIPCServer("", d)

	ln, err := d.ports.Bind(4500)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	conn := d.ports.NewConnection(4500, protocol.Addr{Node: 99}, 5500)
	conn.LocalAddr = protocol.Addr{Node: 1}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.Mu.Unlock()

	serverSide, clientSide := net.Pipe()
	ipc := &ipcConn{Conn: serverSide}
	ipc.trackPort(ln.Port)
	ipc.trackConn(conn.ID)
	s.clients[ipc] = true

	done := make(chan struct{})
	go func() {
		s.handleClient(ipc)
		close(done)
	}()

	if err := clientSide.Close(); err != nil {
		t.Fatalf("close client side: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("handleClient did not exit after IPC disconnect")
	}

	if got := d.ports.GetListener(4500); got != nil {
		t.Fatalf("listener still bound after IPC disconnect")
	}
	got := d.ports.GetConnection(conn.ID)
	if got == nil {
		t.Fatalf("owned connection was removed immediately; want FIN_WAIT cleanup state")
	}
	got.Mu.Lock()
	state := got.State
	got.Mu.Unlock()
	if state != StateFinWait {
		t.Fatalf("owned connection state = %s, want FIN_WAIT", state)
	}
	select {
	case _, ok := <-conn.RecvBuf:
		if ok {
			t.Fatalf("owned connection RecvBuf still open after IPC disconnect")
		}
	default:
		t.Fatalf("owned connection RecvBuf was not closed after IPC disconnect")
	}
	d.ports.RemoveConnection(conn.ID)
}

func TestIPCUnbindReleasesOwnedPortWithoutDisconnect(t *testing.T) {
	d := New(Config{Email: "ipc-unbind@example.com"})
	s := NewIPCServer("", d)

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	ipc := &ipcConn{Conn: serverSide}
	s.clients[ipc] = true

	done := make(chan struct{})
	go func() {
		s.handleClient(ipc)
		close(done)
	}()
	defer func() {
		_ = clientSide.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("handleClient did not exit")
		}
	}()

	writeFrame := func(cmd byte, port uint16) {
		t.Helper()
		msg := []byte{cmd, 0, 0}
		msg[1] = byte(port >> 8)
		msg[2] = byte(port)
		if err := ipcutil.Write(clientSide, msg); err != nil {
			t.Fatalf("write cmd 0x%02x: %v", cmd, err)
		}
	}
	readOK := func(want byte, port uint16) {
		t.Helper()
		resp, err := ipcutil.Read(clientSide)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if len(resp) != 3 || resp[0] != want {
			t.Fatalf("response = %x, want cmd 0x%02x", resp, want)
		}
		got := uint16(resp[1])<<8 | uint16(resp[2])
		if got != port {
			t.Fatalf("response port = %d, want %d", got, port)
		}
	}

	const port uint16 = 4521
	writeFrame(CmdBind, port)
	readOK(CmdBindOK, port)
	if got := d.ports.GetListener(port); got == nil {
		t.Fatalf("listener not bound after bind")
	}

	writeFrame(CmdUnbind, port)
	readOK(CmdUnbindOK, port)
	if got := d.ports.GetListener(port); got != nil {
		t.Fatalf("listener still bound after explicit unbind")
	}

	writeFrame(CmdBind, port)
	readOK(CmdBindOK, port)
	if got := d.ports.GetListener(port); got == nil {
		t.Fatalf("listener not rebound after explicit unbind")
	}
}

func inboundSYNPkt(srcNode uint32, srcPort uint16, seq uint32) *protocol.Packet {
	return &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: srcNode},
		Dst:      protocol.Addr{Node: 1},
		SrcPort:  srcPort,
		DstPort:  protocol.PortManagedScore,
		Seq:      seq,
		Window:   512,
	}
}

func installCleanupTunnelConn(d *Daemon, nodeID uint32) {
	d.tunnels.mu.Lock()
	d.tunnels.paths[nodeID] = &peerPath{direct: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(nodeID)}}
	d.tunnels.peerConns[nodeID] = &cleanupDialedConn{}
	d.tunnels.mu.Unlock()
}

func installRecordingTunnelConn(d *Daemon, nodeID uint32) *recordingDialedConn {
	rec := &recordingDialedConn{}
	d.tunnels.mu.Lock()
	d.tunnels.paths[nodeID] = &peerPath{direct: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(nodeID)}}
	d.tunnels.peerConns[nodeID] = rec
	d.tunnels.mu.Unlock()
	return rec
}

func setConnStateAndActivity(c *Connection, state ConnState, at time.Time) {
	c.Mu.Lock()
	c.State = state
	c.LastActivity = at
	c.Mu.Unlock()
}

func assertStaleIDs(t *testing.T, stale []*Connection, want map[uint32]bool) {
	t.Helper()
	got := make(map[uint32]bool, len(stale))
	for _, c := range stale {
		got[c.ID] = true
	}
	if len(got) != len(want) {
		t.Fatalf("stale IDs = %v, want %v", got, want)
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("stale IDs = %v, missing %d", got, id)
		}
	}
}

type cleanupDialedConn struct{}

func (c *cleanupDialedConn) Send([]byte) error { return nil }
func (c *cleanupDialedConn) RemoteEndpoint() transport.Endpoint {
	return cleanupEndpoint("cleanup")
}
func (c *cleanupDialedConn) Close() error { return nil }

type cleanupEndpoint string

func (e cleanupEndpoint) Network() string { return "test" }
func (e cleanupEndpoint) String() string  { return string(e) }

type recordingDialedConn struct {
	mu     sync.Mutex
	frames [][]byte
}

func (c *recordingDialedConn) Send(frame []byte) error {
	cp := make([]byte, len(frame))
	copy(cp, frame)
	c.mu.Lock()
	c.frames = append(c.frames, cp)
	c.mu.Unlock()
	return nil
}

func (c *recordingDialedConn) RemoteEndpoint() transport.Endpoint {
	return cleanupEndpoint("recording")
}

func (c *recordingDialedConn) Close() error { return nil }

func (c *recordingDialedConn) packets(t *testing.T) []*protocol.Packet {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*protocol.Packet, 0, len(c.frames))
	for _, frame := range c.frames {
		magicLen := len(protocol.TunnelMagic)
		if len(frame) < magicLen || string(frame[:magicLen]) != string(protocol.TunnelMagic[:]) {
			t.Fatalf("frame missing tunnel magic: %x", frame)
		}
		pkt, err := protocol.Unmarshal(frame[magicLen:])
		if err != nil {
			t.Fatalf("unmarshal packet: %v", err)
		}
		out = append(out, pkt)
	}
	return out
}
