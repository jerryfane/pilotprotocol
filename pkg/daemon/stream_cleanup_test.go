package daemon

import (
	"net"
	"testing"
	"time"

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
	d.tunnels.peerConns[nodeID] = &cleanupDialedConn{}
	d.tunnels.mu.Unlock()
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
