package daemon

import (
	"fmt"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func NewPortManager() *PortManager {
	return &PortManager{
		listeners:   make(map[uint16]*Listener),
		connections: make(map[uint32]*Connection),
		nextConnID:  1,
		nextEphPort: protocol.PortEphemeralMin,
	}
}

func (pm *PortManager) Bind(port uint16) (*Listener, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.listeners[port]; exists {
		return nil, fmt.Errorf("port %d already bound", port)
	}

	ln := &Listener{
		Port:     port,
		AcceptCh: make(chan *Connection, AcceptQueueLen),
	}
	pm.listeners[port] = ln
	return ln, nil
}

func (pm *PortManager) Unbind(port uint16) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if ln, ok := pm.listeners[port]; ok {
		close(ln.AcceptCh)
		delete(pm.listeners, port)
	}
}

func (pm *PortManager) GetListener(port uint16) *Listener {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.listeners[port]
}

// ConnectionCountForPort returns the number of active connections on a port.
func (pm *PortManager) ConnectionCountForPort(port uint16) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	count := 0
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if c.LocalPort == port && st != StateClosed && st != StateTimeWait {
			count++
		}
	}
	return count
}

// TotalActiveConnections returns the total number of non-closed connections.
func (pm *PortManager) TotalActiveConnections() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	count := 0
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if st != StateClosed && st != StateTimeWait {
			count++
		}
	}
	return count
}

func (pm *PortManager) AllocEphemeralPort() uint16 {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	start := pm.nextEphPort
	for {
		port := pm.nextEphPort
		pm.nextEphPort++
		if pm.nextEphPort > protocol.PortEphemeralMax {
			pm.nextEphPort = protocol.PortEphemeralMin
		}
		if !pm.portInUse(port) {
			return port
		}
		if pm.nextEphPort == start {
			return port // full wrap, return anyway (16384 ports)
		}
	}
}

// portInUse returns true if any active connection is using the given local port.
// Must be called with pm.mu held.
func (pm *PortManager) portInUse(port uint16) bool {
	for _, c := range pm.connections {
		if c.LocalPort == port {
			c.Mu.Lock()
			st := c.State
			c.Mu.Unlock()
			if st != StateClosed && st != StateTimeWait {
				return true
			}
		}
	}
	return false
}

func (pm *PortManager) NewConnection(localPort uint16, remoteAddr protocol.Addr, remotePort uint16) *Connection {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	conn := &Connection{
		ID:           pm.nextConnID,
		CreatedAt:    time.Now(),
		LocalPort:    localPort,
		RemoteAddr:   remoteAddr,
		RemotePort:   remotePort,
		State:        StateClosed,
		LastActivity: time.Now(),
		SendBuf:      make(chan []byte, SendBufLen),
		RecvBuf:      make(chan []byte, RecvBufSize),
		CongWin:      InitialCongWin,
		SSThresh:     MaxCongWin / 2,
		WindowCh:     make(chan struct{}, 1),
		NagleCh:      make(chan struct{}, 1),
	}
	pm.nextConnID++
	if pm.nextConnID == 0 {
		pm.nextConnID = 1 // wrap around, skip 0 (reserved)
	}
	pm.connections[conn.ID] = conn
	return conn
}

func (pm *PortManager) GetConnection(id uint32) *Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.connections[id]
}

func (pm *PortManager) FindConnection(localPort uint16, remoteAddr protocol.Addr, remotePort uint16) *Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, c := range pm.connections {
		if c.LocalPort == localPort && c.RemoteAddr == remoteAddr && c.RemotePort == remotePort {
			return c
		}
	}
	return nil
}

// ConnectionInfo describes an active connection for diagnostics.
type ConnectionInfo struct {
	ID          uint32
	LocalPort   uint16
	RemoteAddr  string
	RemotePort  uint16
	State       string
	SendSeq     uint32
	RecvAck     uint32
	CongWin     int
	SSThresh    int
	InFlight    int
	SRTT        time.Duration
	RTTVAR      time.Duration
	Unacked     int
	OOOBuf      int
	PeerRecvWin int
	RecvWin     int
	InRecovery  bool
	Stats       ConnStats
}

// ConnectionList returns info about all active connections.
func (pm *PortManager) ConnectionList() []ConnectionInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var list []ConnectionInfo
	for _, c := range pm.connections {
		c.RetxMu.Lock()
		inFlight := c.BytesInFlight()
		unacked := len(c.Unacked)
		congWin := c.CongWin
		ssthresh := c.SSThresh
		srtt := c.SRTT
		rttvar := c.RTTVAR
		peerWin := c.PeerRecvWin
		inRecovery := c.InRecovery
		c.RetxMu.Unlock()
		recvWin := int(c.RecvWindow()) * MaxSegmentSize

		c.RecvMu.Lock()
		ooo := len(c.OOOBuf)
		c.RecvMu.Unlock()

		c.Mu.Lock()
		st := c.State
		sendSeq := c.SendSeq
		recvAck := c.RecvAck
		stats := c.Stats
		c.Mu.Unlock()

		list = append(list, ConnectionInfo{
			ID:          c.ID,
			LocalPort:   c.LocalPort,
			RemoteAddr:  c.RemoteAddr.String(),
			RemotePort:  c.RemotePort,
			State:       st.String(),
			SendSeq:     sendSeq,
			RecvAck:     recvAck,
			CongWin:     congWin,
			SSThresh:    ssthresh,
			InFlight:    inFlight,
			SRTT:        srtt,
			RTTVAR:      rttvar,
			Unacked:     unacked,
			OOOBuf:      ooo,
			PeerRecvWin: peerWin,
			RecvWin:     recvWin,
			InRecovery:  inRecovery,
			Stats:       stats,
		})
	}
	return list
}

// StaleConnections returns connections that should be cleaned up.
// CLOSED and CLOSE_WAIT are cleaned up immediately. FIN_WAIT, TIME_WAIT,
// and passive half-open SYN_RECV connections are cleaned up after
// timeWaitDur. Outbound SYN_SENT is intentionally left to DialConnection's
// retry budget so active dials can report their own timeout reason.
func (pm *PortManager) StaleConnections(timeWaitDur time.Duration) []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	now := time.Now()
	var stale []*Connection
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		la := c.LastActivity
		c.Mu.Unlock()
		switch st {
		case StateClosed, StateCloseWait:
			stale = append(stale, c)
		case StateFinWait, StateTimeWait, StateSynReceived:
			if now.Sub(la) > timeWaitDur {
				stale = append(stale, c)
			}
		}
	}
	return stale
}

// IdleConnections returns connections that have been idle longer than the given duration.
func (pm *PortManager) IdleConnections(maxIdle time.Duration) []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	now := time.Now()
	var idle []*Connection
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		la := c.LastActivity
		c.Mu.Unlock()
		if st == StateEstablished && now.Sub(la) > maxIdle {
			idle = append(idle, c)
		}
	}
	return idle
}

// ResetKeepaliveForNode clears KeepaliveUnacked and refreshes LastActivity on
// every ESTABLISHED connection whose remote node matches nodeID. Called after a
// tunnel rekey so ACKs dropped during the key swap don't trip dead-peer detection
// on otherwise healthy peers. LastActivity is also bumped so the idle-sweep
// doesn't immediately start probing during the brief window where both sides are
// converging on the new shared secret.
func (pm *PortManager) ResetKeepaliveForNode(nodeID uint32) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	now := time.Now()
	for _, c := range pm.connections {
		c.Mu.Lock()
		if c.State == StateEstablished && c.RemoteAddr.Node == nodeID {
			c.KeepaliveUnacked = 0
			c.LastActivity = now
		}
		c.Mu.Unlock()
	}
}

// AllConnections returns all active connections.
func (pm *PortManager) AllConnections() []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	conns := make([]*Connection, 0, len(pm.connections))
	for _, c := range pm.connections {
		conns = append(conns, c)
	}
	return conns
}

func (pm *PortManager) RemoveConnection(id uint32) {
	pm.mu.Lock()
	c := pm.connections[id]
	delete(pm.connections, id)
	pm.mu.Unlock()
	// Stop retransmission goroutine
	if c != nil && c.RetxStop != nil {
		select {
		case <-c.RetxStop:
		default:
			close(c.RetxStop)
		}
	}
}
