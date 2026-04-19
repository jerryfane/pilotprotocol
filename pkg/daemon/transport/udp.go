package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/TeoSlayer/pilotprotocol/internal/pool"
)

// UDPEndpoint wraps *net.UDPAddr to satisfy the Endpoint interface.
// Keeping the concrete type accessible via Addr() lets transport
// internals call UDP-specific syscalls without reaching through the
// abstraction.
type UDPEndpoint struct {
	addr *net.UDPAddr
}

// NewUDPEndpoint wraps an existing *net.UDPAddr. Returns nil if addr
// is nil (matching historical nil-handling in the daemon).
func NewUDPEndpoint(addr *net.UDPAddr) *UDPEndpoint {
	if addr == nil {
		return nil
	}
	return &UDPEndpoint{addr: addr}
}

// Network returns "udp".
func (e *UDPEndpoint) Network() string { return "udp" }

// String returns the UDPAddr's host:port form.
func (e *UDPEndpoint) String() string {
	if e == nil || e.addr == nil {
		return ""
	}
	return e.addr.String()
}

// Addr returns the underlying *net.UDPAddr. Used by the UDP transport
// and by the punch-packet code path which needs the concrete address.
// Callers outside the UDP transport should treat this as an escape
// hatch; preferring Endpoint.String() keeps them transport-agnostic.
func (e *UDPEndpoint) Addr() *net.UDPAddr {
	if e == nil {
		return nil
	}
	return e.addr
}

// UDPTransport is the UDP implementation of Transport. It wraps a
// single *net.UDPConn that serves both inbound reception (Listen) and
// outbound sends (Dial → DialedConn.Send). All concurrent access is
// safe: *net.UDPConn is already threadsafe for WriteToUDP, and the
// read loop has a single owner (the Listen goroutine).
type UDPTransport struct {
	mu      sync.RWMutex
	conn    *net.UDPConn
	sink    chan<- InboundFrame
	done    chan struct{}
	readWg  sync.WaitGroup
	closed  bool
}

// NewUDPTransport constructs an unlistened UDPTransport. Call Listen
// to bind the socket and begin reception.
func NewUDPTransport() *UDPTransport {
	return &UDPTransport{done: make(chan struct{})}
}

// Name returns "udp".
func (t *UDPTransport) Name() string { return "udp" }

// Listen binds the transport to addr and starts the read loop. Returns
// once the socket is bound and the goroutine is live.
func (t *UDPTransport) Listen(addr string, sink chan<- InboundFrame) error {
	t.mu.Lock()
	if t.conn != nil {
		t.mu.Unlock()
		return errors.New("udp transport: already listening")
	}
	if t.closed {
		t.mu.Unlock()
		return errors.New("udp transport: closed")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("udp transport: resolve %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("udp transport: listen %q: %w", addr, err)
	}
	t.conn = conn
	t.sink = sink
	t.mu.Unlock()

	t.readWg.Add(1)
	go t.readLoop()
	return nil
}

// readLoop reads datagrams from the UDP socket and delivers each one
// as an InboundFrame on sink. Exits when the connection is closed.
func (t *UDPTransport) readLoop() {
	defer t.readWg.Done()

	bufPtr := pool.GetLarge()
	defer pool.PutLarge(bufPtr)
	buf := *bufPtr

	for {
		t.mu.RLock()
		conn := t.conn
		t.mu.RUnlock()
		if conn == nil {
			return
		}

		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				slog.Debug("udp transport: read loop stopped", "reason", "conn closed")
			} else {
				// Only log if we didn't close intentionally.
				select {
				case <-t.done:
					// expected shutdown
				default:
					slog.Error("udp transport: read error", "error", err)
				}
			}
			return
		}
		if n < 1 {
			continue
		}

		// Copy the frame — pool buffer must be reused for the next
		// Read call, caller must own the bytes it processes.
		frame := make([]byte, n)
		copy(frame, buf[:n])

		select {
		case t.sink <- InboundFrame{Frame: frame, From: &UDPEndpoint{addr: remote}}:
		case <-t.done:
			return
		}
	}
}

// LocalAddr returns the bound UDP address, or nil if not listening.
func (t *UDPTransport) LocalAddr() net.Addr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.conn == nil {
		return nil
	}
	return t.conn.LocalAddr()
}

// Dial returns a DialedConn pointing at ep. Cheap: the returned Conn
// just holds a reference to the shared socket and the target address.
func (t *UDPTransport) Dial(ctx context.Context, ep Endpoint) (DialedConn, error) {
	if ep.Network() != "udp" {
		return nil, fmt.Errorf("udp transport: wrong network %q", ep.Network())
	}
	udpEP, ok := ep.(*UDPEndpoint)
	if !ok {
		return nil, fmt.Errorf("udp transport: endpoint type %T is not *UDPEndpoint", ep)
	}
	t.mu.RLock()
	conn := t.conn
	t.mu.RUnlock()
	if conn == nil {
		return nil, errors.New("udp transport: not listening")
	}
	return &udpDialedConn{conn: conn, remote: udpEP}, nil
}

// ParseEndpoint inflates a "host:port" string into a UDPEndpoint.
func (t *UDPTransport) ParseEndpoint(s string) (Endpoint, error) {
	ua, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, fmt.Errorf("udp transport: parse %q: %w", s, err)
	}
	return &UDPEndpoint{addr: ua}, nil
}

// Close shuts down the socket and waits for the read loop to exit.
func (t *UDPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	conn := t.conn
	t.conn = nil
	t.mu.Unlock()

	close(t.done)
	var err error
	if conn != nil {
		err = conn.Close()
	}
	t.readWg.Wait()
	return err
}

// WriteToUDPAddr is an escape hatch for sends that must go to an
// arbitrary UDP address (not associated with a cached DialedConn).
// Used by the NAT punch path and beacon registration/discovery code
// that need to send to addresses that are not "peers" in the tunnel
// sense. Kept on the transport (not on a DialedConn) so callers don't
// have to create throwaway Conns for one-shot writes.
func (t *UDPTransport) WriteToUDPAddr(frame []byte, addr *net.UDPAddr) (int, error) {
	t.mu.RLock()
	conn := t.conn
	t.mu.RUnlock()
	if conn == nil {
		return 0, errors.New("udp transport: not listening")
	}
	return conn.WriteToUDP(frame, addr)
}

// Conn exposes the underlying *net.UDPConn for the small number of
// call sites that need to pass it to a stdlib function expecting a
// concrete UDP socket (e.g. standalone STUN discovery). Returns nil
// before Listen or after Close.
func (t *UDPTransport) Conn() *net.UDPConn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn
}

// udpDialedConn is the DialedConn implementation returned by
// UDPTransport.Dial. It holds references to the shared socket and the
// destination address; Send writes a single datagram. There is no
// connection state to tear down, so Close is a no-op beyond returning
// nil.
type udpDialedConn struct {
	conn   *net.UDPConn
	remote *UDPEndpoint
}

func (c *udpDialedConn) Send(frame []byte) error {
	_, err := c.conn.WriteToUDP(frame, c.remote.addr)
	return err
}

func (c *udpDialedConn) RemoteEndpoint() Endpoint {
	return c.remote
}

func (c *udpDialedConn) Close() error {
	// UDP conns don't own the socket; nothing to release. Return nil
	// so caller code can treat Close uniformly.
	return nil
}
