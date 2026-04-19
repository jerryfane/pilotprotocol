package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
)

// TCPEndpoint wraps a TCP "host:port" address and satisfies Endpoint.
type TCPEndpoint struct {
	addr *net.TCPAddr
}

// NewTCPEndpoint wraps an existing *net.TCPAddr. Returns nil if addr is nil.
func NewTCPEndpoint(addr *net.TCPAddr) *TCPEndpoint {
	if addr == nil {
		return nil
	}
	return &TCPEndpoint{addr: addr}
}

// Network returns "tcp".
func (e *TCPEndpoint) Network() string { return "tcp" }

// String returns the TCPAddr's host:port form.
func (e *TCPEndpoint) String() string {
	if e == nil || e.addr == nil {
		return ""
	}
	return e.addr.String()
}

// Addr returns the underlying *net.TCPAddr. Escape hatch for code
// paths that need the concrete type; prefer String() for portability.
func (e *TCPEndpoint) Addr() *net.TCPAddr {
	if e == nil {
		return nil
	}
	return e.addr
}

// DefaultTCPDialTimeout is the default per-dial timeout for outbound
// TCP connections. Intentionally conservative — typical stable
// internet paths handshake in well under a second; the 10s ceiling is
// for slow cellular / high-latency satellite links.
const DefaultTCPDialTimeout = 10 * time.Second

// TCPTransport carries Pilot frames over persistent, length-prefixed
// TCP connections. Frames on the wire are identical to UDP — the only
// difference is a 4-byte big-endian length prefix added per frame
// because TCP is a stream, not a datagram.
//
// One TCPTransport instance manages:
//   - One TCP listener (accepts inbound conns)
//   - A pool of outbound dialled conns, keyed by remote address
//   - One reader goroutine per active conn (inbound or outbound)
//
// Every reader writes received frames onto the shared sink channel
// supplied to Listen — same pattern as UDPTransport. Callers dispatch
// frames by parsing the Pilot magic, not by looking at the transport.
type TCPTransport struct {
	mu          sync.Mutex
	listener    *net.TCPListener
	sink        chan<- InboundFrame
	outbound    map[string]*tcpDialedConn // remote addr string → pooled dialled conn
	inbound     []net.Conn                // accepted conns, for cleanup on Close
	dialTimeout time.Duration
	done        chan struct{}
	wg          sync.WaitGroup
	closed      bool
}

// NewTCPTransport constructs a TCPTransport with the default dial
// timeout. Call SetDialTimeout before Listen to override.
func NewTCPTransport() *TCPTransport {
	return &TCPTransport{
		outbound:    make(map[string]*tcpDialedConn),
		dialTimeout: DefaultTCPDialTimeout,
		done:        make(chan struct{}),
	}
}

// Name returns "tcp".
func (t *TCPTransport) Name() string { return "tcp" }

// SetDialTimeout overrides the per-dial timeout for outbound connections.
func (t *TCPTransport) SetDialTimeout(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d > 0 {
		t.dialTimeout = d
	}
}

// Listen binds the TCP listener and starts the accept loop.
func (t *TCPTransport) Listen(addr string, sink chan<- InboundFrame) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("tcp transport: closed")
	}
	if t.listener != nil {
		t.mu.Unlock()
		return errors.New("tcp transport: already listening")
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("tcp transport: resolve %q: %w", addr, err)
	}
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("tcp transport: listen %q: %w", addr, err)
	}
	t.listener = ln
	t.sink = sink
	t.mu.Unlock()

	t.wg.Add(1)
	go t.acceptLoop()
	return nil
}

// acceptLoop accepts incoming TCP connections and spawns a reader per
// connection. Exits when Close is called.
func (t *TCPTransport) acceptLoop() {
	defer t.wg.Done()
	for {
		t.mu.Lock()
		ln := t.listener
		t.mu.Unlock()
		if ln == nil {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				// Expected shutdown.
			default:
				// Only log unexpected close errors; listener.Close is the normal exit.
				if !isClosedConnErr(err) {
					slog.Error("tcp transport: accept error", "error", err)
				}
			}
			return
		}

		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			_ = conn.Close()
			return
		}
		t.inbound = append(t.inbound, conn)
		t.mu.Unlock()

		t.wg.Add(1)
		go t.readerLoop(conn, "inbound")
	}
}

// readerLoop reads length-prefixed frames from conn and delivers each
// one on sink. Exits when conn closes or Close is called.
func (t *TCPTransport) readerLoop(conn net.Conn, tag string) {
	defer t.wg.Done()
	defer conn.Close()

	remote := conn.RemoteAddr()
	epAddr, ok := remote.(*net.TCPAddr)
	var ep *TCPEndpoint
	if ok {
		ep = &TCPEndpoint{addr: epAddr}
	}

	for {
		frame, err := ipcutil.Read(conn)
		if err != nil {
			select {
			case <-t.done:
			default:
				if !isClosedConnErr(err) {
					slog.Debug("tcp transport: read loop ended", "tag", tag, "remote", remote, "error", err)
				}
			}
			// If this was a pooled outbound conn, drop it from the pool so
			// the next Dial opens a fresh one.
			t.dropOutbound(conn)
			return
		}

		select {
		case t.sink <- InboundFrame{Frame: frame, From: ep}:
		case <-t.done:
			return
		}
	}
}

// LocalAddr returns the bound TCP address, or nil if not listening.
func (t *TCPTransport) LocalAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener == nil {
		return nil
	}
	return t.listener.Addr()
}

// Dial acquires or reuses a pooled outbound connection to ep.
func (t *TCPTransport) Dial(ctx context.Context, ep Endpoint) (DialedConn, error) {
	if ep.Network() != "tcp" {
		return nil, fmt.Errorf("tcp transport: wrong network %q", ep.Network())
	}
	tcpEP, ok := ep.(*TCPEndpoint)
	if !ok {
		return nil, fmt.Errorf("tcp transport: endpoint type %T is not *TCPEndpoint", ep)
	}
	remote := tcpEP.addr.String()

	// Fast path: reuse pooled conn if still live.
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("tcp transport: closed")
	}
	if c, ok := t.outbound[remote]; ok {
		t.mu.Unlock()
		return c, nil
	}
	timeout := t.dialTimeout
	t.mu.Unlock()

	// Dial outside the lock.
	d := net.Dialer{Timeout: timeout}
	rawConn, err := d.DialContext(ctx, "tcp", remote)
	if err != nil {
		return nil, fmt.Errorf("tcp transport: dial %s: %w", remote, err)
	}

	dc := &tcpDialedConn{
		conn:     rawConn,
		remote:   tcpEP,
		transport: t,
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = rawConn.Close()
		return nil, errors.New("tcp transport: closed")
	}
	// Race: another goroutine may have dialled the same remote while we
	// were outside the lock. Prefer the earlier winner; close ours.
	if existing, ok := t.outbound[remote]; ok {
		t.mu.Unlock()
		_ = rawConn.Close()
		return existing, nil
	}
	t.outbound[remote] = dc
	t.mu.Unlock()

	// Start reader so peer-initiated frames on this connection land on
	// the sink just like any other inbound. The reader also handles the
	// "peer closed the conn" case by dropping from the pool.
	t.wg.Add(1)
	go t.readerLoop(rawConn, "outbound")

	return dc, nil
}

// ParseEndpoint parses a "host:port" string into a TCPEndpoint.
func (t *TCPTransport) ParseEndpoint(s string) (Endpoint, error) {
	ta, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		return nil, fmt.Errorf("tcp transport: parse %q: %w", s, err)
	}
	return &TCPEndpoint{addr: ta}, nil
}

// Close tears down the listener, all dialled outbound conns, all
// inbound conns, and waits for reader goroutines to exit.
func (t *TCPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	ln := t.listener
	t.listener = nil
	outbound := t.outbound
	t.outbound = nil
	inbound := t.inbound
	t.inbound = nil
	t.mu.Unlock()

	close(t.done)
	var firstErr error
	if ln != nil {
		if err := ln.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, c := range outbound {
		_ = c.conn.Close()
	}
	for _, c := range inbound {
		_ = c.Close()
	}

	t.wg.Wait()
	return firstErr
}

// dropOutbound removes conn from the outbound pool (called from the
// reader goroutine when the connection dies).
func (t *TCPTransport) dropOutbound(conn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.outbound == nil {
		return
	}
	for addr, c := range t.outbound {
		if c.conn == conn {
			delete(t.outbound, addr)
			return
		}
	}
}

// isClosedConnErr returns true if err is the idiomatic "we closed the
// listener/conn on purpose" error rather than a real read/write failure.
func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// Some stdlib versions wrap the message rather than exposing the
	// sentinel — string match is the portable fallback.
	return err.Error() == "use of closed network connection"
}

// tcpDialedConn is the DialedConn implementation for TCPTransport.
// Send is serialized with a mutex so concurrent callers can't
// interleave length prefix and payload writes on the same socket.
type tcpDialedConn struct {
	sendMu    sync.Mutex
	conn      net.Conn
	remote    *TCPEndpoint
	transport *TCPTransport
}

func (c *tcpDialedConn) Send(frame []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return ipcutil.Write(c.conn, frame)
}

func (c *tcpDialedConn) RemoteEndpoint() Endpoint {
	return c.remote
}

func (c *tcpDialedConn) Close() error {
	// Drop from the pool before closing the underlying conn so a
	// concurrent Dial doesn't hand out the doomed connection.
	c.transport.dropOutbound(c.conn)
	return c.conn.Close()
}
