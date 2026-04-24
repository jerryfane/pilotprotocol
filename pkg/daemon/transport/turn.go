package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
)

// defaultTURNGetTimeout bounds how long we wait on turncreds.Provider.Get
// during Listen / rotate. Cloudflare mints typically finish in <1s, but
// the credentials package itself retries up to 3x with backoff (~2s
// worst-case) so we keep a generous ceiling to cover retry budget + one
// HTTP RTT on a slow path.
const defaultTURNGetTimeout = 30 * time.Second

// turnReadBufSize is the per-loop read buffer for the TURN relay socket.
// Matches pion's internal default for Allocate'd conns.
const turnReadBufSize = 1500

// TURNEndpoint wraps a peer's relayed "host:port" address and satisfies
// the Endpoint interface. Endpoints for this transport identify the
// server-assigned relay address the peer has allocated for itself — not
// the peer's real IP. Sends to a TURNEndpoint go through the local
// TURN client's own relay socket via WriteTo(peerAddr).
type TURNEndpoint struct {
	addr *net.UDPAddr
}

// NewTURNEndpoint validates a host:port string and returns a TURNEndpoint
// pointing at that relayed address. Uses ResolveUDPAddr since TURN relay
// frames travel UDP between TURN server and peer regardless of the
// client↔server transport (udp/tcp/tls).
func NewTURNEndpoint(addr string) (*TURNEndpoint, error) {
	if addr == "" {
		return nil, errors.New("turn endpoint: empty address")
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("turn endpoint: resolve %q: %w", addr, err)
	}
	return &TURNEndpoint{addr: ua}, nil
}

// Network returns "turn".
func (e *TURNEndpoint) Network() string { return "turn" }

// String returns the relayed host:port form.
func (e *TURNEndpoint) String() string {
	if e == nil || e.addr == nil {
		return ""
	}
	return e.addr.String()
}

// Addr returns the underlying *net.UDPAddr. Escape hatch for code paths
// that need the concrete UDPAddr type; prefer String() for portability.
func (e *TURNEndpoint) Addr() *net.UDPAddr {
	if e == nil {
		return nil
	}
	return e.addr
}

// TURNTransport carries Pilot frames over a TURN (RFC 8656) relay using
// a pion/turn v5 client. Unlike UDP and TCP transports, TURN is
// client-only: we do not accept inbound connections. All "listening" is
// really a local relay socket assigned to us by the TURN server; peers
// who know our relayed address can send frames to us via the server.
//
// pion's Client is immutable post-construction (credentials, socket,
// realm are set once in NewClient). Credential rotation therefore means
// tearing down the old client + allocation and building a new pair. The
// rotation goroutine below performs a build-then-swap-then-close dance
// to keep writes serving throughout.
//
// One TURNTransport instance manages exactly one pion client and one
// relay allocation at a time. The sink supplied to Listen is shared
// with the rest of the TunnelManager pipeline; inbound relay frames
// deliver via the shared sink identically to UDP/TCP.
type TURNTransport struct {
	mu       sync.RWMutex
	client   *turn.Client     // current pion TURN client; nil before Listen, nil after Close
	relay    net.PacketConn   // current assigned relay socket
	peerSock net.PacketConn   // raw socket underneath the client (kept for Close)
	provider turncreds.Provider
	sink     chan<- InboundFrame

	closeCh chan struct{}
	wg      sync.WaitGroup
	closed  bool

	getTimeout time.Duration
}

// NewTURNTransport constructs a TURNTransport. The provider lifetime is
// owned by the caller (the daemon closes its own provider on shutdown);
// Close here does not touch the provider. The sink may be overridden by
// Listen's sink argument, mirroring tcp.go's convention.
func NewTURNTransport(provider turncreds.Provider, sink chan<- InboundFrame) *TURNTransport {
	return &TURNTransport{
		provider:   provider,
		sink:       sink,
		closeCh:    make(chan struct{}),
		getTimeout: defaultTURNGetTimeout,
	}
}

// Name returns "turn".
func (t *TURNTransport) Name() string { return "turn" }

// Listen builds a pion TURN client against the provider's current
// credentials, allocates a relay socket, and starts the rotation +
// reader goroutines. The addr parameter is ignored (TURN is
// client-only; the relayed address is dictated by the server). If
// sink is non-nil it overrides the constructor sink, matching tcp.go's
// behaviour.
func (t *TURNTransport) Listen(addr string, sink chan<- InboundFrame) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("turn transport: closed")
	}
	if t.client != nil {
		t.mu.Unlock()
		return errors.New("turn transport: already listening")
	}
	if sink != nil {
		t.sink = sink
	}
	if t.provider == nil {
		t.mu.Unlock()
		return errors.New("turn transport: nil provider")
	}
	provider := t.provider
	t.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), t.getTimeout)
	creds, err := provider.Get(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("turn transport: provider.Get: %w", err)
	}

	client, relay, peerSock, err := buildPionClient(creds)
	if err != nil {
		return fmt.Errorf("turn transport: build pion client: %w", err)
	}

	t.mu.Lock()
	// Re-check closed under lock: Close could have won the race while we
	// were building the client.
	if t.closed {
		t.mu.Unlock()
		_ = relay.Close()
		client.Close()
		_ = peerSock.Close()
		return errors.New("turn transport: closed")
	}
	t.client = client
	t.relay = relay
	t.peerSock = peerSock
	t.mu.Unlock()

	slog.Info("turn transport listening",
		"server", creds.ServerAddr,
		"client_transport", creds.Transport,
		"relay", relay.LocalAddr(),
	)

	t.wg.Add(1)
	go t.readerLoop(relay)

	t.wg.Add(1)
	go t.rotationLoop()

	return nil
}

// LocalAddr returns the server-assigned relay address, or nil if Listen
// has not succeeded (or Close has torn the allocation down). This is
// what the daemon advertises to peers.
func (t *TURNTransport) LocalAddr() net.Addr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.relay == nil {
		return nil
	}
	return t.relay.LocalAddr()
}

// Dial returns a DialedConn that writes to ep via the current relay
// socket. Also issues a CreatePermission against the TURN server for
// the peer's relayed IP so that inbound datagrams from ep (which look
// to our allocation like traffic from the peer's server-side relay IP)
// are delivered to us. Outbound permissions are auto-created by pion's
// WriteTo on first send; this handles the inbound direction that the
// peer's Send cannot do on its own.
//
// The returned conn pins the remote endpoint but reads the live relay
// pointer from the transport on every Send, so credential rotation is
// transparent to callers.
func (t *TURNTransport) Dial(ctx context.Context, ep Endpoint) (DialedConn, error) {
	if ep == nil {
		return nil, errors.New("turn transport: nil endpoint")
	}
	if ep.Network() != "turn" {
		return nil, fmt.Errorf("turn transport: wrong network %q", ep.Network())
	}
	tep, ok := ep.(*TURNEndpoint)
	if !ok {
		return nil, fmt.Errorf("turn transport: endpoint type %T is not *TURNEndpoint", ep)
	}
	if tep.addr == nil {
		return nil, errors.New("turn transport: endpoint has nil addr")
	}

	t.mu.RLock()
	client := t.client
	hasRelay := t.relay != nil
	t.mu.RUnlock()
	if !hasRelay || client == nil {
		return nil, errors.New("turn transport: not listening")
	}

	// Install an explicit permission for the peer's IP. pion's WriteTo
	// side auto-permits the destination, but nothing on our side's
	// allocation permits incoming traffic from the peer until we call
	// CreatePermission. Without this step, the peer's Send indication
	// arrives on our relay and is dropped by our allocation for lack
	// of permission.
	if err := client.CreatePermission(tep.addr); err != nil {
		return nil, fmt.Errorf("turn create permission %s: %w", tep.addr, err)
	}

	return &turnDialedConn{
		remote:    tep,
		peerAddr:  tep.addr,
		transport: t,
	}, nil
}

// ParseEndpoint inflates a host:port string into a *TURNEndpoint.
func (t *TURNTransport) ParseEndpoint(s string) (Endpoint, error) {
	return NewTURNEndpoint(s)
}

// Close tears down the current allocation, pion client, and underlying
// socket, then waits for rotation + reader goroutines to exit.
// Idempotent. Does NOT close the provider (the daemon owns the
// provider's lifetime).
func (t *TURNTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	relay := t.relay
	client := t.client
	peerSock := t.peerSock
	t.relay = nil
	t.client = nil
	t.peerSock = nil
	t.mu.Unlock()

	close(t.closeCh)

	// Close order per pion docs: relay first (sends Refresh(lifetime=0)
	// so the server frees the allocation), then client, then the raw
	// socket underneath. Individual errors are swallowed on close — the
	// only interesting one would be the relay refresh, but a lost
	// refresh just means the server garbage-collects on its own
	// schedule.
	if relay != nil {
		_ = relay.Close()
	}
	if client != nil {
		client.Close()
	}
	if peerSock != nil {
		_ = peerSock.Close()
	}

	t.wg.Wait()
	return nil
}

// readerLoop pulls frames off the provided relay PacketConn and feeds
// them to the sink. Exits when the relay is closed (either by
// rotation swap or by Close). Rotation spawns a new readerLoop for the
// new relay; the old one returns once its relay returns an error from
// ReadFrom.
func (t *TURNTransport) readerLoop(relay net.PacketConn) {
	defer t.wg.Done()

	buf := make([]byte, turnReadBufSize)
	for {
		n, from, err := relay.ReadFrom(buf)
		if err != nil {
			// Either Close() ran (closeCh tripped) or rotation closed
			// this relay. Both are expected exits; we do not log at
			// warning level on any read-side error.
			select {
			case <-t.closeCh:
			default:
			}
			return
		}

		// Build a per-frame endpoint so the caller can identify the
		// sender. The address passed in by pion is the peer's relayed
		// source addr, which IS our peers' advertised turn endpoint.
		epStr := ""
		if from != nil {
			epStr = from.String()
		}
		fromEP, err := NewTURNEndpoint(epStr)
		if err != nil {
			// Unparseable sender — drop silently. Malformed relay
			// traffic is a TURN-server level concern.
			continue
		}

		frame := make([]byte, n)
		copy(frame, buf[:n])

		// No Reply set: TURN replies flow through the same relay
		// socket the caller already has via writeFrame's cached path.
		select {
		case t.sink <- InboundFrame{Frame: frame, From: fromEP, Reply: nil}:
		case <-t.closeCh:
			return
		}
	}
}

// rotationLoop subscribes to provider rotation events and swaps the
// pion client + allocation under the mutex. Rotation failure is
// non-fatal: we log WARN and keep serving the old client; the next
// refresh tick will try again.
func (t *TURNTransport) rotationLoop() {
	defer t.wg.Done()

	sub := t.provider.Subscribe()
	for {
		select {
		case <-t.closeCh:
			return
		case newCreds, ok := <-sub:
			if !ok {
				// Provider closed its Subscribe channel (e.g. the
				// daemon is shutting down and closed the provider
				// first). Exit cleanly.
				return
			}
			if newCreds == nil {
				continue
			}
			t.rotate(newCreds)
		}
	}
}

// rotate builds a new pion client + allocation against newCreds; on
// success, swaps them in under the mutex and tears down the old
// triplet. Spawns a new reader goroutine for the new relay. On
// failure, logs WARN and leaves the old client in place.
func (t *TURNTransport) rotate(newCreds *turncreds.Credentials) {
	newClient, newRelay, newSock, err := buildPionClient(newCreds)
	if err != nil {
		slog.Warn("turn: rotate failed; keeping previous allocation",
			"error", err,
			"server", newCreds.ServerAddr,
		)
		return
	}

	t.mu.Lock()
	if t.closed {
		// Close raced us; discard the new allocation.
		t.mu.Unlock()
		_ = newRelay.Close()
		newClient.Close()
		_ = newSock.Close()
		return
	}
	oldRelay := t.relay
	oldClient := t.client
	oldSock := t.peerSock
	t.relay = newRelay
	t.client = newClient
	t.peerSock = newSock
	t.mu.Unlock()

	// Spawn a reader for the new relay BEFORE closing the old one, so
	// we don't miss frames in the swap window. The old reader will
	// exit on its own once oldRelay.Close() below trips its ReadFrom.
	t.wg.Add(1)
	go t.readerLoop(newRelay)

	// Close old triplet in the documented order.
	if oldRelay != nil {
		_ = oldRelay.Close()
	}
	if oldClient != nil {
		oldClient.Close()
	}
	if oldSock != nil {
		_ = oldSock.Close()
	}

	slog.Info("turn: rotated credentials",
		"server", newCreds.ServerAddr,
		"expires_at", newCreds.ExpiresAt,
		"relay", newRelay.LocalAddr(),
	)
}

// buildPionClient dials the raw client↔server socket per creds.Transport,
// wraps it appropriately, builds a pion turn.Client, calls Listen(), and
// issues an Allocate(). Returns the triplet {client, relay, peerSock}
// for the transport to store + close later.
//
// peerSock is the raw UDP/TCP/TLS socket the TURN client uses for its
// STUN transactions. For UDP it is the same object passed in as
// ClientConfig.Conn; for TCP/TLS it is a turn.NewSTUNConn wrapper
// around a net.Conn. We track the underlying stream separately so
// Close can release it — pion's Client.Close does not close the
// underlying conn.
func buildPionClient(creds *turncreds.Credentials) (*turn.Client, net.PacketConn, net.PacketConn, error) {
	if creds == nil {
		return nil, nil, nil, errors.New("nil credentials")
	}
	if creds.ServerAddr == "" {
		return nil, nil, nil, errors.New("empty ServerAddr")
	}

	var clientConn net.PacketConn
	var underlying net.PacketConn
	switch creds.Transport {
	case "", "udp":
		// Bind an ephemeral UDP4 socket. IPv6 peers should use an
		// explicit -turn-transport=udp on an IPv6 server; the current
		// provider contract does not distinguish, so v4 is the safe
		// default (matches pion's client example).
		sock, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("udp socket: %w", err)
		}
		clientConn = sock
		underlying = sock

	case "tcp":
		conn, err := net.DialTimeout("tcp", creds.ServerAddr, 10*time.Second)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tcp dial %s: %w", creds.ServerAddr, err)
		}
		sc := turn.NewSTUNConn(conn)
		clientConn = sc
		underlying = sc

	case "tls":
		host, _, err := net.SplitHostPort(creds.ServerAddr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tls split server %q: %w", creds.ServerAddr, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dialer := &tls.Dialer{Config: &tls.Config{ServerName: host}}
		c, err := dialer.DialContext(ctx, "tcp", creds.ServerAddr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tls dial %s: %w", creds.ServerAddr, err)
		}
		sc := turn.NewSTUNConn(c)
		clientConn = sc
		underlying = sc

	default:
		return nil, nil, nil, fmt.Errorf("unsupported transport %q", creds.Transport)
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr: creds.ServerAddr,
		TURNServerAddr: creds.ServerAddr,
		Conn:           clientConn,
		Username:       creds.Username,
		Password:       creds.Password,
		// Hint; pion's client learns the authoritative realm from the
		// server's Unauthorized response regardless.
		Realm:         "cloudflare.com",
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		_ = underlying.Close()
		return nil, nil, nil, fmt.Errorf("new client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		_ = underlying.Close()
		return nil, nil, nil, fmt.Errorf("client.Listen: %w", err)
	}

	relay, err := client.Allocate()
	if err != nil {
		client.Close()
		_ = underlying.Close()
		return nil, nil, nil, fmt.Errorf("allocate: %w", err)
	}

	return client, relay, underlying, nil
}

// turnDialedConn is the DialedConn implementation for TURNTransport. A
// single conn object survives credential rotation because its Send
// looks up the live relay pointer on every write rather than caching
// the relay at dial time.
type turnDialedConn struct {
	remote    *TURNEndpoint
	peerAddr  *net.UDPAddr
	transport *TURNTransport
	sendMu    sync.Mutex
}

// Send writes frame via the current relay socket to peerAddr. Serialized
// behind sendMu so concurrent callers on the same conn don't interleave
// writes to the underlying pion allocation (pion itself is goroutine-
// safe, but we keep the TCP-style lock here for parity and so future
// framing changes don't need to revisit this path).
func (c *turnDialedConn) Send(frame []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	c.transport.mu.RLock()
	relay := c.transport.relay
	c.transport.mu.RUnlock()
	if relay == nil {
		return errors.New("turn transport: closed")
	}

	_, err := relay.WriteTo(frame, c.peerAddr)
	if err != nil {
		return fmt.Errorf("turn write to %s: %w", c.peerAddr, err)
	}
	return nil
}

// RemoteEndpoint returns the peer's relayed address we send to.
func (c *turnDialedConn) RemoteEndpoint() Endpoint {
	return c.remote
}

// Close is a no-op. TURN permissions expire naturally after 5 minutes
// of idle, and we do not explicitly release them — the next writeFrame
// to the same peer refreshes as a side effect.
func (c *turnDialedConn) Close() error {
	return nil
}
