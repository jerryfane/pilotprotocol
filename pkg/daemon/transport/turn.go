package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// defaultPermissionRefreshInterval is how often the permission refresh
// loop re-issues CreatePermission for every address in permittedAddrs.
// TURN permissions expire after 5 minutes of idle (RFC 8656 §9.2); we
// refresh at 4 minutes to keep permissions live with comfortable
// headroom against clock skew and server-side timing.
const defaultPermissionRefreshInterval = 4 * time.Minute

// Self-heal thresholds for jf.15. Modeled on RFC 7675 (STUN consent
// freshness) — that spec declares a path dead after 30 s without a
// valid response. We apply the same boundary at the TURN-allocation
// layer: if we've had several consecutive transport failures AND
// >30 s have elapsed since the last successful operation against
// pion's TURN client, the allocation is presumed dead and we
// trigger an atomic rebuild.
//
// The two-axis check (count + time) prevents both noise (5 fast
// failures during a transient network blip) and silence (one
// failure followed by 30 s of nothing, which a count-only check
// would never trip).
const (
	selfHealFailureThreshold = 5
	selfHealStaleWindow      = 30 * time.Second
)

// defaultConsentProbeInterval is how often the consent-freshness
// loop sends a STUN BindingRequest to the TURN server to verify
// the allocation is still alive. Derived from RFC 7675's consent-
// freshness model — that spec uses 4-6 s for WebRTC media paths.
// For our long-lived control-plane allocations 30 s is the right
// balance: low enough that a stuck pion is detected within a
// minute or two (5 failures × 30 s = ~2.5 min worst-case), high
// enough that idle daemons don't spam the TURN server.
//
// The probe target is the TURN server's STUN address itself, NOT
// any peer — a 1 RTT round-trip that proves "pion can talk to
// the allocation server." If pion's allocation is half-dead,
// permission refresh failing, or the underlying socket has gone
// silent, the probe will time out and recordFailure() bumps the
// self-heal counter.
const defaultConsentProbeInterval = 30 * time.Second

// selfHealBackoffSchedule is the exponential-ish retry budget used
// by selfHealLoop after a heal attempt. Mirrors jf.13's
// peerKeepaliveLoop / jf.14.2's rendezvousRefreshLoop bounded-
// retry pattern; the 5-minute cap stops a persistently-broken
// allocation (e.g. Cloudflare TURN outage in the peer's region)
// from burning the API rate-limit budget.
var selfHealBackoffSchedule = []time.Duration{
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
	60 * time.Second,
	5 * time.Minute,
}

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
	client   *turn.Client   // current pion TURN client; nil before Listen, nil after Close
	relay    net.PacketConn // current assigned relay socket
	peerSock net.PacketConn // raw socket underneath the client (kept for Close)
	provider turncreds.Provider
	sink     chan<- InboundFrame

	closeCh chan struct{}
	wg      sync.WaitGroup
	closed  bool

	getTimeout time.Duration

	// permittedAddrs records host:port strings for which we want a
	// CreatePermission on the current pion client. The address is
	// recorded before the pion call succeeds so a broken allocation
	// cannot make us forget the permission target; rotate/self-heal
	// replays this desired set against the next allocation.
	// Value is the wall-clock of the last refresh attempt; used only
	// for diagnostics / future eviction. Protected by mu.
	permittedAddrs map[string]time.Time

	// permissionRefreshInterval controls how often the refresh loop
	// re-issues CreatePermission for every address in permittedAddrs.
	// Default 4 minutes; overridable via setPermissionRefreshInterval
	// for tests.
	permissionRefreshInterval time.Duration

	// onLocalAddrChange, if non-nil, is invoked synchronously
	// (outside the mu lock) whenever the server-assigned relay
	// address changes — initial Allocate succeeds, or a re-allocation
	// follows credential rotation / expiry recovery. Callbacks must
	// be short and non-blocking; they fire on the same goroutine
	// that completes Listen() / rotate(). Set via
	// SetOnLocalAddrChange. (v1.9.0-jf.11b)
	onLocalAddrChange func(string)

	// jf.15 self-heal state. Tracks pion-client health by counting
	// consecutive transport failures (SendViaOwnRelay errors and
	// CreatePermission errors) and the wall time of the last
	// success. selfHealLoop watches selfHealCh; when nudged it
	// fetches fresh credentials and calls rotate() (atomic swap)
	// to rebuild the allocation. Backoff is bounded by
	// selfHealBackoffSchedule.
	//
	// Why two signals (count AND time): a few fast failures during
	// a transient blip shouldn't trigger heal; a single failure
	// followed by 30 s of silence shouldn't trigger either. Both
	// gates must pass.
	lastSuccessNano     atomic.Int64  // unix nanos of most recent success; >0 once any op has succeeded
	consecutiveFailures atomic.Int64  // resets on success, increments on every transport failure
	selfHealCh          chan struct{} // length-1 nudge from failure-detect path
	selfHealAttempt     int           // backoff index (protected by mu)
	selfHealRunning     bool          // serializes concurrent runSelfHeal calls (protected by mu)

	// consentProbeInterval controls how often consentLoop
	// (jf.15.1) sends a STUN BindingRequest to the TURN
	// server. Default defaultConsentProbeInterval (30 s);
	// overridable via setConsentProbeInterval for tests.
	consentProbeInterval time.Duration
}

// NewTURNTransport constructs a TURNTransport. The provider lifetime is
// owned by the caller (the daemon closes its own provider on shutdown);
// Close here does not touch the provider. The sink may be overridden by
// Listen's sink argument, mirroring tcp.go's convention.
func NewTURNTransport(provider turncreds.Provider, sink chan<- InboundFrame) *TURNTransport {
	return &TURNTransport{
		provider:                  provider,
		sink:                      sink,
		closeCh:                   make(chan struct{}),
		getTimeout:                defaultTURNGetTimeout,
		permittedAddrs:            make(map[string]time.Time),
		permissionRefreshInterval: defaultPermissionRefreshInterval,
		selfHealCh:                make(chan struct{}, 1),
		consentProbeInterval:      defaultConsentProbeInterval,
	}
}

// setPermissionRefreshInterval is a test-only hook that overrides how
// often the refresh loop re-issues CreatePermission. Must be called
// before Listen. The runtime invariant is [>= 1ms]; zero or negative
// values keep the default.
func (t *TURNTransport) setPermissionRefreshInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	t.mu.Lock()
	t.permissionRefreshInterval = d
	t.mu.Unlock()
}

// setConsentProbeInterval is the jf.15.1 test hook for the active
// consent-freshness loop's cadence. Same shape as
// setPermissionRefreshInterval. Must be called before Listen.
func (t *TURNTransport) setConsentProbeInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	t.mu.Lock()
	t.consentProbeInterval = d
	t.mu.Unlock()
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

	// v1.9.0-jf.11b: notify subscribers (entmootd's gossip advertiser
	// via the IPC pub/sub primitive) of the new relay address so they
	// can re-publish a fresh transport_ad without waiting for a poll
	// tick.
	t.fireLocalAddrChange()

	t.wg.Add(1)
	go t.readerLoop(relay)

	t.wg.Add(1)
	go t.rotationLoop()

	t.wg.Add(1)
	go t.permissionRefreshLoop()

	// jf.15: self-heal loop. Watches selfHealCh for nudges from
	// recordFailure and atomically rebuilds the pion client +
	// allocation when the consent-freshness threshold trips. Mirrors
	// rotationLoop's shape but reacts to TRANSPORT FAILURE rather
	// than CREDENTIAL ROTATION. Inert until a real failure burst
	// nudges it.
	t.wg.Add(1)
	go t.selfHealLoop()

	// jf.15.1: active consent-freshness probe. Sends a STUN
	// BindingRequest to the TURN server every consentProbeInterval
	// (default 30 s). If the allocation is half-dead — pion's
	// internal state silent, permission refresh hung, underlying
	// socket broken — the probe times out and feeds recordFailure.
	// Without this loop, the only failure detectors were
	// SendViaOwnRelay (only fires when something tries to send) and
	// CreatePermission (only fires on explicit refresh paths).
	// A stuck pion with no traffic stayed stuck forever.
	t.wg.Add(1)
	go t.consentLoop()

	// Stamp lastSuccessNano so the first transport failure doesn't
	// trigger heal on a stale "0" timestamp (which would breach the
	// 30 s window immediately).
	t.lastSuccessNano.Store(time.Now().UnixNano())

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

// SetOnLocalAddrChange registers a callback invoked synchronously
// whenever the server-assigned relay address changes — initial
// Allocate, and any subsequent re-allocation triggered by credential
// rotation or expiry recovery. Pass nil to clear. fn must be short
// and non-blocking; it runs on the goroutine that completed
// Listen() or rotate(). Used by the daemon to publish a
// "turn_endpoint" CmdNotify to subscribed IPC clients (entmootd's
// gossip advertiser). (v1.9.0-jf.11b)
func (t *TURNTransport) SetOnLocalAddrChange(fn func(string)) {
	t.mu.Lock()
	t.onLocalAddrChange = fn
	t.mu.Unlock()
}

// fireLocalAddrChange invokes onLocalAddrChange (if registered) with
// the current relay address. Must be called WITHOUT t.mu held — the
// callback is opaque to us and we don't want to deadlock with code
// in the daemon that reads tunnel state under its own locks.
// (v1.9.0-jf.11b)
func (t *TURNTransport) fireLocalAddrChange() {
	t.mu.RLock()
	fn := t.onLocalAddrChange
	var addr string
	if t.relay != nil {
		addr = t.relay.LocalAddr().String()
	}
	t.mu.RUnlock()
	if fn != nil {
		fn(addr)
	}
}

// SendViaOwnRelay writes frame through our own TURN allocation to an
// arbitrary peer address. The peer observes source = our relay's
// anycast address (e.g. Cloudflare TURN), never our real IP. Used by
// writeFrame in -outbound-turn-only mode to reach peers that have
// NOT advertised their own TURN endpoint — the canonical WebRTC
// `iceTransportPolicy: "relay"` semantic (RFC 8828 Mode 3).
//
// Permission management is handled automatically by pion: the first
// WriteTo for a given destination IP triggers an internal
// CreatePermission; a background goroutine refreshes every ~4 min so
// long-lived destinations stay permissioned. Callers do not need to
// pre-permission via CreatePermission for this path.
//
// Returns error if the transport isn't listening, peerAddr is nil,
// or the underlying UDP WriteTo fails (network error, allocation
// expired, etc.). Does NOT itself gate on peer advertisement — the
// decision "should I route this peer via my own TURN?" is made by
// the caller (writeFrame). v1.9.0-jf.11a.2.
func (t *TURNTransport) SendViaOwnRelay(peerAddr net.Addr, frame []byte) error {
	if peerAddr == nil {
		return errors.New("turn transport: nil peer address")
	}
	t.mu.RLock()
	relay := t.relay
	t.mu.RUnlock()
	if relay == nil {
		return errors.New("turn transport: not listening")
	}
	_, err := relay.WriteTo(frame, peerAddr)
	if err != nil {
		t.recordTURNError(err)
	} else {
		t.recordSuccess()
	}
	return err
}

// CreatePermission proactively installs a TURN permission for addr
// (host:port) on the current allocation so inbound datagrams from
// that address are admitted by the server. Returns an error if the
// transport isn't listening, the address is malformed, or pion's
// CreatePermission errors.
//
// Idempotent: calling twice with the same addr refreshes the
// permission by re-issuing CreatePermission against the current
// client and updating the last-refreshed timestamp. A background
// refresh loop (Listen-scoped) re-issues permissions every
// permissionRefreshInterval so idle permissions don't silently
// expire; rotations transparently re-permit every known address
// against the new client.
//
// This is the "hide-ip side" of the asymmetric-TURN flow: a daemon
// running TURN with -hide-ip calls CreatePermission (via
// TunnelManager.PermitTURNPeer) for every peer that might dial its
// relayed address, so the peer's first unsolicited datagram isn't
// dropped for lack of permission.
func (t *TURNTransport) CreatePermission(addr string) error {
	if addr == "" {
		return errors.New("turn transport: empty permission address")
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("turn transport: resolve %q: %w", addr, err)
	}

	t.mu.RLock()
	client := t.client
	closed := t.closed
	t.mu.RUnlock()
	if closed {
		return errors.New("turn transport: closed")
	}
	if client == nil {
		return errors.New("turn transport: not listening")
	}

	now := time.Now()
	t.mu.Lock()
	if t.permittedAddrs == nil {
		t.permittedAddrs = make(map[string]time.Time)
	}
	t.permittedAddrs[addr] = now
	t.mu.Unlock()

	if err := client.CreatePermission(ua); err != nil {
		t.recordTURNError(err)
		return fmt.Errorf("turn create permission %s: %w", addr, err)
	}
	t.recordSuccess()

	t.mu.Lock()
	t.permittedAddrs[addr] = time.Now()
	t.mu.Unlock()
	return nil
}

// PermittedAddrs returns a snapshot of the addresses for which we
// have an active CreatePermission recorded. Exposed for diagnostics
// and for TunnelManager's bookkeeping; the slice is a copy and safe
// to mutate.
func (t *TURNTransport) PermittedAddrs() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.permittedAddrs))
	for a := range t.permittedAddrs {
		out = append(out, a)
	}
	return out
}

// permissionRefreshLoop periodically re-issues CreatePermission for
// every address in permittedAddrs against the current pion client.
// Without this, permissions expire after ~5 minutes of idle and the
// TURN server begins dropping inbound datagrams from that peer. The
// loop exits on closeCh.
func (t *TURNTransport) permissionRefreshLoop() {
	defer t.wg.Done()

	t.mu.RLock()
	interval := t.permissionRefreshInterval
	t.mu.RUnlock()
	if interval <= 0 {
		interval = defaultPermissionRefreshInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.closeCh:
			return
		case <-ticker.C:
			t.refreshAllPermissions()
		}
	}
}

// refreshAllPermissions re-issues CreatePermission for every
// permitted address against the current pion client. Each failed
// refresh is logged at WARN but does not interrupt the loop; the
// next tick (or the next rotation) will retry. Snapshots addresses
// under RLock and calls pion without the mutex so the refresh can't
// serialize behind a concurrent rotate/swap.
func (t *TURNTransport) refreshAllPermissions() {
	t.mu.RLock()
	client := t.client
	addrs := make([]string, 0, len(t.permittedAddrs))
	for a := range t.permittedAddrs {
		addrs = append(addrs, a)
	}
	t.mu.RUnlock()
	if client == nil || len(addrs) == 0 {
		return
	}

	now := time.Now()
	for _, addr := range addrs {
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			slog.Warn("turn: permission refresh resolve failed; dropping",
				"addr", addr, "error", err)
			t.mu.Lock()
			delete(t.permittedAddrs, addr)
			t.mu.Unlock()
			continue
		}
		if err := client.CreatePermission(ua); err != nil {
			slog.Warn("turn: permission refresh failed",
				"addr", addr, "error", err)
			// jf.15.1: feed periodic-refresh failures into the
			// self-heal counter. The earlier code path
			// (refreshAllPermissions) bypassed t.CreatePermission's
			// recordFailure() hook, so a stuck pion never
			// triggered heal even when its internal permission
			// refreshes were failing for hours. Now both code
			// paths converge on the same health signal.
			t.recordTURNError(err)
			continue
		}
		t.recordSuccess()
		t.mu.Lock()
		if _, ok := t.permittedAddrs[addr]; ok {
			t.permittedAddrs[addr] = now
		}
		t.mu.Unlock()
	}
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
	hasRelay := t.relay != nil
	t.mu.RUnlock()
	if !hasRelay {
		return nil, errors.New("turn transport: not listening")
	}

	// Install an explicit permission for the peer's IP. pion's WriteTo
	// side auto-permits the destination, but nothing on our side's
	// allocation permits incoming traffic from the peer until we call
	// CreatePermission. Without this step, the peer's Send indication
	// arrives on our relay and is dropped by our allocation for lack
	// of permission.
	if err := t.CreatePermission(tep.addr.String()); err != nil {
		return nil, err
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
	// Snapshot the permitted addresses while we still hold the lock so
	// the re-permission pass below sees a consistent set. We re-issue
	// CreatePermission on the new client BEFORE closing the old one so
	// any in-flight inbound datagrams aren't dropped during the swap.
	repermit := make([]string, 0, len(t.permittedAddrs))
	for a := range t.permittedAddrs {
		repermit = append(repermit, a)
	}
	t.mu.Unlock()

	// Re-issue permissions on the new client. Failures are logged but
	// non-fatal; the permission refresh loop will retry at the next
	// tick. Do this outside the mutex so a slow pion transaction
	// doesn't block concurrent Sends / Dials.
	for _, addr := range repermit {
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			slog.Warn("turn: rotate re-permission resolve failed",
				"addr", addr, "error", err)
			continue
		}
		if err := newClient.CreatePermission(ua); err != nil {
			slog.Warn("turn: rotate re-permission failed",
				"addr", addr, "error", err)
			continue
		}
	}

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

	// v1.9.0-jf.11b: notify subscribers of the new relay address.
	// Cloudflare hands out a new port on each Allocate (the typical
	// rotation case), so this is the moment subscribers must know
	// about — otherwise they keep advertising the previous (now
	// dead) allocation in transport_ads.
	t.fireLocalAddrChange()
}

// consentLoop is the active health probe added in jf.15.1. It
// periodically calls pion's SendBindingRequest against the TURN
// server itself — the canonical RFC 7675 STUN-binding probe.
// Success → recordSuccess (zeros the failure counter); failure
// → recordFailure (which may trigger heal once the threshold
// trips).
//
// This catches the case where pion's INTERNAL state has gone
// silent (allocation half-dead, permission refresh thread
// hung, underlying socket broken) but no peer has tried to
// SendViaOwnRelay recently. Without an active probe, a stuck
// pion stays stuck indefinitely if no traffic flows.
//
// Cadence is t.consentProbeInterval (default 30 s) with
// startup jitter to spread fleet-wide ticks. Per-call
// transaction has its own internal timeout inside pion;
// failures surface as a returned error.
//
// (v1.9.0-jf.15.1)
func (t *TURNTransport) consentLoop() {
	defer t.wg.Done()

	t.mu.RLock()
	interval := t.consentProbeInterval
	t.mu.RUnlock()
	if interval <= 0 {
		interval = defaultConsentProbeInterval
	}

	// Jitter so a fleet-wide restart doesn't synchronize probes.
	// Pick from [0, interval/4) — small, just enough to avoid
	// lockstep.
	jitter := time.Duration(0)
	if interval >= 4*time.Millisecond {
		jitter = time.Duration(int64(interval) / 4)
		if jitter > 0 {
			jitter = time.Duration(timeNow().UnixNano() % int64(jitter))
		}
	}
	select {
	case <-t.closeCh:
		return
	case <-time.After(jitter):
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-t.closeCh:
			return
		case <-ticker.C:
			t.runConsentProbe()
		}
	}
}

// runConsentProbe performs one consent-freshness check by
// asking pion to send a STUN BindingRequest to the TURN server.
// If the allocation is healthy, pion gets back a XOR-MAPPED-
// ADDRESS attribute and we recordSuccess. If the binding-request
// transaction fails (timeout, server rejection, transport
// error), we recordFailure — which feeds the same self-heal
// counter as SendViaOwnRelay/CreatePermission failures.
//
// Snapshot client under RLock so a concurrent rotate() can't
// race with us; the actual transaction runs without t.mu held
// because pion's PerformTransaction can take seconds and we
// don't want to serialize Send paths behind it.
func (t *TURNTransport) runConsentProbe() {
	t.mu.RLock()
	client := t.client
	closed := t.closed
	t.mu.RUnlock()
	if closed || client == nil {
		return
	}
	if _, err := client.SendBindingRequest(); err != nil {
		slog.Debug("turn: consent probe failed",
			"error", err)
		t.recordTURNError(err)
		return
	}
	t.recordSuccess()
}

// timeNow is a swappable wall-clock used by consentLoop's
// jitter pick. Tests can override; production uses time.Now.
var timeNow = time.Now

// recordSuccess marks the most recent allocation operation
// (SendViaOwnRelay or CreatePermission) as successful: stamps
// the success timestamp and resets the consecutive-failures
// counter. Atomic-only; no lock held.
//
// (v1.9.0-jf.15)
func (t *TURNTransport) recordSuccess() {
	t.lastSuccessNano.Store(time.Now().UnixNano())
	t.consecutiveFailures.Store(0)
}

// recordFailure increments the consecutive-failure counter and,
// if both the count threshold AND the staleness window are
// breached, nudges the self-heal loop. The two-axis check
// follows RFC 7675: we declare the path dead only when N
// consecutive failures coincide with a long-enough silence
// window (default 30 s). This prevents heal-on-noise (a fast
// burst of 5 failures inside a 1 s blip) and heal-on-staleness
// (one failure at startup followed by 30 s of silence).
//
// Atomic load+CAS-style; safe to call concurrently from any
// transport-hot path.
//
// (v1.9.0-jf.15)
func (t *TURNTransport) recordFailure() {
	fails := t.consecutiveFailures.Add(1)
	if fails < int64(selfHealFailureThreshold) {
		return
	}
	lastNs := t.lastSuccessNano.Load()
	// lastNs == 0 when no operation has ever succeeded since Listen.
	// In that case the threshold count alone is the trigger — there's
	// no useful "time since last success" to compare against.
	if lastNs > 0 {
		elapsed := time.Since(time.Unix(0, lastNs))
		if elapsed < selfHealStaleWindow {
			return
		}
	}
	// Non-blocking nudge: if the channel is already full, the loop
	// will already process when it picks up the existing signal.
	t.nudgeSelfHeal()
}

func (t *TURNTransport) recordTURNError(err error) {
	if isFatalTURNError(err) {
		t.recordFatalFailure(err)
		return
	}
	t.recordFailure()
}

func (t *TURNTransport) recordFatalFailure(err error) {
	t.consecutiveFailures.Add(1)
	if t.nudgeSelfHeal() {
		slog.Warn("turn: fatal transport error; triggering self-heal",
			"error", err)
	}
}

func (t *TURNTransport) nudgeSelfHeal() bool {
	select {
	case t.selfHealCh <- struct{}{}:
		return true
	default:
		return false
	}
}

func isFatalTURNError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "sendto: cannot allocate memory") ||
		strings.Contains(text, "no buffer space available") ||
		strings.Contains(text, "use of closed network connection")
}

// selfHealLoop is the goroutine that responds to recordFailure
// nudges by rebuilding the pion TURN client + allocation. Mirrors
// the rotationLoop/permissionRefreshLoop shape: select on
// closeCh + signal channel, exit on shutdown.
//
// Backoff is bounded (selfHealBackoffSchedule, 5 s -> 5 min cap)
// so a persistently-broken allocation (e.g. a Cloudflare regional
// outage) doesn't burn API budget. The attempt counter resets
// only on a successful rebuild.
//
// (v1.9.0-jf.15)
func (t *TURNTransport) selfHealLoop() {
	defer t.wg.Done()
	for {
		select {
		case <-t.closeCh:
			return
		case <-t.selfHealCh:
			t.runSelfHeal()
		}
	}
}

// runSelfHeal performs one rebuild attempt: fetches fresh
// credentials from the provider (cached values are fine —
// rebuilding the allocation is independent of credential
// rotation, and the provider's cache is exactly what we want)
// and calls rotate() to do the atomic swap.
//
// Serializes with itself via selfHealRunning so a flood of
// nudges during the rebuild window doesn't fan out to multiple
// concurrent rotates. Concurrent rotation from rotationLoop is
// still safe (rotate() is idempotent under the same mutex), but
// avoiding waste matters — each rotate call burns one Cloudflare
// Allocate request.
func (t *TURNTransport) runSelfHeal() {
	t.mu.Lock()
	if t.selfHealRunning {
		t.mu.Unlock()
		return
	}
	t.selfHealRunning = true
	attempt := t.selfHealAttempt
	provider := t.provider
	closed := t.closed
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		t.selfHealRunning = false
		t.mu.Unlock()
	}()

	if closed || provider == nil {
		return
	}

	// Apply backoff for this attempt before fetching credentials.
	// Skip the wait for attempt 0 (first heal after fresh failure
	// burst) — operators expect rapid recovery on the first try.
	if attempt > 0 {
		backoff := selfHealBackoffSchedule[len(selfHealBackoffSchedule)-1]
		if attempt-1 < len(selfHealBackoffSchedule) {
			backoff = selfHealBackoffSchedule[attempt-1]
		}
		slog.Debug("turn: self-heal: backing off before retry",
			"attempt", attempt, "backoff", backoff)
		select {
		case <-t.closeCh:
			return
		case <-time.After(backoff):
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), t.getTimeout)
	creds, err := provider.Get(ctx)
	cancel()
	if err != nil {
		slog.Warn("turn: self-heal: provider.Get failed",
			"attempt", attempt, "error", err)
		t.bumpHealAttempt()
		// Re-arm: another nudge is harmless (selfHealCh is len-1).
		// Without this, a Get-failure on attempt 0 leaves the loop
		// idle until the next transport failure — which can be a
		// long way off if writeFrame is fail-closing.
		select {
		case t.selfHealCh <- struct{}{}:
		default:
		}
		return
	}

	relayBefore := t.relay // for diagnostics only
	t.rotate(creds)
	t.mu.RLock()
	relayAfter := t.relay
	t.mu.RUnlock()

	if relayBefore == relayAfter {
		// rotate() failed to swap — keep backing off.
		t.bumpHealAttempt()
		select {
		case t.selfHealCh <- struct{}{}:
		default:
		}
		return
	}

	// Success — reset attempt + counters so the next failure burst
	// has a fresh budget.
	t.mu.Lock()
	t.selfHealAttempt = 0
	t.mu.Unlock()
	t.consecutiveFailures.Store(0)
	t.lastSuccessNano.Store(time.Now().UnixNano())

	slog.Info("turn: self-heal completed (allocation rebuilt)",
		"new_relay", relayAfter.LocalAddr())
}

func (t *TURNTransport) bumpHealAttempt() {
	t.mu.Lock()
	t.selfHealAttempt++
	t.mu.Unlock()
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
		c.transport.recordTURNError(err)
		return fmt.Errorf("turn write to %s: %w", c.peerAddr, err)
	}
	c.transport.recordSuccess()
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

// turnRelayDialedConn is the DialedConn implementation for the
// asymmetric-TURN path: a dialer without its own TURN allocation
// sends raw UDP through the shared UDP socket to the peer's TURN
// relay address. The TURN server accepts these datagrams when the
// hide-ip peer has proactively issued a CreatePermission for the
// sender's source IP (see TURNTransport.CreatePermission).
//
// There is no pion client on this side of the link — just the
// shared *UDPTransport and the peer's resolved relay address.
// Send reuses UDPTransport.WriteToUDPAddr, the same escape-hatch
// used by NAT punch and beacon registration.
//
// Identified by Name() == "turn-relay" so writeFrame's cached-conn
// filter (which excludes "udp") lets it through.
type turnRelayDialedConn struct {
	udp      *UDPTransport
	peerAddr *net.UDPAddr
	remote   *TURNEndpoint
	sendMu   sync.Mutex
	closed   atomic.Bool
}

// Name returns "turn-relay". Distinguishes this conn from the pion-
// backed "turn" conn in writeFrame's cached-conn precedence logic.
func (c *turnRelayDialedConn) Name() string { return "turn-relay" }

// Send writes frame to the peer's TURN relay address via the shared
// UDP socket. Serialized behind sendMu so concurrent callers don't
// interleave with an observable error from the underlying
// WriteToUDPAddr (matching turnDialedConn's serialization).
// Returns an error if the conn has been closed.
func (c *turnRelayDialedConn) Send(frame []byte) error {
	if c.closed.Load() {
		return errors.New("turn-relay: closed")
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if _, err := c.udp.WriteToUDPAddr(frame, c.peerAddr); err != nil {
		return fmt.Errorf("turn-relay write to %s: %w", c.peerAddr, err)
	}
	return nil
}

// RemoteEndpoint returns the peer's TURN endpoint. Stable for the
// lifetime of the conn.
func (c *turnRelayDialedConn) RemoteEndpoint() Endpoint {
	return c.remote
}

// Close marks the conn as closed; subsequent Sends fail. No-op on
// the wire — UDP is connectionless and the shared socket belongs
// to the UDPTransport, not this conn. Idempotent via atomic CAS.
func (c *turnRelayDialedConn) Close() error {
	c.closed.Store(true)
	return nil
}

// DialTURNRelayViaUDP returns a DialedConn that sends raw UDP frames
// to ep's relay address using udp as the outbound socket. No pion
// client is required on the caller side — this is the "I don't have
// TURN locally, but I need to reach a peer who does" path.
//
// The caller (TunnelManager.DialTURNRelayForPeer) is responsible for
// choosing between this path and the symmetric turnDialedConn path
// when both daemons have local TURN allocations.
//
// Errors: nil endpoint, endpoint with no underlying UDPAddr, or a
// non-listening UDP transport.
func DialTURNRelayViaUDP(udp *UDPTransport, ep *TURNEndpoint) (*turnRelayDialedConn, error) {
	if udp == nil {
		return nil, errors.New("turn-relay: nil udp transport")
	}
	if ep == nil {
		return nil, errors.New("turn-relay: nil endpoint")
	}
	if ep.addr == nil {
		return nil, errors.New("turn-relay: endpoint has nil addr")
	}
	if udp.Conn() == nil {
		return nil, errors.New("turn-relay: udp transport not listening")
	}
	return &turnRelayDialedConn{
		udp:      udp,
		peerAddr: ep.addr,
		remote:   ep,
	}, nil
}
