package daemon

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/gossip"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// replayWindowSize is the number of nonces tracked in the sliding window bitmap
// for replay detection (H8 fix). Nonces within [maxNonce-replayWindowSize, maxNonce]
// are tracked; nonces below the window are rejected.
const replayWindowSize = 256

// peerCrypto holds per-peer encryption state.
type peerCrypto struct {
	aead        cipher.AEAD
	nonce       uint64  // monotonic send counter (atomic)
	noncePrefix [4]byte // random prefix for nonce domain separation
	// Replay detection (H8 fix): sliding window bitmap instead of simple high-water mark.
	replayMu      sync.Mutex
	maxRecvNonce  uint64                        // highest nonce received
	replayBitmap  [replayWindowSize / 64]uint64 // bitmap for nonces in [max-windowSize, max]
	ready         bool                          // true once key exchange is complete
	authenticated bool                          // true if peer proved Ed25519 identity
	peerX25519Key [32]byte                      // peer's X25519 public key (for detecting rekeying)
}

// checkAndRecordNonce returns true if the nonce is valid (not replayed, not too old).
// Must be called with replayMu held.
//
// Note on nonce wraparound: the counter is uint64, so it wraps after 2^64 packets.
// At 1 billion packets/sec this takes ~585 years — purely theoretical. If a
// connection ever approaches this limit, rekeying (new secure handshake) resets
// the counter naturally.
func (pc *peerCrypto) checkAndRecordNonce(counter uint64) bool {
	if pc.maxRecvNonce == 0 {
		// First packet ever
		pc.maxRecvNonce = counter
		pc.setReplayBit(counter)
		return true
	}

	if counter > pc.maxRecvNonce {
		// New maximum — shift window forward
		shift := counter - pc.maxRecvNonce
		if shift >= replayWindowSize {
			// Clear entire bitmap
			pc.replayBitmap = [replayWindowSize / 64]uint64{}
		} else {
			// Clear the new positions that the shifted window will occupy
			for s := uint64(0); s < shift; s++ {
				newBit := (counter - s) % replayWindowSize
				pc.replayBitmap[newBit/64] &^= 1 << (newBit % 64)
			}
		}
		pc.maxRecvNonce = counter
		pc.setReplayBit(counter)
		return true
	}

	// counter <= maxRecvNonce
	diff := pc.maxRecvNonce - counter
	if diff >= replayWindowSize {
		return false // too old
	}

	// Check if already seen
	bit := counter % replayWindowSize
	if pc.replayBitmap[bit/64]&(1<<(bit%64)) != 0 {
		return false // replay
	}
	pc.setReplayBit(counter)
	return true
}

func (pc *peerCrypto) setReplayBit(counter uint64) {
	bit := counter % replayWindowSize
	pc.replayBitmap[bit/64] |= 1 << (bit % 64)
}

// TunnelManager manages tunnels to peer daemons. Bytes travel over
// one of several pluggable transports (UDP today, TCP as an optional
// fallback for UDP-hostile networks, QUIC/WebSocket/… in the future).
// The socket lifecycle for each transport lives inside
// pkg/daemon/transport; TunnelManager picks which transport to use
// for each peer based on the advertised endpoints and a preference
// order.
type TunnelManager struct {
	mu      sync.RWMutex
	udp     *transport.UDPTransport     // owns the UDP socket; nil before Listen
	tcp     *transport.TCPTransport     // optional TCP fallback; nil when `-tcp-listen` is not set
	turn    *transport.TURNTransport    // optional TURN relay; nil when `-turn-provider` is empty
	inbound chan transport.InboundFrame // sink every transport writes to; dispatchLoop reads

	// paths is the single source of truth for how to reach each peer.
	// It replaces the pre-v1.9.0-jf.4 pair (peers map[uint32]*net.UDPAddr
	// + relayPeers map[uint32]bool) which had two independent failure
	// modes:
	//   1. Asymmetric relay state — each side's relayPeers[peer] bit
	//      drifted independently. A sent via relay, B's map still said
	//      "A is direct", B's reply went to a stale direct addr, black
	//      hole. Bug observable from live three-way test, not a v1.9.x
	//      regression — predates the fork.
	//   2. handleRelayDeliver wrote beaconAddr into peers[peer] as a
	//      placeholder, which poisoned the v1.9.0-jf.2 NAT-drift
	//      refresh, same-LAN detection, and accounting.
	// The reply-on-ingress design (WireGuard, Tailscale DERP, libp2p
	// Circuit Relay v2) records the path the last authenticated frame
	// arrived on and always replies there. No cross-daemon coordination
	// needed; symmetry falls out of the per-peer state.
	paths     map[uint32]*peerPath              // node_id → last-authenticated ingress path
	peerTCP   map[uint32]*transport.TCPEndpoint // node_id → TCP endpoint, populated from registry lookup when advertised
	peerTURN  map[uint32]*transport.TURNEndpoint // node_id → TURN relayed endpoint, populated from SetPeerEndpoints
	peerConns map[uint32]transport.DialedConn   // node_id → cached DialedConn (whichever transport won the last Dial)

	// turnPermittedPeers records host:port strings for which we have
	// issued CreatePermission on the local TURN allocation (via
	// PermitTURNPeer). Value is the wall-clock of the first
	// observation. Entries are evicted after
	// turnPermittedPeerEvictTTL of no re-observation so the set stays
	// bounded under peer churn. Only populated when tm.turn != nil.
	turnPermittedPeers map[string]time.Time

	// outboundTURNOnly, when true, forces writeFrame to route EVERY
	// outbound frame through the local TURN allocation. Set from
	// Config.OutboundTURNOnly in daemon.Start() before any frames
	// flow. Read-mostly thereafter; guarded by tm.mu because
	// writeFrame reads it under RLock alongside other fields. v1.9.0-jf.11a.
	outboundTURNOnly bool
	crypto    map[uint32]*peerCrypto            // node_id → encryption state
	recvCh    chan *IncomingPacket
	done      chan struct{}  // closed on Close() to stop dispatchLoop
	readWg    sync.WaitGroup // tracks dispatchLoop goroutine for clean shutdown
	closeOnce sync.Once

	// Encryption config
	encrypt bool             // if true, attempt encrypted tunnels
	privKey *ecdh.PrivateKey // our X25519 private key
	pubKey  []byte           // our X25519 public key (32 bytes)
	nodeID  uint32           // our node ID (set after registration)

	// Identity authentication (Ed25519)
	identity    *crypto.Identity                        // our Ed25519 identity for signing
	peerPubKeys map[uint32]ed25519.PublicKey            // node_id → Ed25519 pubkey (from registry)
	verifyFunc  func(uint32) (ed25519.PublicKey, error) // callback to fetch peer pubkey

	// Per-peer capability bitmap, learned from the trailing varint
	// appended to authenticated key-exchange (PILA) frames. Older
	// daemons don't append anything; for them caps stays 0 and the
	// engine will skip sending them gossip frames. See gossip.CapGossip
	// for bit definitions.
	peerCaps map[uint32]uint64

	// lastRecoveryPILA bounds how often we emit an unsolicited PILA
	// to a peer we have no crypto state for. See
	// maybeSendRecoveryPILA for the full story. Rate-limited to
	// avoid any amplification-loop concern if a peer (or attacker)
	// keeps feeding us un-decryptable frames.
	lastRecoveryPILA map[uint32]time.Time
	// Our own capability bitmap, appended to outbound PILA frames so
	// peers can learn that we support gossip. Zero when the daemon
	// hasn't opted in (e.g. during tests, or pre-engine bootstrap).
	localCaps uint64

	// Pending sends waiting for key exchange to complete
	pendMu  sync.Mutex
	pending map[uint32][][]byte // node_id → queued frames

	// NAT traversal: beacon-coordinated hole-punching and relay.
	// Relay status is tracked per-peer in `paths` (above); the legacy
	// relayPeers map was removed in v1.9.0-jf.4 in favor of
	// reply-on-ingress routing.
	beaconAddr *net.UDPAddr // beacon address for punch/relay

	// Rekey notification: invoked with peer node_id after a tunnel rekey completes.
	// The daemon uses this to reset per-connection keepalive counters on affected
	// connections so that ACKs dropped during the key swap don't trip dead-peer
	// detection.
	rekeyCallback func(uint32)

	// Gossip: the additive peer-discovery layer's membership view.
	// Populated as a side-effect of registry lookups (registry-sourced
	// entries) and, once the gossip Engine is wired in (Phase C+D),
	// by inbound gossip frames. Phase B leaves this unused by the
	// dial path; only the populate-side plumbing lands here.
	gossipView *gossip.MembershipView

	// Webhook
	webhook *WebhookClient

	// Metrics
	BytesSent   uint64
	BytesRecv   uint64
	PktsSent    uint64
	PktsRecv    uint64
	EncryptOK   uint64
	EncryptFail uint64
}

type IncomingPacket struct {
	Packet *protocol.Packet
	From   *net.UDPAddr
}

// peerPath is the per-peer "how to reach them" state.
//
//   - direct: last UDP endpoint from which we successfully decrypted +
//     authenticated a frame sent direct (not via relay). Nil if we have
//     never seen a direct frame from this peer. Updated opportunistically
//     so that if direct connectivity comes back after a relay-only
//     period, we prefer direct.
//
//   - viaRelay: true if the last authenticated frame from this peer
//     arrived via the beacon relay. When true, writeFrame routes
//     outbound traffic through the beacon. When false and `direct` is
//     set, writeFrame sends direct. When false and `direct` is nil,
//     writeFrame falls back to the caller-supplied address (bootstrap
//     during registry-resolve; the addr will be replaced by the first
//     authenticated decrypt).
//
//   - lastSeen: wall-clock of the last authenticated decrypt. Not
//     currently consumed by routing decisions; kept for future
//     staleness heuristics and debugging (pilotctl peers).
//
// Consistency rule: both fields are updated by the three authenticated
// decrypt paths (handleAuthKeyExchange, handleKeyExchange,
// handleEncrypted). Only the direct field is "promoted" on inbound
// direct frames; inbound relay frames flip viaRelay to true but do
// not overwrite direct. This way a peer that is currently relay-only
// still has its last-known-good direct addr in place for the next
// time we get a direct frame from them.
type peerPath struct {
	direct   *net.UDPAddr
	viaRelay bool
	lastSeen time.Time
}

// turnPermittedPeerEvictTTL is how long an entry stays in
// turnPermittedPeers after its last refresh. A peer that goes silent
// for longer than this is assumed gone; we drop the bookkeeping so the
// set doesn't grow unbounded under churn. The underlying pion
// permission will expire on the server side shortly after we stop
// refreshing it (RFC 8656 §9.2 — 5 minute idle expiry).
const turnPermittedPeerEvictTTL = 30 * time.Minute

// turnPermittedPeerEvictInterval is how often the eviction goroutine
// wakes up to scan turnPermittedPeers for entries past TTL.
const turnPermittedPeerEvictInterval = 5 * time.Minute

// maxPendingPerPeer limits how many packets can be queued per peer
// while waiting for key exchange to complete. Prevents unbounded growth
// if key exchange is slow or fails.
const maxPendingPerPeer = 64

// maxPendingPeers limits the total number of peers with pending key exchanges.
const maxPendingPeers = 256

// RecvChSize is the capacity of the incoming packet channel.
// Increased from 1024 to 8192 for 1M-node scale to prevent drops during
// bursts (e.g., many peers sending simultaneously after a cron trigger).
const RecvChSize = 8192

func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		udp:                transport.NewUDPTransport(),
		inbound:            make(chan transport.InboundFrame, RecvChSize),
		paths:              make(map[uint32]*peerPath),
		peerTCP:            make(map[uint32]*transport.TCPEndpoint),
		peerTURN:           make(map[uint32]*transport.TURNEndpoint),
		peerConns:          make(map[uint32]transport.DialedConn),
		turnPermittedPeers: make(map[string]time.Time),
		crypto:             make(map[uint32]*peerCrypto),
		peerPubKeys:        make(map[uint32]ed25519.PublicKey),
		peerCaps:           make(map[uint32]uint64),
		lastRecoveryPILA:   make(map[uint32]time.Time),
		pending:            make(map[uint32][][]byte),
		recvCh:             make(chan *IncomingPacket, RecvChSize),
		done:               make(chan struct{}),
		gossipView:         gossip.NewMembershipView(),
	}
}

// getOrCreatePath returns the peerPath for nodeID, creating a fresh
// one (zero-value fields) if absent. Caller must hold tm.mu.Lock.
func (tm *TunnelManager) getOrCreatePath(nodeID uint32) *peerPath {
	p := tm.paths[nodeID]
	if p == nil {
		p = &peerPath{}
		tm.paths[nodeID] = p
	}
	return p
}

// updatePathDirect records that a direct authenticated frame arrived
// from `from` for this peer. Always updates the direct address and
// clears viaRelay. Caller must hold tm.mu.Lock.
//
// Side effect: if the local daemon is running TURN (tm.turn != nil)
// and `from` is a real UDP address (not a relay marker or the
// unspecified zero-addr), track it in turnPermittedPeers so a later
// pion CreatePermission can admit this peer's datagrams on our
// relay. The actual pion call is deferred out of the locked
// critical section by recording the address and issuing the
// permission asynchronously via permitTURNPeerAsync; this keeps the
// auth-fast-path free of RTT-bound network I/O.
func (tm *TunnelManager) updatePathDirect(nodeID uint32, from *net.UDPAddr) {
	p := tm.getOrCreatePath(nodeID)
	if from != nil {
		p.direct = from
	}
	p.viaRelay = false
	p.lastSeen = time.Now()

	// Auto-permission hook: only meaningful when we are running TURN.
	// Best-effort and guarded against relay/zero markers.
	if tm.turn != nil && from != nil && !from.IP.IsUnspecified() && from.Port != 0 {
		// Fire the permission asynchronously so the lock holder
		// (auth-path callers) isn't blocked on a pion STUN round
		// trip. The goroutine does its own lock handling.
		addr := from.String()
		go tm.permitTURNPeerAsync(addr)
	}
}

// updatePathRelay records that a relayed authenticated frame arrived
// for this peer. Flips viaRelay to true but does NOT overwrite
// direct — we keep the last-known-good direct endpoint in case
// direct reachability returns. Caller must hold tm.mu.Lock.
func (tm *TunnelManager) updatePathRelay(nodeID uint32) {
	p := tm.getOrCreatePath(nodeID)
	p.viaRelay = true
	p.lastSeen = time.Now()
}

// GossipView returns the membership view backing the gossip overlay.
// Callers populate it as a side-effect of registry lookups (see
// daemon.ensureTunnel) and, once the gossip Engine is wired in, as
// inbound frames arrive. The view is always non-nil.
func (tm *TunnelManager) GossipView() *gossip.MembershipView {
	return tm.gossipView
}

// SetLocalCaps sets the capability bitmap this daemon advertises in
// its authenticated key-exchange frames. Call before the first
// outbound PILA is sent (typically at daemon startup, once all
// features — notably gossip — are wired up). Safe to call multiple
// times; the new value takes effect on the next outbound PILA.
func (tm *TunnelManager) SetLocalCaps(caps uint64) {
	tm.mu.Lock()
	tm.localCaps = caps
	tm.mu.Unlock()
}

// PeerCaps returns the capability bitmap a given peer advertised in
// its most recent authenticated key-exchange. Returns 0 if we've
// never authenticated with this peer or if the peer didn't
// advertise any caps (legacy daemon).
func (tm *TunnelManager) PeerCaps(nodeID uint32) uint64 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.peerCaps[nodeID]
}

// GossipCapablePeers returns the set of peers with whom we have an
// established encrypted tunnel and who have advertised CapGossip on
// their most recent PILA frame. Used by the gossip Engine to pick
// tick targets.
func (tm *TunnelManager) GossipCapablePeers() []uint32 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	out := make([]uint32, 0, len(tm.peerCaps))
	for nodeID, caps := range tm.peerCaps {
		if !gossip.HasCap(caps, gossip.CapGossip) {
			continue
		}
		if pc := tm.crypto[nodeID]; pc == nil || !pc.ready {
			continue
		}
		out = append(out, nodeID)
	}
	return out
}

// PeerPubKey returns the Ed25519 public key we have cached for the
// given peer, or (nil, false) if we have not yet authenticated with
// them. Used by the gossip Engine as a KeyLookup source so inbound
// records are cross-checked against the identity the registry bound
// to this node_id, not just TOFU-accepted.
func (tm *TunnelManager) PeerPubKey(nodeID uint32) (ed25519.PublicKey, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	pk, ok := tm.peerPubKeys[nodeID]
	return pk, ok
}

// ListenTCP starts an optional TCP listener alongside the UDP tunnel.
// When configured, peers that advertise a TCP endpoint (via the
// registry's multi-transport endpoints list) can be reached over TCP
// when direct UDP dial fails. The TCP listener delivers inbound
// frames to the same dispatchLoop as UDP — Pilot's wire format is
// transport-agnostic.
func (tm *TunnelManager) ListenTCP(addr string) error {
	if tm.tcp != nil {
		return fmt.Errorf("tcp transport already listening")
	}
	tm.tcp = transport.NewTCPTransport()
	if err := tm.tcp.Listen(addr, tm.inbound); err != nil {
		tm.tcp = nil
		return err
	}
	slog.Info("tcp transport listening", "addr", tm.tcp.LocalAddr())
	return nil
}

// TCPLocalAddr returns the bound TCP address, or nil if TCP is not
// enabled. Used by daemon code that wants to advertise the TCP
// endpoint in its registry registration.
func (tm *TunnelManager) TCPLocalAddr() net.Addr {
	if tm.tcp == nil {
		return nil
	}
	return tm.tcp.LocalAddr()
}

// AddPeerTCPEndpoint records an advertised TCP endpoint for a peer so
// subsequent sends can fall back to TCP when direct UDP fails. Call
// this from the registry-lookup path when parsing a multi-transport
// endpoint list.
func (tm *TunnelManager) AddPeerTCPEndpoint(nodeID uint32, addr string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("resolve tcp %q: %w", addr, err)
	}
	tm.mu.Lock()
	tm.peerTCP[nodeID] = transport.NewTCPEndpoint(tcpAddr)
	tm.mu.Unlock()
	return nil
}

// HasTCPEndpoint reports whether we've recorded a TCP endpoint for
// the given peer.
func (tm *TunnelManager) HasTCPEndpoint(nodeID uint32) bool {
	tm.mu.RLock()
	_, ok := tm.peerTCP[nodeID]
	tm.mu.RUnlock()
	return ok
}

// ListenTURN starts the TURN transport using provider to mint (and, for
// short-lived creds, rotate) credentials. Mirrors ListenTCP: builds the
// transport lazily, delivers inbound relay frames to the same
// dispatchLoop as UDP/TCP. Returns an error if TURN is already
// listening or the initial allocation fails.
func (tm *TunnelManager) ListenTURN(provider turncreds.Provider) error {
	if tm.turn != nil {
		return fmt.Errorf("turn transport already listening")
	}
	if provider == nil {
		return fmt.Errorf("turn transport: nil provider")
	}
	t := transport.NewTURNTransport(provider, tm.inbound)
	if err := t.Listen("", tm.inbound); err != nil {
		return err
	}
	tm.turn = t
	// Start the permitted-peer eviction goroutine. Only meaningful
	// when we are running TURN — no other code path populates
	// turnPermittedPeers.
	tm.startTURNPermissionEviction()
	slog.Info("turn transport listening", "relay", t.LocalAddr())
	return nil
}

// SetOutboundTURNOnly latches the OutboundTURNOnly flag. Called once
// from daemon.Start() before any frames flow. When true, writeFrame
// routes every outbound frame through the local TURN allocation
// (fail-closed: if no TURN cached conn is available, returns an error
// rather than falling back to beacon or direct UDP). v1.9.0-jf.11a.
func (tm *TunnelManager) SetOutboundTURNOnly(b bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.outboundTURNOnly = b
}

// TURNLocalAddr returns the server-assigned relay address, or nil if
// TURN is not enabled. Used by daemon code that wants to advertise the
// relay endpoint in DaemonInfo / gossip.
func (tm *TunnelManager) TURNLocalAddr() net.Addr {
	if tm.turn == nil {
		return nil
	}
	return tm.turn.LocalAddr()
}

// SetTURNOnLocalAddrChange forwards a callback into the TURN transport
// that fires whenever the server-assigned relay address changes —
// initial Allocate succeeds or a re-allocation completes after
// credential rotation / expiry recovery. No-op when TURN is not
// enabled. Safe to call any time after ListenTURN succeeds; the
// daemon currently wires this in Start() to publish a "turn_endpoint"
// CmdNotify to subscribed IPC clients (entmootd's gossip
// advertiser). (v1.9.0-jf.11b)
func (tm *TunnelManager) SetTURNOnLocalAddrChange(fn func(string)) {
	if tm.turn == nil {
		return
	}
	tm.turn.SetOnLocalAddrChange(fn)
}

// AddPeerTURNEndpoint records a peer's advertised TURN relay address so
// subsequent sends can route through the TURN transport. Call from
// handleSetPeerEndpoints when peering advertises a "turn" endpoint.
func (tm *TunnelManager) AddPeerTURNEndpoint(nodeID uint32, addr string) error {
	ep, err := transport.NewTURNEndpoint(addr)
	if err != nil {
		return fmt.Errorf("turn endpoint %q: %w", addr, err)
	}
	tm.mu.Lock()
	tm.peerTURN[nodeID] = ep
	tm.mu.Unlock()
	return nil
}

// HasTURNEndpoint reports whether we've recorded a TURN endpoint for
// the given peer.
func (tm *TunnelManager) HasTURNEndpoint(nodeID uint32) bool {
	tm.mu.RLock()
	_, ok := tm.peerTURN[nodeID]
	tm.mu.RUnlock()
	return ok
}

// DialTURNRelayForPeer is the asymmetric-TURN (v1.9.0-jf.9) analogue
// of DialTURNForPeer for daemons without a local TURN allocation.
// It sends raw UDP through the shared UDP socket to the peer's
// advertised TURN relay address, bypassing pion on our side. The
// hide-ip peer's pion allocation accepts these datagrams when it
// has proactively permissioned our source IP (see
// TURNTransport.CreatePermission).
//
// Precedence:
//   - If this daemon has its own TURN allocation (tm.turn != nil),
//     delegate to DialTURNForPeer. Two hide-ip peers talking to each
//     other prefer the full pion → pion path (channel-binding, TURN
//     ChannelData framing) over raw-UDP-to-relay.
//   - Otherwise, build a turnRelayDialedConn over tm.udp and cache
//     it in peerConns under first-writer-wins semantics (mirrors
//     DialTCPForPeer + DialTURNForPeer).
//
// Returns an error if no TURN endpoint is known for the node or if
// building the conn fails (e.g. UDP transport not listening).
func (tm *TunnelManager) DialTURNRelayForPeer(ctx context.Context, nodeID uint32) error {
	tm.mu.RLock()
	localTURN := tm.turn
	ep := tm.peerTURN[nodeID]
	udpT := tm.udp
	tm.mu.RUnlock()

	if ep == nil {
		return fmt.Errorf("no turn endpoint known for node %d", nodeID)
	}
	// Prefer the full pion path when we have a local allocation —
	// lets two hide-ip peers talk to each other over symmetric TURN.
	if localTURN != nil {
		return tm.DialTURNForPeer(ctx, nodeID)
	}
	if udpT == nil {
		return fmt.Errorf("turn-relay: no udp transport")
	}
	conn, err := transport.DialTURNRelayViaUDP(udpT, ep)
	if err != nil {
		return fmt.Errorf("turn-relay dial node %d: %w", nodeID, err)
	}

	tm.mu.Lock()
	if existing, ok := tm.peerConns[nodeID]; ok {
		tm.mu.Unlock()
		_ = conn.Close()
		_ = existing
		return nil
	}
	tm.peerConns[nodeID] = conn
	tm.mu.Unlock()
	slog.Info("peer switched to turn-relay", "node_id", nodeID, "remote", ep.String())
	return nil
}

// PermitTURNPeer proactively installs a CreatePermission on the
// local TURN allocation for the given host:port so the TURN server
// admits inbound datagrams from that address. No-op when tm.turn
// is nil (nothing to permit against). Idempotent: repeated calls
// refresh both the internal timestamp and the permission itself.
//
// Validates the input is parseable as a UDP address; an empty or
// malformed address returns an error.
//
// Intended call sites:
//   - updatePathDirect (auto-permission on authenticated direct
//     ingress — best-effort).
//   - Explicit caller (e.g. Entmoot roster seeding, if wired in
//     later) for peers who might never direct-UDP us before they
//     try the TURN relay path.
func (tm *TunnelManager) PermitTURNPeer(addr string) error {
	if addr == "" {
		return fmt.Errorf("permit turn peer: empty address")
	}
	if _, err := net.ResolveUDPAddr("udp", addr); err != nil {
		return fmt.Errorf("permit turn peer %q: %w", addr, err)
	}

	tm.mu.RLock()
	t := tm.turn
	tm.mu.RUnlock()
	if t == nil {
		return nil
	}

	if err := t.CreatePermission(addr); err != nil {
		return fmt.Errorf("permit turn peer %q: %w", addr, err)
	}

	tm.mu.Lock()
	if tm.turnPermittedPeers == nil {
		tm.turnPermittedPeers = make(map[string]time.Time)
	}
	tm.turnPermittedPeers[addr] = time.Now()
	tm.mu.Unlock()
	return nil
}

// permitTURNPeerAsync is the goroutine target used by
// updatePathDirect to issue a CreatePermission out of the locked
// auth-path. Logs any error at DEBUG; this is best-effort.
func (tm *TunnelManager) permitTURNPeerAsync(addr string) {
	if err := tm.PermitTURNPeer(addr); err != nil {
		slog.Debug("auto-permit turn peer failed", "addr", addr, "error", err)
	}
}

// startTURNPermissionEviction launches a background goroutine that
// periodically prunes turnPermittedPeers entries whose last refresh
// is older than turnPermittedPeerEvictTTL. Keeps the permitted-peer
// set bounded under churn. Exits when tm.done is closed.
//
// Called from ListenTURN (only meaningful when we are running TURN).
func (tm *TunnelManager) startTURNPermissionEviction() {
	tm.readWg.Add(1)
	go func() {
		defer tm.readWg.Done()
		ticker := time.NewTicker(turnPermittedPeerEvictInterval)
		defer ticker.Stop()
		for {
			select {
			case <-tm.done:
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-turnPermittedPeerEvictTTL)
				tm.mu.Lock()
				for a, ts := range tm.turnPermittedPeers {
					if ts.Before(cutoff) {
						delete(tm.turnPermittedPeers, a)
					}
				}
				tm.mu.Unlock()
			}
		}
	}()
}

// DialTURNForPeer establishes a turnDialedConn for the peer and caches
// it so subsequent writeFrame calls route via TURN. Mirrors
// DialTCPForPeer: called from the fall-back path once UDP retries +
// TCP fallback have both exhausted but a TURN relay endpoint is known
// (or explicitly in hide-IP mode where TURN is the only advertised
// path).
func (tm *TunnelManager) DialTURNForPeer(ctx context.Context, nodeID uint32) error {
	tm.mu.RLock()
	t := tm.turn
	ep := tm.peerTURN[nodeID]
	tm.mu.RUnlock()

	if t == nil {
		return fmt.Errorf("turn transport not enabled")
	}
	if ep == nil {
		return fmt.Errorf("no turn endpoint known for node %d", nodeID)
	}
	conn, err := t.Dial(ctx, ep)
	if err != nil {
		return fmt.Errorf("turn dial node %d: %w", nodeID, err)
	}

	tm.mu.Lock()
	// Prefer any earlier winner (matches DialTCPForPeer's race handling).
	if existing, ok := tm.peerConns[nodeID]; ok {
		tm.mu.Unlock()
		_ = conn.Close()
		_ = existing
		return nil
	}
	tm.peerConns[nodeID] = conn
	tm.mu.Unlock()
	slog.Info("peer switched to turn", "node_id", nodeID, "remote", ep.String())
	return nil
}

// SetWebhook configures the webhook client for event notifications.
func (tm *TunnelManager) SetWebhook(wc *WebhookClient) {
	tm.mu.Lock()
	tm.webhook = wc
	tm.mu.Unlock()
}

// EnableEncryption generates an X25519 keypair and enables tunnel encryption.
func (tm *TunnelManager) EnableEncryption() error {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate tunnel key: %w", err)
	}
	tm.privKey = priv
	tm.pubKey = priv.PublicKey().Bytes()
	tm.encrypt = true
	slog.Info("tunnel encryption enabled", "scheme", "X25519+AES-256-GCM")
	return nil
}

// SetNodeID sets our node ID (called after registration).
func (tm *TunnelManager) SetNodeID(id uint32) {
	atomic.StoreUint32(&tm.nodeID, id)
}

// loadNodeID atomically loads our node ID.
func (tm *TunnelManager) loadNodeID() uint32 {
	return atomic.LoadUint32(&tm.nodeID)
}

// SetIdentity sets our Ed25519 identity for signing authenticated key exchanges.
func (tm *TunnelManager) SetIdentity(id *crypto.Identity) {
	tm.mu.Lock()
	tm.identity = id
	tm.mu.Unlock()
}

// SetPeerVerifyFunc sets a callback to fetch a peer's Ed25519 public key from the registry.
func (tm *TunnelManager) SetPeerVerifyFunc(fn func(uint32) (ed25519.PublicKey, error)) {
	tm.mu.Lock()
	tm.verifyFunc = fn
	tm.mu.Unlock()
}

// SetRekeyCallback sets a callback invoked with peer node_id after a tunnel rekey
// completes. The daemon installs this to reset keepalive counters on connections
// routed over the rekeying peer; without it, in-flight ACKs lost during the key
// swap can trip dead-peer detection on the next idle-sweep and cause tunnel flap.
func (tm *TunnelManager) SetRekeyCallback(fn func(uint32)) {
	tm.mu.Lock()
	tm.rekeyCallback = fn
	tm.mu.Unlock()
}

// SetBeaconAddr configures the beacon address for NAT hole-punching and relay.
func (tm *TunnelManager) SetBeaconAddr(addr string) error {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve beacon: %w", err)
	}
	tm.mu.Lock()
	tm.beaconAddr = a
	tm.mu.Unlock()
	return nil
}

// SetRelayPeer explicitly marks a peer as needing relay through the
// beacon (e.g. called by DialConnection when direct UDP retries
// exhaust — a hint that the peer is behind symmetric NAT). After
// v1.9.0-jf.4 this is a fast path that updates the viaRelay bit on
// paths; the decrypt-side update rules will reconfirm or override
// based on observed traffic.
func (tm *TunnelManager) SetRelayPeer(nodeID uint32, relay bool) {
	tm.mu.Lock()
	p := tm.getOrCreatePath(nodeID)
	p.viaRelay = relay
	tm.mu.Unlock()
	if relay {
		slog.Info("peer marked for relay", "node_id", nodeID)
	}
}

// IsRelayPeer returns true if the last authenticated frame from the
// peer arrived via beacon relay (or an explicit SetRelayPeer(true)
// has been recorded since).
func (tm *TunnelManager) IsRelayPeer(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	p := tm.paths[nodeID]
	return p != nil && p.viaRelay
}

// SendViaBeacon writes a pre-encoded tunnel frame through the beacon
// relay toward nodeID without mutating path.viaRelay for that peer.
//
// Used by the racing dial path in DialConnection (v1.9.0-jf.11a.3):
// a relay SYN retransmission goroutine runs alongside direct UDP
// retries with a 200 ms RFC 8305 head-start. Whichever path first
// elicits an authenticated reply flips viaRelay naturally via
// updatePathRelay()/updatePathDirect() on ingress, so the sender
// side does NOT call SetRelayPeer during the race. Calling
// SetRelayPeer from a losing relay retry would poison the path for
// the next dial — SendViaBeacon sidesteps that by bypassing path
// state entirely.
//
// The encoding matches writeFrame's tier-1 beacon-relay envelope:
// [BeaconMsgRelay][senderNodeID(4)][destNodeID(4)][frame...].
//
// Returns an error if no beacon is configured (the racing dial's
// relay goroutine no-ops in that case instead of propagating).
func (tm *TunnelManager) SendViaBeacon(nodeID uint32, frame []byte) error {
	tm.mu.RLock()
	bAddr := tm.beaconAddr
	tm.mu.RUnlock()
	if bAddr == nil {
		return fmt.Errorf("beacon not configured")
	}
	msg := make([]byte, 1+4+4+len(frame))
	msg[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(msg[1:5], tm.loadNodeID())
	binary.BigEndian.PutUint32(msg[5:9], nodeID)
	copy(msg[9:], frame)
	n, err := tm.udp.WriteToUDPAddr(msg, bAddr)
	if err == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(n))
	}
	return err
}

// SendPacketViaBeacon is the marshaled-packet variant of SendViaBeacon:
// marshals pkt, wraps it in the appropriate tunnel frame (encrypted if
// a key exchange has completed, plaintext otherwise), and ships the
// frame through the beacon relay envelope without touching viaRelay.
// Mirrors SendTo's encrypt/plaintext branching so the relay-retry
// goroutine in DialConnection doesn't have to duplicate that logic.
func (tm *TunnelManager) SendPacketViaBeacon(nodeID uint32, pkt *protocol.Packet) error {
	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if tm.encrypt {
		tm.mu.RLock()
		pc := tm.crypto[nodeID]
		tm.mu.RUnlock()
		if pc != nil && pc.ready {
			frame := tm.encryptFrame(pc, data)
			return tm.SendViaBeacon(nodeID, frame)
		}
		// No key yet — let the normal Send path handle queueing;
		// the racing relay goroutine shouldn't kick off a key
		// exchange (that's the primary dial's job).
		return fmt.Errorf("no ready key for node %d", nodeID)
	}
	frame := make([]byte, 4+len(data))
	copy(frame[0:4], protocol.TunnelMagic[:])
	copy(frame[4:], data)
	return tm.SendViaBeacon(nodeID, frame)
}

// RelayPeerIDs returns the node IDs of all peers whose last
// authenticated path is via relay.
func (tm *TunnelManager) RelayPeerIDs() []uint32 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var ids []uint32
	for id, p := range tm.paths {
		if p != nil && p.viaRelay {
			ids = append(ids, id)
		}
	}
	return ids
}

// RegisterWithBeacon sends a MsgDiscover to the beacon from the tunnel socket
// using the real nodeID, so the beacon knows our endpoint for punch coordination.
func (tm *TunnelManager) RegisterWithBeacon() {
	tm.mu.RLock()
	bAddr := tm.beaconAddr
	tm.mu.RUnlock()
	if bAddr == nil || tm.udp == nil {
		return
	}
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], tm.loadNodeID())
	if _, err := tm.udp.WriteToUDPAddr(msg, bAddr); err != nil {
		slog.Warn("beacon registration failed", "error", err)
	} else {
		slog.Debug("registered with beacon", "node_id", tm.loadNodeID(), "beacon", bAddr)
	}
}

// RequestHolePunch asks the beacon to coordinate NAT hole-punching with a target peer.
func (tm *TunnelManager) RequestHolePunch(targetNodeID uint32) {
	tm.mu.RLock()
	bAddr := tm.beaconAddr
	tm.mu.RUnlock()
	if bAddr == nil || tm.udp == nil {
		return
	}
	// Format: [MsgPunchRequest(1)][ourNodeID(4)][targetNodeID(4)]
	msg := make([]byte, 9)
	msg[0] = protocol.BeaconMsgPunchRequest
	binary.BigEndian.PutUint32(msg[1:5], tm.loadNodeID())
	binary.BigEndian.PutUint32(msg[5:9], targetNodeID)
	if _, err := tm.udp.WriteToUDPAddr(msg, bAddr); err != nil {
		slog.Debug("hole punch request failed", "target", targetNodeID, "error", err)
	} else {
		slog.Debug("hole punch requested", "target", targetNodeID)
	}
}

// writeFrame sends a raw frame to a peer. Route selection in order:
//  1. Beacon relay if the peer's path says viaRelay (last authenticated
//     frame from them arrived via relay, or DialConnection explicitly
//     flipped them to relay-mode after direct retries exhausted). Keeps
//     both sides symmetric by construction: each side independently
//     replies on the path it received from.
//  2. A cached non-UDP DialedConn (e.g. TCP fallback installed by
//     DialTCPForPeer, or a TURN conn from DialTURNForPeer, or the
//     v1.9.0-jf.9 asymmetric turn-relay conn from
//     DialTURNRelayForPeer). Lets a peer stick to the alternate
//     transport once we've chosen it.
//  3. Direct UDP write, preferring the path's recorded direct addr
//     over the caller-supplied addr (handles NAT drift; the decrypt-
//     side refresh in handleEncrypted keeps path.direct current).
//  4. v1.9.0-jf.9 asymmetric-TURN fallback: if no UDP destination is
//     known and the peer has advertised a TURN endpoint, lazily dial
//     it via DialTURNRelayForPeer and retry the cached-conn path.
//     Lets a daemon without local TURN still reach a hide-ip peer.
//
// TCP / TURN fallback are deliberate steps: the caller decides when
// to switch a peer off direct UDP (typically after direct UDP SYN
// retries exhaust in DialConnection). Once switched, writeFrame
// keeps using the cached conn until it dies, at which point the
// cache is cleared and the next writeFrame falls back to UDP.
func (tm *TunnelManager) writeFrame(nodeID uint32, addr *net.UDPAddr, frame []byte) error {
	tm.mu.RLock()
	p := tm.paths[nodeID]
	var relay bool
	var pathDirect *net.UDPAddr
	if p != nil {
		relay = p.viaRelay
		pathDirect = p.direct
	}
	bAddr := tm.beaconAddr
	cachedConn := tm.peerConns[nodeID]
	hasTURNEp := tm.peerTURN[nodeID] != nil
	turnOnly := tm.outboundTURNOnly
	tm.mu.RUnlock()

	// v1.9.0-jf.11a: OutboundTURNOnly mode — force all outbound frames
	// through the local TURN allocation. Reject every tier that would
	// route via beacon (leaks metadata to beacon operator) or direct
	// UDP (leaks our source IP to the peer). Fail-closed: if no TURN
	// path exists, return an error rather than silently falling back.
	if turnOnly {
		// Use cached turn/turn-relay conn if present (populated by
		// DialTURNForPeer or DialTURNRelayForPeer).
		if cachedConn != nil {
			net := cachedConn.RemoteEndpoint().Network()
			if net == "turn" || net == "turn-relay" {
				if err := cachedConn.Send(frame); err == nil {
					atomic.AddUint64(&tm.PktsSent, 1)
					atomic.AddUint64(&tm.BytesSent, uint64(len(frame)))
					return nil
				} else {
					// Cached TURN conn failed. Evict and fall through to dial.
					tm.mu.Lock()
					if tm.peerConns[nodeID] == cachedConn {
						delete(tm.peerConns, nodeID)
						_ = cachedConn.Close()
					}
					tm.mu.Unlock()
					slog.Debug("outbound-turn-only: cached turn conn failed, re-dialling",
						"node_id", nodeID, "network", net, "error", err)
				}
			}
		}
		// Lazily dial turn-relay if the peer advertised a TURN endpoint.
		// The jf.9 fallback path; reuses DialTURNRelayForPeer which in
		// turn uses the local TURN client's allocation (or raw UDP if
		// tm.turn is nil, per jf.9's asymmetric mode).
		if hasTURNEp {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			dialErr := tm.DialTURNRelayForPeer(ctx, nodeID)
			cancel()
			if dialErr == nil {
				tm.mu.RLock()
				cc := tm.peerConns[nodeID]
				tm.mu.RUnlock()
				if cc != nil {
					if err := cc.Send(frame); err == nil {
						atomic.AddUint64(&tm.PktsSent, 1)
						atomic.AddUint64(&tm.BytesSent, uint64(len(frame)))
						return nil
					}
				}
			} else {
				slog.Debug("outbound-turn-only: turn-relay dial failed",
					"node_id", nodeID, "error", dialErr)
			}
		}
		// v1.9.0-jf.11a.2: peer did not advertise TURN, but WE have our
		// own TURN allocation. Route via our own relay to the peer's
		// real UDP address — the canonical WebRTC
		// iceTransportPolicy='relay' semantic (RFC 8828 Mode 3). Peer
		// sees source = our TURN anycast, never our real IP.
		//
		// Address priority: caller-supplied > pathDirect.
		// (peerTCP isn't useful here — TURN forwards UDP; the peer's
		// TCP endpoint isn't UDP-reachable even at the same host:port.)
		//
		// pion's auto-CreatePermission on first WriteTo per destination
		// IP handles the TURN protocol dance transparently. Refresh
		// every ~4 min; no manual plumbing needed.
		if tm.turn != nil {
			var peerAddr *net.UDPAddr
			switch {
			case addr != nil:
				peerAddr = addr
			case pathDirect != nil:
				peerAddr = pathDirect
			}
			if peerAddr != nil {
				if err := tm.turn.SendViaOwnRelay(peerAddr, frame); err == nil {
					atomic.AddUint64(&tm.PktsSent, 1)
					atomic.AddUint64(&tm.BytesSent, uint64(len(frame)))
					return nil
				} else {
					slog.Debug("outbound-turn-only: send via own relay failed",
						"node_id", nodeID, "peer_addr", peerAddr.String(),
						"error", err)
				}
			}
		}
		return fmt.Errorf("outbound-turn-only: no TURN path for node %d "+
			"(peer advertised no TURN endpoint, local TURN allocation "+
			"missing or dial failed, and no known UDP-reachable address "+
			"for this peer; tunnel traffic refused rather than leak "+
			"source IP via direct UDP or beacon)", nodeID)
	}

	// Tier 1 (beacon relay) — SKIPPED when this peer advertised a
	// TURN endpoint (v1.9.0-jf.10). A TURN advertisement is an
	// explicit "route me through TURN, not via any third-party
	// relay" signal from the peer, typically paired with -hide-ip.
	// Honouring beacon would leak routing metadata to the beacon's
	// operator (defeating the hide-ip purpose). Fall through to the
	// cached-conn tier → turn-relay fallback tier instead. Beacon
	// stays the default for all peers that did NOT advertise TURN.
	if relay && bAddr != nil && !hasTURNEp {
		// MsgRelay: [0x05][senderNodeID(4)][destNodeID(4)][frame...]
		msg := make([]byte, 1+4+4+len(frame))
		msg[0] = protocol.BeaconMsgRelay
		binary.BigEndian.PutUint32(msg[1:5], tm.loadNodeID())
		binary.BigEndian.PutUint32(msg[5:9], nodeID)
		copy(msg[9:], frame)
		n, err := tm.udp.WriteToUDPAddr(msg, bAddr)
		if err == nil {
			atomic.AddUint64(&tm.PktsSent, 1)
			atomic.AddUint64(&tm.BytesSent, uint64(n))
		}
		return err
	}

	// If path has a direct addr recorded (from the last authenticated
	// decrypt), prefer it over the caller-supplied addr. This is what
	// keeps v1.9.0-jf.2's NAT-drift refresh effective: writeFrame
	// follows the last-known-good endpoint even if the caller
	// snapshotted a stale one before a NAT rotation.
	//
	// v1.9.0-jf.10: skip direct UDP too when peerTURN is advertised.
	// Otherwise a stale pathDirect (from before the peer went
	// -hide-ip) would bypass turn-relay and leak the peer's IP back
	// to them. Honour the "route me via TURN" signal strictly.
	if hasTURNEp {
		addr = nil
	} else if pathDirect != nil {
		addr = pathDirect
	}

	// Phase 4: if a cached non-UDP conn exists for this peer, use it
	// first. The cache is populated by DialTCPForPeer, DialTURNForPeer,
	// and (v1.9.0-jf.9) DialTURNRelayForPeer. UDP conns are not cached
	// here — they're effectively free to re-issue via WriteToUDPAddr.
	if cachedConn != nil && cachedConn.RemoteEndpoint().Network() != "udp" {
		if err := cachedConn.Send(frame); err == nil {
			atomic.AddUint64(&tm.PktsSent, 1)
			atomic.AddUint64(&tm.BytesSent, uint64(len(frame)))
			return nil
		} else {
			// Cached conn is dead (e.g. peer closed TCP). Drop it so the
			// next sender can re-dial, and fall through to UDP.
			tm.mu.Lock()
			if tm.peerConns[nodeID] == cachedConn {
				delete(tm.peerConns, nodeID)
				_ = cachedConn.Close()
			}
			tm.mu.Unlock()
			slog.Debug("cached peer conn failed, falling back",
				"node_id", nodeID,
				"network", cachedConn.RemoteEndpoint().Network(),
				"error", err)
		}
	}

	if addr == nil {
		// v1.9.0-jf.9: last-resort asymmetric-TURN fallback. If the peer
		// advertised a TURN endpoint and we have no UDP destination,
		// lazily build a turn-relay conn and retry the cached-conn
		// path. Avoids re-dialling if a conn was installed by a racing
		// writer between our initial read and this tier.
		if hasTURNEp {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			dialErr := tm.DialTURNRelayForPeer(ctx, nodeID)
			cancel()
			if dialErr == nil {
				tm.mu.RLock()
				cc := tm.peerConns[nodeID]
				tm.mu.RUnlock()
				if cc != nil && cc.RemoteEndpoint().Network() != "udp" {
					if err := cc.Send(frame); err == nil {
						atomic.AddUint64(&tm.PktsSent, 1)
						atomic.AddUint64(&tm.BytesSent, uint64(len(frame)))
						return nil
					} else {
						return fmt.Errorf("turn-relay send after dial: %w", err)
					}
				}
			} else {
				slog.Debug("turn-relay fallback dial failed", "node_id", nodeID, "error", dialErr)
			}
		}
		return fmt.Errorf("no address for node %d", nodeID)
	}
	n, err := tm.udp.WriteToUDPAddr(frame, addr)
	if err == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(n))
	}
	return err
}

// DialTCPForPeer establishes (or reuses) a TCP connection to the peer
// and caches it so subsequent writeFrame calls for that peer route
// via TCP. Called from the daemon's fall-back path when direct UDP
// SYN retries exhaust but a TCP endpoint is known. Returns an error
// if TCP is not configured on this TunnelManager, no TCP endpoint is
// known for the peer, or the dial itself fails.
func (tm *TunnelManager) DialTCPForPeer(ctx context.Context, nodeID uint32) error {
	tm.mu.RLock()
	t := tm.tcp
	ep := tm.peerTCP[nodeID]
	tm.mu.RUnlock()

	if t == nil {
		return fmt.Errorf("tcp transport not enabled")
	}
	if ep == nil {
		return fmt.Errorf("no tcp endpoint known for node %d", nodeID)
	}
	conn, err := t.Dial(ctx, ep)
	if err != nil {
		return fmt.Errorf("tcp dial node %d: %w", nodeID, err)
	}

	tm.mu.Lock()
	// If another goroutine already cached a conn, prefer its. Close ours
	// to avoid leaking sockets.
	if existing, ok := tm.peerConns[nodeID]; ok {
		tm.mu.Unlock()
		_ = conn.Close()
		_ = existing // keep existing reference live for clarity
		return nil
	}
	tm.peerConns[nodeID] = conn
	tm.mu.Unlock()
	slog.Info("peer switched to tcp", "node_id", nodeID, "remote", ep.String())
	return nil
}

// ClearCachedConn drops any cached DialedConn for a peer. Called when
// the daemon observes fresh UDP activity from a peer that was
// previously on TCP, so the peer can fall back to UDP.
func (tm *TunnelManager) ClearCachedConn(nodeID uint32) {
	tm.mu.Lock()
	conn, ok := tm.peerConns[nodeID]
	if ok {
		delete(tm.peerConns, nodeID)
	}
	tm.mu.Unlock()
	if ok && conn != nil {
		_ = conn.Close()
	}
}

// getPeerPubKey returns the cached Ed25519 public key for a peer, fetching from
// registry if needed.
func (tm *TunnelManager) getPeerPubKey(nodeID uint32) (ed25519.PublicKey, error) {
	tm.mu.RLock()
	if pk, ok := tm.peerPubKeys[nodeID]; ok {
		tm.mu.RUnlock()
		return pk, nil
	}
	fn := tm.verifyFunc
	tm.mu.RUnlock()

	if fn == nil {
		return nil, fmt.Errorf("no verify function")
	}

	pk, err := fn(nodeID)
	if err != nil {
		return nil, err
	}

	tm.mu.Lock()
	tm.peerPubKeys[nodeID] = pk
	tm.mu.Unlock()
	return pk, nil
}

// Listen starts the UDP listener for incoming tunnel traffic. The
// underlying *net.UDPConn is owned by the transport layer; this
// method also starts the dispatchLoop goroutine that consumes frames
// from every registered transport via the shared inbound sink.
func (tm *TunnelManager) Listen(addr string) error {
	if err := tm.udp.Listen(addr, tm.inbound); err != nil {
		return err
	}

	tm.readWg.Add(1)
	go tm.dispatchLoop()
	return nil
}

func (tm *TunnelManager) Close() error {
	var connErr error
	tm.closeOnce.Do(func() {
		close(tm.done) // signal dispatchLoop to stop sending
		if tm.udp != nil {
			connErr = tm.udp.Close() // causes the UDP transport's readLoop to return;
			// the sink channel is drained by dispatchLoop until done fires.
		}
		if tm.tcp != nil {
			// Close TCP last so dispatchLoop has drained whatever UDP
			// produced first. tcp.Close tears down all pooled dialled
			// conns + the listener and waits for its goroutines.
			if tcpErr := tm.tcp.Close(); tcpErr != nil && connErr == nil {
				connErr = tcpErr
			}
		}
		if tm.turn != nil {
			// Close TURN after TCP so the relay sends its Refresh(lifetime=0)
			// before the process exits, returning the allocation to the
			// server promptly.
			if turnErr := tm.turn.Close(); turnErr != nil && connErr == nil {
				connErr = turnErr
			}
		}
		tm.readWg.Wait() // wait for dispatchLoop to fully exit before closing recvCh
		close(tm.recvCh) // unblock routeLoop (H5 fix — prevents goroutine leak)
	})
	return connErr
}

func (tm *TunnelManager) LocalAddr() net.Addr {
	if tm.udp == nil {
		return nil
	}
	return tm.udp.LocalAddr()
}

// extractFrameNodeID pulls the peer's nodeID out of the first 4 bytes
// of a Pilot tunnel frame's payload (the bytes immediately after the
// 4-byte magic). Works for PILA/PILK/PILS which all place
// [magic(4)][nodeID(4)][...] at the front; returns false for beacon
// messages, plaintext packets, or anything else where the nodeID
// isn't at that offset.
func extractFrameNodeID(frame []byte) (uint32, bool) {
	if len(frame) < 8 {
		return 0, false
	}
	switch [4]byte{frame[0], frame[1], frame[2], frame[3]} {
	case protocol.TunnelMagicAuthEx, protocol.TunnelMagicKeyEx, protocol.TunnelMagicSecure:
		return binary.BigEndian.Uint32(frame[4:8]), true
	}
	return 0, false
}

// dispatchLoop consumes InboundFrames produced by any registered
// transport and routes them to the per-magic handlers. It is the
// single place where we interpret Pilot's wire format at the tunnel
// layer; individual transports are dumb byte-movers.
//
// Phase 1b scope: only the UDP transport is wired in, so every frame
// arrives with a *transport.UDPEndpoint. Handlers still take
// *net.UDPAddr — we unwrap the concrete type here until Phase 1c
// abstracts the handler signatures to transport.Endpoint.
func (tm *TunnelManager) dispatchLoop() {
	defer tm.readWg.Done()

	for {
		select {
		case <-tm.done:
			return
		case inbound, ok := <-tm.inbound:
			if !ok {
				return
			}
			buf := inbound.Frame
			n := len(buf)
			if n < 1 {
				continue
			}

			// Unwrap the concrete UDP address for handlers that still
			// take *net.UDPAddr. For non-UDP frames (TCP/QUIC/…) we pass
			// nil — handlers that use `from` for peer-address learning
			// just skip that update for non-UDP, and TCP peers are
			// tracked via peerConns (cached Reply channel) instead.
			var remote *net.UDPAddr
			if udpEP, ok := inbound.From.(*transport.UDPEndpoint); ok {
				remote = udpEP.Addr()
			}

			// Phase 4: for frames that carry a peer nodeID and arrive
			// on a connection-oriented transport (TCP), cache the Reply
			// conn so writeFrame can route subsequent sends back through
			// the same connection. This is essential for NAT'd peers
			// that dialled us inbound — they have no separately-
			// listenable endpoint we could Dial to, so replies must
			// flow through the accepted socket.
			if inbound.Reply != nil && inbound.Reply.RemoteEndpoint().Network() != "udp" {
				if pid, ok := extractFrameNodeID(buf); ok {
					tm.mu.Lock()
					if existing, exists := tm.peerConns[pid]; !exists || existing == nil {
						tm.peerConns[pid] = inbound.Reply
					} else if existing.RemoteEndpoint().String() != inbound.Reply.RemoteEndpoint().String() {
						// Peer reconnected on a different remote address (e.g. NAT
						// mapping shifted) — prefer the newer conn. Don't close
						// the old: the readerLoop will eventually hit EOF and
						// clean it up.
						tm.peerConns[pid] = inbound.Reply
					}
					tm.mu.Unlock()
				}
			}

			// Beacon messages use single-byte type codes < 0x10.
			// All tunnel magic starts with 'P' (0x50), so no collision.
			if buf[0] < 0x10 {
				if remote != nil {
					tm.handleBeaconMessage(buf[:n], remote)
				}
				continue
			}

			if n < 4 {
				continue
			}

			magic := [4]byte{buf[0], buf[1], buf[2], buf[3]}

			switch magic {
			case protocol.TunnelMagicAuthEx:
				// Authenticated key exchange: [PILA][4-byte nodeID][32-byte X25519][32-byte Ed25519][64-byte sig]
				tm.handleAuthKeyExchange(buf[4:n], remote, false)
				continue

			case protocol.TunnelMagicKeyEx:
				// Key exchange packet: [PILK][4-byte nodeID][32-byte pubkey]
				tm.handleKeyExchange(buf[4:n], remote, false)
				continue

			case protocol.TunnelMagicSecure:
				// Encrypted packet: [PILS][4-byte nodeID][12-byte nonce][ciphertext+tag]
				tm.handleEncrypted(buf[4:n], remote, false /* direct */)
				continue

			case protocol.TunnelMagicPunch:
				// NAT punch packet — expected during hole-punching, silently acknowledged
				slog.Debug("NAT punch received", "from", inbound.From)
				continue

			case protocol.TunnelMagic:
				// Plaintext packet
				if n < 4+protocol.PacketHeaderSize() {
					continue
				}
				data := make([]byte, n-4)
				copy(data, buf[4:n])

				pkt, err := protocol.Unmarshal(data)
				if err != nil {
					slog.Error("tunnel unmarshal error", "remote", inbound.From, "error", err)
					continue
				}

				atomic.AddUint64(&tm.PktsRecv, 1)
				atomic.AddUint64(&tm.BytesRecv, uint64(n))
				select {
				case tm.recvCh <- &IncomingPacket{Packet: pkt, From: remote}:
				case <-tm.done:
					return
				}

			default:
				continue // unknown magic
			}
		}
	}
}

// handleAuthKeyExchange processes an authenticated key exchange packet.
// Format: [4-byte nodeID][32-byte X25519 pubkey][32-byte Ed25519 pubkey][64-byte Ed25519 signature]
// The signature is over: "auth:" + nodeID(4 bytes) + X25519-pubkey(32 bytes)
// fromRelay indicates this was received via beacon relay — don't update peer endpoint.
func (tm *TunnelManager) handleAuthKeyExchange(data []byte, from *net.UDPAddr, fromRelay bool) {
	if len(data) < 4+32+32+64 {
		return
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	peerX25519PubKey := data[4:36]
	peerEd25519PubKey := ed25519.PublicKey(data[36:68])
	signature := data[68:132]

	// Optional trailing varint: peer's capability bitmap. Older
	// daemons don't emit anything after byte 132; for them peerCaps
	// stays at its zero value and the gossip engine skips the peer.
	var peerCaps uint64
	if len(data) > 132 {
		if c, n := binary.Uvarint(data[132:]); n > 0 {
			peerCaps = c
		}
	}

	if !tm.encrypt || tm.privKey == nil {
		return
	}

	// Verify the Ed25519 signature over the auth challenge
	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(challenge[4:8], peerNodeID)
	copy(challenge[8:40], peerX25519PubKey)

	// Fetch expected pubkey from registry FIRST — reject if unavailable
	expectedPubKey, err := tm.getPeerPubKey(peerNodeID)
	if err != nil || expectedPubKey == nil {
		slog.Warn("auth key exchange rejected: cannot verify peer identity from registry", "peer_node_id", peerNodeID, "error", err)
		return
	}

	// Verify the packet-provided Ed25519 pubkey matches the registry.
	// On mismatch, invalidate cache and re-fetch — the peer may have restarted
	// with a new identity since we last cached their key.
	if !peerEd25519PubKey.Equal(expectedPubKey) {
		tm.mu.Lock()
		delete(tm.peerPubKeys, peerNodeID)
		tm.mu.Unlock()
		expectedPubKey, err = tm.getPeerPubKey(peerNodeID)
		if err != nil || expectedPubKey == nil {
			slog.Warn("auth key exchange rejected: cannot re-verify peer identity", "peer_node_id", peerNodeID, "error", err)
			return
		}
		if !peerEd25519PubKey.Equal(expectedPubKey) {
			slog.Error("auth key exchange: Ed25519 pubkey mismatch with registry", "peer_node_id", peerNodeID)
			return
		}
		slog.Info("auth key exchange: peer pubkey updated from registry", "peer_node_id", peerNodeID)
	}

	// Verify signature against the registry-verified key
	if !crypto.Verify(expectedPubKey, challenge, signature) {
		slog.Error("auth key exchange signature verification failed", "peer_node_id", peerNodeID)
		return
	}

	authenticated := true

	// Derive shared secret from X25519
	pc, err := tm.deriveSecret(peerX25519PubKey)
	if err != nil {
		slog.Error("auth key exchange failed", "peer_node_id", peerNodeID, "error", err)
		return
	}
	pc.authenticated = authenticated

	tm.mu.Lock()
	oldPC := tm.crypto[peerNodeID]
	hadCrypto := oldPC != nil
	keyChanged := hadCrypto && oldPC.peerX25519Key != pc.peerX25519Key
	tm.crypto[peerNodeID] = pc
	// Reply-on-ingress: update the peer's path based on where this
	// authenticated frame actually arrived from.
	if fromRelay {
		tm.updatePathRelay(peerNodeID)
	} else {
		tm.updatePathDirect(peerNodeID, from)
	}
	// Cache the peer's Ed25519 pubkey and advertised caps bitmap.
	tm.peerPubKeys[peerNodeID] = peerEd25519PubKey
	tm.peerCaps[peerNodeID] = peerCaps
	tm.mu.Unlock()

	if keyChanged {
		slog.Info("peer rekeyed (auth), re-establishing tunnel", "peer_node_id", peerNodeID)
	} else {
		slog.Info("encrypted tunnel established", "auth", authenticated, "peer_node_id", peerNodeID, "endpoint", from, "relay", fromRelay)
	}
	tm.webhook.Emit("tunnel.established", map[string]interface{}{
		"peer_node_id": peerNodeID, "authenticated": authenticated,
		"relay": fromRelay, "rekeyed": keyChanged,
	})

	if !hadCrypto || keyChanged {
		tm.sendKeyExchangeToNode(peerNodeID)
	}

	tm.flushPending(peerNodeID)

	if keyChanged {
		tm.notifyRekey(peerNodeID)
	}
}

// notifyRekey invokes the installed rekey callback, if any, to let the daemon
// reset per-connection state (keepalive counters) on connections routed over
// this peer's tunnel.
func (tm *TunnelManager) notifyRekey(peerNodeID uint32) {
	tm.mu.RLock()
	cb := tm.rekeyCallback
	tm.mu.RUnlock()
	if cb != nil {
		cb(peerNodeID)
	}
}

// handleKeyExchange processes an incoming unauthenticated key exchange packet.
// Format: [4-byte nodeID][32-byte X25519 pubkey]
// If we have an identity and the peer has a registered pubkey, reject unauthenticated
// exchange and require authenticated (PILA) instead.
// fromRelay indicates this was received via beacon relay — don't update peer endpoint.
func (tm *TunnelManager) handleKeyExchange(data []byte, from *net.UDPAddr, fromRelay bool) {
	if len(data) < 36 {
		return
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	peerPubKey := data[4:36]

	// If we don't have encryption enabled, ignore key exchange silently
	if !tm.encrypt || tm.privKey == nil {
		return
	}

	// If we have identity, check if peer has a registered pubkey — if so,
	// reject unauthenticated exchange and respond with authenticated instead
	tm.mu.RLock()
	hasIdentity := tm.identity != nil
	tm.mu.RUnlock()
	if hasIdentity {
		expectedPubKey, err := tm.getPeerPubKey(peerNodeID)
		if err == nil && expectedPubKey != nil {
			slog.Warn("rejecting unauthenticated key exchange from peer with known identity", "peer_node_id", peerNodeID)
			tm.sendKeyExchangeToNode(peerNodeID)
			return
		}
	}

	// Derive shared secret
	pc, err := tm.deriveSecret(peerPubKey)
	if err != nil {
		slog.Error("key exchange failed", "peer_node_id", peerNodeID, "error", err)
		return
	}

	tm.mu.Lock()
	oldPC := tm.crypto[peerNodeID]
	hadCrypto := oldPC != nil
	// Detect rekeying: peer restarted with a new keypair
	keyChanged := hadCrypto && oldPC.peerX25519Key != pc.peerX25519Key
	tm.crypto[peerNodeID] = pc
	// Reply-on-ingress path update.
	if fromRelay {
		tm.updatePathRelay(peerNodeID)
	} else {
		tm.updatePathDirect(peerNodeID, from)
	}
	tm.mu.Unlock()

	if keyChanged {
		slog.Info("peer rekeyed, re-establishing tunnel", "peer_node_id", peerNodeID)
	} else {
		slog.Info("encrypted tunnel established", "peer_node_id", peerNodeID, "endpoint", from, "relay", fromRelay)
	}
	tm.webhook.Emit("tunnel.established", map[string]interface{}{
		"peer_node_id": peerNodeID, "authenticated": false,
		"relay": fromRelay, "rekeyed": keyChanged,
	})

	// Respond with our key if this is a new peer or the peer rekeyed
	if !hadCrypto || keyChanged {
		tm.sendKeyExchangeToNode(peerNodeID)
	}

	// Flush any pending packets now that encryption is ready
	tm.flushPending(peerNodeID)

	if keyChanged {
		tm.notifyRekey(peerNodeID)
	}
}

// handleEncrypted decrypts an incoming encrypted packet.
// Format: [4-byte nodeID][12-byte nonce][ciphertext+GCM tag]
//
// fromRelay reports whether this frame was extracted from a beacon-
// relay envelope (true) or arrived direct on the UDP socket (false).
// Used to update the peer's path state via the reply-on-ingress rule
// (v1.9.0-jf.4).
func (tm *TunnelManager) handleEncrypted(data []byte, from *net.UDPAddr, fromRelay bool) {
	if len(data) < 4+12+16 { // nodeID + nonce + min GCM tag
		return
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	nonce := data[4:16]
	ciphertext := data[16:]

	tm.mu.RLock()
	pc := tm.crypto[peerNodeID]
	tm.mu.RUnlock()

	if pc == nil || !pc.ready {
		slog.Warn("encrypted packet from node but no key", "peer_node_id", peerNodeID)
		// Auto-recovery: our key state for this peer is missing
		// (typical after a one-sided daemon restart — surviving peer
		// retains its session keys derived from our old X25519 pubkey,
		// we generated a new one on restart, and the peer keeps
		// sending us un-decryptable frames indefinitely). Reply with
		// an unsolicited PILA so the peer observes our new pubkey and
		// re-handshakes. Rate-limited to avoid turning us into a PILA
		// amplifier if an attacker (or a persistent misconfigured
		// peer) spams un-decryptable frames.
		//
		// Route the PILA through the same path the bad frame came in
		// on: direct if direct (from has the peer's real UDP addr),
		// via beacon relay if the bad frame arrived relayed (from is
		// a zero-addr marker, so we must use the MsgRelay envelope).
		tm.maybeSendRecoveryPILA(peerNodeID, from, fromRelay)
		return
	}

	// Replay detection using sliding window bitmap (H8 fix)
	recvCounter := binary.BigEndian.Uint64(nonce[len(nonce)-8:])
	pc.replayMu.Lock()
	if !pc.checkAndRecordNonce(recvCounter) {
		pc.replayMu.Unlock()
		slog.Warn("tunnel nonce replay detected", "peer_node_id", peerNodeID, "counter", recvCounter, "max", pc.maxRecvNonce)
		tm.webhook.Emit("security.nonce_replay", map[string]interface{}{
			"peer_node_id": peerNodeID, "counter": recvCounter,
		})
		return
	}
	pc.replayMu.Unlock()

	// H3 fix: verify sender's nodeID as AAD
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, peerNodeID)
	plaintext, err := pc.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		atomic.AddUint64(&tm.EncryptFail, 1)
		slog.Error("tunnel decrypt error", "peer_node_id", peerNodeID, "error", err)
		// Undo the nonce record on decrypt failure — it was not a valid packet
		pc.replayMu.Lock()
		bit := recvCounter % replayWindowSize
		pc.replayBitmap[bit/64] &^= 1 << (bit % 64)
		pc.replayMu.Unlock()
		return
	}

	pkt, err := protocol.Unmarshal(plaintext)
	if err != nil {
		slog.Error("tunnel unmarshal error after decrypt", "peer_node_id", peerNodeID, "error", err)
		return
	}

	atomic.AddUint64(&tm.PktsRecv, 1)
	atomic.AddUint64(&tm.BytesRecv, uint64(len(data)+4)) // +4 for PILS magic

	// Reply-on-ingress path update (v1.9.0-jf.4).
	//
	// Direct frame: update path.direct so subsequent writeFrame calls
	// follow the peer's current UDP endpoint. Handles CGN-style NAT
	// port rotation observed live on a UAE ISP — the tunnel stays
	// alive from keepalives, but fresh stream SYNs were going to the
	// stale mapping before this refresh existed.
	//
	// Relay frame: flip path.viaRelay = true so our next outbound
	// traffic to this peer routes through the beacon, symmetric with
	// how the inbound arrived. Do NOT touch path.direct — we keep
	// the last-known-good direct endpoint so direct can resume if
	// reachability returns.
	//
	// Two-phase lock check avoids write-lock churn when state is
	// already current, which is the steady-state case.
	if from != nil {
		tm.mu.RLock()
		p := tm.paths[peerNodeID]
		var stale bool
		if p == nil {
			stale = true
		} else if fromRelay {
			stale = !p.viaRelay
		} else {
			// direct — stale if viaRelay is set OR direct addr differs.
			stale = p.viaRelay || p.direct == nil || p.direct.Port != from.Port || !p.direct.IP.Equal(from.IP)
		}
		tm.mu.RUnlock()
		if stale {
			tm.mu.Lock()
			if fromRelay {
				tm.updatePathRelay(peerNodeID)
			} else {
				tm.updatePathDirect(peerNodeID, from)
			}
			tm.mu.Unlock()
		}
	}

	select {
	case tm.recvCh <- &IncomingPacket{Packet: pkt, From: from}:
	case <-tm.done:
	}
}

// deriveSecret computes a shared AES-256-GCM cipher from the peer's public key.
func (tm *TunnelManager) deriveSecret(peerPubKeyBytes []byte) (*peerCrypto, error) {
	if tm.privKey == nil {
		return nil, fmt.Errorf("no private key")
	}

	curve := ecdh.X25519()
	peerKey, err := curve.NewPublicKey(peerPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse peer key: %w", err)
	}

	shared, err := tm.privKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// HKDF-SHA256 key derivation (H1 fix)
	mac := hmac.New(sha256.New, nil) // HKDF-Extract: PRK = HMAC-SHA256(nil salt, IKM)
	mac.Write(shared)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk) // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
	mac.Write([]byte("pilot-tunnel-v1"))
	mac.Write([]byte{0x01})
	key := mac.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	// Zero intermediate key material (H4 fix)
	for i := range shared {
		shared[i] = 0
	}
	for i := range key {
		key[i] = 0
	}
	for i := range prk {
		prk[i] = 0
	}

	// Generate random nonce prefix for domain separation
	pc := &peerCrypto{aead: aead, ready: true}
	copy(pc.peerX25519Key[:], peerPubKeyBytes)
	if _, err := rand.Read(pc.noncePrefix[:]); err != nil {
		return nil, fmt.Errorf("nonce prefix: %w", err)
	}

	return pc, nil
}

// sendKeyExchangeToNode sends an authenticated key exchange if identity is available,
// otherwise falls back to unauthenticated. Uses nodeID-based routing (relay-aware via writeFrame).
func (tm *TunnelManager) sendKeyExchangeToNode(peerNodeID uint32) {
	tm.mu.RLock()
	hasIdentity := tm.identity != nil
	// addr is only used as a fallback if path has no direct address
	// recorded (pre-handshake state); writeFrame prefers path.direct
	// when set. Relay routing is decided entirely by path.viaRelay.
	var addr *net.UDPAddr
	if p := tm.paths[peerNodeID]; p != nil {
		addr = p.direct
	}
	tm.mu.RUnlock()

	frame := tm.buildKeyExchangeFrame()
	if frame == nil {
		return
	}

	if hasIdentity {
		authFrame := tm.buildAuthKeyExchangeFrame()
		if authFrame != nil {
			frame = authFrame
		}
	}

	if err := tm.writeFrame(peerNodeID, addr, frame); err != nil {
		slog.Error("send key exchange failed", "peer_node_id", peerNodeID, "error", err)
	}
}

// buildAuthKeyExchangeFrame builds an authenticated key exchange frame.
// Returns nil if identity is not available.
//
// Frame layout:
//
//	[0:4]     PILA magic
//	[4:8]     our node ID (BE uint32)
//	[8:40]    our X25519 pubkey (32B)
//	[40:72]   our Ed25519 pubkey (32B)
//	[72:136]  signature over "auth" || nodeID || X25519pub
//	[136:]    OPTIONAL varint capability bitmap (see gossip.CapGossip)
//
// Older daemons truncate at byte 136 and never read the trailing
// varint, preserving backward compatibility; newer daemons read the
// remainder as Uvarint and treat parse errors / absent bytes as 0.
func (tm *TunnelManager) buildAuthKeyExchangeFrame() []byte {
	tm.mu.RLock()
	id := tm.identity
	caps := tm.localCaps
	tm.mu.RUnlock()
	if tm.pubKey == nil || id == nil {
		return nil
	}

	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], []byte("auth"))
	binary.BigEndian.PutUint32(challenge[4:8], tm.loadNodeID())
	copy(challenge[8:40], tm.pubKey)
	signature := id.Sign(challenge)

	ed25519PubKey := []byte(id.PublicKey)

	base := 4 + 4 + 32 + 32 + 64
	var capsBuf [binary.MaxVarintLen64]byte
	var capsLen int
	if caps != 0 {
		capsLen = binary.PutUvarint(capsBuf[:], caps)
	}
	frame := make([]byte, base+capsLen)
	copy(frame[0:4], protocol.TunnelMagicAuthEx[:])
	binary.BigEndian.PutUint32(frame[4:8], tm.loadNodeID())
	copy(frame[8:40], tm.pubKey)
	copy(frame[40:72], ed25519PubKey)
	copy(frame[72:136], signature)
	if capsLen > 0 {
		copy(frame[136:], capsBuf[:capsLen])
	}
	return frame
}

// recoveryPILAInterval bounds how often we emit an unsolicited
// authenticated key-exchange (PILA) frame to a peer we have no
// crypto state for. Short enough to recover within a single gossip
// tick after a one-sided daemon restart, long enough that a
// spoofed nodeID can't turn us into a PILA amplifier.
const recoveryPILAInterval = 60 * time.Second

// maybeSendRecoveryPILA emits an unsolicited PILA to the observed
// source address when we receive an encrypted packet we cannot
// decrypt (no crypto state cached for that peer). This is the
// auto-recovery path for the asymmetric-restart case: peer A
// restarts and loses its per-peer X25519 keys, peer B still holds
// stale session keys and keeps sending encrypted traffic that A
// can't decrypt. Without this hook, A would silently drop B's
// frames forever; B's side of the tunnel never notices because its
// own keepalive ACKs appear to succeed at the tunnel level.
//
// Sending the PILA back announces A's new X25519 pubkey; B's
// handleAuthKeyExchange detects the key mismatch, invalidates its
// stale state, and re-handshakes. Rate-limited per peer to prevent
// reflection abuse (a spoofed nodeID in a packet could otherwise
// turn us into an amplifier, since PILA is ~136 bytes vs the 28+
// bytes an attacker has to send to trigger it).
// maybeSendRecoveryPILA emits an unsolicited authenticated-key-exchange
// frame to a peer we have no crypto state for. viaRelay should be true
// when the trigger frame arrived through the beacon — in that case we
// wrap the PILA in a MsgRelay envelope so it travels the same path
// back. Direct-path senders see addr = peer's actual UDP endpoint and
// viaRelay = false.
func (tm *TunnelManager) maybeSendRecoveryPILA(nodeID uint32, addr *net.UDPAddr, viaRelay bool) {
	// For direct sends we need a real address; for relay sends we
	// need the beacon addr. Bail early if neither makes sense.
	if !viaRelay && addr == nil {
		return
	}
	tm.mu.Lock()
	last := tm.lastRecoveryPILA[nodeID]
	now := time.Now()
	if !last.IsZero() && now.Sub(last) < recoveryPILAInterval {
		tm.mu.Unlock()
		return
	}
	tm.lastRecoveryPILA[nodeID] = now
	bAddr := tm.beaconAddr
	tm.mu.Unlock()

	frame := tm.buildAuthKeyExchangeFrame()
	if frame == nil {
		// Identity or X25519 key isn't loaded yet — nothing to send.
		return
	}

	// Consistency with RegisterWithBeacon / RequestHolePunch: both
	// guard on tm.udp != nil. If the daemon is still mid-startup
	// (Listen hasn't completed), the recovery path must not panic
	// on a nil UDP transport.
	if tm.udp == nil {
		slog.Debug("recovery PILA skipped: UDP transport not listening yet", "peer_node_id", nodeID)
		return
	}

	if viaRelay {
		if bAddr == nil {
			slog.Debug("recovery PILA skipped: via-relay trigger but no beacon configured", "peer_node_id", nodeID)
			return
		}
		// MsgRelay wrapper: [0x05][senderID][destID][PILA frame]
		env := make([]byte, 1+4+4+len(frame))
		env[0] = protocol.BeaconMsgRelay
		binary.BigEndian.PutUint32(env[1:5], tm.loadNodeID())
		binary.BigEndian.PutUint32(env[5:9], nodeID)
		copy(env[9:], frame)
		if _, err := tm.udp.WriteToUDPAddr(env, bAddr); err != nil {
			slog.Debug("recovery PILA (relay) send failed", "peer_node_id", nodeID, "error", err)
			return
		}
		slog.Info("sent recovery PILA (relay) to peer with unknown key", "peer_node_id", nodeID)
		return
	}

	if _, err := tm.udp.WriteToUDPAddr(frame, addr); err != nil {
		slog.Debug("recovery PILA send failed", "peer_node_id", nodeID, "addr", addr, "error", err)
		return
	}
	slog.Info("sent recovery PILA to peer with unknown key", "peer_node_id", nodeID, "addr", addr)
}

// buildKeyExchangeFrame builds an unauthenticated key exchange frame.
func (tm *TunnelManager) buildKeyExchangeFrame() []byte {
	if tm.pubKey == nil {
		return nil
	}
	frame := make([]byte, 4+4+32)
	copy(frame[0:4], protocol.TunnelMagicKeyEx[:])
	binary.BigEndian.PutUint32(frame[4:8], tm.loadNodeID())
	copy(frame[8:40], tm.pubKey)
	return frame
}

// flushPending sends any queued packets for a peer now that encryption is ready.
func (tm *TunnelManager) flushPending(nodeID uint32) {
	tm.pendMu.Lock()
	frames := tm.pending[nodeID]
	delete(tm.pending, nodeID)
	tm.pendMu.Unlock()

	if len(frames) == 0 {
		return
	}

	tm.mu.RLock()
	var addr *net.UDPAddr
	if p := tm.paths[nodeID]; p != nil {
		addr = p.direct
	}
	pc := tm.crypto[nodeID]
	tm.mu.RUnlock()

	if pc == nil || !pc.ready {
		return
	}

	for _, plaintext := range frames {
		encrypted := tm.encryptFrame(pc, plaintext)
		if err := tm.writeFrame(nodeID, addr, encrypted); err != nil {
			slog.Error("flush pending to node failed", "node_id", nodeID, "error", err)
		}
	}
	slog.Debug("flushed pending packets", "node_id", nodeID, "count", len(frames))
}

// encryptFrame encrypts a marshaled packet and returns a full tunnel frame.
// Format: [PILS][4-byte nodeID][12-byte nonce][ciphertext+GCM tag]
func (tm *TunnelManager) encryptFrame(pc *peerCrypto, plaintext []byte) []byte {
	nonce := make([]byte, pc.aead.NonceSize())
	copy(nonce[0:4], pc.noncePrefix[:])
	counter := atomic.AddUint64(&pc.nonce, 1)
	binary.BigEndian.PutUint64(nonce[pc.aead.NonceSize()-8:], counter)

	// H3 fix: bind sender's nodeID as AAD
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, tm.loadNodeID())
	ciphertext := pc.aead.Seal(nil, nonce, plaintext, aad)
	atomic.AddUint64(&tm.EncryptOK, 1)

	frame := make([]byte, 4+4+len(nonce)+len(ciphertext))
	copy(frame[0:4], protocol.TunnelMagicSecure[:])
	binary.BigEndian.PutUint32(frame[4:8], tm.loadNodeID())
	copy(frame[8:8+len(nonce)], nonce)
	copy(frame[8+len(nonce):], ciphertext)

	return frame
}

// Send encapsulates and sends a packet to the given node.
func (tm *TunnelManager) Send(nodeID uint32, pkt *protocol.Packet) error {
	tm.mu.RLock()
	p := tm.paths[nodeID]
	tm.mu.RUnlock()

	// Accept relay-only paths (direct=nil, viaRelay=true) because
	// writeFrame will route via the beacon without needing a direct
	// endpoint. Reject only if we have no entry at all, or an entry
	// with neither direct nor relay viable.
	if p == nil || (p.direct == nil && !p.viaRelay) {
		return fmt.Errorf("no tunnel to node %d", nodeID)
	}
	// addr is non-nil only for direct peers; writeFrame ignores it for
	// relay peers (routes via beaconAddr instead).
	return tm.SendTo(p.direct, nodeID, pkt)
}

// SendTo sends a packet to a specific UDP address (relay-aware).
func (tm *TunnelManager) SendTo(addr *net.UDPAddr, nodeID uint32, pkt *protocol.Packet) error {
	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Check if we should encrypt
	if tm.encrypt {
		tm.mu.RLock()
		pc := tm.crypto[nodeID]
		tm.mu.RUnlock()

		if pc != nil && pc.ready {
			frame := tm.encryptFrame(pc, data)
			return tm.writeFrame(nodeID, addr, frame)
		}

		// No key yet — initiate key exchange and queue the packet (C1 fix: no plaintext fallback)
		tm.sendKeyExchangeToNode(nodeID)
		tm.pendMu.Lock()
		if _, exists := tm.pending[nodeID]; !exists && len(tm.pending) >= maxPendingPeers {
			tm.pendMu.Unlock()
			return fmt.Errorf("too many pending key exchanges")
		}
		q := tm.pending[nodeID]
		if len(q) >= maxPendingPerPeer {
			q = q[1:] // drop oldest
		}
		tm.pending[nodeID] = append(q, data)
		tm.pendMu.Unlock()
		return nil // queued, will be sent encrypted after key exchange
	}

	return tm.sendPlaintextToNode(nodeID, addr, data)
}

// sendPlaintextToNode sends a marshaled packet with PILT magic (relay-aware).
func (tm *TunnelManager) sendPlaintextToNode(nodeID uint32, addr *net.UDPAddr, data []byte) error {
	frame := make([]byte, 4+len(data))
	copy(frame[0:4], protocol.TunnelMagic[:])
	copy(frame[4:], data)
	return tm.writeFrame(nodeID, addr, frame)
}

// AddPeer registers a peer's real UDP endpoint. Treated as an
// authoritative direct-endpoint installation (mirrors WireGuard's
// `wg set peer ... endpoint`): the caller is explicitly claiming this
// is a valid, current direct address, so any stale relay-mode bit is
// cleared too. If the peer's path drifts back to relay-only at some
// later point, the decrypt-side update rules in handleEncrypted will
// flip viaRelay back on via observed ingress.
//
// The caller-facing contract: "install this as the best-known direct
// path, reset any prior relay-fallback state." This prevents the
// regression where a prior SetRelayPeer(true) (e.g. after a dial-
// timeout fallback) persists through a subsequent AddPeer that was
// supposed to install a fresh, known-good direct addr.
func (tm *TunnelManager) AddPeer(nodeID uint32, addr *net.UDPAddr) {
	tm.mu.Lock()
	p := tm.getOrCreatePath(nodeID)
	p.direct = addr
	p.viaRelay = false
	// No path.lastSeen update here — this is a seed, not an observed
	// ingress. The first authenticated decrypt from this peer will
	// promote the entry to "seen live".
	tm.mu.Unlock()
	slog.Debug("added peer", "node_id", nodeID, "addr", addr)

	// If encryption is enabled, initiate key exchange (relay-aware)
	if tm.encrypt {
		tm.sendKeyExchangeToNode(nodeID)
	}
}

// RemovePeer removes a peer and wipes all per-peer state. Mirrors
// WireGuard's `wg set peer ... remove` semantics: after removal, a
// future re-add observes a fresh zero-state and cannot be surprised
// by stale capability bits, recovery-PILA rate limiters, or cached
// TCP endpoints belonging to a previous incarnation of this
// nodeID.
//
// v1.9.0-jf.5: previously this function only cleared `paths` and
// `crypto`, leaving `peerCaps`, `peerPubKeys`, `peerTCP`,
// `peerConns`, and `lastRecoveryPILA` entries behind. Those could
// silently persist across a peer rejoin and influence gossip
// capability probing, TCP fallback routing, and recovery-PILA rate
// limiting in ways that depended on the previous peer instance —
// not always correct when the re-added peer is a fresh daemon at
// the same node_id.
func (tm *TunnelManager) RemovePeer(nodeID uint32) {
	tm.mu.Lock()
	delete(tm.paths, nodeID)
	delete(tm.crypto, nodeID)
	delete(tm.peerCaps, nodeID)
	delete(tm.peerPubKeys, nodeID)
	delete(tm.peerTCP, nodeID)
	delete(tm.peerTURN, nodeID)
	delete(tm.lastRecoveryPILA, nodeID)
	// peerConns owns a DialedConn — close before deleting so the
	// underlying TCP/QUIC socket is released.
	if conn, ok := tm.peerConns[nodeID]; ok {
		_ = conn.Close()
		delete(tm.peerConns, nodeID)
	}
	tm.mu.Unlock()
}

// HasPeer checks if we have a tunnel to a node — meaning an entry in
// the paths map, which exists whenever AddPeer or any authenticated
// decrypt has run for the peer. Accepts both direct-only and relay-
// only paths.
func (tm *TunnelManager) HasPeer(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, ok := tm.paths[nodeID]
	return ok
}

// HasCrypto returns true if we have an encryption context for a peer (proving prior key exchange).
func (tm *TunnelManager) HasCrypto(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, ok := tm.crypto[nodeID]
	return ok
}

// IsEncrypted returns true if the tunnel to a peer is encrypted.
func (tm *TunnelManager) IsEncrypted(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	pc := tm.crypto[nodeID]
	return pc != nil && pc.ready
}

// PeerCount returns the number of known peers.
func (tm *TunnelManager) PeerCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.paths)
}

// PeerInfo describes a known peer.
type PeerInfo struct {
	NodeID        uint32
	Endpoint      string
	Encrypted     bool
	Authenticated bool // true if peer proved Ed25519 identity
	Relay         bool // true if using beacon relay (symmetric NAT)
}

// PeerList returns all known peers and their endpoints. Endpoint is
// the last-known direct UDP addr if any; relay-only peers (direct=nil
// and viaRelay=true) surface as "(relay)" so the dashboard makes the
// path mode visible.
func (tm *TunnelManager) PeerList() []PeerInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var list []PeerInfo
	for id, p := range tm.paths {
		pc := tm.crypto[id]
		endpoint := "(relay)"
		if p != nil && p.direct != nil {
			endpoint = p.direct.String()
		}
		list = append(list, PeerInfo{
			NodeID:        id,
			Endpoint:      endpoint,
			Encrypted:     pc != nil && pc.ready,
			Authenticated: pc != nil && pc.authenticated,
			Relay:         p != nil && p.viaRelay,
		})
	}
	return list
}

// handleBeaconMessage processes beacon protocol messages received on the tunnel socket.
func (tm *TunnelManager) handleBeaconMessage(data []byte, from *net.UDPAddr) {
	if len(data) < 1 {
		return
	}
	switch data[0] {
	case protocol.BeaconMsgDiscoverReply:
		slog.Debug("beacon discover reply on tunnel socket", "from", from)
	case protocol.BeaconMsgPunchCommand:
		tm.handlePunchCommand(data[1:])
	case protocol.BeaconMsgRelayDeliver:
		tm.handleRelayDeliver(data[1:])
	default:
		slog.Debug("unknown beacon message on tunnel socket", "type", data[0], "from", from)
	}
}

// handlePunchCommand processes a beacon punch command, sending a punch packet
// to the specified target to create a NAT mapping.
func (tm *TunnelManager) handlePunchCommand(data []byte) {
	// Format: [iplen(1)][IP(4 or 16)][port(2)]
	if len(data) < 1 {
		return
	}
	ipLen := int(data[0])
	if ipLen != 4 && ipLen != 16 {
		return
	}
	if len(data) < 1+ipLen+2 {
		return
	}
	ip := net.IP(make([]byte, ipLen))
	copy(ip, data[1:1+ipLen])
	port := binary.BigEndian.Uint16(data[1+ipLen:])
	addr := &net.UDPAddr{IP: ip, Port: int(port)}

	// Skip punches to non-routable addresses. This can happen when the beacon
	// is itself behind a NAT/LB that rewrites client source IPs (e.g. GCP Cloud
	// NAT advertises 10.128.0.12 for every registrant), producing punch targets
	// that are unreachable from anywhere. Mirrors the STUN-result filter in
	// daemon.go (isPrivateAddr).
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		slog.Warn("skipping NAT punch to non-routable target", "target", addr)
		return
	}

	// Send punch packets to create NAT mapping (send multiple for reliability).
	// Goes via the UDP transport directly — punch is UDP-specific and
	// bypasses the writeFrame/relay routing deliberately.
	if tm.udp == nil {
		return
	}
	punch := make([]byte, 4)
	copy(punch, protocol.TunnelMagicPunch[:])
	for i := 0; i < 3; i++ {
		_, _ = tm.udp.WriteToUDPAddr(punch, addr)
	}
	slog.Info("NAT punch sent", "target", addr)
}

// handleRelayDeliver processes a beacon relay delivery, extracting the inner tunnel frame.
//
// v1.9.0-jf.4: the preliminary pre-decrypt "mark as relay" step was
// removed. Previously we poisoned tm.peers[srcNodeID] with the
// beacon's address as a placeholder, which then polluted downstream
// code that read tm.peers as "the peer's real UDP endpoint" (same-
// LAN detection, accounting, the NAT-drift refresh). The new path-
// update rule fires inside the authenticated decrypt handlers
// (updatePathRelay, via fromRelay=true) — only authenticated frames
// cause state changes, and unauthenticated frames can't pollute
// anything. A relayed frame from a peer we've never seen simply
// doesn't affect state until its authenticated contents arrive at
// one of the handlers below.
func (tm *TunnelManager) handleRelayDeliver(data []byte) {
	// Format: [srcNodeID(4)][payload...]
	if len(data) < 5 {
		return
	}
	srcNodeID := binary.BigEndian.Uint32(data[0:4])
	payload := data[4:]

	// Best-effort webhook: emit "relay activated" once per peer.
	// Safe to race; the worst case is we emit twice. Use a probe read
	// so we don't grab the write lock on every relayed packet.
	tm.mu.RLock()
	p := tm.paths[srcNodeID]
	alreadyRelay := p != nil && p.viaRelay
	tm.mu.RUnlock()
	if !alreadyRelay {
		tm.webhook.Emit("tunnel.relay_activated", map[string]interface{}{
			"peer_node_id": srcNodeID,
		})
	}

	if len(payload) < 4 {
		return
	}

	// From-addr for the inner frame: we don't know the peer's real
	// UDP endpoint from the relay envelope alone (the beacon could be
	// between us and any peer). Use a zero-value UDPAddr as an
	// explicit "unknown — came via relay" marker. The decrypt handlers
	// use the fromRelay=true flag for path routing, not this addr;
	// this addr only surfaces to IncomingPacket.From for logging.
	srcAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}

	// Process the inner tunnel frame
	magic := [4]byte{payload[0], payload[1], payload[2], payload[3]}
	switch magic {
	case protocol.TunnelMagicAuthEx:
		tm.handleAuthKeyExchange(payload[4:], srcAddr, true)
	case protocol.TunnelMagicKeyEx:
		tm.handleKeyExchange(payload[4:], srcAddr, true)
	case protocol.TunnelMagicSecure:
		tm.handleEncrypted(payload[4:], srcAddr, true /* fromRelay */)
	case protocol.TunnelMagic:
		if len(payload) < 4+protocol.PacketHeaderSize() {
			return
		}
		frameData := make([]byte, len(payload)-4)
		copy(frameData, payload[4:])
		pkt, err := protocol.Unmarshal(frameData)
		if err != nil {
			slog.Error("tunnel unmarshal error from relay", "src_node", srcNodeID, "error", err)
			return
		}
		atomic.AddUint64(&tm.PktsRecv, 1)
		atomic.AddUint64(&tm.BytesRecv, uint64(len(payload)))
		select {
		case tm.recvCh <- &IncomingPacket{Packet: pkt, From: srcAddr}:
		case <-tm.done:
		}
	}
}

// RecvCh returns the channel for incoming packets.
func (tm *TunnelManager) RecvCh() <-chan *IncomingPacket {
	return tm.recvCh
}

// DiscoverEndpoint sends a STUN discover to the beacon and returns the observed public endpoint.
func DiscoverEndpoint(beaconAddr string, nodeID uint32, conn *net.UDPConn) (*net.UDPAddr, error) {
	bAddr, err := net.ResolveUDPAddr("udp", beaconAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve beacon: %w", err)
	}

	// Send discover message
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], nodeID)

	if _, err := conn.WriteToUDP(msg, bAddr); err != nil {
		return nil, fmt.Errorf("send discover: %w", err)
	}

	// Read reply
	buf := make([]byte, 64)
	conn.SetReadDeadline(fixedTimeout())
	n, _, err := conn.ReadFromUDP(buf)
	conn.SetReadDeadline(zeroTime())
	if err != nil {
		return nil, fmt.Errorf("discover reply: %w", err)
	}

	// Format: [type(1)][iplen(1)][IP(4 or 16)][port(2)]
	if n < 4 || buf[0] != protocol.BeaconMsgDiscoverReply {
		return nil, fmt.Errorf("invalid discover reply")
	}
	ipLen := int(buf[1])
	if ipLen != 4 && ipLen != 16 {
		return nil, fmt.Errorf("invalid discover reply: bad IP length %d", ipLen)
	}
	if n < 2+ipLen+2 {
		return nil, fmt.Errorf("invalid discover reply: too short")
	}

	ip := net.IP(make([]byte, ipLen))
	copy(ip, buf[2:2+ipLen])
	port := binary.BigEndian.Uint16(buf[2+ipLen : 2+ipLen+2])

	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}
