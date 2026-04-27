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
	paths     map[uint32]*peerPath               // node_id → last-authenticated ingress path
	peerTCP   map[uint32]*transport.TCPEndpoint  // node_id → TCP endpoint, populated from registry lookup when advertised
	peerTURN  map[uint32]*transport.TURNEndpoint // node_id → TURN relayed endpoint, populated from SetPeerEndpoints
	peerConns map[uint32]transport.DialedConn    // node_id → cached DialedConn (whichever transport won the last Dial)

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
	crypto           map[uint32]*peerCrypto // node_id → encryption state
	recvCh           chan *IncomingPacket
	done             chan struct{}  // closed on Close() to stop dispatchLoop
	readWg           sync.WaitGroup // tracks dispatchLoop goroutine for clean shutdown
	closeOnce        sync.Once

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
	// lastAuthKEXResponse bounds same-key replies to authenticated
	// recovery PILA requests. A verified peer may repeat a request when
	// our first reciprocal PILA was lost; we answer those idempotently,
	// but not for every duplicate frame.
	lastAuthKEXResponse map[uint32]time.Time
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

	// jf.15.2: per-tier send observability. Counters always
	// populated regardless of traceSends; gated INFO log fires
	// only when traceSends is true. Tier index follows
	// SendTier* constants below.
	PktsSentByTier  [numSendTiers]uint64
	BytesSentByTier [numSendTiers]uint64

	// traceSends, when true, gates per-event INFO logging in
	// writeFrame and SendTo. Set once at daemon.Start; never
	// changed at runtime in production. Tests may toggle via
	// SetTraceSends.
	traceSends bool
}

// Send-tier identifiers used by jf.15.2's per-tier counters and
// gated trace logs. The index space MUST stay stable — operators
// rely on the JSON map keys for diagnostics.
const (
	SendTierOutboundTurnOnlyCached   = 0
	SendTierOutboundTurnOnlyJF9      = 1
	SendTierOutboundTurnOnlyOwnRelay = 2
	SendTierBeaconRelay              = 3
	SendTierCachedConn               = 4
	SendTierJF9Fallback              = 5
	SendTierDirectUDP                = 6
	SendTierQueuedPendingKey         = 7
	numSendTiers                     = 8
)

// sendTierName returns a stable string label for the given tier
// index. Used for INFO log fields and the JSON snapshot's map
// keys. Returns "unknown" for out-of-range indices to keep the
// caller from panicking on a future tier-table addition.
func sendTierName(tier int) string {
	switch tier {
	case SendTierOutboundTurnOnlyCached:
		return "outbound_turn_only_cached"
	case SendTierOutboundTurnOnlyJF9:
		return "outbound_turn_only_jf9"
	case SendTierOutboundTurnOnlyOwnRelay:
		return "outbound_turn_only_own_relay"
	case SendTierBeaconRelay:
		return "beacon_relay"
	case SendTierCachedConn:
		return "cached_conn"
	case SendTierJF9Fallback:
		return "jf9_fallback"
	case SendTierDirectUDP:
		return "direct_udp"
	case SendTierQueuedPendingKey:
		return "queued_pending_key"
	default:
		return "unknown"
	}
}

// recordTierSend is the jf.15.2 helper that bumps the per-tier
// counters AND emits a gated INFO log line, in one call.
//
// Always called AFTER the tier's underlying Send / WriteToUDPAddr
// resolves. result is "ok" or "err: <msg>". When err is non-nil,
// counters are NOT incremented (a failed send didn't put bytes
// on the wire); the log fires regardless to make the failure
// observable. dstAddr is best-effort — pass "" if not known.
func (tm *TunnelManager) recordTierSend(
	tier int, nodeID uint32, bytesLen int,
	dstAddr string, viaRelay bool, err error,
) {
	if err == nil {
		atomic.AddUint64(&tm.PktsSentByTier[tier], 1)
		atomic.AddUint64(&tm.BytesSentByTier[tier], uint64(bytesLen))
	}
	if !tm.traceSends {
		return
	}
	result := "ok"
	if err != nil {
		result = "err: " + err.Error()
	}
	slog.Info("writeFrame",
		"node_id", nodeID,
		"tier", sendTierName(tier),
		"bytes", bytesLen,
		"dst_addr", dstAddr,
		"result", result,
		"via_relay", viaRelay,
	)
}

// SetTraceSends toggles jf.15.2's per-send INFO logging at
// runtime. Test-only hook; production sets this once at
// daemon.Start via Config.TraceSends.
func (tm *TunnelManager) SetTraceSends(on bool) {
	tm.mu.Lock()
	tm.traceSends = on
	tm.mu.Unlock()
}

// addrString is a nil-safe helper for trace-log dst_addr
// fields. Returns "" instead of panicking on a nil *net.UDPAddr.
func addrString(a *net.UDPAddr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// SnapshotPktsByTier returns an atomic snapshot of the per-tier
// packet counters as a map keyed by stable tier name. Used by
// pilotctl info to expose where each peer's traffic is going
// without requiring the high-volume -trace-sends flag.
//
// Tiers with zero packets are still included so operators can
// confirm "this tier never fired" vs "this tier hasn't been
// queried yet". (v1.9.0-jf.15.2)
func (tm *TunnelManager) SnapshotPktsByTier() map[string]uint64 {
	out := make(map[string]uint64, numSendTiers)
	for i := 0; i < numSendTiers; i++ {
		out[sendTierName(i)] = atomic.LoadUint64(&tm.PktsSentByTier[i])
	}
	return out
}

// SnapshotBytesByTier mirrors SnapshotPktsByTier for bytes.
// (v1.9.0-jf.15.2)
func (tm *TunnelManager) SnapshotBytesByTier() map[string]uint64 {
	out := make(map[string]uint64, numSendTiers)
	for i := 0; i < numSendTiers; i++ {
		out[sendTierName(i)] = atomic.LoadUint64(&tm.BytesSentByTier[i])
	}
	return out
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
		udp:                 transport.NewUDPTransport(),
		inbound:             make(chan transport.InboundFrame, RecvChSize),
		paths:               make(map[uint32]*peerPath),
		peerTCP:             make(map[uint32]*transport.TCPEndpoint),
		peerTURN:            make(map[uint32]*transport.TURNEndpoint),
		peerConns:           make(map[uint32]transport.DialedConn),
		turnPermittedPeers:  make(map[string]time.Time),
		crypto:              make(map[uint32]*peerCrypto),
		peerPubKeys:         make(map[uint32]ed25519.PublicKey),
		peerCaps:            make(map[uint32]uint64),
		lastRecoveryPILA:    make(map[uint32]time.Time),
		lastAuthKEXResponse: make(map[uint32]time.Time),
		pending:             make(map[uint32][][]byte),
		recvCh:              make(chan *IncomingPacket, RecvChSize),
		done:                make(chan struct{}),
		gossipView:          gossip.NewMembershipView(),
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

// AddPeerTURNEndpoint records a peer's advertised TURN relay address,
// evicts stale cached conns when that address changes, and permissions
// the peer's allocation on our local TURN allocation when present.
func (tm *TunnelManager) AddPeerTURNEndpoint(nodeID uint32, addr string) error {
	ep, err := transport.NewTURNEndpoint(addr)
	if err != nil {
		return fmt.Errorf("turn endpoint %q: %w", addr, err)
	}
	oldAddr, newAddr, evicted := tm.storePeerTURNEndpoint(nodeID, ep)
	if evicted != nil {
		_ = evicted.Close()
		slog.Debug("evicted stale peer conn after turn endpoint change",
			"node_id", nodeID, "old_addr", oldAddr, "new_addr", newAddr)
	}
	if err := tm.permitPeerTURNEndpoint(newAddr); err != nil {
		slog.Debug("permit turn peer on endpoint install failed",
			"node_id", nodeID, "addr", newAddr, "error", err)
	}
	return nil
}

func (tm *TunnelManager) storePeerTURNEndpoint(
	nodeID uint32,
	ep *transport.TURNEndpoint,
) (oldAddr string, newAddr string, evicted transport.DialedConn) {
	newAddr = ep.String()
	tm.mu.Lock()
	defer tm.mu.Unlock()
	prevEp := tm.peerTURN[nodeID]
	tm.peerTURN[nodeID] = ep
	if prevEp == nil {
		return "", newAddr, nil
	}
	oldAddr = prevEp.String()
	if oldAddr == newAddr {
		return oldAddr, newAddr, nil
	}
	if cached := tm.peerConns[nodeID]; cached != nil && dialedConnNetwork(cached) != "udp" {
		evicted = cached
		delete(tm.peerConns, nodeID)
	}
	return oldAddr, newAddr, evicted
}

func (tm *TunnelManager) permitPeerTURNEndpoint(addr string) error {
	// TURN permissions are bilateral: after learning a peer's relay
	// allocation over rendezvous or transport ads, permission that
	// allocation locally so inbound relay traffic is not silently dropped.
	return tm.PermitTURNPeer(addr)
}

// HasTURNEndpoint reports whether we've recorded a TURN endpoint for
// the given peer.
func (tm *TunnelManager) HasTURNEndpoint(nodeID uint32) bool {
	tm.mu.RLock()
	_, ok := tm.peerTURN[nodeID]
	tm.mu.RUnlock()
	return ok
}

// PeerTURNEndpoint returns the host:port string of the peer's
// recorded TURN endpoint, or "" if none is recorded. Used by
// the daemon's rendezvous lookup path (v1.9.0-jf.14) to decide
// whether a fresh record from the rendezvous differs from what's
// already in the path table — no point reinstalling an
// identical address.
func (tm *TunnelManager) PeerTURNEndpoint(nodeID uint32) string {
	tm.mu.RLock()
	ep := tm.peerTURN[nodeID]
	tm.mu.RUnlock()
	if ep == nil {
		return ""
	}
	return ep.String()
}

// KnownTURNPeers returns the node IDs of every peer with a
// recorded TURN endpoint. Used by the rendezvous peer-refresh
// loop (v1.9.0-jf.15.7) to walk peers we should periodically
// re-look-up — Cloudflare and similar TURN providers rotate
// allocation addresses every ~30 min, and without a periodic
// re-fetch our cached peerTURN points at a dead allocation the
// moment the peer rotates. Snapshot is a copy; safe to mutate.
func (tm *TunnelManager) KnownTURNPeers() []uint32 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	out := make([]uint32, 0, len(tm.peerTURN))
	for id, ep := range tm.peerTURN {
		if ep != nil {
			out = append(out, id)
		}
	}
	return out
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

// AuthenticatedPeerIDs returns the node IDs of all peers whose
// encrypted-tunnel state is ready (i.e. shared crypto keys are
// installed and at least one authenticated frame has flowed).
// Used by the daemon's peer-keepalive loop (v1.9.0-jf.13) to emit
// periodic permission-refresh frames to every reachable peer.
//
// Snapshots under RLock; the returned slice is safe to iterate
// without holding the lock.
func (tm *TunnelManager) AuthenticatedPeerIDs() []uint32 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	out := make([]uint32, 0, len(tm.crypto))
	for nodeID, pc := range tm.crypto {
		if pc != nil && pc.ready {
			out = append(out, nodeID)
		}
	}
	return out
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

// writeFrame sends a raw frame to a peer. Route precedence lives in
// route_policy.go; this method snapshots tunnel state and executes the
// selected candidates.
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
	cachedNet := dialedConnNetwork(cachedConn)
	hasPeerTURN := tm.peerTURN[nodeID] != nil
	hasLocalTURN := tm.turn != nil
	turnOnly := tm.outboundTURNOnly
	tm.mu.RUnlock()

	plan := planFrameRoutes(frameRoutePolicyInput{
		outboundTURNOnly: turnOnly,
		relay:            relay,
		hasBeacon:        bAddr != nil,
		hasLocalTURN:     hasLocalTURN,
		hasPeerTURN:      hasPeerTURN,
		cachedConnNet:    cachedNet,
		callerAddr:       addr,
		pathDirect:       pathDirect,
	})

	for _, candidate := range plan.candidates {
		done, err := tm.executeFrameRouteCandidate(nodeID, frame, candidate, frameRouteExecState{
			relay:      relay,
			beaconAddr: bAddr,
			cachedConn: cachedConn,
		})
		if done {
			return err
		}
	}

	if plan.failClosed {
		return fmt.Errorf("outbound-turn-only: no TURN path for node %d "+
			"(peer advertised no TURN endpoint, local TURN allocation "+
			"missing or dial failed, and no known UDP-reachable address "+
			"for this peer; tunnel traffic refused rather than leak "+
			"source IP via direct UDP or beacon)", nodeID)
	}
	return fmt.Errorf("no address for node %d", nodeID)
}

type frameRouteExecState struct {
	relay      bool
	beaconAddr *net.UDPAddr
	cachedConn transport.DialedConn
}

func (tm *TunnelManager) executeFrameRouteCandidate(
	nodeID uint32,
	frame []byte,
	candidate routeCandidate,
	state frameRouteExecState,
) (bool, error) {
	switch candidate.kind {
	case routeCandidateBeacon:
		return tm.sendFrameViaBeaconRoute(nodeID, frame, candidate.tier, state.beaconAddr, state.relay)
	case routeCandidateCachedConn:
		return tm.sendFrameViaCachedConnRoute(nodeID, frame, candidate.tier, state.cachedConn, state.relay)
	case routeCandidatePeerTURN:
		return tm.sendFrameViaPeerTURNRoute(nodeID, frame, candidate.tier, state.relay)
	case routeCandidateOwnTURNRelay:
		return tm.sendFrameViaOwnTURNRelayRoute(nodeID, frame, candidate.tier, candidate.addr, state.relay)
	case routeCandidateDirectUDP:
		return tm.sendFrameViaDirectUDPRoute(nodeID, frame, candidate.tier, candidate.addr, state.relay)
	default:
		return false, nil
	}
}

func (tm *TunnelManager) sendFrameViaBeaconRoute(
	nodeID uint32,
	frame []byte,
	tier int,
	beaconAddr *net.UDPAddr,
	relay bool,
) (bool, error) {
	if beaconAddr == nil {
		return false, nil
	}
	msg := make([]byte, 1+4+4+len(frame))
	msg[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(msg[1:5], tm.loadNodeID())
	binary.BigEndian.PutUint32(msg[5:9], nodeID)
	copy(msg[9:], frame)
	n, err := tm.udp.WriteToUDPAddr(msg, beaconAddr)
	tm.recordTierSend(tier, nodeID, len(frame), beaconAddr.String(), relay, err)
	if err == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(n))
	}
	return true, err
}

func (tm *TunnelManager) sendFrameViaCachedConnRoute(
	nodeID uint32,
	frame []byte,
	tier int,
	conn transport.DialedConn,
	relay bool,
) (bool, error) {
	if conn == nil || conn.RemoteEndpoint() == nil {
		return false, nil
	}
	err := conn.Send(frame)
	tm.recordTierSend(tier, nodeID, len(frame), conn.RemoteEndpoint().String(), relay, err)
	if err == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(len(frame)))
		return true, nil
	}
	tm.evictCachedConnIfSame(nodeID, conn)
	slog.Debug("cached peer conn failed, falling back",
		"node_id", nodeID,
		"network", conn.RemoteEndpoint().Network(),
		"error", err)
	return false, err
}

func (tm *TunnelManager) sendFrameViaPeerTURNRoute(
	nodeID uint32,
	frame []byte,
	tier int,
	relay bool,
) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	dialErr := tm.DialTURNRelayForPeer(ctx, nodeID)
	cancel()
	if dialErr != nil {
		tm.recordTierSend(tier, nodeID, len(frame), "", relay, dialErr)
		slog.Debug("turn-relay fallback dial failed", "node_id", nodeID, "error", dialErr)
		return false, nil
	}
	tm.mu.RLock()
	conn := tm.peerConns[nodeID]
	tm.mu.RUnlock()
	if conn == nil || conn.RemoteEndpoint() == nil || conn.RemoteEndpoint().Network() == "udp" {
		return false, nil
	}
	ok, _ := tm.sendFrameViaCachedConnRoute(nodeID, frame, tier, conn, relay)
	return ok, nil
}

func (tm *TunnelManager) sendFrameViaOwnTURNRelayRoute(
	nodeID uint32,
	frame []byte,
	tier int,
	addr *net.UDPAddr,
	relay bool,
) (bool, error) {
	if tm.turn == nil || addr == nil {
		return false, nil
	}
	err := tm.turn.SendViaOwnRelay(addr, frame)
	tm.recordTierSend(tier, nodeID, len(frame), addr.String(), relay, err)
	if err == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(len(frame)))
		return true, nil
	}
	slog.Debug("outbound-turn-only: send via own relay failed",
		"node_id", nodeID, "peer_addr", addr.String(), "error", err)
	return false, nil
}

func (tm *TunnelManager) sendFrameViaDirectUDPRoute(
	nodeID uint32,
	frame []byte,
	tier int,
	addr *net.UDPAddr,
	relay bool,
) (bool, error) {
	if addr == nil {
		return false, nil
	}
	n, err := tm.udp.WriteToUDPAddr(frame, addr)
	tm.recordTierSend(tier, nodeID, len(frame), addr.String(), relay, err)
	if err == nil {
		atomic.AddUint64(&tm.PktsSent, 1)
		atomic.AddUint64(&tm.BytesSent, uint64(n))
	}
	return true, err
}

func dialedConnNetwork(conn transport.DialedConn) string {
	if conn == nil || conn.RemoteEndpoint() == nil {
		return ""
	}
	return conn.RemoteEndpoint().Network()
}

func (tm *TunnelManager) evictCachedConnIfSame(nodeID uint32, conn transport.DialedConn) {
	tm.mu.Lock()
	if tm.peerConns[nodeID] == conn {
		delete(tm.peerConns, nodeID)
		_ = conn.Close()
	}
	tm.mu.Unlock()
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

			remote := udpAddrFromEndpoint(inbound.From)

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
				tm.handleAuthKeyExchange(buf[4:n], inbound.From, false)
				continue

			case protocol.TunnelMagicKeyEx:
				// Key exchange packet: [PILK][4-byte nodeID][32-byte pubkey]
				tm.handleKeyExchange(buf[4:n], inbound.From, false)
				continue

			case protocol.TunnelMagicSecure:
				// Encrypted packet: [PILS][4-byte nodeID][12-byte nonce][ciphertext+tag]
				tm.handleEncrypted(buf[4:n], inbound.From, false /* direct */)
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

func udpAddrFromEndpoint(ep transport.Endpoint) *net.UDPAddr {
	udpEP, ok := ep.(*transport.UDPEndpoint)
	if !ok || udpEP == nil {
		return nil
	}
	return udpEP.Addr()
}

func turnAddrFromEndpoint(ep transport.Endpoint) string {
	turnEP, ok := ep.(*transport.TURNEndpoint)
	if !ok || turnEP == nil {
		return ""
	}
	return turnEP.String()
}

// recordAuthenticatedIngress applies the reply-on-ingress rule after a
// key exchange frame has been accepted. UDP sources update path.direct;
// beacon sources mark relay mode; TURN sources install the peer's relay
// address and CreatePermission without poisoning path.direct with a
// relay IP.
func (tm *TunnelManager) recordAuthenticatedIngress(nodeID uint32, from transport.Endpoint, fromRelay bool, forceTURNInstall bool) {
	var turnAddr string
	if !fromRelay {
		turnAddr = turnAddrFromEndpoint(from)
	}

	tm.mu.Lock()
	if fromRelay {
		tm.updatePathRelay(nodeID)
	} else if turnAddr != "" {
		// Keep the peer visible/last-seen without treating the TURN
		// allocation as a direct UDP endpoint.
		tm.updatePathDirect(nodeID, nil)
	} else {
		tm.updatePathDirect(nodeID, udpAddrFromEndpoint(from))
	}
	tm.mu.Unlock()

	if turnAddr != "" && forceTURNInstall {
		if err := tm.AddPeerTURNEndpoint(nodeID, turnAddr); err != nil {
			slog.Debug("authenticated ingress turn endpoint install failed",
				"peer_node_id", nodeID, "addr", turnAddr, "error", err)
		}
	}
}

// refreshAuthenticatedIngress is the low-churn version used for
// decrypted data frames. It updates path state only when the observed
// ingress path differs from the current one.
func (tm *TunnelManager) refreshAuthenticatedIngress(nodeID uint32, from transport.Endpoint, fromRelay bool) {
	if fromRelay {
		tm.mu.RLock()
		p := tm.paths[nodeID]
		stale := p == nil || !p.viaRelay
		tm.mu.RUnlock()
		if stale {
			tm.mu.Lock()
			tm.updatePathRelay(nodeID)
			tm.mu.Unlock()
		}
		return
	}

	if turnAddr := turnAddrFromEndpoint(from); turnAddr != "" {
		tm.mu.RLock()
		p := tm.paths[nodeID]
		cur := tm.peerTURN[nodeID]
		stalePath := p == nil
		staleTurn := cur == nil || cur.String() != turnAddr
		tm.mu.RUnlock()
		if stalePath {
			tm.mu.Lock()
			tm.updatePathDirect(nodeID, nil)
			tm.mu.Unlock()
		}
		if staleTurn {
			if err := tm.AddPeerTURNEndpoint(nodeID, turnAddr); err != nil {
				slog.Debug("encrypted ingress turn endpoint install failed",
					"peer_node_id", nodeID, "addr", turnAddr, "error", err)
			}
		}
		return
	}

	fromUDP := udpAddrFromEndpoint(from)
	if fromUDP == nil {
		return
	}
	tm.mu.RLock()
	p := tm.paths[nodeID]
	stale := p == nil || p.viaRelay || p.direct == nil ||
		p.direct.Port != fromUDP.Port || !p.direct.IP.Equal(fromUDP.IP)
	tm.mu.RUnlock()
	if stale {
		tm.mu.Lock()
		tm.updatePathDirect(nodeID, fromUDP)
		tm.mu.Unlock()
	}
}

// handleAuthKeyExchange processes an authenticated key exchange packet.
// Format: [4-byte nodeID][32-byte X25519 pubkey][32-byte Ed25519 pubkey][64-byte Ed25519 signature]
// The signature is over: "auth:" + nodeID(4 bytes) + X25519-pubkey(32 bytes)
// fromRelay indicates this was received via beacon relay — don't update peer endpoint.
func (tm *TunnelManager) handleAuthKeyExchange(data []byte, from transport.Endpoint, fromRelay bool) {
	if len(data) < 4+32+32+64 {
		return
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	peerX25519PubKey := data[4:36]
	peerEd25519PubKey := ed25519.PublicKey(data[36:68])
	signature := data[68:132]

	peerCaps, kexFlags := parseAuthKEXTrailer(data[132:])

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
	if hadCrypto && !keyChanged {
		oldPC.authenticated = true
		pc = oldPC
	} else {
		tm.crypto[peerNodeID] = pc
	}
	// Cache the peer's Ed25519 pubkey and advertised caps bitmap.
	tm.peerPubKeys[peerNodeID] = peerEd25519PubKey
	tm.peerCaps[peerNodeID] = peerCaps
	shouldReply := !hadCrypto || keyChanged
	if !shouldReply && kexFlags&authKEXFlagRequest != 0 {
		now := time.Now()
		last := tm.lastAuthKEXResponse[peerNodeID]
		if last.IsZero() || now.Sub(last) >= authKEXResponseInterval {
			tm.lastAuthKEXResponse[peerNodeID] = now
			shouldReply = true
		}
	}
	tm.mu.Unlock()

	tm.recordAuthenticatedIngress(peerNodeID, from, fromRelay, true)

	if keyChanged {
		slog.Info("peer rekeyed (auth), re-establishing tunnel", "peer_node_id", peerNodeID)
	} else {
		slog.Info("encrypted tunnel established", "auth", authenticated, "peer_node_id", peerNodeID, "endpoint", from, "relay", fromRelay)
	}
	tm.webhook.Emit("tunnel.established", map[string]interface{}{
		"peer_node_id": peerNodeID, "authenticated": authenticated,
		"relay": fromRelay, "rekeyed": keyChanged,
	})

	if shouldReply {
		// v1.9.0-jf.12: pass the observed source so the reply lands
		// at the peer's freshly-observed address, not a stale
		// path.direct. Skipped (nil) for relay-delivered frames so
		// writeFrame's tier-1 (beacon-relay) keeps routing the reply
		// back through the relay path.
		var src transport.Endpoint
		if !fromRelay {
			src = from
		}
		tm.sendKeyExchangeToEndpoint(peerNodeID, src, authKEXFlagResponse)
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
func (tm *TunnelManager) handleKeyExchange(data []byte, from transport.Endpoint, fromRelay bool) {
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
			// v1.9.0-jf.12: nudge the peer with our auth'd key
			// exchange. Use the observed source addr so we don't
			// nudge into a stale cached endpoint.
			var src transport.Endpoint
			if !fromRelay {
				src = from
			}
			tm.sendKeyExchangeToEndpoint(peerNodeID, src, authKEXFlagResponse)
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
	tm.mu.Unlock()

	tm.recordAuthenticatedIngress(peerNodeID, from, fromRelay, false)

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
		// v1.9.0-jf.12: prefer observed source over cached path.direct
		// so post-rotation handshakes converge in one round trip.
		var src transport.Endpoint
		if !fromRelay {
			src = from
		}
		tm.sendKeyExchangeToEndpoint(peerNodeID, src, 0)
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
func (tm *TunnelManager) handleEncrypted(data []byte, from transport.Endpoint, fromRelay bool) {
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

	tm.refreshAuthenticatedIngress(peerNodeID, from, fromRelay)

	fromUDP := udpAddrFromEndpoint(from)
	select {
	case tm.recvCh <- &IncomingPacket{Packet: pkt, From: fromUDP}:
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
//
// observedSrc, when non-nil, is the source UDP address of the
// inbound authenticated frame that triggered this reply (passed by
// handleAuthKeyExchange / handleKeyExchange). Per the WireGuard
// endpoint-learning rule, the reply MUST go to that observed source
// — it's the freshest evidence of where the peer is reachable, and
// using it breaks the chicken-and-egg deadlock that arose post-TURN-
// allocation rotation: peer B had A's OLD TURN cached in
// path[A].direct, B's reply to A's handshake went to OLD TURN, frame
// dropped at Cloudflare, A's auth never completed.
//
// When observedSrc is nil (caller-initiated KEX from startup, AddPeer,
// or the SendTo queue path — none of which have an inbound frame to
// react to), we fall back to path.direct as before. (v1.9.0-jf.12)
func (tm *TunnelManager) sendKeyExchangeToNode(peerNodeID uint32, observedSrc *net.UDPAddr) {
	var observed transport.Endpoint
	if observedSrc != nil {
		observed = transport.NewUDPEndpoint(observedSrc)
	}
	tm.sendKeyExchangeToEndpoint(peerNodeID, observed, 0)
}

func (tm *TunnelManager) sendKeyExchangeToEndpoint(peerNodeID uint32, observed transport.Endpoint, authFlags uint64) {
	tm.mu.RLock()
	hasIdentity := tm.identity != nil
	tm.mu.RUnlock()

	frame := tm.buildKeyExchangeFrame()
	if frame == nil {
		return
	}

	if hasIdentity {
		authFrame := tm.buildAuthKeyExchangeFrameWithFlags(authFlags)
		if authFrame != nil {
			frame = authFrame
		}
	}

	if err := tm.writeFrameToEndpoint(peerNodeID, observed, frame); err != nil {
		slog.Error("send key exchange failed", "peer_node_id", peerNodeID, "error", err)
	}
}

func (tm *TunnelManager) writeFrameToEndpoint(nodeID uint32, ep transport.Endpoint, frame []byte) error {
	switch observed := ep.(type) {
	case nil:
		return tm.writeFrame(nodeID, nil, frame)
	case *transport.UDPEndpoint:
		return tm.writeFrame(nodeID, observed.Addr(), frame)
	case *transport.TURNEndpoint:
		return tm.writeFrameToTURNEndpoint(nodeID, observed, frame)
	default:
		return tm.writeFrame(nodeID, nil, frame)
	}
}

func (tm *TunnelManager) writeFrameToTURNEndpoint(nodeID uint32, ep *transport.TURNEndpoint, frame []byte) error {
	if ep == nil {
		return tm.writeFrame(nodeID, nil, frame)
	}
	if err := tm.AddPeerTURNEndpoint(nodeID, ep.String()); err != nil {
		return err
	}
	return tm.sendFrameViaExplicitTURNEndpoint(nodeID, ep, frame)
}

func (tm *TunnelManager) sendFrameViaExplicitTURNEndpoint(nodeID uint32, ep *transport.TURNEndpoint, frame []byte) error {
	tm.mu.RLock()
	cached := tm.peerConns[nodeID]
	t := tm.turn
	udpT := tm.udp
	tm.mu.RUnlock()

	if explicitTURNConnMatches(cached, ep) {
		if ok, err := tm.sendFrameViaCachedConnRoute(nodeID, frame, SendTierCachedConn, cached, false); ok || err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		conn transport.DialedConn
		err  error
	)
	if t != nil {
		conn, err = t.Dial(ctx, ep)
	} else if udpT != nil {
		conn, err = transport.DialTURNRelayViaUDP(udpT, ep)
	} else {
		err = fmt.Errorf("turn endpoint send: no turn or udp transport")
	}
	if err != nil {
		tm.recordTierSend(SendTierJF9Fallback, nodeID, len(frame),
			ep.String(), false, err)
		return err
	}

	existing, closeOld := tm.cacheExplicitTURNConn(nodeID, ep, conn)
	if existing != nil {
		_ = conn.Close()
		_, err := tm.sendFrameViaCachedConnRoute(nodeID, frame, SendTierCachedConn, existing, false)
		return err
	}
	if closeOld != nil {
		_ = closeOld.Close()
	}

	_, err = tm.sendFrameViaCachedConnRoute(nodeID, frame, SendTierJF9Fallback, conn, false)
	return err
}

func explicitTURNConnMatches(conn transport.DialedConn, ep *transport.TURNEndpoint) bool {
	return conn != nil &&
		ep != nil &&
		conn.RemoteEndpoint() != nil &&
		conn.RemoteEndpoint().Network() == "turn" &&
		conn.RemoteEndpoint().String() == ep.String()
}

func (tm *TunnelManager) cacheExplicitTURNConn(
	nodeID uint32,
	ep *transport.TURNEndpoint,
	conn transport.DialedConn,
) (existing transport.DialedConn, closeOld transport.DialedConn) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if existing := tm.peerConns[nodeID]; explicitTURNConnMatches(existing, ep) {
		return existing, nil
	}
	if existing := tm.peerConns[nodeID]; existing != nil {
		closeOld = existing
	}
	tm.peerConns[nodeID] = conn
	return nil, closeOld
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
//	[136:]    OPTIONAL varint capability bitmap, then optional KEX flags
//
// Older daemons truncate at byte 136 and never read the trailing
// varints, preserving backward compatibility; newer daemons read caps
// first and then request/response flags. A flags-only frame emits caps=0
// first so old peers do not confuse flags for gossip capabilities.
func (tm *TunnelManager) buildAuthKeyExchangeFrame() []byte {
	return tm.buildAuthKeyExchangeFrameWithFlags(0)
}

func (tm *TunnelManager) buildAuthKeyExchangeFrameWithFlags(kexFlags uint64) []byte {
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
	var trailer [2 * binary.MaxVarintLen64]byte
	var trailerLen int
	if caps != 0 || kexFlags != 0 {
		trailerLen += binary.PutUvarint(trailer[trailerLen:], caps)
	}
	if kexFlags != 0 {
		trailerLen += binary.PutUvarint(trailer[trailerLen:], kexFlags)
	}
	frame := make([]byte, base+trailerLen)
	copy(frame[0:4], protocol.TunnelMagicAuthEx[:])
	binary.BigEndian.PutUint32(frame[4:8], tm.loadNodeID())
	copy(frame[8:40], tm.pubKey)
	copy(frame[40:72], ed25519PubKey)
	copy(frame[72:136], signature)
	if trailerLen > 0 {
		copy(frame[136:], trailer[:trailerLen])
	}
	return frame
}

const (
	authKEXFlagRequest  uint64 = 1 << 0
	authKEXFlagResponse uint64 = 1 << 1

	// recoveryPILAInterval bounds how often we emit an unsolicited
	// authenticated key-exchange (PILA) frame to a peer we have no
	// crypto state for. Short enough to recover within a single gossip
	// tick after a one-sided daemon restart, long enough that a
	// spoofed nodeID can't turn us into a PILA amplifier.
	recoveryPILAInterval = 60 * time.Second

	// authKEXResponseInterval bounds repeated responses to verified
	// same-key recovery requests. This closes the lost-first-response
	// deadlock without turning duplicate PILA requests into a packet echo.
	authKEXResponseInterval = 5 * time.Second
)

func parseAuthKEXTrailer(trailer []byte) (caps uint64, flags uint64) {
	if len(trailer) == 0 {
		return 0, 0
	}
	c, n := binary.Uvarint(trailer)
	if n <= 0 {
		return 0, 0
	}
	caps = c
	if len(trailer) <= n {
		return caps, 0
	}
	f, m := binary.Uvarint(trailer[n:])
	if m > 0 {
		flags = f
	}
	return caps, flags
}

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
func (tm *TunnelManager) maybeSendRecoveryPILA(nodeID uint32, from transport.Endpoint, viaRelay bool) {
	// v1.9.0-jf.15.6: do NOT bail when addr==nil for the non-relay
	// case. Frames delivered through pion TURN arrive at the inbound
	// loop wrapped as *transport.TURNEndpoint, not *UDPEndpoint, so
	// the type-assertion at handleAuthKeyExchange's caller site
	// (tunnel.go ~1614) leaves `remote` nil. handleEncrypted then
	// hands us (addr=nil, viaRelay=false) — the exact case the old
	// guard rejected. That meant a laptop receiving VPS's encrypted
	// frames via TURN could observe "no key" indefinitely without
	// ever firing the recovery PILA, perpetuating the bilateral
	// crypto-state deadlock the recovery path was specifically
	// designed to break.
	//
	// writeFrame already resolves the destination by nodeID through
	// its tier ladder (peerTURN, peerConns, pathDirect, own-relay)
	// and returns an error when no path exists; we log Debug at the
	// caller and the rate-limit cooldown still prevents amplifier
	// abuse on truly unreachable peers. So the guard is no longer
	// needed for the direct case.
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

	frame := tm.buildAuthKeyExchangeFrameWithFlags(authKEXFlagRequest)
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

	// v1.9.0-jf.15.5: route through writeFrame, NOT raw tm.udp.WriteToUDPAddr.
	// For outbound-turn-only peers (e.g. -hide-ip), writeFrame respects
	// the TURN-routing constraint: the PILA goes out via our local TURN
	// allocation to the peer's known direct address (path.direct, e.g.
	// the peer's real registry-published IP), where the peer is
	// reachable. Bypassing writeFrame to send raw UDP from tm.udp would
	// (a) emit from our real IP — leaking it through the recovery path
	// and defeating -hide-ip — and (b) usually fail outright, because
	// our real IP isn't permissioned on the peer's TURN allocation.
	// For non-turn-only peers, writeFrame's direct-UDP tier produces
	// identical behaviour to the old tm.udp call. Pass addr so
	// writeFrame's caller-supplied addr precedence (jf.12) applies —
	// but writeFrame will substitute path.direct or null-out addr per
	// its existing tier rules (jf.10's hasTURNEp drop, etc).
	if err := tm.writeFrameToEndpoint(nodeID, from, frame); err != nil {
		slog.Debug("recovery PILA send failed", "peer_node_id", nodeID, "endpoint", from, "error", err)
		return
	}
	slog.Info("sent recovery PILA to peer with unknown key", "peer_node_id", nodeID, "endpoint", from)
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
	hasTURNEp := tm.peerTURN[nodeID] != nil
	cachedConn := tm.peerConns[nodeID]
	tm.mu.RUnlock()

	// Accept any known peer path and let writeFrame's transport ladder
	// decide the concrete route. TURN-ingress peers can have
	// direct=nil/viaRelay=false while still being reachable through
	// peerTURN or a cached DialedConn; rejecting that shape here skips
	// the very tiers that know how to route it.
	if p == nil && !hasTURNEp && cachedConn == nil {
		return fmt.Errorf("no tunnel to node %d", nodeID)
	}
	// addr is non-nil only for direct peers; writeFrame ignores it for
	// relay peers (routes via beaconAddr instead).
	var direct *net.UDPAddr
	if p != nil {
		direct = p.direct
	}
	return tm.SendTo(direct, nodeID, pkt)
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
		// Caller-initiated; no inbound frame to react to. Pass nil so
		// sendKeyExchangeToNode falls back to path.direct (jf.12).
		tm.sendKeyExchangeToNode(nodeID, nil)
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
		queueDepth := len(tm.pending[nodeID])
		tm.pendMu.Unlock()
		// jf.15.2: count this no-emit branch in the per-tier
		// stats and emit a gated trace. Use err=nil so the
		// counter increments — "queued" is the operation, the
		// counter answers "how many sends ended up queued".
		// Caller-side observers see 0-byte tier counter growth
		// vs N-byte direct_udp counter growth and can tell
		// where their traffic is actually going.
		tm.recordTierSend(SendTierQueuedPendingKey, nodeID,
			len(data), addrString(addr), false, nil)
		if tm.traceSends {
			slog.Info("send queued pending key exchange",
				"node_id", nodeID,
				"bytes", len(data),
				"queue_depth", queueDepth,
			)
		}
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

	// If encryption is enabled, initiate key exchange (relay-aware).
	// Caller-initiated; no inbound frame, so observedSrc is nil and
	// the cached path.direct (which we just set above) is used (jf.12).
	if tm.encrypt {
		tm.sendKeyExchangeToNode(nodeID, nil)
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
	delete(tm.lastAuthKEXResponse, nodeID)
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
	srcEP := transport.NewUDPEndpoint(srcAddr)

	// Process the inner tunnel frame
	magic := [4]byte{payload[0], payload[1], payload[2], payload[3]}
	switch magic {
	case protocol.TunnelMagicAuthEx:
		tm.handleAuthKeyExchange(payload[4:], srcEP, true)
	case protocol.TunnelMagicKeyEx:
		tm.handleKeyExchange(payload[4:], srcEP, true)
	case protocol.TunnelMagicSecure:
		tm.handleEncrypted(payload[4:], srcEP, true /* fromRelay */)
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
