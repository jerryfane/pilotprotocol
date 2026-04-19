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

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/gossip"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
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
	inbound chan transport.InboundFrame // sink every transport writes to; dispatchLoop reads

	peers     map[uint32]*net.UDPAddr            // node_id → real UDP endpoint (primary / legacy)
	peerTCP   map[uint32]*transport.TCPEndpoint  // node_id → TCP endpoint, populated from registry lookup when advertised
	peerConns map[uint32]transport.DialedConn    // node_id → cached DialedConn (whichever transport won the last Dial)
	crypto    map[uint32]*peerCrypto             // node_id → encryption state
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
	// Our own capability bitmap, appended to outbound PILA frames so
	// peers can learn that we support gossip. Zero when the daemon
	// hasn't opted in (e.g. during tests, or pre-engine bootstrap).
	localCaps uint64

	// Pending sends waiting for key exchange to complete
	pendMu  sync.Mutex
	pending map[uint32][][]byte // node_id → queued frames

	// NAT traversal: beacon-coordinated hole-punching and relay
	beaconAddr *net.UDPAddr    // beacon address for punch/relay
	relayPeers map[uint32]bool // peers that need relay (symmetric NAT)

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
		udp:         transport.NewUDPTransport(),
		inbound:     make(chan transport.InboundFrame, RecvChSize),
		peers:       make(map[uint32]*net.UDPAddr),
		peerTCP:     make(map[uint32]*transport.TCPEndpoint),
		peerConns:   make(map[uint32]transport.DialedConn),
		crypto:      make(map[uint32]*peerCrypto),
		peerPubKeys: make(map[uint32]ed25519.PublicKey),
		peerCaps:    make(map[uint32]uint64),
		pending:     make(map[uint32][][]byte),
		relayPeers:  make(map[uint32]bool),
		recvCh:      make(chan *IncomingPacket, RecvChSize),
		done:        make(chan struct{}),
		gossipView:  gossip.NewMembershipView(),
	}
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

// SetRelayPeer marks a peer as needing relay through the beacon (symmetric NAT).
func (tm *TunnelManager) SetRelayPeer(nodeID uint32, relay bool) {
	tm.mu.Lock()
	tm.relayPeers[nodeID] = relay
	tm.mu.Unlock()
	if relay {
		slog.Info("peer marked for relay", "node_id", nodeID)
	}
}

// IsRelayPeer returns true if the peer is in relay mode.
func (tm *TunnelManager) IsRelayPeer(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.relayPeers[nodeID]
}

// RelayPeerIDs returns the node IDs of all relay-flagged peers.
func (tm *TunnelManager) RelayPeerIDs() []uint32 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var ids []uint32
	for id, isRelay := range tm.relayPeers {
		if isRelay {
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
//  1. Beacon relay if the peer is marked for relay (UDP-only).
//  2. A cached non-UDP DialedConn (e.g. TCP fallback installed by
//     DialTCPForPeer). Lets a peer stick to TCP once we've chosen it.
//  3. Direct UDP write to the provided addr (today's default path).
//
// TCP fallback is a deliberate step: the caller decides when to
// switch a peer to TCP (typically after direct UDP SYN retries
// exhaust in DialConnection). Once switched, writeFrame keeps using
// the cached TCP conn until it dies, at which point the cache is
// cleared and the next writeFrame falls back to UDP.
func (tm *TunnelManager) writeFrame(nodeID uint32, addr *net.UDPAddr, frame []byte) error {
	tm.mu.RLock()
	relay := tm.relayPeers[nodeID]
	bAddr := tm.beaconAddr
	cachedConn := tm.peerConns[nodeID]
	tm.mu.RUnlock()

	if relay && bAddr != nil {
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

	// Phase 4: if a cached non-UDP conn exists for this peer, use it
	// first. The cache is populated by DialTCPForPeer (called from the
	// daemon's dial-failure path). UDP conns are not cached here —
	// they're effectively free to re-issue via WriteToUDPAddr.
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
				tm.handleEncrypted(buf[4:n], remote)
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
	if !fromRelay {
		tm.peers[peerNodeID] = from
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
	if !fromRelay {
		tm.peers[peerNodeID] = from
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
func (tm *TunnelManager) handleEncrypted(data []byte, from *net.UDPAddr) {
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
// otherwise falls back to unauthenticated. Uses nodeID-based routing (relay-aware).
func (tm *TunnelManager) sendKeyExchangeToNode(peerNodeID uint32) {
	tm.mu.RLock()
	hasIdentity := tm.identity != nil
	addr := tm.peers[peerNodeID]
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
	addr := tm.peers[nodeID]
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
	addr, ok := tm.peers[nodeID]
	tm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no tunnel to node %d", nodeID)
	}

	return tm.SendTo(addr, nodeID, pkt)
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

// AddPeer registers a peer's real UDP endpoint.
func (tm *TunnelManager) AddPeer(nodeID uint32, addr *net.UDPAddr) {
	tm.mu.Lock()
	tm.peers[nodeID] = addr
	tm.mu.Unlock()
	slog.Debug("added peer", "node_id", nodeID, "addr", addr)

	// If encryption is enabled, initiate key exchange (relay-aware)
	if tm.encrypt {
		tm.sendKeyExchangeToNode(nodeID)
	}
}

// RemovePeer removes a peer.
func (tm *TunnelManager) RemovePeer(nodeID uint32) {
	tm.mu.Lock()
	delete(tm.peers, nodeID)
	delete(tm.crypto, nodeID)
	tm.mu.Unlock()
}

// HasPeer checks if we have a tunnel to a node.
func (tm *TunnelManager) HasPeer(nodeID uint32) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, ok := tm.peers[nodeID]
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
	return len(tm.peers)
}

// PeerInfo describes a known peer.
type PeerInfo struct {
	NodeID        uint32
	Endpoint      string
	Encrypted     bool
	Authenticated bool // true if peer proved Ed25519 identity
	Relay         bool // true if using beacon relay (symmetric NAT)
}

// PeerList returns all known peers and their endpoints.
func (tm *TunnelManager) PeerList() []PeerInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var list []PeerInfo
	for id, addr := range tm.peers {
		pc := tm.crypto[id]
		list = append(list, PeerInfo{
			NodeID:        id,
			Endpoint:      addr.String(),
			Encrypted:     pc != nil && pc.ready,
			Authenticated: pc != nil && pc.authenticated,
			Relay:         tm.relayPeers[id],
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
func (tm *TunnelManager) handleRelayDeliver(data []byte) {
	// Format: [srcNodeID(4)][payload...]
	if len(data) < 5 {
		return
	}
	srcNodeID := binary.BigEndian.Uint32(data[0:4])
	payload := data[4:]

	// Mark this peer as relay-capable (they sent through relay, so they're behind NAT)
	tm.mu.Lock()
	wasRelay := tm.relayPeers[srcNodeID]
	tm.relayPeers[srcNodeID] = true
	// Ensure we have a peer entry (use beacon addr as placeholder for relay peers)
	if _, ok := tm.peers[srcNodeID]; !ok && tm.beaconAddr != nil {
		tm.peers[srcNodeID] = tm.beaconAddr
	}
	tm.mu.Unlock()
	if !wasRelay {
		tm.webhook.Emit("tunnel.relay_activated", map[string]interface{}{
			"peer_node_id": srcNodeID,
		})
	}

	if len(payload) < 4 {
		return
	}

	// Get peer's stored address for packet handling
	tm.mu.RLock()
	srcAddr := tm.peers[srcNodeID]
	tm.mu.RUnlock()
	if srcAddr == nil {
		srcAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}

	// Process the inner tunnel frame
	magic := [4]byte{payload[0], payload[1], payload[2], payload[3]}
	switch magic {
	case protocol.TunnelMagicAuthEx:
		tm.handleAuthKeyExchange(payload[4:], srcAddr, true)
	case protocol.TunnelMagicKeyEx:
		tm.handleKeyExchange(payload[4:], srcAddr, true)
	case protocol.TunnelMagicSecure:
		tm.handleEncrypted(payload[4:], srcAddr)
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
