# Changelog

All notable changes to this fork (`jerryfane/pilotprotocol`) of
[TeoSlayer/pilotprotocol](https://github.com/TeoSlayer/pilotprotocol) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions use the upstream tag with a `-jf.N` suffix for fork-local iterations.
Each entry is intended to be upstream-able as a discrete bug fix.

## [Unreleased]

## [v1.9.0-jf.9] - 2026-04-24

### Added

- **Asymmetric TURN.** A peer that opts into `-hide-ip` runs TURN
  locally; the rest of the mesh can now reach it without configuring
  their own TURN provider. Before jf.9, every mesh member needed a
  TURN allocation (Cloudflare API token + pion client) to dial a
  hide-ip peer — `DialTURNForPeer` hard-errored with `"turn transport
  not enabled"` when the local daemon had no allocation. That forced
  the wrong deployment model: *"everyone on the mesh pays for
  Cloudflare to talk to one hide-ip peer."* The new **`turn-relay`**
  transport shares the daemon's existing UDP socket and sends raw
  datagrams to the peer's advertised relay address. The TURN server
  accepts these frames because the hide-ip peer has proactively
  issued a `CreatePermission` for the sender's source IP.

  Implementation summary:

  - **Hide-ip side** (`pkg/daemon/transport/turn.go`):
    - New `TURNTransport.CreatePermission(addr string) error` wraps
      pion's `Client.CreatePermission` with address parsing and
      tracks the permitted set in a new `permittedAddrs` map.
    - New background goroutine `permissionRefreshLoop` re-issues
      CreatePermission for every permitted address every 4 minutes
      (RFC 8656 §9.2 says 5-minute idle expiry; 4 leaves headroom
      for clock skew + server-side timing). Test hook
      `setPermissionRefreshInterval` for deterministic tests.
    - Credential rotation now re-permits every permitted address
      against the new pion client before closing the old one.
      Without this, every rotation (every TTL/2 on Cloudflare —
      typically 5–15 min) would silently invalidate every peer's
      permission until the next full dial cycle.

  - **Dialer side** (`pkg/daemon/transport/turn.go`):
    - New `turnRelayDialedConn` implements `DialedConn` with
      `Name() == "turn-relay"`. `Send` reuses
      `UDPTransport.WriteToUDPAddr` — the same escape-hatch the NAT
      punch and beacon registration paths already use. No new
      socket code; the dialer holds no pion state.
    - New free function `DialTURNRelayViaUDP(udp, ep)` validates
      inputs and returns the conn. Errors on nil `udp`/`ep` or an
      un-listened UDP transport.

  - **TunnelManager integration** (`pkg/daemon/tunnel.go`):
    - New `DialTURNRelayForPeer(ctx, nodeID)` mirrors
      `DialTURNForPeer`'s fetch→dial→cache sequence but chooses raw
      UDP when `tm.turn == nil`. Delegation guard: if the local
      daemon has its own TURN allocation it still prefers the full
      pion path (lets two hide-ip peers talk to each other
      symmetrically). Result is cached in `peerConns[nodeID]` with
      the same first-writer-wins race handling as `DialTCPForPeer`.
    - New `PermitTURNPeer(addr)` validates the address and calls
      `tm.turn.CreatePermission` when a local TURN allocation
      exists; no-op otherwise. Bookkeeping lives in
      `turnPermittedPeers map[string]time.Time`; a goroutine
      launched at `ListenTURN` evicts entries past 30 minutes of no
      refresh.
    - Auto-permission hook in `updatePathDirect`: every
      authenticated direct-UDP ingress fires an async
      `PermitTURNPeer(from)` — zero-addr and unspecified-IP
      markers (relay-sourced frames) are skipped. First time a
      peer direct-UDPs us, we permit them; the permission survives
      rotation + refresh so their later TURN-relay dials land.
    - `writeFrame` grows a final fallback tier: when no direct UDP
      addr is known and the peer has advertised a TURN endpoint,
      synchronously dial via `DialTURNRelayForPeer` and retry the
      cached-conn path. Mirrors how `DialTCPForPeer` is called from
      `DialConnection`'s retry loop today.

  No wire-format changes. Entmoot's v1.4.0 `SetPeerEndpoints` flow
  still delivers TURN endpoints unchanged (jf.7 wire format is
  unchanged). Existing symmetric TURN-to-TURN (both peers have
  `-turn-provider`) keeps jf.8's `turnDialedConn` path bit-for-bit
  identical — the new path only fires when the local daemon has no
  TURN allocation.

  No new dependencies.

### Behaviour notes

- **Pre-jf.9 dialers without TURN still can't reach hide-ip peers.**
  Only jf.9+ daemons unlock the asymmetric path; the jf.8 behaviour
  is preserved for users who haven't rolled the daemon out yet.
- **Permission bootstrap for brand-new peers.** The auto-permission
  hook in `updatePathDirect` fires on every authenticated direct
  ingress, so a peer who ever direct-UDP's us is permitted for
  subsequent TURN-relay dials. A peer whose very first packet is a
  TURN-relay attempt (never direct-UDP'd us) will see its first few
  frames dropped by the server. Pilot's existing retry cadence
  (dial → UDP → TCP → TURN-relay) makes this self-healing within
  ~1s under normal conditions. Future work (deferred): drive
  permissions from Pilot's trust-store so roster members are
  permitted at startup.

## [v1.9.0-jf.8] - 2026-04-24

### Added

- **TURN (RFC 8656) client transport.** A third transport alongside
  UDP hole-punch and TCP fallback. The daemon can now allocate a
  relay via a standards-compliant TURN server and route peer traffic
  through it, enabling relay-only operation for peers who want to
  hide their source IP from the mesh. Two credential providers ship:

  - **static** — long-lived username/password for self-hosted
    `coturn` or any RFC-8656-compliant TURN server.
  - **cloudflare** — Cloudflare Realtime TURN (1 TB/mo free tier).
    Mints short-lived ICE credentials by `POST` to
    `https://rtc.live.cloudflare.com/v1/turn/keys/{TURN_KEY_ID}/credentials/generate-ice-servers`
    with `Authorization: Bearer {API_TOKEN}`. A background refresh
    loop re-mints at `TTL/2` and rotates the allocation in place
    (new pion client + Allocate, swap under mutex, close old).

  New package `pkg/daemon/turncreds/` (independent of pion/turn)
  defines the `Provider` interface + the two implementations.
  New file `pkg/daemon/transport/turn.go` implements the
  `Transport` interface using `github.com/pion/turn/v5` (MIT). The
  daemon's `writeFrame` dial-priority chain is unchanged — TURN
  rides the existing `peerConns` cached-conn slot, populated via
  the new `DialTURNForPeer`. `IPCServer.handleSetPeerEndpoints`
  gains a `"turn"` case routing to `AddPeerTURNEndpoint`; wire
  format is unchanged (the `network` string was already free-form
  in jf.7). `DaemonInfo` grows `TURNEndpoint string,omitempty` so
  Entmoot (or any other driver) can discover the relay address to
  advertise.

  Seven new CLI flags: `-turn-provider`, `-turn-server`,
  `-turn-transport`, `-turn-static-user`, `-turn-static-pass`,
  `-cloudflare-turn-creds-file`, `-cloudflare-turn-ttl`.

- **Three new subcommands:**
  - `pilot-daemon turn-setup cloudflare -token-id=X` — prompts
    for the API token on stdin (never flags, keeps it out of
    `ps` + shell history), test-mints once, writes
    `~/.pilot/cloudflare-turn.json` with mode 0600.
  - `pilot-daemon turn-setup static -server=X -user=U
    -pass-stdin` — reads password from stdin, performs a live
    TURN allocation to verify, writes `~/.pilot/static-turn.json`
    with mode 0600.
  - `pilot-daemon turn-test` — auto-detects the configured
    provider, runs one mint + connect + allocate + close cycle,
    prints step-by-step progress:
    ```
    turn-test: minting Cloudflare credentials... ok (ttl=1h0m0s)
    turn-test: connecting to turn.cloudflare.com:3478 (udp)... ok
    turn-test: allocating relay... ok
    turn-test: relayed address: 141.101.90.15:52341
    turn-test: closing... ok
    turn-test: PASS
    ```
    Exits 0 on PASS, 1 on any step failure, 2 if no config found.

  These fit the existing Entmoot subcommand pattern (`entmootd
  group create`, `invite create`, `roster add`). `main()` grows a
  small subcommand dispatcher at the top of `main.go`; normal
  daemon invocation (no subcommand) is unchanged.

### Compatibility

- Wire format between daemons: unchanged. jf.8 daemons interop
  with jf.7 peers as today.
- `SetPeerEndpoints` IPC: unchanged wire, new dispatch target.
  jf.7 drivers (entmootd v1.2.0-v1.3.0) work unchanged against a
  jf.8 daemon; they just won't advertise TURN endpoints.
- `DaemonInfo` gains `turn_endpoint` via JSON `omitempty`; jf.7
  drivers decoding it see the empty string.
- TURN is disabled by default (`-turn-provider=""`). Existing
  deployments are unaffected until TURN is explicitly configured.

### Dependencies

- Added `github.com/pion/turn/v5` v5.0.3 (MIT). Pulls pion/stun,
  pion/logging, pion/transport, pion/dtls, pion/randutil,
  wlynxg/anet, and `golang.org/x/crypto` transitively.
- Added `golang.org/x/term` for TTY-aware password prompts in
  `turn-setup`.

## [v1.9.0-jf.7] - 2026-04-21

### Added
- **`Driver.SetPeerEndpoints(nodeID, endpoints)`** — new IPC
  command for installing externally-sourced TCP endpoints for
  a peer into the daemon's `peerTCP` map. Designed for
  application-layer transport-advertisement protocols that
  distribute endpoints through their own signed-gossip channel
  rather than relying on the central registry (see Entmoot
  v1.2.0, companion release). Reuses the existing
  `TunnelManager.AddPeerTCPEndpoint` install path verbatim;
  registry-sourced endpoints still take precedence when both
  sources exist. Self-dials rejected via the `ErrDialToSelf`
  guard added in jf.6.

  Wire format is a simple TLV inside the existing IPC frame:
  `[cmd][node_id u32 BE][n u8][n * (net_len u8, net, addr_len
  u8, addr)]`. Bounds: max 8 endpoints, network ≤16 bytes,
  addr ≤255 bytes — payload trivially under 2 KiB. UDP
  entries are accepted on the wire but ignored by the daemon
  (advisory only; the existing dial path rediscovers them via
  registry + same-LAN probes).

  New opcodes `CmdSetPeerEndpoints=0x25` / `CmdSetPeerEndpointsOK=0x26`.
  No change to the wire protocol between daemons — this is a
  NEW IPC command between driver and local daemon only.

## [v1.9.0-jf.6] - 2026-04-21

### Fixed
- **Self-dial rejected with typed sentinel.** `ensureTunnel` and
  `DialConnection` now reject attempts to dial the local node's
  own NodeID, returning `protocol.ErrDialToSelf`. Previously, a
  caller that handed its own ID here (common when bootstrap /
  roster listings contain self — every Entmoot invite to date
  included the issuer as a bootstrap peer) would pass through to
  the registry resolve + same-LAN detection branch. On
  multi-homed hosts the same-LAN matcher finds BOTH a
  docker-bridge LAN entry (e.g. `172.17.0.1`) AND a public-IP
  entry for the local node, which triggers establishment of
  multiple duplicate self-tunnels. The duplicate tunnels then
  retransmit into each other — observed live on the VPS hub as a
  ~5,900 packets/second self-amplified loop consuming two CPU
  cores of pilot-daemon and saturating the packet buffers,
  starving real peer streams and reinflating gossip
  propagation to minute-scale latencies.

  Mirrors go-libp2p-swarm's canonical `ErrDialToSelf` guard in
  `dialPeer`. Fast-fail with a typed sentinel (not a silent
  discard) so caller-side filter violations are visible rather
  than masked. Pairs with Entmoot v1.0.8's caller-side filter
  in `BootstrapPeers` parse + invite mint.

## [v1.9.0-jf.5] - 2026-04-20

### Fixed
- `maybeSendRecoveryPILA` now routes through the beacon when the
  un-decryptable frame that triggered it arrived via relay. Prior
  to this fix, an auto-recovery PILA in response to a relay-
  origin frame was written to a zero-addr marker and dropped
  silently — so relay-only peers could not recover from
  one-sided crypto-state desync (e.g. after a VPS restart with a
  surviving laptop on the other side). Direct recovery path is
  unchanged.
- `AddPeer` now resets `path.viaRelay = false`. A prior
  `SetRelayPeer(peer, true)` (typical after a direct-dial
  timeout) no longer persists through a subsequent `AddPeer`
  with a known-good direct endpoint. Matches WireGuard's
  "explicit endpoint is authoritative" semantics. Recovered
  the relay→direct fallback case that the reachability-probe
  loop relies on.
- `RemovePeer` now wipes all per-peer state: `paths`, `crypto`,
  `peerCaps`, `peerPubKeys`, `peerTCP`, `peerConns`,
  `lastRecoveryPILA`. Previously only `paths` + `crypto` were
  cleared, leaving stale fields behind for a potential re-add
  of the same `node_id`. Mirrors WireGuard's `wg set peer …
  remove` contract of "zero all per-peer state." Cached
  `peerConns` entries are `.Close()`'d before deletion to
  release TCP / QUIC sockets.
- `Daemon.handlePacket` no longer auto-calls `AddPeer` with the
  relay-origin zero-addr marker (`0.0.0.0:0`). Guards against
  the same class of pollution the v1.9.0-jf.4 refactor removed
  from `handleRelayDeliver`. The authenticated-decrypt handlers
  in `tunnel.go` already capture correct path state via
  `updatePathRelay` during relay ingress; the daemon-level
  auto-add was fighting that capture.
- `maybeSendRecoveryPILA` defensively checks `tm.udp != nil`
  before attempting the relay-wrapped write, matching the
  existing guard in `RegisterWithBeacon` and `RequestHolePunch`.
  Prevents a nil-deref panic if recovery fires during startup
  before `Listen` completes.

## [v1.9.0-jf.4] - 2026-04-20

### Fixed
- Relay-mediated tunnels could establish encrypted + authenticated
  peer state, but stream-layer SYN dials timed out indefinitely
  because two latent upstream-Pilot design bugs interacted badly:
  (a) `TunnelManager.relayPeers[peer]=bool` was tracked per-daemon
  without any symmetry guarantee, so A could flip the bit and
  route via relay while B still thought A was direct and replied
  to a stale `peers[A]` address; (b) `handleRelayDeliver` stored
  the beacon's address under `peers[srcNodeID]` as a placeholder
  when a relay frame arrived from a peer we hadn't seen before,
  which then polluted same-LAN detection, the v1.9.0-jf.2 NAT-
  drift refresh, and the direct-UDP fallback branch of
  `writeFrame`. Observed live in the three-node deployment: VPS
  ↔ laptop tunnel reported `relay=true` and keepalives flowed,
  but every `DialConnection` from VPS to the laptop (and vice
  versa) timed out.

  Replaced `peers map[uint32]*net.UDPAddr` and
  `relayPeers map[uint32]bool` with a single
  `paths map[uint32]*peerPath` where each entry records the last
  authenticated ingress path (direct addr XOR via-relay). Every
  authenticated decrypt updates the entry; `writeFrame` routes
  replies on the same path the request arrived on. This is the
  reply-on-ingress pattern used by WireGuard (roaming) and
  Tailscale DERP — symmetry falls out of per-peer observed state
  instead of requiring cross-daemon coordination. Neither `peers`
  nor `relayPeers` exist anymore; the `IsRelayPeer` / `HasPeer` /
  `PeerList` accessors keep their existing signatures and are
  now thin wrappers over `paths`.

### Added
- `DialRelayInitialRTO = 3 * time.Second`. `DialConnection`'s SYN
  retransmission budget now starts at 3 s when the peer is in
  relay mode, up from the direct-path default of 1 s. Relay
  RTT is 2-3× direct (observed ~300 ms through a US-based
  beacon between an Italian and a UAE peer, vs ~80 ms direct).
  The 1 s budget was too tight and caused spurious dial
  timeouts even on otherwise-healthy relay tunnels.
- `peerPath` internal type and `updatePathDirect` /
  `updatePathRelay` helpers on `TunnelManager` that the three
  authenticated decrypt handlers call on every successful frame.

### Known gap
- Integration test for "A→B direct UDP blocked, beacon relay
  works" was scoped out of this release; the existing harness
  uses a real UDP socket and has no write-path filter for
  simulating selective blackholes. The refactor is covered by
  unit tests (`tunnel_path_test.go`) and by live validation on
  the three-node deployment. A proper integration test would
  need either root iptables or a write-path filter hook; filed
  for Pilot v1.10.

## [v1.9.0-jf.3] - 2026-04-19

### Fixed
- Tunnel auto-recovery after one-sided daemon restart. When peer A
  restarts and loses its per-peer X25519 keys, peer B retains stale
  session keys derived from A's previous X25519 pubkey and keeps
  sending encrypted traffic that A can no longer decrypt. Prior to
  this fix, A would silently log `encrypted packet from node but
  no key` indefinitely and never recover — B's side never observed
  the mismatch because its own keepalive ACKs appeared to succeed
  at the tunnel level. Observed live on the three-node canary
  during the v1.9.0-jf.2 upgrade: after VPS restarted, both Phobos
  and laptop stayed in the stale-crypto limbo until their daemons
  were manually restarted. Fixed by emitting an unsolicited PILA
  to the observed source address on every decrypt failure caused
  by a missing crypto state, rate-limited to once per 60 s per
  peer to bound reflection/amplification abuse. Recovery is now
  automatic and typically completes within ~200-300 ms of the
  peer's next keepalive.

## [v1.9.0-jf.2] - 2026-04-19

### Fixed
- Cached peer endpoint (`TunnelManager.peers[nodeID]`) was only
  refreshed during PILA/PILK key exchanges. On networks where the
  peer's NAT rotates source ports between rekeys (observed live on
  a UAE CGN ISP), VPS-initiated frames went to the stale UDP
  address and were silently dropped by the NAT, while the peer's
  own keepalives kept the tunnel looking alive. Manifested as
  "dial timeout" on outbound stream SYNs even though
  `pilotctl peers` reported the peer as encrypted + authenticated.
  Fixed by refreshing the cached endpoint inside `handleEncrypted`
  after a successful decrypt, guarded by an RLock pre-check so
  data-plane packets don't churn the write lock when the cache is
  already current.
- `install.sh` now re-signs binaries with the host's ad-hoc codesign
  identity and clears `com.apple.quarantine` xattrs on macOS. Under
  macOS 26.2 Tahoe, Gatekeeper stalls interactively-launched
  cross-compiled Go binaries at `_dyld_start` (before the Go
  runtime runs), which manifested as `pilotctl info` hanging
  indefinitely on Apple Silicon laptops. No-op on Linux.

## [v1.9.0-jf.1] - 2026-04-19

### Added
- Gossip-based peer discovery overlay. New package
  `pkg/daemon/gossip` implementing a signed-record membership view
  (`GossipRecord`, `GossipSync`, `GossipDelta`), anti-entropy engine
  with a 25 s tick (`gossip.Engine`), and a canonical sign-bytes
  encoding driven by the daemon's existing Ed25519 identity. Upgraded
  daemons exchange multi-transport endpoint advertisements directly
  over their encrypted tunnels, breaking the coupling between fork
  capabilities and upstream registry cooperation: the `endpoints`
  field no longer has to be propagated through the registry for a
  TCP-fallback peer to be discoverable. The registry remains the
  identity root (`node_id ↔ public_key` binding) and the bootstrap
  entry point; gossip only refreshes the reachability half of the
  directory.
- New protocol constants `protocol.PortGossip = 1005` (the
  ProtoControl port gossip frames ride on) and `gossip.CapGossip =
  0x01` (the capability bit advertised in the authenticated
  key-exchange trailer). The PILA frame format is extended with a
  trailing Uvarint capability bitmap — older daemons truncate at the
  legacy 132-byte body and never see it, preserving wire
  compatibility with unmodified upstream daemons.
- `Daemon.SetGossipHandler`, `Daemon.SendGossipFrame`,
  `Daemon.GossipView`, `Daemon.TriggerGossipTick`, and
  `TunnelManager.{SetLocalCaps, PeerCaps, GossipCapablePeers,
  PeerPubKey, GossipView}` accessors used to glue the gossip Engine
  into the daemon lifecycle without creating a package cycle.
- `daemon.Config.GossipInterval` overrides the default 25 s tick
  cadence (primarily a test knob for fast convergence assertions).

### Fixed
- Registry snapshot persistence dropped the `Endpoints` field on
  every save/load round-trip. `snapshotNode` now includes `Endpoints
  []NodeEndpoint`, and both the save and load paths round-trip the
  field. Without this fix, restarting a patched rendezvous reset
  every peer's TCP endpoint advertisement to empty until peers
  re-registered.
- `DialConnection` wrote `conn.State = StateSynSent` without holding
  `conn.Mu`. The connection is already reachable from the ports
  map by that point so concurrent sweeps (e.g.
  `PortManager.ResetKeepaliveForNode`) could observe the field
  mid-write. Surfaced by the race detector once background gossip
  tickers added concurrent `handlePacket` activity. Fixed with a
  brief `conn.Mu.Lock/Unlock` around the early-init writes.

## [v1.8.0-jf.1] - 2026-04-19

### Added
- Pluggable transport layer. New `pkg/daemon/transport` package with
  `Transport`, `Endpoint`, `DialedConn`, and `InboundFrame` interfaces.
  Every transport's `Listen` goroutine feeds a shared sink consumed by
  `TunnelManager.dispatchLoop`; sends flow through `DialedConn`. Adding
  a new byte-movement protocol (QUIC, WebSocket, etc.) is now purely
  additive — the core tunnel layer is transport-agnostic.
- `TCPTransport` implementation (`pkg/daemon/transport/tcp.go`) using
  4-byte big-endian length-prefix framing (`internal/ipcutil`, 1 MiB
  cap). Persistent connections are pooled by remote address; inbound
  accepted sockets are surfaced as `InboundFrame.Reply` so peers that
  dialled us inbound can receive replies on the same connection without
  re-dialling. Covered by `tcp_test.go` (9 cases: round-trip,
  multi-frame, conn reuse, dial timeout, peer disconnect, parallel
  sends, endpoint parse, wrong network, idempotent close).
- Registry multi-transport endpoints. Registration, lookup, and resolve
  responses now carry an optional `endpoints: [{network, addr}, ...]`
  array. Old registries silently drop the field — no signature
  incompatibility, no wire break. New helpers:
  `registry.NodeEndpoint`, `registry.Client.RegisterWithKeyAndEndpoints`,
  `registry.EndpointsFromResponse`.
- `daemon.Config.TCPListenAddr` and `daemon.Config.TCPEndpoint` plus
  the `-tcp-listen` / `-tcp-endpoint` flags on `cmd/daemon` and
  `cmd/pilotctl`. When set, the daemon listens on TCP alongside UDP
  and advertises the TCP endpoint in the registry.
- TCP dial fallback in `DialConnection`. After direct UDP SYN retries
  exhaust (`DialDirectRetries`), the dialer checks whether the peer
  advertised a TCP endpoint (`TunnelManager.HasTCPEndpoint`) and
  attempts a TCP dial bounded by `DialTCPFallbackTimeout` (5 s) before
  falling through to the existing beacon-relay path. The cached
  `DialedConn` sticks for subsequent sends via `writeFrame`'s new
  non-UDP preference — peers on UDP-hostile networks (corporate
  firewalls, carrier-grade NAT, UDP-blocking ISPs) now establish over
  TCP without any peer-side configuration.

### Changed
- `TunnelManager` no longer owns a `*net.UDPConn` directly. The
  connection is held by `transport.UDPTransport`; `TunnelManager.conn`,
  `peers map[uint32]*net.UDPAddr`, and `IncomingPacket.From
  *net.UDPAddr` were replaced by `udp *transport.UDPTransport`,
  `tcp *transport.TCPTransport` (optional), `peerEndpoints`,
  `peerConns map[uint32]transport.DialedConn`, and `IncomingPacket.From
  transport.Endpoint`. Pure refactor — wire bytes are byte-identical
  to v1.7.2-jf.3 when only UDP is configured.

## [v1.7.2-jf.3] - 2026-04-19

### Changed
- `install.sh` now pulls from `jerryfane/pilotprotocol` releases and source
  instead of `TeoSlayer/pilotprotocol`. Header URLs updated to
  `https://raw.githubusercontent.com/jerryfane/pilotprotocol/main/install.sh`
  so SKILL-documented installs land the patched binaries by default.

### Added
- `beaconKeepaliveLoop` running on an independent 25 s ticker
  (`DefaultBeaconKeepaliveInterval`), separate from the 60 s registry
  heartbeat, so the UDP mapping to the beacon stays alive under consumer
  NAT UDP timeouts (~30-60 s) and relay forwarding remains reachable
  between registry ticks.
- Registry heartbeat can now carry and verify the daemon's current
  registration address. New `registry.Client.HeartbeatWithAddr` plus
  extended signed challenge (`heartbeat:{nodeID}:{addr}`); server-side
  `handleHeartbeat` re-sanitises against the TCP source IP and updates
  `node.RealAddr` if it changed. **Not yet enabled by default** — the
  daemon still calls the plain `Heartbeat` because the upstream public
  registry verifies only the unextended challenge; switch the call site
  once the registry is known to have the matching patch.

### Changed
- `RelayProbeInterval` reduced from 5 min to 60 s so peers marked for
  relay recover quickly after a transient probe failure.
- `handlePacket` now invokes `PortManager.ResetKeepaliveForNode` on every
  successfully routed packet, not just ACK/FIN stream frames. Covers
  datagram, control, and non-ACK stream paths where the peer is
  demonstrably alive but would otherwise have tripped dead-peer detection
  during rekey windows.

### Fixed
- `-public` visibility no longer silently reverts on daemon restart.
  `pilotctl set-public` / `set-private` and the `-public` launch flag now
  persist to `~/.pilot/config.json` via a new `writeConfigKey` helper in
  `cmd/pilotctl/main.go`; daemon start reads the persisted value as a
  fallback when the flag isn't explicitly passed.

## [v1.7.2-jf.2] - 2026-04-18

### Fixed
- Encrypted tunnel flap every ~5 min at `NetworkSync` rekey boundaries.
  `TunnelManager` now exposes `SetRekeyCallback`; the daemon installs
  `PortManager.ResetKeepaliveForNode` at startup, and both rekey branches
  (`handleEncryptedKeyExchange`, `handleKeyExchange`) call
  `tm.notifyRekey(peerNodeID)` after `flushPending` when `keyChanged` is
  true. The helper clears `KeepaliveUnacked` and refreshes `LastActivity`
  on every `StateEstablished` connection routed over the rekeying peer so
  in-flight ACKs dropped during the key swap don't trip dead-peer
  detection.
- Files: `pkg/daemon/ports.go`, `pkg/daemon/tunnel.go`,
  `pkg/daemon/daemon.go`.

## [v1.7.2-jf.1] - 2026-04-18

Commit `2d4e657` on `main`.

### Fixed
- NAT hole-punch packets sent to non-routable targets. `handlePunchCommand`
  in `pkg/daemon/tunnel.go` now drops punches to RFC1918, loopback,
  link-local, and unspecified addresses before writing to the UDP socket
  (mirroring the existing `isPrivateAddr` filter used for STUN results),
  logging `skipping NAT punch to non-routable target` at WARN. Daemon
  falls through to the existing relay-fallback path.
