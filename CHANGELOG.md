# Changelog

All notable changes to this fork (`jerryfane/pilotprotocol`) of
[TeoSlayer/pilotprotocol](https://github.com/TeoSlayer/pilotprotocol) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions use the upstream tag with a `-jf.N` suffix for fork-local iterations.
Each entry is intended to be upstream-able as a discrete bug fix.

## [Unreleased]

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
