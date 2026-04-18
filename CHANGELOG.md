# Changelog

All notable changes to this fork (`jerryfane/pilotprotocol`) of [TeoSlayer/pilotprotocol](https://github.com/TeoSlayer/pilotprotocol).

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions use the upstream tag with a `-jf.N` suffix for fork-local iterations. The goal is to make every patch upstream-able as a discrete bug fix.

## [Unreleased]

Client-side reliability fixes so any agent can join an Entmoot group over the public Pilot infrastructure without self-hosting any services. Tracked in `/root/.claude/plans/tender-wondering-wombat.md`. All five below are implemented; awaiting commit + push.

### Fixed

- **`-public` visibility silently reverting on daemon restart.** `pilotctl set-public` and the `-public` launch flag are now persisted to `~/.pilot/config.json`. Future daemon starts read the saved value if the flag isn't explicitly passed, so a node that's public stays public across restarts until explicitly `set-private`'d.

  Symptom this fixes: after a `pilotctl daemon stop` / `pilotctl daemon start` cycle, the node silently flipped to private, no `real_addr` was published to the registry, and peers could no longer dial the node. Every `pilotctl ping` from the outside failed with `dial: daemon: dial timeout` because the daemon had no target endpoint to send packets to.

  Files: `cmd/pilotctl/main.go` (new `writeConfigKey` helper, fallback read in daemon-start args, `Save` call in `cmdSetPublic` / `cmdSetPrivate`).

- **Registry `real_addr` goes stale when the daemon's observed endpoint changes.** The registry heartbeat now optionally carries the daemon's current registration address (`HeartbeatWithAddr`). Server-side, `handleHeartbeat` re-sanitizes against the connection's TCP source IP and updates `node.RealAddr` if the value differs. Signed challenge is extended to include the address when present so a third party cannot alter another node's endpoint.

  Symptom this fixes: after a change to `-endpoint` (or any mid-session shift in the advertised address) the registry returned the stale `real_addr` until the daemon fully re-registered. Peers dialing the old address hit dead NAT mappings.

  Files: `pkg/registry/client.go` (new `HeartbeatWithAddr`), `pkg/registry/server.go` (`handleHeartbeat` signature, sanitize + update).

- **Beacon NAT mapping dying between registry heartbeats.** Added `beaconKeepaliveLoop` running on an independent `DefaultBeaconKeepaliveInterval = 25s` ticker, distinct from the 60s registry heartbeat. Keeps the UDP mapping to the beacon alive for peers behind consumer-grade NATs (typical UDP timeout 30-60s), so relay forwarding remains reachable between registry ticks.

  Symptom this fixes: `gossip: push` and `gossip: fetch` dials to NAT'd peers failed with `dial: daemon: dial timeout` even when those peers were known to the registry and had active tunnels moments earlier. Captured UDP showed all outbound packets going to the beacon (relay mode) with zero responses — beacon had a stale mapping because our 60s heartbeat was slower than the peer's NAT expiry.

  Files: `pkg/daemon/daemon.go` (new constant, new goroutine, startup wiring).

- **`relayProbeLoop` cadence reduced from 5 min to 60s.** Once a peer is marked for relay, the loop probes direct connectivity and un-marks on success (log line `"relay→direct fallback succeeded"`). The previous 5-minute cadence meant a transient probe failure kept a peer on the slower relay path for five minutes before any recovery attempt. 60s makes transient stalls (e.g. during a tunnel rekey) self-heal quickly.

  Files: `pkg/daemon/daemon.go:108` (`RelayProbeInterval` constant).

- **`KeepaliveUnacked` reset on any successfully routed packet, not just ACK/FIN.** Extended the existing per-connection reset behaviour so any packet from a peer — stream ACK or not, datagram, control — also refreshes liveness on that peer's established connections via `ResetKeepaliveForNode`. Covers cases where the peer is demonstrably alive (sending key-exchange frames during a rekey, sending datagrams, sending control packets) but no ACK-flagged stream packet arrived within the idle-sweep window.

  Files: `pkg/daemon/daemon.go` (`handlePacket` now calls `d.ports.ResetKeepaliveForNode(pkt.Src.Node)` before dispatching by protocol).

## [v1.7.2-jf.2] - 2026-04-18

### Fixed

- **Tunnel flap every ~5 minutes at rekey boundaries.** Encrypted tunnels with authenticated peers would repeatedly tear down with `dead peer detected (3 keepalives unanswered), sending RST` on a 5-minute cadence matching `DefaultNetworkSyncInterval`. Symptom: entmootd gossip push/fetch dials hit `dial: daemon: dial timeout` in the ~30s gap between RST and tunnel re-establishment.

  Root cause: `Connection.KeepaliveUnacked` was reset to 0 only on incoming ACK or FIN frames (`daemon.go:1593, 1653`). When the peer's X25519 key rotates on the `NetworkSync` boundary, in-flight ACKs encrypted under the old key are briefly undecryptable. The idle-sweep loop (15s cadence) sends keepalive probes to any connection idle > `DefaultKeepaliveInterval` (60s) and RSTs after 3 unacked probes (hardcoded at `daemon.go:2787`). The rekey handler in `tunnel.go` did not touch per-connection state, so a healthy tunnel that happened to rekey while idle would trip dead-peer detection within ~45-70s.

  Fix: `TunnelManager` now exposes `SetRekeyCallback`. The daemon installs `PortManager.ResetKeepaliveForNode` as the callback at startup. Both rekey branches (`handleEncryptedKeyExchange`, `handleKeyExchange`) invoke `tm.notifyRekey(peerNodeID)` after `flushPending` when `keyChanged` is true. The helper clears `KeepaliveUnacked` and refreshes `LastActivity` on every ESTABLISHED connection routed over the rekeying peer — `LastActivity` refresh is important so the next idle-sweep doesn't immediately start probing during the brief window where both sides are converging on the new shared secret.

  Files:
  - `pkg/daemon/ports.go` — new `ResetKeepaliveForNode` helper.
  - `pkg/daemon/tunnel.go` — new `rekeyCallback` field, `SetRekeyCallback` setter, `notifyRekey` helper, invocation in both rekey success paths.
  - `pkg/daemon/daemon.go` — wires `d.tunnels.SetRekeyCallback(d.ports.ResetKeepaliveForNode)` at daemon startup.

## [v1.7.2-jf.1] - 2026-04-18

Commit `2d4e657` on `main`.

### Fixed

- **NAT hole-punch packets sent to non-routable targets.** `handlePunchCommand` in `tunnel.go` would build a `*net.UDPAddr` directly from the IP/port echoed by the beacon and send punch packets without validating the host. When the beacon itself is behind a NAT/LB that rewrites client source IPs (e.g. GCP Cloud NAT, which advertises `10.128.0.12` for every registrant regardless of their actual public IP), the punch target is a non-routable private address. Every punch attempt lands in the VPS's own LAN subnet, times out after 6-8s, and Pilot falls back to relay mode. Symptom: peers stuck in relay even when direct connectivity would work, and `NAT punch sent target=10.128.0.12:<peer-port>` log lines at regular intervals.

  Root cause: no sanity check on beacon-provided target addresses. Registration already has a private-IP filter via `isPrivateAddr` (`daemon.go:637`), but the punch-target path did not mirror it.

  Fix: drop punches to private (RFC1918), loopback, link-local, and unspecified addresses before sending any packets. Emits `skipping NAT punch to non-routable target` at WARN level so operators can see when this fires. Daemon falls through to the existing relay-fallback path, which works correctly.

  Files:
  - `pkg/daemon/tunnel.go` — `handlePunchCommand` adds a filter check on the target IP before the `conn.WriteToUDP` loop.
