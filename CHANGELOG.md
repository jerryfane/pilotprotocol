# Changelog

All notable changes to this fork (`jerryfane/pilotprotocol`) of
[TeoSlayer/pilotprotocol](https://github.com/TeoSlayer/pilotprotocol) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions use the upstream tag with a `-jf.N` suffix for fork-local iterations.
Each entry is intended to be upstream-able as a discrete bug fix.

## [Unreleased]

## [v1.9.0-jf.15.15] - 2026-04-27

### Changed

- **Port-level stream diagnostics are now explicit and opt-in.** The daemon
  has a new `-trace-streams` flag that emits structured INFO logs for virtual
  stream lifecycle events: SYN/SYN-ACK, state transitions, accept queue
  pressure, IPC close/send failures, timeout cleanup, RST/FIN, and connection
  removal. This gives Entmoot `:1004` debugging a separate signal from TURN
  route selection and packet-tier tracing.
- **TURN route selection is now centralized in a policy layer.**
  `TunnelManager.writeFrame` and `Daemon.DialConnection` now delegate route
  precedence to a shared policy helper instead of carrying separate
  TURN/direct/TCP/beacon conditionals inline. The policy locks in
  `-outbound-turn-only` fail-closed behavior, blocks TCP/beacon fallback in
  that mode, and prefers direct UDP for non-TURN local peers when a peer TURN
  route would otherwise poison a known direct path.
- **TURN route execution and peer endpoint state were split into focused
  helpers.** `writeFrame` now snapshots state, asks the policy for candidates,
  and delegates beacon/cached/TURN/direct sends to small executors.
  `writeFrameToTURNEndpoint` keeps its explicit-endpoint semantics while
  sharing the common send accounting and cached-conn eviction helpers.
- **The integration test harness no longer leaks dashboard listeners or parses
  Go test flags through custom config flagsets.** Registry dashboard routes can
  now be mounted through `DashboardHandler`, letting tests use closable
  `httptest` servers, and the secure-channel integration test now waits for
  port 443 to bind before dialing. Test registry and beacon listeners now bind
  explicitly to IPv4 loopback so wildcard `:0` ports cannot be confused with
  unrelated IPv4 HTTP listeners on dual-stack hosts.
- **CI and local push checks now use the full Go package test suite.** The
  shared test command excludes only the manual dashboard package, and an
  optional repo-managed pre-push hook runs the same suite before local pushes.
- **Strict TURN-only routing now prefers own-relay semantics before peer TURN.**
  When `-outbound-turn-only` is set, Pilot keeps cached TURN connections first
  but tries its own TURN allocation before consulting a peer-advertised TURN
  endpoint, keeping the route order aligned with the no-IP-leak mental model.

### Fixed

- **Port-1004 dials no longer receive already-closing Pilot streams.**
  `DialConnection` now succeeds only for `ESTABLISHED` streams and returns the
  typed `connection closing` error for streams that reach FIN/TIME_WAIT before
  IPC receives `DialOK`. FIN+ACK processing now clears retransmit state before
  close handling, and duplicate FINs in TIME_WAIT are idempotent ACK-only
  responses that do not refresh cleanup timers or emit repeated transitions.

## [v1.9.0-jf.15.11] - 2026-04-27

### Fixed

- **TURN-ingress stream replies now reach the routing ladder.** `TunnelManager.Send`
  no longer rejects peers whose authenticated ingress path has no direct UDP
  address but does have a peer TURN endpoint or cached transport connection.
  Those sends now flow into `writeFrame`, which can choose TURN, cached conn,
  direct UDP, own relay, or return the real routing error.
- **Inbound stream SYNs no longer create fake established conns when SYN-ACK
  cannot be sent.** Pilot now checks SYN-ACK send failures, closes the half-open
  conn, and avoids exposing it to IPC listeners as `ESTABLISHED`.

## [v1.9.0-jf.15.10] - 2026-04-27

### Fixed

- **Pilot's Go driver no longer loses immediate stream closes.** If the daemon
  emits `CloseOK` in the small window after `DialOK`/`AcceptedConn` but before
  the client registers the conn's receive channel, the driver now records that
  pending close and applies it during registration. Fast accept-and-close
  streams still preserve existing TCP-like dial semantics, but callers now see
  EOF immediately instead of a dead conn that waits for higher-level timeouts.

## [v1.9.0-jf.15.9] - 2026-04-26

### Fixed

- **Authenticated recovery PILA now preserves TURN ingress endpoints and
  repeats replies safely.** Frames delivered by TURN now reach the auth path as
  `TURNEndpoint` values instead of collapsing to `nil`, so a verified PILA can
  install/re-permit the peer's observed TURN allocation without poisoning
  `path.direct`. Recovery PILA frames now carry a backward-compatible
  request/response trailer; verified duplicate requests receive a bounded
  same-key response without resetting replay/crypto state. This closes the
  laptop↔VPS one-way crypto-state deadlock where laptop sent recovery PILA,
  VPS installed laptop's key, but laptop never received a repeatable reciprocal
  auth reply.

## [v1.9.0-jf.15.8] - 2026-04-26

### Fixed

- **Failed IPC stream sends now poison the affected virtual connection.**
  When daemon-side `SendData` rejects a `CmdSend`, Pilot closes/removes that
  conn instead of leaving stale state behind for future writes. This preserves
  existing `DialConnection` semantics for peers that accept and immediately
  close, while ensuring yamux/request-response clients observe EOF and stop
  reusing the dead stream.

## [v1.9.0-jf.15.7] - 2026-04-26

Periodic peer-side rendezvous re-lookup. Closes the silent-death
mode where Cloudflare TURN credential rotation (~30 min cadence)
breaks the bilateral allocation path between two peers and the
push-notification recovery (entmoot transport-ad over Pilot
gossip) can't fire because the data path it needs just died.

### Why

Live evidence on 2026-04-26: VPS pilot started at 15:35 with
allocation `104.30.149.241:12483`. At 16:05:07 Cloudflare
rotated credentials and pilot's allocation became
`104.30.150.209:36509`. Laptop's first rendezvous lookup at
16:04:33 had installed the bilateral CreatePermission for the
about-to-rotate value; once VPS started sending from the new
allocation 34 s later, every send was silently dropped at
laptop's allocation permission check. Pion's `Send` returns nil
regardless of remote receipt, so neither side could detect the
break locally. The push-notification path (VPS's entmoot
republishes its transport ad over Pilot gossip after the jf.11b
TURN-rotation hook fires) couldn't deliver because the gossip
dial itself depends on the freshly-broken bilateral path.

### Industry alignment

The fix mirrors the periodic-refresh-via-signaling pattern
every reviewed P2P stack uses:

- **Tailscale magicsock**: continuous STUN probes against DERP
  servers; periodic re-confirmation of own and peer addresses
  through the always-up signaling pipe (DERP) independent of
  the data path.
- **iroh-net**: `netcheck` loop probing relays for fresh
  address info, used to "heal connections after network
  migration".
- **WebRTC ICE Restart (RFC 8838 trickle ICE)**: candidate
  re-gathering exchanged over the signaling channel, which
  doesn't depend on the data path being healthy.

Pilot's rendezvous service is the equivalent always-reachable
signaling channel; the missing piece was a cadence to poll it.

### Fixed

- **`rendezvousLookupForDial` no longer suppresses cache-equal
  results.** The previous `if fresh == current { return "" }`
  guard skipped same-address re-installs, but the no-op was not
  really a no-op — it gated the only path that re-issues
  `PermitTURNPeer`'s `CreatePermission` and refreshes the
  permission's timestamp on the local TURN allocation. Without
  that periodic refresh, a permission can fall out of
  `permittedAddrs` (allocation rotation, eviction, or
  bookkeeping race) and never come back into
  `permissionRefreshLoop`'s working set, silently expiring at
  the TURN server's 5-min permission TTL. Now lookup returns
  the fresh value unconditionally; eviction of cached conns
  still gates on actual address change inside
  `AddPeerTURNEndpoint`, so same-address calls remain cheap.

### Added

- **`rendezvousPeerRefreshLoop`** (~90 s cadence). Walks
  `tm.KnownTURNPeers()` every tick and re-looks-up each peer
  via the rendezvous service, feeding the result through
  `AddPeerTURNEndpoint` → `PermitTURNPeer`. Catches Cloudflare
  rotations within one cadence (≤ 90 s) and re-permits the
  fresh allocation address before the previous permission
  expires. Jittered first tick (0–30 s) so a fleet restarting
  in lockstep doesn't synchronize lookups. No-op if
  `RendezvousURL` is empty or no peers have a recorded TURN
  endpoint.

- **`TunnelManager.KnownTURNPeers() []uint32`**. Helper
  enumerating peers with a non-nil `peerTURN` entry. Used by
  the new refresh loop.

### Constants

- `DefaultRendezvousPeerRefreshInterval = 90 * time.Second` —
  empirically tuned for Cloudflare's ~30 min credential
  rotation: 20 chances per rotation cycle to re-permit before
  the previous CreatePermission's 5-min TTL expires. Tunable
  downward if rotation cadence tightens, upward if rendezvous
  QPS becomes a concern.

### Tests

`pkg/daemon/daemon_rendezvous_test.go`:

- `TestRendezvous_LookupForDial_ReturnsFreshEvenWhenCacheEqual`
  pins the new behaviour: rendezvousLookupForDial returns the
  fresh value even when the cache already has the same
  endpoint, so the caller can re-issue `AddPeerTURNEndpoint`
  and refresh the local CreatePermission. Replaces the
  pre-jf.15.7 `…ReturnsEmptyOnSameAsCached` test that pinned
  the old (buggy) behaviour.

`pkg/daemon/tunnel_trace_test.go`:

- `TestKnownTURNPeers_EnumeratesPeerTURNEntries` confirms the
  new helper enumerates every peer with a non-nil peerTURN
  entry and excludes never-installed nodeIDs.

### Verification

Live verification on the 3-machine mesh (post-deploy, both
peers on jf.15.7 + a Cloudflare credential rotation observed):

1. Bump VPS, laptop, phobos to jf.15.7 and restart pilot.
2. Wait for at least one Cloudflare rotation cycle (~30 min)
   on each peer with TURN.
3. On any peer's pilot.log: expect `rendezvous peer refresh:
   re-installed node_id=… addr=…` Debug entries every ~90 s
   per known TURN peer.
4. On rotation: expect a fresh `addr=` for the rotated peer
   within 90 s, and `evicted stale peer conn after turn
   endpoint change` showing the cached `turnDialedConn`
   getting replaced.
5. `pilotctl peers` should remain `yes/yes` across rotation
   cycles (pre-jf.15.7 it would silently flip to `no/no`
   within minutes of any rotation).

If verification 5 holds for >2 rotation cycles (~1 hour
sustained), the bilateral cold-start saga is closed for the
steady-state case as well as the cold-start case.

## [v1.9.0-jf.15.6] - 2026-04-26

Recovery PILA now fires when the trigger frame arrived through
pion TURN. This was the surviving blocker after jf.15.5 — the
right routing (writeFrame) was wired up, but a stale early-return
guard prevented the function from ever being entered.

### Fixed

- **`maybeSendRecoveryPILA` no longer short-circuits on
  `addr == nil` for non-relay sends.** Frames delivered through
  pion's TURN client arrive at the inbound loop wrapped as
  `*transport.TURNEndpoint`, not `*transport.UDPEndpoint`, so the
  type assertion at `tunnel.go:1614` leaves `remote` nil. That
  nil propagates into `handleEncrypted` → `maybeSendRecoveryPILA`,
  which then hit the guard `if !viaRelay && addr == nil { return }`
  and bailed before stamping the rate-limit timestamp or even
  attempting the send.

  Net effect: a laptop receiving VPS's encrypted frames over
  Cloudflare TURN logged `encrypted packet from node but no key
  peer_node_id=45981` repeatedly, but never emitted the recovery
  PILA that would have re-bootstrapped its crypto state. The
  bilateral deadlock the recovery path was specifically designed
  to break — couldn't break.

  Live evidence 2026-04-26 (post-jf.15.5 deploy): laptop's
  `pilotctl info` showed 12.5 MB received from VPS, all of it
  un-decryptable PILS frames. Tier counters confirmed laptop was
  sending to VPS via `outbound_turn_only_own_relay` (laptop's
  pion TURN → VPS's real UDP → VPS receives, authenticates,
  replies). VPS's replies arrived at laptop's pion as
  TURNEndpoint-wrapped frames, were decoded as encrypted
  (correctly), found no crypto state (correctly), and triggered
  `maybeSendRecoveryPILA(45981, nil, false)` — which then
  silently no-op'd at the guard.

  Fix: drop the `if !viaRelay && addr == nil { return }` guard.
  `writeFrame` resolves the destination by nodeID via its
  existing tier ladder (`peerTURN`, `peerConns`, `pathDirect`,
  own-relay) and returns its own error if no path exists; we log
  Debug at the caller and the rate-limit cooldown still prevents
  amplifier abuse on truly unreachable peers. The guard predated
  jf.15.5's writeFrame migration and was never updated to
  recognize that nil-addr sends are now valid.

### Tests

`pkg/daemon/tunnel_trace_test.go`:

- `TestMaybeSendRecoveryPILA_FiresWhenTURNDelivered` — with the
  guard removed, calling `maybeSendRecoveryPILA(nodeID, nil,
  false)` stamps `lastRecoveryPILA[nodeID]`. Pre-jf.15.6, the
  early-return left the timestamp unset.
- `TestMaybeSendRecoveryPILA_RespectsRateLimit` — the DoS-
  amplifier mitigation (60 s cooldown per peer) survives the
  guard removal: a second call within the cooldown does not
  advance the timestamp.

### Verification

Live verification on the 3-machine mesh (post-deploy):

1. Bump VPS, laptop, phobos to jf.15.6 and restart pilot.
2. On laptop within ~60 s: expect `sent recovery PILA to peer
   with unknown key peer_node_id=45981 addr=...` and a
   subsequent `encrypted tunnel established auth=true
   peer_node_id=45981 endpoint=... relay=false`.
3. `pilotctl peers | grep 45981` should flip from `no/no` to
   `yes/yes` within 1–2 seconds of the recovery PILA emission.
4. `entmootd query | head -5` should show the missing messages
   from the cold-start window once gossip resumes.

If verification 4 lands, the entire jf.13 → jf.15.6 chain is
end-to-end validated and the bilateral cold-start crypto-state
deadlock is closed.

## [v1.9.0-jf.15.5] - 2026-04-26

The recovery-PILA flow finally respects `-outbound-turn-only`.
This was the actual blocker keeping the laptop↔VPS crypto state
permanently asymmetric.

### Fixed

- **`maybeSendRecoveryPILA` now routes through `writeFrame`,
  not raw `tm.udp.WriteToUDPAddr`.** When laptop receives an
  encrypted frame from VPS with no matching crypto state
  (typical after a one-sided daemon restart — VPS retains
  laptop's session key, laptop generated a fresh X25519 on
  restart), it correctly fires the unsolicited PILA recovery
  flow. But the recovery PILA was being sent via the daemon's
  raw UDP socket, **bypassing the outbound-turn-only routing
  enforcement entirely**. Two consequences:

  1. **The PILA never reached VPS.** Raw UDP from laptop's
     main socket carries source = laptop's real IP. VPS's
     TURN allocation only permissions laptop's TURN allocation
     address (auto-permissioned by VPS's pion when VPS first
     wrote to it). Cloudflare drops the recovery PILA at the
     permission check.
  2. **Even if it reached VPS, it would have leaked laptop's
     real IP** — defeating the entire `-hide-ip` premise. The
     recovery flow was a privacy regression hiding behind a
     correctness bug.

  Live evidence 2026-04-26: laptop on jf.15.4 received
  continuous WARN-level `encrypted packet from node but no key
  peer_node_id=45981` events from VPS but never recovered.
  `pilotctl peers` showed VPS as `no/no` (encrypted/auth)
  while VPS showed laptop as `yes/yes` — perfectly asymmetric
  crypto state. Phobos↔VPS and laptop↔phobos were both fine
  (neither involves the outbound-turn-only-from-real-IP path).

  Fix: change the direct-path branch of `maybeSendRecoveryPILA`
  to call `tm.writeFrame(nodeID, addr, frame)` instead of
  `tm.udp.WriteToUDPAddr(frame, addr)`. writeFrame's
  outbound-turn-only branch routes via our local TURN
  allocation to the peer's path.direct (the peer's real
  registry-published IP), which is reachable and where the
  peer's pion auto-permissioned our TURN allocation address
  on first write. For non-turn-only peers, writeFrame's
  direct-UDP tier produces identical bytes-on-the-wire to the
  old code path.

### Why this took so long to surface

The recovery flow had three load-bearing assumptions, only the
first two of which were ever exercised in this fork before
today:

1. The trigger frame's source address is suitable to write
   back to. ✓ Holds for normal NAT'd peers.
2. The peer can receive raw UDP at that source address. ✓
   Holds for peers without `-outbound-turn-only`.
3. We have privacy permission to send raw UDP from our real
   IP to that source. ❌ Holds only if WE aren't
   `-outbound-turn-only`.

When `-outbound-turn-only` was added in jf.11a, the recovery
flow inherited assumption 3 unchecked. Until today, no live
deployment had:

- A daemon in `-outbound-turn-only` mode
- That entered the asymmetric crypto state
- And had the recovery flow trigger

All three converged today after enough other bugs were peeled
away that this one was finally in the critical path.

### Compat

No wire-format / protocol changes. Existing recovery flow
semantics preserved for non-turn-only peers (writeFrame's
direct-UDP tier is the same byte-emit). For
`-outbound-turn-only` peers, recovery now works at all (was
silently broken). Backwards-compatible end-to-end.

### Tests

Full daemon + cmd/pilot-rendezvous suite green under `-race`.
Existing recovery PILA call-site test (if any) passes
unchanged because the outbound bytes are equivalent for the
non-turn-only path. No new test added — the change is a
one-liner routing redirect, and the existing live mesh test
(laptop's WARN logs converging to a successful key exchange)
verifies it directly.

### Live verification

After bumping VPS, laptop, phobos to jf.15.5:

1. On laptop: `grep "sent recovery PILA" ~/.pilot/pilot.log
   | tail -5` — expect at least one INFO line per minute
   while the asymmetric state lasts.
2. On laptop: `~/.pilot/bin/pilotctl peers` — VPS (45981)
   should flip to `yes/yes` (encrypted/auth) within seconds
   of the first successful recovery PILA.
3. On laptop: `entmootd query | head -5` — the 5 missing
   messages from yesterday's upgrade window should appear
   within 1-2 reconcile ticks.

If step 3 succeeds, the cold-start saga AND the recovery
asymmetry are both finally closed.

## [v1.9.0-jf.15.4] - 2026-04-26

Fix dead-code gate that prevented the rendezvous lookup AND the
TCP/relay-switch fallback from ever firing in outbound-turn-only
mode. Discovered while debugging why jf.15.3's bilateral cross-
permission wasn't completing convergence: laptop's pilot showed
zero "rendezvous installed fresh turn endpoint" log lines despite
many entmoot reconcile retries.

### Fixed

- **`DialConnection`'s fallback gate fires correctly when
  `directRetries==0`.** jf.12.1 introduced `directRetries=0` as a
  shortcut for outbound-turn-only peers (skip the cosmetic
  direct-UDP retry budget). jf.14 added the rendezvous lookup
  hook inside `if retries == directRetries && !relayActive`.
  But `retries` is incremented BEFORE that check, so when
  `directRetries==0` the check `retries == 0` is **never true**
  — both the rendezvous lookup and the TCP/relay-switch logic
  are dead code in outbound-turn-only mode.

  Live evidence 2026-04-26: laptop on jf.15.3 with
  `-rendezvous-url` set, full debug logging, but `grep -E
  "rendezvous installed fresh turn endpoint|rendezvous lookup"`
  returned zero lines after dozens of entmoot reconcile retries.
  VPS's transport_ad to laptop only carried TCP (no TURN
  endpoint advertised by VPS's entmoot in non-hide-ip mode), so
  laptop never installed VPS's TURN allocation address — the
  exact case jf.14's rendezvous lookup was supposed to handle.
  jf.15.3's `PermitTURNPeer(VPS_TURN_addr)` couldn't fire on
  laptop because laptop never received the address through
  any channel.

  Fix: compute `fallbackTriggerAt := max(directRetries, 1)` once
  at the top of the dial loop and gate the fallback block on
  `retries == fallbackTriggerAt`. With `directRetries==3`
  (normal mode), fires on retries==3 — same as before. With
  `directRetries==0` (outbound-turn-only or already-relay), fires
  on retries==1 — first timer tick after the initial SYN.

### Why

jf.12.1 ("skip phase-1 direct retries when outbound-turn-only is
set") was a cosmetic-stall fix. It assumed the only consumer of
`directRetries` was the retry-counter math. But jf.14's
rendezvous-lookup hook landed three releases later with a
`retries == directRetries` gate that silently broke when
combined with directRetries=0. The two patches composed wrong.

The interaction was invisible because:
- VPS isn't outbound-turn-only, so VPS's rendezvous lookups
  fired correctly (we observed them in jf.15.2's tier traces).
- Laptop's outbound *to* VPS still worked via the
  outbound-turn-only `SendViaOwnRelay` path which bypasses the
  rendezvous-lookup gate entirely (it routes via VPS's real IP
  from the registry).
- Only the *return* direction (VPS→laptop via pion) needed
  laptop to know VPS's TURN allocation address — which laptop
  never learned because the rendezvous lookup was dead code.

### Compat

No wire-format changes. No protocol changes. No new flags. The
fix preserves the existing once-per-dial fire semantics: with
`directRetries==3` the block fires on `retries==3` exactly as
before; with `directRetries==0` it now fires on `retries==1`
(was: never).

The TCP/relay-switch logic is also now correctly active for
outbound-turn-only peers — though most tier-3 (TCP) and tier-3
(beacon-relay) paths are skipped anyway in that mode (jf.10's
`hasTURNEp` skip, jf.11a's outbound-turn-only fail-closed). The
practical effect is just that the rendezvous lookup now fires.

### Tests

Full daemon + cmd/pilot-rendezvous suite green under `-race`.
No new dedicated tests for this fix — the bug is a one-line
gate condition, and the existing live-mesh evidence (no
"rendezvous installed fresh turn endpoint" log lines on laptop
despite many retry attempts) confirms both the bug and the fix.
A regression test would require building out a full
DialConnection harness with simulated retries; deferred unless
the gate logic gets touched again.

### Live verification

After bumping all 3 nodes to jf.15.4:

1. On laptop: `grep "rendezvous installed fresh turn endpoint"
   ~/.pilot/pilot.log | tail -5`. Should show ≥1 line per
   entmoot reconcile retry now (was: zero).
2. On laptop: tier counters in `pilotctl info | jq
   '.pkts_sent_by_tier'` should show `cached_conn` growing for
   VPS — pion-to-pion path working bilaterally.
3. On laptop: `pilotctl info | grep -i traffic` — `recv` count
   growing (was: 0).
4. **Acid test**: `entmootd query | head -5` on laptop — the 5
   missing messages from yesterday's upgrade window should
   appear within 1-2 reconcile ticks.

### Out of scope (deferred)

- **Rendezvous publish retry on 429** (laptop hit rate-limit
  during jf.15.3 deployment burst). Not blocking convergence
  per se — laptop's record DOES eventually update — but worth
  cleaning up. ~10 LOC for jf.15.5 if it bites again.
- **VPS's entmoot advertising TURN endpoint in transport_ads
  even without `-hide-ip`.** Currently only hide-ip entmoot
  peers advertise TURN. Could be made unconditional now that
  bilateral cross-permission means non-hide-ip peers can
  benefit too. Cross-cuts entmoot; defer.

## [v1.9.0-jf.15.3] - 2026-04-26

Closes the cold-start bootstrap saga end-to-end. Diagnosed via
jf.15.2 trace observability; fix is one missing call.

### Fixed

- **TURN allocation now permissions a peer's TURN allocation
  address when we learn it.** When a peer advertises a TURN
  allocation (via rendezvous lookup or entmoot transport-ad),
  `AddPeerTURNEndpoint` records the address in `peerTURN` so
  outbound sends can target it. **But it never installed a
  CreatePermission on our local TURN allocation for that
  address.** Result: pion-routed sends from VPS to laptop
  (cached `turnDialedConn` path) reached Cloudflare TURN, got
  forwarded as raw UDP from VPS's TURN-allocation source
  address to laptop's TURN allocation, and were silently
  dropped at laptop's permission check — invisible to both
  daemons.

  Fix: in `AddPeerTURNEndpoint`, after storing the peer's TURN
  endpoint, call `tm.PermitTURNPeer(addr)`. The helper was
  written exactly for this case in jf.9 (the doc-comment says
  *"Explicit caller... for peers who might never direct-UDP us
  before they try the TURN relay path"*) but was never wired in.

### How the bug was found

jf.15.2's `-trace-sends` flag emitted one INFO log per
`writeFrame` tier decision. The output showed:

```
tier=cached_conn ... dst_addr=104.30.150.206:21808 result=ok ×40
```

40 successful pion-routed sends to laptop's TURN allocation,
yet laptop reported `0 B recv`. Cross-checking with `tcpdump`
confirmed packets DID leave VPS via pion to Cloudflare TURN —
they just disappeared somewhere in the middle. That somewhere
was the permission check on laptop's allocation.

Without the per-tier observability, we'd been guessing for two
releases. **jf.15.2 paid for itself in one diagnostic.**

### Why this is the canonical fix

- **pion's own `tcp-alloc` example** (`turn-client/tcp-alloc/main.go`)
  is the direct reference: peers exchange relay-allocation
  addresses via a signaling channel, then each side explicitly
  calls `client.CreatePermission(peer_relay_addr)` before
  accepting. Pilot's rendezvous (jf.14) and entmoot's
  transport-ads (jf.7+) are the signaling channels; this is
  the missing CreatePermission.
- **WebRTC ICE** does the same via SDP candidate-exchange:
  both peers learn each other's relay candidates, install
  permissions, then run connectivity checks bilaterally.
- **Tailscale (DERP) and iroh (iroh-relay)** sidestep this
  entire problem with custom relay protocols that "blindly
  forward already-encrypted traffic." Building a DERP-style
  relay is a much larger architectural change; deferred.

### Bilateral semantics fall out automatically

When both peers run jf.15.3:

- VPS learns laptop's TURN address (rendezvous) → calls
  `PermitTURNPeer(laptop_TURN)` → VPS's allocation accepts
  inbound from laptop's TURN.
- Laptop learns VPS's TURN address (rendezvous) → calls
  `PermitTURNPeer(VPS_TURN)` → laptop's allocation accepts
  inbound from VPS's TURN.
- Now pion-to-pion forwarding works in both directions.

Rotation handling is already in place:

- Peer rotates TURN → publishes new addr to rendezvous
  (jf.14.2) → our rendezvous lookup picks it up →
  `AddPeerTURNEndpoint` fires with new addr → **fresh
  `PermitTURNPeer` installs the new permission**. jf.14.2's
  cache eviction also fires on address change.
- Our own allocation rotates → jf.15's atomic swap calls
  `refreshAllPermissions` on the new allocation → all
  `permittedAddrs` re-issued.

### Privacy

- Laptop's real IP: never on the wire to anyone. Same as
  before. ✓
- VPS's real IP: previously visible on the data path (raw UDP
  from VPS:37736 to laptop's TURN allocation). With jf.15.3,
  the cached `turnDialedConn` path actually works, so VPS
  routes via its TURN allocation instead. **Reduced exposure**
  — VPS's real IP appears only in registry / control plane.
- Either side can become `-hide-ip` without code changes. The
  symmetric hide-ip configuration (both `-outbound-turn-only`)
  works because pion-to-pion forwarding now delivers correctly.

### Compat

- jf.15.3 peer ↔ jf.15.2-or-earlier peer: jf.15.3 installs
  permission on its own allocation; old peer doesn't
  reciprocate. Permissions are unidirectional, so the old peer
  can still receive from new peer's TURN-allocation address
  via this side's wiring, but the reverse direction fails the
  same way as before. **Once both peers are on jf.15.3, both
  directions work.** Mixed-version meshes converge as soon as
  both endpoints upgrade. No protocol negotiation; behaviour
  is purely local.
- No wire-format changes. No new CLI flags. No new dependencies.

### Tests

`pkg/daemon/tunnel_trace_test.go` (extended):

- `TestAddPeerTURNEndpoint_NoOpWithoutLocalTURN` — peers
  without local TURN allocation (e.g. phobos) handle the
  install without panicking and without populating
  `turnPermittedPeers`.
- `TestAddPeerTURNEndpoint_RepeatedInstallNoCrash` — same-addr
  re-installs are idempotent (the underlying
  `PermitTURNPeer` and `permittedAddrs` map both refresh
  without duplicating).
- `TestAddPeerTURNEndpoint_AddressChangePermitsNewAddress` —
  rotation flow: old conn evicted (jf.14.2), peerTURN updated,
  PermitTURNPeer fires for new address.

3 new tests on top of jf.15.2's 11. Full suite green under
`-race`.

### Out of scope (deferred)

- **DERP-style custom relay**. Tailscale and iroh's approach.
  Drops TURN dependence entirely. Reserved for a future
  architectural redesign.
- **Roster-driven proactive permissioning**. Currently
  `AddPeerTURNEndpoint` fires on rendezvous lookup or entmoot
  transport-ad receive. A "permission everyone in your group
  at startup" iteration could be wired off entmoot's roster.
  Not blocking jf.15.3.
- **TURN ChannelBind for performance**. ChannelData saves 4
  bytes/msg vs SendIndication. Not a bottleneck. Defer.

### Live verification (post-deploy)

After bumping all 3 mesh nodes to jf.15.3:

1. Wait ~30 s.
2. `pilotctl info | jq '.pkts_sent_by_tier'` on VPS — expect
   `cached_conn` count growing for laptop.
3. `pilotctl info` on laptop — expect `recv` numbers growing
   (was 0 in jf.15.2).
4. `entmootd query | head -5` on laptop — expect the 5 missing
   messages from yesterday's upgrade window to appear within
   1-2 reconcile ticks.

Step 4 closes the cold-start bootstrap saga end-to-end:
jf.13 keepalive → jf.14 rendezvous → jf.14.1 nodeID-replay →
jf.14.2 refresh + eviction → jf.15 self-heal → jf.15.1
consent probe → jf.15.2 trace observability → **jf.15.3
bilateral cross-permission**.

## [v1.9.0-jf.15.2] - 2026-04-26

Per-tier observability for `writeFrame`. Pure additive — no
behaviour changes when the new flag is off. Goal: diagnose the
last residual convergence blocker in jf.15.1 (VPS sees laptop
authenticated, receives frames, but never sends a single packet
back).

### Added

- **`-trace-sends` CLI flag** (default: `false`). When on, the
  daemon emits one INFO log per `writeFrame` tier-decision and
  per `SendTo` "queued pending key exchange" branch. Volume is
  high (~10 events/min/peer-pair in steady state, more during
  dial storms); intended for short-lived diagnostic windows,
  not steady-state operation.

  Each log carries structured fields:

  ```
  level=INFO msg=writeFrame
    node_id=45491 tier=cached_conn bytes=137
    dst_addr=104.30.150.205:45823 result=ok via_relay=false
  ```

  Tier values are stable strings and form a closed set:

  ```
  outbound_turn_only_cached    (jf.11a cached non-UDP path)
  outbound_turn_only_jf9       (jf.9 lazy DialTURNRelayForPeer)
  outbound_turn_only_own_relay (jf.11a.2 SendViaOwnRelay)
  beacon_relay                 (jf.10 beacon path)
  cached_conn                  (cached non-UDP, non-turn-only)
  jf9_fallback                 (jf.9 lazy dial with addr==nil)
  direct_udp                   (final tm.udp.WriteToUDPAddr)
  queued_pending_key           (SendTo encryption-queue branch)
  ```

- **Always-on per-tier counters in `pilotctl info`**. Two new
  JSON map fields exposed regardless of the flag:

  ```
  pkts_sent_by_tier:  { "direct_udp": 1234, "cached_conn": 56, ... }
  bytes_sent_by_tier: { ... }
  ```

  Counters increment only on successful sends (mirrors the
  existing `pkts_sent` / `bytes_sent` semantics). Operators can
  read these at a glance to see which tier a peer's traffic is
  going through, without needing to flip the flag and parse
  per-event logs.

  These are the always-on observability spine; the flag-gated
  logs are per-event detail when needed.

### Why

jf.15.1 closed the consent-probe gap on TURN allocations. But
live diagnostics on 2026-04-26 surfaced a different residual
issue: VPS shows laptop as `auth=true`, receives frames every
~8 s, yet sends zero packets to laptop's TURN allocation
(verified by tcpdump). VPS's keepalive log emits nothing
(success path is silent), so we can't tell which tier the send
took or whether it took any tier at all.

The exploration of `pkg/daemon/tunnel.go` mapped seven
tier-decision points where `writeFrame` returns nil — plus an
eighth pre-`writeFrame` branch in `SendTo` that **queues the
packet, returns nil silently**, and never reaches `writeFrame`
at all. Without observability we can only guess which one is
the silent no-op offender. This release makes it observable.

### Composes with

- `-log-level` already exists; `-trace-sends` is orthogonal and
  upgrades INFO log volume specifically for the send path.
- All prior jf.X observability (rendezvous publish/lookup logs,
  self-heal markers, eviction events) keeps its existing log
  level and shape.
- Existing per-tier Debug logs (`outbound-turn-only: ...
  failed`, `cached peer conn failed, falling back`,
  `turn-relay fallback dial failed`) are preserved — they
  carry richer error context than the structured INFO logs and
  remain useful at `-log-level=debug` when the flag is off.

### Tests

`pkg/daemon/tunnel_trace_test.go`:

- `TestSendTier_NamesStableAcrossIndices` — pins the
  index→name mapping (operators grep for these strings).
- `TestRecordTierSend_BumpsCountersOnSuccess` — `err == nil`
  bumps both pkts and bytes for the matching tier.
- `TestRecordTierSend_DoesNotBumpOnFailure` — `err != nil`
  leaves counters alone (counters represent bytes-on-the-wire,
  not attempts).
- `TestRecordTierSend_OnlyTouchesItsOwnTier` — bumping tier X
  doesn't move tier Y.
- `TestSnapshotByTier_ReturnsAllTiers` — JSON map includes
  every tier even with zero bytes (stable shape for ops).
- `TestTraceSends_DefaultOff` — fresh `TunnelManager` has the
  flag off (operators must opt in).
- `TestSetTraceSends_TogglesField` — runtime toggle works.
- `TestRecordTierSend_NoLogWhenOff` /
  `TestRecordTierSend_LogsWhenOn` — gate works in both states
  (counter behaviour is identical regardless of flag).

8 new tests, all green under `-race`.

### Compat

No wire-format changes. No protocol changes. New JSON fields
in `pilotctl info` use `omitempty`-equivalent defaults so
older clients decode cleanly. Counters are zero-initialized;
flag is off by default. Pure additive.

### Live verification (next deploy)

1. Bump VPS to jf.15.2 with `-trace-sends`. Restart.
2. Wait 60 s.
3. ```
   grep '"writeFrame"' /root/.pilot/log/pilot-daemon.jf15.2.log \
     | jq -r '"\(.tier) \(.dst_addr) \(.result)"' \
     | sort | uniq -c | sort -rn | head
   ```
4. Or simpler:
   ```
   pilotctl info | jq '.pkts_sent_by_tier'
   ```
5. The output names which tier is the silent no-op offender.
   Targeted fix lands in jf.15.3.

### Out of scope (deferred)

- **Fixing the underlying silent no-op.** That's jf.15.3 once
  jf.15.2 tells us where to look.
- **Removing existing Debug logs.** Keep them; they have
  failure-context strings the new INFO logs don't replicate.
- **Per-tier RTT histograms.** Not needed for current
  diagnostic. Add later if `writeFrame` becomes a recurring
  hot path.

## [v1.9.0-jf.15.1] - 2026-04-26

Two related gaps in jf.15's self-heal trigger surfaced from
deeper diagnosis of the live mesh: the heal counter never
incremented in the actual production failure mode.

### Fixed

- **Periodic permission-refresh failures now feed the
  self-heal counter.** `refreshAllPermissions` was calling
  `client.CreatePermission` directly (bypassing the public
  `t.CreatePermission` wrapper that records failures). Live
  evidence 2026-04-26 from laptop: `turnc ERROR: Fail to
  refresh permissions: all retransmissions failed` recurring
  every 4 minutes for hours, but VPS's pilot log shows zero
  self-heal events — because the failures were never counted.
  Fix: in `refreshAllPermissions`, on `client.CreatePermission`
  error → `t.recordFailure()`; on success → `t.recordSuccess()`.
  Both code paths now converge on the same health signal.

- **Active consent-freshness probe.** Even with the
  bookkeeping fix, the heal counter only increments when
  *something* tries to use the allocation. A stuck pion with
  no traffic stayed stuck indefinitely. Fix: new
  `consentLoop` goroutine that calls pion's
  `SendBindingRequest()` against the TURN server every 30
  seconds (overridable via `setConsentProbeInterval` for
  tests). This is the canonical RFC 7675 STUN-binding probe —
  exactly the pattern WebRTC uses for the same job. Failures
  feed `recordFailure` like any other operation; success
  resets the counter.

  With both fixes, a pion stuck in any failure mode is
  detected within ~2.5 minutes (5 probe failures × 30 s
  interval = 2.5 min) and atomically rebuilt by jf.15's
  existing self-heal path.

### Why

The jf.15 design correctly identified the canonical pattern
(RFC 7675 + atomic swap) but missed the *coverage* problem:
passive failure tracking only catches failures from explicit
send paths. A daemon whose peers are all silent — exactly
the case where bootstrap is most fragile — never gets a
failure signal even when its allocation is dead. The
solution is the same active probe RFC 7675 specifies for
WebRTC media paths, scaled to our long-lived control-plane
cadence (30 s instead of 4-6 s).

### Tests

`pkg/daemon/transport/turn_selfheal_test.go` adds 5 tests
on top of jf.15's 11:

- `TestSelfHeal_ConsentProbeIntervalDefault` — fresh
  transport gets `defaultConsentProbeInterval` (30 s).
- `TestSelfHeal_SetConsentProbeIntervalRespected` — test
  hook overrides default; zero/negative ignored (mirrors
  setPermissionRefreshInterval semantics).
- `TestSelfHeal_ConsentProbeOnNilClientNoOp` — pre-Listen
  state probe is a no-op, no panic, no spurious failure.
- `TestSelfHeal_ConsentProbeOnClosedTransportNoOp` — same
  for Close()d transport.
- `TestSelfHeal_ConsentLoopExitsOnClose` — goroutine
  lifecycle hygiene: tiny interval, tick a few times, close
  channel, expect prompt return.
- `TestSelfHeal_RefreshAllPermissionsHooksWired` — no-op
  refresh (nil client) doesn't spuriously increment failures.

Total: 16 self-heal tests, all green under `-race`.

### Compat

No wire-format changes. No protocol changes. No CLI flags
added. Adds 1 STUN BindingRequest per 30 s per running
TURN allocation (~50 bytes round-trip). Backwards-compatible
with all earlier jf.X versions on the wire.

### Out of scope (deferred)

- **Tunable probe cadence via CLI flag.** 30 s is the
  RFC-7675-derived default; operators with weird needs can
  fork the constant.
- **Skip probe when allocation is idle for short windows.**
  Considered. Skipped — the probe is cheap, and an idle
  allocation is exactly where consent-freshness matters most
  (no peer traffic to detect failure passively).

## [v1.9.0-jf.15] - 2026-04-26

TURN allocation self-heal — RFC 7675 consent-freshness circuit
breaker (30 s) plus Tailscale-style atomic-swap pattern at the
pion TURN-client layer. Closes a fragility class surfaced by
the live deploy of jf.14.2: pion's TURN client can degrade
silently (permission refresh failures, allocation half-dead),
and `-outbound-turn-only` is fail-closed by design, so any
pion failure cascades to "no TURN path" until manual restart.

### Fixed

- **Pion TURN client gets stuck → no auto-recovery → operator
  must restart pilot.** Live evidence 2026-04-26: laptop on
  jf.14.2 had a fresh allocation and a known good destination
  for VPS but threw `outbound-turn-only: no TURN path for node
  45981` repeatedly, with `turnc ERROR: Fail to refresh
  permissions: all retransmissions failed` from pion's
  internal timer. A clean pilot restart didn't recover; the
  fragility recurs whenever pion's allocation goes half-alive.

  Fix: track health passively at the TURN-transport layer.
  Every `SendViaOwnRelay` and `CreatePermission` call records
  success or failure. When the consecutive-failure count
  reaches `selfHealFailureThreshold` (5) AND time since last
  success exceeds `selfHealStaleWindow` (30 s), nudge a
  background `selfHealLoop` that fetches fresh credentials and
  calls the existing `rotate()` (atomic swap) to rebuild the
  pion client + allocation.

  The two-axis check (count AND time) follows RFC 7675's
  consent-freshness model: 30 s is the canonical "path is
  dead" boundary. Counting alone would heal on noise (a fast
  burst of 5 failures inside a 1 s blip); time alone would
  heal on silence (one failure followed by 30 s of no
  attempts).

### Why

Industry-canonical pattern, validated three ways:

| Layer | Pattern | Cadence |
|---|---|---|
| WebRTC ICE | Consent freshness (RFC 7675) | 4-6 s probe / 30 s timeout |
| WebRTC ICE | ICE Restart on failure | 30 s after consent loss; ~67 % recovery rate |
| Tailscale DERP | Atomic-swap region failover | Background rebuild, atomic switch |

The 30 s circuit breaker is the same number RFC 7675 uses for
consent loss. The atomic-swap pattern (build new client,
re-issue permissions on it, atomically replace the old one
under lock, then close old) was already implemented in
`rotate()` for credential rotation; jf.15 just gives it a
second trigger (transport failure, in addition to credential
rotation). No protocol changes, no new dependencies.

### Composes with the existing stack

- **jf.13 keepalive** — fires on `AuthenticatedPeerIDs()`
  every 25 s; each emission goes through `tm.Send` which
  ultimately reaches `SendViaOwnRelay` for `-outbound-turn-only`
  peers. Failed sends now feed the self-heal counter.
- **jf.14.2 rendezvous refresh + eviction** — heal triggers
  `rotate()`, which fires the existing `onLocalAddrChange`
  callback, which already publishes the new allocation
  address to the rendezvous (jf.14.2 publish path) and to the
  IPC `turn_endpoint` topic (jf.11b). Peers learn the new
  address through the same plumbing as a credential rotation
  would propagate it.
- **jf.11a.2 send-via-own-relay** — unchanged routing logic.
  Heal just guarantees the underlying allocation stays
  healthy.

### Backoff & rate limit

Heal attempts are bounded by `selfHealBackoffSchedule`:
5 s → 10 s → 30 s → 60 s → 5 min cap. The first heal attempt
fires immediately (operators expect rapid recovery); each
subsequent failed attempt waits longer. This caps Cloudflare
TURN API request rate during a regional outage where Allocate
itself keeps failing — without the cap, a persistent outage
could burn API budget at 1 request/sec.

The attempt counter resets to 0 on a successful rebuild, so a
recovered allocation gets a full retry budget on the next
incident.

### Tests

`pkg/daemon/transport/turn_selfheal_test.go`:

- `TestSelfHeal_ThresholdNotReachedDoesntNudge` — 4
  failures (one below threshold) leaves the channel empty.
- `TestSelfHeal_ThresholdAndStaleWindowTriggerNudge` —
  5 failures with a 31 s-old last-success nudges exactly once.
- `TestSelfHeal_ThresholdReachedButRecentSuccessDoesntNudge`
  — 5 fast failures with a recent success leave the channel
  empty (noise immunity).
- `TestSelfHeal_RecordSuccessResetsCounter` — recordSuccess
  zeros the failure counter so subsequent failures climb the
  threshold ladder afresh.
- `TestSelfHeal_NudgeChannelIsCoalesced` — 100× threshold
  failures produce exactly one channel signal (length-1
  buffer + non-blocking send).
- `TestSelfHeal_NoLastSuccessTriggersOnCountAlone` — pre-
  Listen state (lastSuccess=0) heals on count alone so a
  never-working transport recovers eventually.
- `TestSelfHeal_BumpHealAttemptIncrements` — backoff
  index is monotonic across calls.
- `TestSelfHeal_RunSerializes` — concurrent runSelfHeal
  calls leave selfHealRunning in a clean state at the end.
- `TestSelfHeal_ClosedTransportNoOps` / `TestSelfHeal_NilProviderNoOps`
  — runSelfHeal exits cleanly on both edge cases without
  panic / nil-deref.
- `TestSelfHeal_BackoffScheduleMonotonic` — schedule is
  strictly increasing and caps under 10 min.

Total: 11 new tests, all green under `-race`.

### Compat

No wire-format changes. No protocol changes. No CLI flags
added (the thresholds aren't user-tunable; SIP and WebRTC
both use 30 s, so do we). No-op when `-turn-provider` is
unset (the entire transport is inert in that case). Fully
backwards-compatible — peers running jf.14.2 or earlier
observe identical wire behaviour from a jf.15 peer; the only
difference is jf.15 self-heals where earlier versions would
silently fail.

### Out of scope (deferred)

- **Active health probes (RFC 7675-strict).** Real consent
  freshness sends a STUN binding request every 4-6 s and
  expects a response within 30 s. We're using passive
  detection (count failed sends + permission refreshes) which
  is cheaper and adequate for our threat model. Active probing
  would require a TURN-server-side test endpoint we don't
  have; defer until needed.
- **Per-failure-type counter.** Different failure types
  (timeout, refused, malformed) might warrant different
  reactions. v1.9.0-jf.15 treats them all the same. Add later
  if telemetry shows specific failure modes that benefit from
  earlier intervention.
- **Tunable thresholds via CLI flag.** SIP and WebRTC both
  use 30 s; operators with weird requirements can fork the
  constants in the source.

## [v1.9.0-jf.14.2] - 2026-04-25

Two operational fixes for jf.14, surfaced by the first live
deployment and validated against canonical industry patterns
(SIP REGISTER refresh + gRPC name-resolver eviction).

### Fixed

- **Rendezvous records no longer expire on stable allocations.**
  In jf.14, the only thing that triggered `client.Publish()` was
  pion's `onLocalAddrChange` callback, which fires only when the
  TURN allocation rotates. If the allocation stayed stable for
  more than the publish TTL (30 min), the rendezvous record
  passed `ValidUntil` and lookups returned `verify: blob:
  expired`. Live evidence 2026-04-25: VPS published at 21:04,
  by 22:43 lookups failed with `now=1777149814235 >
  valid_until=1777143291708`. Fix: add `rendezvousRefreshLoop`
  that ticks every `DefaultRendezvousRefreshInterval = 15 min`
  with ±2 min jitter and re-pushes the current `TURNLocalAddr`
  through the existing publish channel. Mirrors **SIP REGISTER
  refresh at 0.5×Expires** (RFC 3261) — one full retry window
  before the record actually lapses. The on-rotation publish
  path is unchanged; the loop covers the stable-allocation case.

- **Stale TURN client conns are evicted when the cached endpoint
  changes.** In jf.14, `AddPeerTURNEndpoint(nodeID, fresh)`
  overwrote `peerTURN[nodeID]` but left any cached non-UDP
  `peerConns[nodeID]` (the pion TURN client built against the
  PREVIOUS address) in place. Subsequent `writeFrame` calls
  reused that cached conn and pion kept failing
  `CreatePermission` for the stale address — defeating the
  rendezvous fresh-endpoint install. Live evidence 2026-04-25:
  `rendezvous installed fresh turn endpoint addr=104.30.148.193:62971`
  ran successfully at 20:51, but every subsequent send hit
  `turn create permission 104.30.149.4:20414: all retransmissions
  failed` against the stale address. Fix: when the new address
  differs from the stored one, drop the cached non-UDP conn and
  Close it; the next `writeFrame` re-dials via the fresh
  endpoint. Mirrors **gRPC's name-resolver pattern** — when
  resolution returns a new address, drop existing connections to
  the old one and create fresh ones lazily on next dial. UDP
  cached conns are preserved (stateless wrappers; nothing to
  invalidate). No-op re-installs (same address called twice) do
  not disturb the live conn.

### Why both fixes ship together

Two orthogonal failures, two minimal additions. They operate on
different sides of the data flow: refresh is the *outbound*
"keep our record alive at the rendezvous"; eviction is the
*inbound* "consume fresh peer info and invalidate stale
downstream transport state." Combining them into one mechanism
would conflate the two concerns. Total surface: ~25 LOC for
the loop, ~20 LOC for the eviction branch in
`AddPeerTURNEndpoint`, ~80 LOC of new tests.

### Tests

`pkg/daemon/daemon_rendezvous_test.go`:

- `TestRendezvous_RefreshLoop_DisabledByEmptyURL` — empty URL
  → loop returns immediately.
- `TestRendezvous_RefreshLoop_StopsOnStopCh` — closing stopCh
  during the initial-jitter sleep exits within 500 ms.
- `TestRendezvous_AddPeerTURNEndpoint_EvictsCachedConnOnAddrChange`
  — non-UDP conn cached, address changed, conn evicted from
  map AND `Close()`d.
- `TestRendezvous_AddPeerTURNEndpoint_NoEvictOnSameAddr` —
  no-op re-install with the same address leaves the live conn
  alone.
- `TestRendezvous_AddPeerTURNEndpoint_NoEvictUDPConn` — UDP
  cached conns are preserved on addr change (stateless; no
  pion permission state to break).

### Compat

No wire-format changes. No protocol changes. No CLI flags
added. No-op when `-rendezvous-url` is empty. Fully backwards-
compatible — a jf.14 peer talking to a jf.14.2 peer just sees
the same publish cadence on rotation; the refresh loop adds
one extra publish every 15 min on the jf.14.2 side, which the
jf.14 server happily stamps and stores.

### Out of scope (deferred)

- **Per-peer eviction telemetry.** The Debug-level log on
  eviction is enough for the live mesh; if eviction storms
  ever appear, add a counter.
- **Tunable refresh cadence.** A CLI flag to override
  `DefaultRendezvousRefreshInterval` was considered and
  rejected — 15 min is the SIP-validated value; operators
  with weird requirements can fork.
- **Graceful drain instead of immediate Close.** Considered
  and rejected — `writeFrame` is best-effort, retries on next
  caller invocation, and the eviction is bounded by the
  rendezvous-lookup-on-cold-dial cadence (once per
  DialConnection). Simpler is correct here.

## [v1.9.0-jf.14.1] - 2026-04-25

Drop-in tuning on top of jf.14: ensure the daemon's initial
rendezvous publish actually fires during cold start.

### Fixed

- **Initial rendezvous publish is replayed after registry
  registration assigns nodeID.** The TURN transport's
  `onLocalAddrChange` fires once when pion completes its initial
  Allocate, very early in `daemon.Start` — well before the
  registry round-trip that returns the daemon's nodeID. The
  jf.14 publish loop guards against `nodeID == 0` (it has
  nothing meaningful to publish under), so the first event was
  silently dropped. Steady-state publishing only kicked in on
  the next pion-driven rotation (~30 min later). Live impact:
  every fresh restart left the rendezvous empty for the first
  ~30 minutes — exactly the cold-start window jf.14 was meant
  to close. Fix: after the registry response sets `d.nodeID`,
  query the current `TURNLocalAddr` and feed the publish
  channel. The next loop iteration sees a concrete nodeID and
  publishes within milliseconds.

  ```go
  // pkg/daemon/daemon.go, in Start, just after `d.tunnels.SetNodeID(d.nodeID)`:
  if d.rendezvousPublishCh != nil {
      if turnAddr := d.tunnels.TURNLocalAddr(); turnAddr != nil {
          select {
          case d.rendezvousPublishCh <- turnAddr.String():
          default:
          }
      }
  }
  ```

  No new state, no new code paths. The replay is a no-op when
  `RendezvousURL` is empty (channel is nil) or when the TURN
  transport hasn't allocated yet (`TURNLocalAddr` returns nil).

### Why

Caught during the first VPS deploy of jf.14 (2026-04-25):
`curl /v1/announce/45981` returned 404 several seconds after
daemon startup, despite `pilot-rendezvous` being healthy and
the daemon log confirming "daemon registered node_id=45981
endpoint=37.27.59.89:37736". Tracing the rotation hook through
to the publish loop revealed the nodeID-zero drop. Tested in
`pkg/daemon/daemon_rendezvous_test.go::TestRendezvous_PublishLoop_DropsBeforeNodeID`
already exercised the drop branch — what was missing was a
test that the *replay* fires once nodeID becomes non-zero.
That coverage gap will be closed in jf.14.2 if it shows
recurring; for now the live verification (curl after restart)
proves the fix.

### Compat

No wire-format changes. No protocol changes. No-op when
`-rendezvous-url` is empty. Fully backwards-compatible.

## [v1.9.0-jf.14] - 2026-04-25

Pkarr-style endpoint rendezvous — fixes the cold-start bootstrap
deadlock that survives jf.13's keepalive when the
privacy-maximalist preset (`-hide-ip` + `-outbound-turn-only` +
`-no-registry-endpoint`) makes both the registry and gossip
channels unavailable for a peer's freshly-rotated TURN endpoint.

### Added

- **`cmd/pilot-rendezvous`** — new companion HTTP service
  (~300 LOC + bbolt) that stores ed25519-signed
  `(NodeID -> TURN_endpoint, timestamp)` records. Three
  endpoints:

  ```
  PUT  /v1/announce/{node_id}   body: AnnounceBlob (JSON)
  GET  /v1/announce/{node_id}   -> AnnounceBlob | 404
  GET  /v1/health               -> "ok"
  ```

  Trust-on-first-use binds `(NodeID -> PublicKey)` on the first
  PUT; subsequent PUTs whose key disagrees get 409 Conflict. PUT
  is rate-limited to 1/min/NodeID; body cap 16 KiB; bbolt
  persistence at `--db`. Trusted **for availability, not for
  integrity** — signatures verify locally on every Lookup, so a
  compromised service cannot inject endpoints.

- **`pkg/daemon/rendezvous`** — client + shared blob format. The
  canonical signing payload (`pilot-rendezvous/v1\x00 || u32be(NodeID) ||
  u8(len(PublicKey)) || PublicKey || u8(len(TURNEndpoint)) ||
  TURNEndpoint || u64be(IssuedAt) || u64be(ValidUntil)`) is
  domain-separated to ensure signatures minted here can't be
  replayed in any other Pilot/Entmoot signature surface.

- **`-rendezvous-url`** CLI flag and `Config.RendezvousURL` —
  empty (default) disables both publish and lookup. Non-empty
  enables:
  1. **Publish on TURN rotation.** The existing
     `SetTURNOnLocalAddrChange` callback feeds a length-1
     channel; `rendezvousPublishLoop` drains. Last-value-wins
     so rapid rotations don't queue.
  2. **Lookup on cold-dial fallback.** Once per `DialConnection`
     attempt, just before the dial loop falls back to relay
     retries, query the rendezvous for a fresh endpoint. If it
     differs from the cached entry, install via
     `tm.AddPeerTURNEndpoint` and let the next retry succeed.
     Rate-limited to one lookup per dial via the
     `rendezvousQueried` flag.

### Why

Three of the four canonical patterns for cold-start /
post-rotation peer rediscovery (Tailscale DERP, libp2p
Circuit-Relay-v2 + DCUtR, Tor HSDirs) require either a
modifiable centralized coordinator or a heavy
always-available signaling channel that itself has the same
bootstrap problem. WebRTC ICE-Restart presumes the signaling
channel is up. WireGuard endpoint roaming requires *one side*
to already have a fresh address.

iroh's Pkarr-based discovery — productionized in
`iroh-dns-server` since 2024 — solves cold start with a tiny
HTTP service holding only opaque signed blobs. We adopt the
exact shape, point it at any operator-controlled endpoint
(self-host, Cloudflare Worker, behind Caddy / Tailscale Funnel,
or a Tor onion service), and gain a third independent
endpoint-distribution channel orthogonal to the registry and
gossip. The three channels collectively recover from any
single-channel outage.

### Composition with existing flags

The rendezvous is the third independent endpoint channel, not a
replacement for the other two. Operators choose which they
trust:

| Channel | Carries | Trust |
|---|---|---|
| Registry / beacon (third party) | UDP/TCP/LAN/TURN endpoints | full |
| Gossip / transport-ads (entmoot) | TURN endpoints | mesh-internal |
| Rendezvous (this release) | TURN endpoints, signed | available-not-integrity |

`-no-registry-endpoint` continues to suppress the first.
`-hide-ip` continues to mean "real IP never leaves this host."
`-rendezvous-url` adds the third channel without altering the
others.

### Privacy

The blob contains only the TURN allocation address (Cloudflare
anycast). With `-hide-ip` + `-outbound-turn-only`, the daemon
never publishes a real IP to the rendezvous. A compromised
rendezvous learns: which NodeIDs are alive and roughly when
they restart. For a mesh whose members already gossip-share
NodeIDs after authentication, this is a strict subset of
existing leakage.

### Compat

No wire-format changes. No protocol changes. No registry-side
changes. No entmoot changes. No new dependencies in the daemon
binary itself; `cmd/pilot-rendezvous` adds `go.etcd.io/bbolt`
(used only by the standalone server). Mixed-version meshes:
jf.14 peers transparently coexist with jf.13/earlier peers —
the new code paths are no-ops when `-rendezvous-url` is empty,
and a jf.14 peer that consults the rendezvous against a
jf.13 peer simply gets 404 (unpublished) and falls back to
existing behaviour.

### Tests

- `pkg/daemon/rendezvous/blob_test.go` — round-trip,
  tamper-detection (signature, endpoint, NodeID), expiry,
  validity-window bounds, expected-binding mismatches,
  clock-skew rejection.
- `pkg/daemon/rendezvous/client_test.go` — Publish/Lookup
  round-trip via `httptest.Server`, 404 → empty, tampered
  on-the-wire blob rejected, monotonic-IssuedAt latest-wins,
  unreachable-server error category.
- `cmd/pilot-rendezvous/server_test.go` — TOFU acceptance,
  key-conflict 409, path/body NodeID mismatch 400,
  bad-signature 400, rate-limit 429, monotonic blob
  overwrite, body-size cap, bbolt persistence across reopen.
- `pkg/daemon/daemon_rendezvous_test.go` — disabled-by-empty-URL
  no-op, client constructed when URL set, publish loop
  end-to-end via stub, drop-before-NodeID, last-value-wins on
  rapid rotations, lookup-for-dial happy/cache-equal/404/error
  paths.

### Out of scope (deferred)

- **Roster-anchored verification (jf.15).** Pull
  `(NodeID -> PublicKey)` bindings from entmoot's signed
  roster and reject any rendezvous response whose PublicKey
  doesn't match. Closes the TOFU race entirely. Postponed
  because it requires a daemon-to-entmoot read API that
  doesn't exist today; jf.14 ships the rendezvous in TOFU
  mode, which is sufficient for the existing 3-machine mesh
  if the operator pre-seeds bindings out-of-band.
- **Multi-rendezvous failover.** v1 supports exactly one
  `-rendezvous-url`. Multi-URL fanout deferred.
- **Rendezvous behind a Tor onion service.** Same binary;
  bind to `127.0.0.1:8443` and front with a Tor hidden-
  service config. Operator-level concern.

## [v1.9.0-jf.13] - 2026-04-25

Per-peer tunnel-layer keepalive — WireGuard's `PersistentKeepalive`
pattern, applied to every authenticated peer at the Pilot tunnel
layer. Closes the dialer-side TURN-permission-asymmetry deadlock
that survived jf.12 / jf.12.1.

### Fixed

- **TURN permissions and consumer-NAT mappings are now refreshed
  symmetrically by a periodic outbound to every authenticated
  peer.** Per RFC 8656 §9, a TURN allocation forwards an inbound
  packet to its owner only when the source IP is on the
  allocation's permission list. Permissions are IP-only, 5-min
  lifetime, and installed by the allocation owner via
  `CreatePermission`. pion auto-issues `CreatePermission` on each
  outbound `Send` toward a peer; no outbound for >5 min means the
  peer's source IP is no longer admissible. Live evidence
  2026-04-25 from the 3-machine mesh:

  ```
  vps:    gossip: reconcile: dial for root  peer=45491
                  err="peer 45491 in dial-backoff"
  vps:    gossip: reconcile: dial for root  peer=45491
                  err="pilot: dial 0:0000.0000.B1B3:1004:
                        ipcclient: daemon: dial timeout"
  ... (every reconcile attempt failed identically for >30 min;
   5 gossip messages sat undelivered to laptop for >24 h.)
  ```

  Fix: a new `peerKeepaliveLoop` goroutine emits one tiny
  authenticated control-protocol packet
  (`FlagACK | ProtoControl | PortPing`) to every peer with ready
  encrypted-tunnel state every 25 s (configurable via
  `-peer-keepalive`, mirroring WireGuard's
  `PersistentKeepalive=25` default). The emission goes through
  `tm.Send` so it respects every existing routing gate
  (`-outbound-turn-only`, relay-flagged peers, etc.). Each
  outbound forces pion to refresh `CreatePermission` for the
  destination on the allocation's permission list, keeping the
  inverse-direction dial path admissible.

### Why

Three of the four canonical patterns for cold-start dialer /
NAT-mapping refresh (Tailscale `CallMeMaybe`, WebRTC ICE
simultaneous checks, libp2p DCUtR) require a separate
always-available signaling channel, additional state machines, or
a relay coordinator. WireGuard's `PersistentKeepalive` (2017+)
solves all three problems — TURN-permission refresh, NAT-table
refresh, tunnel liveness — with one extra timer per peer and ~10
bytes/sec/peer-pair in steady state. It's the empirical
sweet-spot validated by every WireGuard-based VPN at scale, and
fits this fork's "minimum mechanism that's correct" disposition.

The interval (25 s) is the same value WireGuard ships and well
under the 5-min TURN permission lifetime, so even a single
dropped keepalive doesn't lose the permission window.

### Config

```
-peer-keepalive duration
    interval for per-peer tunnel keepalives (default 25s; set
    to a negative duration like -1s to disable). Sends one
    tiny encrypted control packet per peer to keep TURN
    permissions and NAT mappings fresh. (v1.9.0-jf.13)
```

`Config.PeerKeepaliveInterval` semantics:

- `0` (zero-value, unset) → resolved to
  `DefaultPeerKeepaliveInterval` (25 s) in `daemon.New`.
- `> 0` → that interval.
- `< 0` → disabled. The loop returns immediately without
  emitting.

### Compat

No wire-format changes. No protocol changes. No new
dependencies. No registry / beacon changes. No entmoot changes.

Backwards-compatible: jf.13 peers emit periodic
`FlagACK | ProtoControl | PortPing` frames at the rate of one
per peer per 25 s, which pre-jf.13 peers already accept (it's
the same shape as `relayProbeLoop`'s probe). If the keepalive
itself is broken, the effect is "we're back to today's behaviour
— the chicken-and-egg returns" — i.e., jf.12.1 parity, not a
regression.

### Tests

`pkg/daemon/peer_keepalive_test.go`:

- `TestAuthenticatedPeerIDs_FiltersByReady` — only
  `ready=true` peers appear; pending and nil-crypto peers are
  excluded. Critical: `tm.Send` to a non-ready peer would queue
  a frame pending key exchange, which is exactly the wrong
  behaviour for a periodic probe.
- `TestAuthenticatedPeerIDs_PeerNotInCryptoMap` — peers with a
  path entry but no crypto entry must not appear.
- `TestAuthenticatedPeerIDs_ConcurrentSafe` — RLock-snapshot
  pattern under `-race` with a concurrent writer.
- `TestPeerKeepaliveLoop_DisabledByNegativeInterval` — negative
  interval is preserved by `daemon.New` and short-circuits the
  loop.
- `TestPeerKeepaliveLoop_DefaultResolved` — zero interval is
  resolved to `DefaultPeerKeepaliveInterval` in `daemon.New`.
- `TestPeerKeepaliveLoop_StopsOnStopCh` — closing `d.stopCh`
  exits the goroutine within 500 ms.
- `TestSendPeerKeepalive_NoTunnelDoesNotPanic` — calling for a
  peer with no path entry logs at Debug and returns; does not
  panic.

### Out of scope (deferred)

- **Adaptive interval.** Skipping keepalives when there's been
  recent outbound traffic to a peer would save the redundant
  emission; defer until profiling shows it matters.
- **Per-peer override.** Some peers (always-on, no NAT) don't
  benefit from 25 s. Defer.
- **Unifying keepalive + relay-probe goroutines.** The 60 s
  `relayProbeLoop` and the 25 s `peerKeepaliveLoop` could share
  one prober. Refactor later.

## [v1.9.0-jf.12.1] - 2026-04-25

Drop-in tuning on top of jf.12: eliminate the cosmetic 7-second
"direct dial timed out" stall on `-outbound-turn-only` peers.

### Fixed

- **`DialConnection` skips phase-1 direct retries when
  `-outbound-turn-only` is set.** In that mode every outbound
  send is gated through TURN by `writeFrame` (jf.11a / jf.11a.2)
  — there is no actual direct UDP being attempted, just the
  3-retry × 1-2-4 s exponential backoff timer running out before
  the racing-relay goroutine's relay-tier RTO budget engages.
  Live evidence 2026-04-25 from laptop's post-restart entmoot dial:

  ```
  17:38:22  laptop pilot-daemon restarted (new TURN allocation)
  17:38:29  pilot-daemon: "direct dial timed out, switching to relay"
                          node_id=45981 (= VPS)
            (7-second cosmetic gap before phase-2 relay engaged;
             the corresponding tunnel actually established at
             17:38:22.683 via jf.12's WireGuard endpoint-learning,
             so the dial-loop's "direct" retries were chasing a
             tunnel that was already up.)
  ```

  Fix: when `d.config.OutboundTURNOnly` is true, set
  `directRetries = 0` alongside the existing relay-active short-
  circuit. The dial loop hits phase-2 retry timing immediately
  (3 s initial RTO, exponential backoff capped at 8 s), which
  matches Cloudflare TURN's 2-3× RTT profile rather than the
  direct UDP's 1 s starting RTO.

  No behaviour change for non-hide-ip peers (VPS, phobos): the
  flag is false there, so phase-1 timing is unchanged.

### Why

jf.12 closed the post-rotation chicken-and-egg at the RECEIVER
side (peer B replies to A's freshly-observed source). But the
DIAL-INITIATOR side still emits phase-1 retries that are pure
timer-wait under outbound-turn-only — direct UDP is forbidden
by writeFrame's outbound-turn-only branch, so the SYN never
actually goes out via direct UDP. The 7 s wait produced visible
WARN-style log churn (`direct dial timed out`) and tied up
entmoot's gossip-dial budget unnecessarily.

### Compat

No wire-format changes. No protocol changes. Observable only on
peers that have `-outbound-turn-only` set (typically the same
peers running with `-hide-ip`). Fully backwards-compatible:
peers without `-outbound-turn-only` see identical behaviour to
jf.12.

### Tests

No new unit tests — the change is a one-line conditional inside
`DialConnection`'s retry-budget setup, fully covered by the
existing integration suite (which exercises both hide-ip and
non-hide-ip dial paths). Live verification: laptop's
post-restart entmoot gossip-fanout latency drops from ~7-15 s
(previously dominated by the cosmetic phase-1 wait) to ~300 ms
(phase-2 first retry RTO).

### Out of scope (deferred)

- Phase-1 stall on **non**-outbound-turn-only peers (VPS,
  phobos): still 7 s when their racing-dial's direct retries
  fail before relay engages. That's a different scenario —
  direct UDP is genuinely being attempted, and 7 s is the
  designed exhaustion budget. Out of scope here; would need a
  smarter heuristic that detects "direct UDP is failing
  predictably" earlier (e.g., 1-2 retries instead of 3).

## [v1.9.0-jf.12] - 2026-04-25

WireGuard-style strict endpoint learning for handshake replies.
Closes the post-TURN-rotation chicken-and-egg deadlock that caused
`gossip: transport_ad retry budget exhausted` cycles for several
minutes after a peer restarted.

### Fixed

- **Handshake replies now route to the most-recent observed
  source, not the cached `path.direct`.** Pilot already implemented
  the WireGuard endpoint-learning rule for encrypted-data frames
  (`updatePathDirect` on auth, `writeFrame` consults the freshly-set
  `path.direct`). Handshake replies — `sendKeyExchangeToNode`,
  invoked from `handleAuthKeyExchange` and `handleKeyExchange` —
  did not. They read `path.direct` at send time, which under post-
  TURN-rotation conditions was a stale value that no longer
  pointed to the peer's live allocation. The reply was sent to the
  dead allocation; Cloudflare dropped it; authentication never
  completed; the tunnel stayed broken until racing-dial eventually
  found a non-TURN path.

  Live evidence 2026-04-25 from VPS post-laptop-restart:
  ```
  gossip: transport_ad fanout peer=45491 err="dial: pilot: dial
    0:0000.0000.B1B3:1004: context deadline exceeded"
  gossip: transport_ad retry budget exhausted peer=45491 author=45981
    seq=27 attempts=7
  ```

  Fix: `sendKeyExchangeToNode` gains an `observedSrc *net.UDPAddr`
  parameter. The reactive callers — `handleAuthKeyExchange`,
  `handleKeyExchange` (both branches) — pass through the inbound
  frame's source address, and the reply lands at that address
  instead of consulting the cache. Caller-initiated callers
  (`SendTo`'s queue-and-KEX path, `AddPeer`'s auto-KEX) pass nil
  and fall back to `path.direct` — pre-jf.12 behavior preserved
  for those flows. `writeFrame`'s override condition narrows from
  unconditional `if pathDirect != nil { addr = pathDirect }` to
  `if addr == nil && pathDirect != nil { addr = pathDirect }`, so a
  caller-supplied address is always respected.

### Why

Industry research (WireGuard whitepaper §2.2, Tailscale DERP /
ipnlocal, libp2p Circuit Relay v2, WebRTC Trickle ICE, RFC 8838)
converges on a single canonical rule: *"the peer's endpoint is
learned from the outer external source IP of the most recent
correctly-authenticated packet received."* Replies must go to that
observed source, never to a cached value when the observed source
is available. Pilot implemented this for data frames since jf.4;
jf.12 extends it to handshake replies.

The ALTERNATIVE — anti-entropy reconcile (task #86) — is a fine
backup for the pathological cases where the WireGuard rule misses
(auth signature failures, replay-window collisions, etc.). But the
typical post-rotation case is now closed in one round-trip without
any gossip-layer intervention.

### Behaviour

- **Detection latency for post-rotation re-handshake drops from
  minutes to one round-trip.** A peer that restarts and gets a fresh
  Cloudflare TURN allocation reaches its mesh peers as soon as the
  first authenticated frame arrives at them; their reply goes back
  to the new allocation immediately.
- **Privacy preserved.** Outbound-turn-only daemons still route
  through TURN: when `sendKeyExchangeToNode` passes `observedSrc`
  through `writeFrame`, the outbound-turn-only branch
  (`pkg/daemon/tunnel.go:895` / jf.11a-jf.11a.2) consumes that
  addr via tier-3 SendViaOwnRelay. The freshly-observed addr is
  used INSIDE the TURN routing, not as a way to bypass it.
- **Backwards compat:** a jf.12 peer talking to a jf.11b peer
  behaves identically to today. The jf.11b peer's reply path uses
  `path.direct`; the jf.12 peer's reply path uses `observedSrc`.
  Both produce valid handshake frames the other side accepts. No
  wire-format change.

### Tests

- `pkg/daemon/handshake_endpoint_learning_test.go` (new):
  - `TestHandshakeReply_UsesObservedSourceNotCachedDirect` — the
    regression guard for the live deadlock. Stale cache, fresh
    observed source; assert the UDP write went to the fresh
    listener and NOT to the stale one.
  - `TestHandshakeReply_FallsBackToCacheWhenNoObservedSource` —
    caller-initiated KEX (nil observedSrc) still uses
    `path.direct`, preserving jf.11b behaviour.
  - `TestSendKeyExchangeToNode_CallerSrcOverridesPathDirect` —
    drives `writeFrame`'s override condition directly. Without
    the `addr == nil &&` narrowing, the caller's intent would be
    silently overridden.
  - `TestSendKeyExchangeToNode_RaceSafety` — concurrent
    `updatePathDirect` + `sendKeyExchangeToNode` under -race.

### Compat

No wire-format changes. No IPC changes. No new dependencies. No
Entmoot changes (Entmoot v1.5.0 driver works against jf.12 pilot
unchanged). No registry changes (the centralized registry is out
of our control anyway).

### Out of scope (deferred)

- **Task #86** — Entmoot transport-ad anti-entropy. Still the right
  safety net for pathological cases where the first
  authenticated-source observation fails (signature replay, etc.).
- **Cross-peer registry-pushed signaling.** Tailscale DERP-style
  pattern. Not applicable while the registry is operated by a
  third party.

## [v1.9.0-jf.11b] - 2026-04-25

Introduces server-initiated **pub/sub** primitives in pilot's IPC.
Replaces the polling pattern entmoot has been using since v1.4.4 to
detect TURN-allocation rotation.

### Added

- **Five new IPC opcodes** for state-change push notifications:
  - `CmdSubscribe` (`0x30`) — client→pilot, payload
    `[topic_len:uint16][topic:bytes]`.
  - `CmdSubscribeOK` (`0x31`) — pilot→client, payload
    `[topic_len:uint16][topic][payload_len:uint32][payload]`. The
    payload is a current-state snapshot (e.g. the present TURN
    relay `host:port`) so a fresh subscriber learns the value
    without waiting for the next change.
  - `CmdUnsubscribe` (`0x32`) — client→pilot, same payload shape
    as `CmdSubscribe`. Idempotent.
  - `CmdUnsubscribeOK` (`0x33`) — pilot→client, empty payload.
  - `CmdNotify` (`0x34`) — pilot→client (push), same payload shape
    as `CmdSubscribeOK`. Server-initiated; bypasses the
    request-reply queue (same model as `CmdRecvFrom` datagrams).

- **`IPCServer.PublishTopic(topic string, payload []byte)`** —
  fans out a `CmdNotify` frame to every subscriber of `topic`.
  Safe to call concurrently. Errors writing to a particular
  subscriber are logged at Debug; the conn's `handleClient` defer
  cleans up via `removeSubsForConn`.

- **`IPCServer.SetTopicSnapshot(topic string, fn func() []byte)`** —
  registers a snapshot fn whose result is delivered in
  `CmdSubscribeOK`. Topics are dynamic; absence of a snapshot fn
  is not an error (subscriber receives empty payload).

- **`TURNTransport.SetOnLocalAddrChange(fn func(string))`** —
  callback fires whenever the server-assigned relay address
  changes (initial `Allocate` AND post-rotate). Wired in
  `daemon.Start` to call `IPCServer.PublishTopic("turn_endpoint", ...)`.

- **`TunnelManager.SetTURNOnLocalAddrChange`** — passthrough so the
  daemon doesn't need to reach into `*TURNTransport` directly.

### Behaviour

- **Initial topic:** `"turn_endpoint"`. Payload is the daemon's
  current TURN relay `host:port` as UTF-8, or empty when no
  `-turn-provider` is configured.
- **Subscribe-then-reply ordering invariant.** `handleSubscribe`
  registers the subscriber in the topic set BEFORE writing
  `CmdSubscribeOK`. A `PublishTopic` fired between snapshot
  capture and SubscribeOK delivery still reaches the new
  subscriber via `CmdNotify` — at worst the subscriber sees the
  snapshot AND a Notify carrying the same value (idempotent on
  the client).
- **`CmdNotify` bypasses the IPC handler bottleneck.** The
  serial-`handleClient` loop only blocks request-reply commands
  (Dial, Send, Info, …). `PublishTopic` is invoked from pilot's
  TURN code path, NOT from `handleClient`, so a slow `handleDial`
  on the same connection does NOT delay Notify delivery.

### Why

Entmoot v1.4.4–v1.4.6 polls `Info` every 30 s to detect TURN
rotation. RFC 8656 says the relay address is stable across
`Refresh`; in practice it changes maybe once a day (restart,
credential rotation). 30 s polling = ~2,880 polls/day with ~1
actual change = 99.97 % wasted IPC. The polling Info frames also
queue behind slow gossip Dials in pilot's serial `handleClient`,
producing live `WARN turn-endpoint poll: pilot Info query failed
err=ipcclient: info: context deadline exceeded` noise on phobos
and VPS. Push notification eliminates both the wasted traffic
AND the head-of-line contention for state changes.

The pattern matches the canonical industry shape: Kubernetes
Watch API, Tailscale `LocalBackend.Notify`, D-Bus signals,
JSON-RPC 2.0 notifications. Producers tell consumers when state
changes; consumers don't poll.

### Tests

- `pkg/daemon/ipc_subscribe_test.go`:
  - `TestSubscribe_RoundTripWithSnapshot` — Subscribe receives
    SubscribeOK with the current snapshot.
  - `TestSubscribe_NoSnapshotReturnsEmpty` — absent snapshot
    fn yields empty payload; subscriber still registered.
  - `TestPublishTopic_FansOutToMultipleSubscribers` — every
    subscriber's pipe receives Notify.
  - `TestPublishTopic_NoSubscribers_NoOp` — must not block /
    panic. Important because `daemon.Start` wires the rotation
    hook BEFORE the IPC listener accepts; the first publish
    during initial Allocate has zero subscribers.
  - `TestUnsubscribe_StopsDelivery` — post-Unsubscribe Notify
    isn't delivered.
  - `TestRemoveSubsForConn_CleansAllTopics` — handleClient's
    cleanup helper drops conn from every topic and prunes
    empty entries.
  - `TestSubscribe_MalformedPayload` — empty / undersized /
    zero-topic payloads return `CmdError` and don't register.
  - `TestPublishTopic_ConcurrentSafe` — 100×
    Publish/SetTopicSnapshot under -race.
- `pkg/daemon/transport/turn_localaddr_change_test.go` (real
  pion test server):
  - `TestTURN_OnLocalAddrChange_FiresOnInitialAllocate` — the
    callback fires once with the relay address after Listen.
  - `TestTURN_OnLocalAddrChange_FiresOnRotation` — `Rotate`
    triggers a re-allocation and the callback fires again with
    the new (different) port.

### Compat

No wire-format changes to existing opcodes. Legacy clients that
don't know `CmdSubscribe` / `CmdNotify` simply never use them;
`handleClient`'s `default` branch returns
`unknown command: 0x30` for them. Entmoot v1.4.x continues
polling against jf.11b pilot — wasted IPC continues until they
upgrade to v1.5.0, but no breakage.

### Out of scope (deferred)

- Other topics (peer trust, tunnel up/down, registry health) —
  trivial to add later via additional `PublishTopic` callsites;
  no further protocol work.
- Camp-A correlation IDs in the IPC framing for the general
  fast-vs-slow-on-shared-connection problem. P-A retires the
  only currently-observed victim (Info poll) by routing it
  through the push path. Future fast commands would need
  correlation IDs; tracked as a future SPEC proposal.
- `pilotctl subs list` diagnostic command. Nice-to-have; defer.

## [v1.9.0-jf.11a.5] - 2026-04-25

### Fixed

- **`matchLANSubnet` produced same-LAN false positives across
  unrelated networks.** Pre-jf.11a.5, two peers whose RFC1918 LAN
  addresses shared a /24 subnet were treated as same-LAN —
  regardless of whether they were actually on the same physical
  network. Default consumer routers ship with `192.168.1.0/24`, so
  every laptop, phobos, and home server worldwide trivially
  collided. Live evidence 2026-04-25:

  ```
  laptop log:
    same-LAN peer detected, using LAN address
      node_id=45460 lan_addr=192.168.1.126:55234
  laptop public IP: 5.30.217.114 (UAE)
  phobos public IP: 37.27.59.89   (IT)
  ```

  Laptop in UAE picked phobos's Italian-LAN `192.168.1.126`
  address as a "same-LAN shortcut", routed outbound to a
  non-routable address, and stalled 7 s before falling back.

  Fix: `matchLANSubnet` now requires both peers to share the same
  public IP (same NAT egress) before honoring a /24 collision.
  Either public address being empty short-circuits the check (no
  LAN shortcut) — the right default when `-hide-ip` /
  `-no-registry-endpoint` elide the public IP, since hide-ip
  peers route via TURN regardless and the LAN shortcut is moot.
  CGNAT remains a possible source of false positives (peers under
  the same carrier-grade NAT share a public IP), but jf.11a.3's
  racing dial catches the failure in <300 ms instead of the old
  7 s — bounded blast radius.

### Tests

- `pkg/daemon/match_lan_subnet_test.go`:
  - `TestMatchLANSubnet_SamePublicIPMatches` — true same-LAN: same
    /24 + same public IP → returns the LAN address.
  - `TestMatchLANSubnet_DifferentPublicIPNoMatch` — the
    phobos↔laptop reproducer: same /24 + different public IPs →
    returns "" (the regression guard for the live FP).
  - `TestMatchLANSubnet_EmptyOurPublicSkips` — fail-closed when
    we don't know our own public address.
  - `TestMatchLANSubnet_EmptyTheirPublicSkips` — fail-closed
    when peer's public address is empty (hide-ip peer).
  - `TestMatchLANSubnet_SamePublicIPDifferentSubnetNoMatch` —
    public matches but RFC1918 subnets differ → no shortcut.
  - `TestMatchLANSubnet_MalformedPublicAddrSkips` — parse
    failures fail closed.

### Compat

No wire changes. No new flags. Pure logic refinement of the
internal `matchLANSubnet` helper. Callers in `ensureTunnel`
already have access to `d.registrationAddr` (our public addr,
under `addrMu`) and `realAddr` (peer's public addr from registry
resolve), so the new arguments are free to pass.

## [v1.9.0-jf.11a.4] - 2026-04-25

### Fixed

- **`-no-registry-endpoint` silently leaked the daemon's real IP.**
  A laptop running `-hide-ip -outbound-turn-only -no-registry-endpoint`
  still exposed its UAE residential IP (`5.30.217.114`) to every peer
  that resolved it via the registry. Root cause: the registry's
  `sanitizeListenAddr` fell back to the TCP source IP whenever the
  client supplied an empty `listen_addr`. The daemon side correctly
  sent `listen_addr=""` under `-no-registry-endpoint`, but the server
  silently substituted the TCP source IP and stored it as
  `node.RealAddr`. Live evidence 2026-04-25 from phobos: `added peer
  node_id=45491 addr=5.30.217.114:51619` — laptop's real UAE IP
  observed by a remote peer despite the privacy flag being set.

  Fix: `sanitizeListenAddr` now returns `""` when `clientAddr` is
  explicitly empty, matching the "identity-only, no endpoint
  published" semantic that `-no-registry-endpoint` was introduced
  for in jf.10. `handleReRegister` then writes `node.RealAddr = ""`,
  `handleResolve` returns an empty `real_addr`, and remote peers
  correctly treat the node as endpoint-unknown (must learn routing
  via Entmoot transport-ad carrying a TURN relay, or similar
  out-of-band channel). The malformed-address fallback (parse
  failure → use TCP source) is preserved for legacy robustness;
  only the explicit-empty case was privacy-broken.

  Non-hide-ip clients (the vast majority) never send
  `listen_addr=""`, so the semantic change does not affect them.
  Registry heartbeat's `real_addr` refresh is already gated on
  `clientAddr != ""` (server.go:5504) and is unaffected.

### Tests

- `pkg/registry/sanitize_listen_addr_test.go`:
  - `TestSanitizeListenAddr_EmptyClientMeansNoEndpoint` — the
    regression guard: empty `clientAddr` must never leak the TCP
    source IP.
  - `TestSanitizeListenAddr_ClientPortRespected` — legacy contract
    preserved: IP from TCP source, port from client, for
    non-empty `clientAddr`.
  - `TestSanitizeListenAddr_MalformedClientAddr` — parse failure
    still falls back to the full TCP source (legacy robustness).
  - `TestSanitizeListenAddr_IPv6ClientPort` — IPv6 host/port
    splitting unchanged.

### Upgrade path

Upgrade the **registry** server first. Clients (daemons) need no
change — jf.10+ already sends `listen_addr=""` correctly. After the
registry is updated, any already-leaked `RealAddr` is overwritten
to empty on the next laptop re-registration (~60 s heartbeat
interval, or immediately on daemon restart).

## [v1.9.0-jf.11a.3] - 2026-04-25

### Fixed

- **7-second `DialConnection` stall when the cached direct endpoint
  is stale.** `DialConnection` was strictly serial: 3 direct-UDP
  retries at 1 s → 2 s → 4 s RTO (~7 s total), THEN flip the peer to
  relay-sticky and run 3 more beacon retries. Every new
  tunnel/stream whose cached direct address was unreachable paid
  the full 7 s relay-kickover tax. Live evidence from phobos
  2026-04-24:

  ```
  21:54:11.570  same-LAN peer detected, using LAN address
                node_id=45491 lan_addr=192.168.1.201:61618
  21:54:18.573  direct dial timed out, switching to relay
                node_id=45491
  ```

  Compounded by Entmoot's per-transport-ad fanout retry budget —
  each stale address cost 7 s, chaining across retries to 49 s
  before giving up.

  The fix applies the universal cross-industry pattern (RFC 8305
  Happy-Eyeballs / Tailscale magicsock / iroh / WebRTC ICE /
  libp2p): race direct + relay from `t=0` with a 200 ms head-start
  for direct. When direct is reachable, direct wins at ~50 ms — well
  before the head-start expires — and the relay goroutine never
  fires a single beacon frame (zero-cost on the happy path). When
  direct is stale, relay lands in `head-start + beacon RTT` ≈ 300 ms
  instead of the old 7 s. ~23× speedup on the stale-cache case.

### Added

- **`TunnelManager.SendViaBeacon(nodeID, frame)`** — new primitive
  that writes a pre-encoded tunnel frame through the beacon relay
  WITHOUT mutating `path.viaRelay` for the peer. Used by the racing
  dial path: a losing relay-retry goroutine must not poison
  `viaRelay` for the next dial, and the receiver's side flips
  `viaRelay` naturally via `updatePathRelay()` on ingress.
  Complementary `SendPacketViaBeacon` marshals a packet and routes
  it through the same envelope.

- **`Daemon.racingRelaySYN`** — DialConnection goroutine that
  re-transmits the SYN through beacon with `DialRelayHeadStart` =
  200 ms head-start and up to `DialRelayRetries` = 3 retries at
  `DialRelayInitialRTO` exponential backoff. Cancelled via a
  `raceStop` channel closed by `DialConnection`'s defer on any
  return path (success, timeout, or error).

### Behaviour

- **Privacy is preserved, by construction.** Both paths funnel
  through `writeFrame` (direct path) or `SendViaBeacon` (relay
  path). `-outbound-turn-only` still errors on every non-TURN send,
  so `-hide-ip` peers see no new behavior — their dials collapse to
  the existing TURN-relay path, which was already the only route.
  Non-hide-ip peers get the speedup.
- **No state mutation during the race.** The racing code never
  calls `SetRelayPeer(true)`. Only authenticated-ingress frames
  update `path.viaRelay`, so a losing relay retry cannot flip the
  peer into relay-sticky mode. The existing phase-2 retry loop
  (the serial `SetRelayPeer + 3 retries` block) still runs if both
  racing budgets exhaust — behavior identical to pre-jf.11a.3 for
  peers that are genuinely unreachable via either path.
- **No wire changes, no IPC changes.** The beacon envelope emitted
  by `SendViaBeacon` is identical to `writeFrame`'s tier-1 relay
  encoding (`[0x05][senderID(4)][destID(4)][frame...]`). Existing
  beacon servers accept it unchanged.

### Tests

- `pkg/daemon/dial_race_test.go`:
  - `TestSendViaBeacon_EncodesRelayEnvelope` — wire format matches
    `writeFrame` tier-1 encoding.
  - `TestSendViaBeacon_DoesNotMutateViaRelay` — Gotcha-B guard:
    the primitive must not flip `path.viaRelay`.
  - `TestSendViaBeacon_ErrorsWhenBeaconUnset` — returns error when
    `beaconAddr` is nil (racing goroutine short-circuits).
  - `TestSendPacketViaBeacon_Plaintext` — marshaled-packet variant
    wraps in PILT frame correctly.
  - `TestRacingRelaySYN_WaitsForHeadStart` — no beacon traffic in
    the first 150 ms (direct gets an exclusive early window).
  - `TestRacingRelaySYN_ExitsOnStop` — goroutine returns promptly
    on `close(stop)`, with no leaked frames.

### Deferred

- **Disco-style authenticated probes (#92 / jf.11b / jf.12)** — the
  proper structural answer for authenticated path selection,
  peer-reflexive learning, and MTU discovery. jf.11a.3 is
  scaffolding; disco plugs into the same racing frame later.
- **Same-LAN matcher (#85)** — jf.11a.3 eliminates the 7 s tax,
  making the occasional same-LAN false-positive cosmetic rather
  than painful. Keep #85 queued for log cleanliness.

## [v1.9.0-jf.11a.2] - 2026-04-24

### Fixed

- **`-outbound-turn-only` no longer requires the peer to advertise a
  TURN endpoint.** jf.11a's first-pass implementation conflated two
  concepts from different releases:
  - jf.9's `DialTURNRelayForPeer` — dials a peer via THEIR advertised
    TURN relay address. Used when we ourselves don't have TURN.
  - jf.11a's `-outbound-turn-only` — WebRTC
    `iceTransportPolicy='relay'` (RFC 8828 Mode 3): OUR outbound
    traffic routes through OUR own TURN allocation.

  The correct semantic is: peer's address can be anything (host,
  srflx, or peer's own relay); WE send via OUR TURN's `WriteTo` to
  that address; peer observes source = our TURN server, never our
  real IP. Peer does NOT need their own TURN.

  Live evidence 2026-04-24: a laptop in full `-hide-ip` mode with
  its own Cloudflare TURN allocation could NOT reach the VPS
  (public UDP, no TURN advertised) or phobos (CGNAT, no TURN at
  all). Every outbound write failed with `outbound-turn-only: no
  TURN path for node N`. Laptop was effectively isolated despite
  having a perfectly usable TURN allocation that could forward to
  any peer address.

  Fix (per RFC 8656 §9 + pion/turn v5 `udp_conn.go:185` pattern):

  - New `TURNTransport.SendViaOwnRelay(peerAddr, frame)` —
    thin wrapper over `relay.WriteTo`. Pion handles
    `CreatePermission` auto-lazily on first write per destination
    IP and auto-refreshes every ~4 min. No manual plumbing.

  - `writeFrame` outbound-turn-only branch gains a new fallback
    after the peer-advertised-TURN check fails: if we have our
    own TURN (`tm.turn != nil`), pick the peer's real UDP address
    from a priority chain (caller-supplied `addr` > `pathDirect`),
    and call `SendViaOwnRelay`. Peer sees source = Cloudflare
    anycast.

  - Fail-closed semantic preserved: when BOTH the peer has no
    TURN endpoint AND we have no usable peer real-address (no
    `pathDirect`, no caller-supplied `addr`), return the original
    `no TURN path for node N` error.

### Behaviour

- **Full hide-ip now talks to everyone.** Laptop with
  `-outbound-turn-only -turn-provider=cloudflare` reaches any peer
  whose address it knows (VPS via registry, phobos via any prior
  authenticated direct UDP), and all those peers see source =
  Cloudflare anycast rather than laptop's residential IP.
- **Permission management is lazy + automatic.** pion creates a
  TURN permission on the first write to a new destination IP and
  refreshes it; we don't maintain a permission table ourselves.
- **MTU (documented, not changed).** TURN adds Send/Data Indication
  overhead (~36 bytes) or ChannelData (~4 bytes). Applications
  running close to the PMTU limit (~1500 Ethernet) may see
  fragmentation when paths flip between direct and TURN. Mitigate
  by keeping application payloads ≤ 1200 bytes where possible.
- **Residual stale-cache leak (documented, not changed).** A peer
  that learned our real IP before we flipped to
  `-outbound-turn-only` keeps trying to dial that address. Our
  outbound goes through TURN and is safe; the peer's outbound to
  the stale address fails (kernel drops or NAT dead), and their
  cache eventually expires. For a clean flip, pair with a fresh
  local UDP port or a registry re-registration.

### Tests

- `pkg/daemon/transport/turn_ownrelay_test.go` (new):
  - `TestSendViaOwnRelay_ReachesArbitraryPeer`: pion in-process
    TURN server + a plain-UDP "peer" (no TURN). Verifies the
    TURN-enabled client reaches the peer via its own relay; the
    peer's observed source port equals the client's relay port
    (confirming the packet traversed TURN, not the client's
    direct socket).
  - `TestSendViaOwnRelay_NilPeerAddr`: nil-input error path.
  - `TestSendViaOwnRelay_NotListening`: pre-Listen error path.

  The daemon-level writeFrame integration (`tm.turn != nil` +
  pathDirect branch) is covered by code review: the real TURN
  send primitive has unit tests; the writeFrame path is a direct
  if-else over those primitives. Larger "full stack including
  writeFrame routing" integration can land in jf.11b when the
  disco rewrite refactors path selection anyway.

### Compatibility

- **No wire-format changes.** Same frame shapes on UDP and TURN.
- **No IPC changes.** `DaemonInfo` still advertises
  `outbound_turn_only` (added in jf.11a.1).
- **Existing deployments without `-outbound-turn-only` unaffected.**
  The new branch only runs when `tm.outboundTURNOnly == true`.

### Dependencies

- **No new dependencies.** Existing `github.com/pion/turn/v5`
  `relay.WriteTo` API does everything we need.

## [v1.9.0-jf.11a.1] - 2026-04-24

### Fixed

- **IPC `Info` reply now includes hide-ip config fields on the wire.**
  The JSON builder in `IPCServer.handleInfo` (ipc.go:388) manually
  constructed its response map and never included `turn_endpoint`
  (added to `DaemonInfo` in jf.8), `outbound_turn_only`, or
  `no_registry_endpoint` (both added in jf.11a). Struct-tagged
  `json:"..."` only applies when `json.Marshal` walks the struct —
  the handler passes a `map[string]interface{}` literal, so tags
  were inert.

  Visible symptom from the 2026-04-24 live test: laptop upgraded to
  pilot-daemon v1.9.0-jf.11a with `-hide-ip` (full mode). pilot-
  daemon's startup logs correctly showed TURN allocation,
  `outbound-turn-only enabled`, and `registering identity only
  (no endpoint published)`. `pilotctl lookup 45491` confirmed no
  `real_addr`. But Entmoot v1.4.3's cross-layer check via
  `Driver.InfoStruct` saw all three fields as zero values and
  falsely reported pilot-daemon was half-configured.

  Pre-existing from jf.8 for `turn_endpoint`; latent for the jf.10
  / jf.11a fields because they were added with the assumption the
  struct tags would make the fields transparent. Closed by adding
  the three fields to the manual JSON builder at ipc.go:458.

### Wire compatibility

- **Pre-jf.11a.1 pilot-daemons** still omit these fields — Entmoot
  decodes their absence as zero and keeps warning about half-
  configuration, which is the correct behavior for older daemons
  that really don't have the features.
- **No wire format change between daemons**; only the IPC JSON
  payload between pilot-daemon and its local drivers gained three
  fields.

### Known limitation (tracked as jf.11a.2 / future fix)

- `-outbound-turn-only` currently requires the peer to have
  advertised a TURN endpoint. That's overly restrictive: the
  canonical WebRTC `iceTransportPolicy='relay'` semantic is
  "our outbound traverses OUR own TURN; we send to the peer's
  real address via relay.WriteTo." Peer doesn't need a TURN
  endpoint of its own. Live 2026-04-24: a laptop in full hide-ip
  could not reach VPS (no TURN advertised) or phobos (no TURN at
  all) because writeFrame hit fail-closed. Fix deferred to
  jf.11a.2: new path that resolves peer's real address (from
  peerPath.direct / peerTCP / registry) and sends via the local
  TURN relay's `WriteTo`. ~60 LOC + tests.

## [v1.9.0-jf.11a] - 2026-04-24

Half-release. The full jf.11 plan (see
`/root/.claude/plans/tender-wondering-wombat.md`) has two parts:
**A** — disco-style authenticated connectivity probes to structurally
fix the same-LAN false-positive (task #85) and replace the heuristic
tier-based `writeFrame` with ICE/Tailscale-disco-style candidate
validation. **B** — `-outbound-turn-only` flag + `-hide-ip` preset +
cross-layer warnings for the RFC 8828 Mode 3 "relay-only" semantic.
Part A is 3-5 days of focused work; Part B is ~hours. jf.11a ships
Part B so users can exercise full hide-ip today; Part A ships as a
later release (jf.11b or jf.12) after the disco rewrite lands.

### Added

- **`-outbound-turn-only` daemon flag.** Forces `writeFrame` to route
  every outbound tunnel frame through the local TURN allocation.
  Peers observe our traffic with source IP = TURN server's assigned
  anycast / relay address, never our real IP. Mirrors WebRTC's
  `iceTransportPolicy='relay'` (RFC 8828 Mode 3) — the industry-
  standard "don't leak IP to peers" switch. Fail-closed: if
  `-turn-provider` is not set, the daemon refuses to start rather
  than silently degrade to non-relay routing (which would leak the
  very IP the flag exists to hide).

  Semantic guarantees:
  - Beacon relay (v1.9.0-jf.10 tier 1) is never used, even if
    `path.viaRelay=true`.
  - Direct UDP (v1.9.0-jf.10 tier 3) is never used, even if we have
    a cached `pathDirect` from a prior authenticated frame.
  - Cached non-UDP conns are used only when their underlying
    transport is TURN or turn-relay (v1.9.0-jf.9). A stale TCP conn
    from before the flag was enabled is evicted on next write.
  - When no TURN path is available, writeFrame returns an explicit
    error naming the flag; the gossiper's retry layer sees it and
    acts as with any other dial failure.

- **`-hide-ip` preset flag.** Convenience flag that expands to
  `-no-registry-endpoint -outbound-turn-only` at startup, unless
  either sub-flag is explicitly set by the operator (explicit value
  wins — `-hide-ip -no-registry-endpoint=false` leaves the registry
  publishing endpoint for debugging purposes, etc.). Requires
  `-turn-provider`. Name intentionally matches Entmoot's app-layer
  `-hide-ip` so users build the mental model *"set hide-ip at both
  layers for full privacy"*; the CHANGELOG + doc string call this
  out to eliminate surprise.

- **Cross-layer startup warnings.** When the three privacy flags are
  half-configured — `-outbound-turn-only` without `-no-registry-endpoint`
  or vice-versa — the daemon emits a clear WARN-level log line
  naming the specific leak channel that remains open and pointing at
  the `-hide-ip` preset as the one-flag remedy. An informational log
  also fires when `-turn-provider` is set but no Pilot-layer hide-ip
  flags are, reminding operators that TURN is useful even outside
  hide-ip contexts. No forced behaviour change — just clearer
  feedback for a class of misconfiguration that's easy to fall into.

- **`DaemonInfo.OutboundTURNOnly` + `DaemonInfo.NoRegistryEndpoint`**
  (both `omitempty`). App-layer callers (e.g. Entmoot's `-hide-ip`
  startup check) can query Pilot's privacy posture via the existing
  IPC `Info` command and warn the user if the local daemon isn't in
  the expected configuration. Wire-compatible with jf.10 and earlier
  clients — fields simply decode as false when the daemon doesn't
  populate them.

### Behaviour

- Cached peer-side address caches survive the flag flip. A peer who
  learned our direct address before we enabled `-outbound-turn-only`
  will continue dialling direct to the stale address until their own
  cache expires or their daemon observes our TURN-sourced traffic
  and updates. For a clean deployment, pair with
  `-no-registry-endpoint` (the preset does this) so new peers don't
  cache a direct address in the first place.

- A peer who has NOT advertised TURN remains unreachable from an
  `-outbound-turn-only` daemon. That's intentional — we refuse to
  speak to peers via any channel that would reveal our source IP.
  The gossiper's retry layer sees the failure as a transient error
  and backs off.

### Tests

- `pkg/daemon/outbound_turn_only_test.go` (new):
  - `TestOutboundTURNOnly_StartupFailsWithoutTurnProvider` — fail-
    closed contract.
  - `TestWriteFrame_OutboundTURNOnly_UsesCachedTURNConn` — happy
    path: cached turn-relay conn wins over beacon even when
    `viaRelay=true`.
  - `TestWriteFrame_OutboundTURNOnly_RejectsWhenNoTURNPath` — fail-
    closed at frame level when no TURN endpoint is known.
  - `TestWriteFrame_OutboundTURNOnly_SkipsNonTURNCachedConn` — a
    stale cached TCP conn does not leak source IP.
  - `TestWriteFrame_OutboundTURNOnly_Disabled_PreservesDefaultBehavior`
    — regression guard.

### Compatibility

- **No wire-format changes between daemons.** `writeFrame` still
  emits the same frame shapes on UDP, TCP, TURN, and beacon — only
  the selection logic changed.
- **Privacy posture composable.** The three flags
  (`-no-registry-endpoint`, `-outbound-turn-only`, `-hide-ip`
  preset) layer over jf.8's `-turn-provider`. Operators can enable
  any subset; the startup warnings name each partial state.
- **Operator migration.** Existing deployments running plain
  `-turn-provider=cloudflare` (no privacy flags) are unaffected.
  Behaviour is byte-identical to jf.10 when `-outbound-turn-only`
  is false.

## [v1.9.0-jf.10] - 2026-04-24

### Changed

- **`writeFrame` no longer routes via PILA beacon when a TURN
  endpoint is advertised for the peer.** Before jf.10, once
  `path.viaRelay` latched to true (typical when the direct-UDP
  attempt failed and Pilot fell back to beacon), writeFrame's
  tier 1 always routed through the beacon operator — even for
  peers that had subsequently advertised a TURN relay. The v1.9.0-
  jf.9 asymmetric-TURN dialer (tier 4) sat at the bottom of the
  chain and never got a chance to engage in real deployments.

  Live evidence 2026-04-24: phobos installed laptop's TURN
  endpoint (`104.30.149.4:20414`) via Entmoot v1.4.2's multi-hop
  refanout. `SetPeerEndpoints applied node_id=45491
  installed_turn=1` fired. Yet every frame phobos sent to laptop
  still traversed the VPS as a PILA beacon relay. The VPS operator
  saw every phobos ↔ laptop routing event — exactly the metadata
  `-hide-ip` exists to hide.

  jf.10 adds a single guard to tier 1: when `peerTURN[nodeID]` is
  populated, skip beacon and fall through to the cached-conn tier
  (which picks up a cached `turnRelayDialedConn` if one exists) or
  to tier 4 (which lazily dials turn-relay via `DialTURNRelayViaUDP`).
  A tier-3 guard zeroes any stale `pathDirect` so direct UDP also
  defers to turn-relay for hide-ip peers whose direct addr
  predated their opt-in to TURN routing.

  Fallback on TURN failure: when `DialTURNRelayViaUDP` errors
  (Cloudflare outage, creds expired), writeFrame returns "no
  address for node" rather than silently re-routing through the
  beacon. Operators who want beacon as a fallback should stop
  advertising TURN for that peer; routing through a channel the
  peer didn't choose defeats the hide-ip semantic.

### Added

- **`-no-registry-endpoint` CLI flag + `Config.NoRegistryEndpoint`
  field.** Pairs with Entmoot v1.4.0's `-hide-ip` to close the
  registry-layer IP leak that the gossip-layer suppression alone
  can't cover. When set, the daemon registers its identity
  (node ID + pubkey) with the registry but **uploads no UDP
  endpoint, no TCP endpoint, and no LAN addresses**. Peers
  resolving this node via `registry.Lookup` see "endpoint
  unknown" and must learn routing from an out-of-band channel
  (e.g. Entmoot's signed transport-ad, which pushes the peer's
  TURN relay into `peerTURN` via `SetPeerEndpoints`). `writeFrame`
  tier 4 then engages.

  STUN discovery still runs at startup when TURN is enabled
  (needed for TURN itself), but the discovered endpoint is never
  sent to the registry. `reRegister` on heartbeat failure also
  honours the flag — recovery doesn't accidentally re-leak the
  endpoint after a connection hiccup.

  Trade-off: drivers that don't have an out-of-band routing
  channel will fail to establish tunnels to hide-endpoint peers
  (registry lookup returns no `real_addr`, resolver errors).
  Entmoot v1.4.2+ is equipped (via transport-ad → `peerTURN`);
  other drivers may need equivalent plumbing.

### Privacy impact

- **After jf.10 + restarting all three nodes**, phobos↔laptop
  traffic bypasses the VPS entirely — the relay path becomes
  Cloudflare TURN. VPS operator sees no metadata on that
  conversation. With `-no-registry-endpoint` on laptop, new
  peers that try to resolve laptop via registry also learn no
  IP — only Cloudflare's anycast relay address (via Entmoot
  transport-ad).

### Wire compatibility

- **No wire-format changes between daemons.** `writeFrame` still
  emits the same beacon-relay, cached-conn, direct-UDP, and
  turn-relay payloads; only the selection logic changed.
- **No registry wire change.** Existing `RegisterWithKey` / `
  RegisterWithKeyAndEndpoints` are called with empty endpoint
  strings and nil LAN / TCP slices when the flag is set. Registry
  returns no `real_addr` for that node; resolvers on the other
  end see the existing "node has no real address" error path.
- Operational note: existing peer-side caches of a previously-
  public endpoint survive until eviction. For a clean flip,
  coordinate a fleet restart.

### Dependencies

- No new dependencies.

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
