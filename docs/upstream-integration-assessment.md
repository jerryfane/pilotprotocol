# Upstream Integration Assessment

This report summarizes changes made in the parent repository after our fork point and rates how interesting they are for our fork to integrate.

## Comparison

| Item | Ref | Date | Subject |
| --- | --- | --- | --- |
| Our fork head | `3bc202d` | 2026-05-03 | Release Pilot v1.9.0-jf.15.24 |
| Upstream head | `7d728ec` | 2026-05-02 | Add --advertise-addr flag to beacon for MIG public-DNAT deployments |
| Common ancestor | `3f5d3d9` | 2026-02-08 | Change heartbeat interval to every 30 minutes |

Compared range: `main..upstream/main`.

High-level divergence at the time of this report:

| Direction | Commits | Files changed | Insertions | Deletions |
| --- | ---: | ---: | ---: | ---: |
| Upstream-only | 522 | 1,420 | 264,217 | 5,080 |
| Fork-only | 283 | 630 | 166,979 | 5,697 |
| Current tree diff | - | 1,286 | 35,749 | 133,604 |

## Scoring Rubric

| Score | Meaning |
| ---: | --- |
| 5 | High-value; likely worth integrating soon. |
| 4 | Valuable; integrate after conflict and risk review. |
| 3 | Useful but optional, or needs product decision. |
| 2 | Low priority or likely duplicated by our fork. |
| 1 | Probably not worth integrating. |

## Integration Candidates

| Area | Upstream changes | Evidence | Interest | Merge risk | Recommendation | Notes |
| --- | --- | --- | ---: | --- | --- | --- |
| Tunnel reliability and congestion control | Large v1.9.1 reliability push around SACK, duplicate ACK handling, fast recovery, cwnd/ssthresh behavior, RTT/RTO accounting, retransmit timers, zero-window handling, and sequence wraparound. | Commits such as `b423131`, `f2d0a90`, `cc4f243`, `c09b34d`, `795ae62`; many files under `pkg/daemon/*_bug_test.go`. | 5 | High | Port carefully, not as a bulk merge. | This overlaps directly with our stream/TURN work, so it should be reviewed behavior by behavior. The test cases may be as valuable as the fixes. |
| Daemon networking hardening | NAT remap learning, NAT keepalives, blackhole relay flips, cancellable/deduplicated dials, stale connection pruning, accept queue health, webhook shutdown events, and IPC quota fixes. | `8ac2e4e`, `7b16a3c`, `2f4f893`, `44115e7`, `646fa06`, `a259388`, `3178d72`, `550ed9e`. | 5 | High | Cherry-pick or manually port focused fixes. | Treat these as operational reliability fixes. They need reconciliation with our own route policy, relay fallback, and IPC lifecycle changes. |
| Security hardening | SSRF validation for registry URL surfaces, snapshot restore validation, resource exhaustion caps, replay/rekey fixes, unauthenticated crypto-map and relay-peer caps. | `b683706`, `7dccf8c`, `0b8b4e4`, `aecb842`, `315d249`, `d6d84a4`, `d814fee`, `bef0c46`, `e9305e5`. | 5 | Medium | Integrate selectively after checking for existing equivalents. | These are generally high-value and should be prioritized even if feature work is deferred. |
| Registry durability and operations | WAL replay and caps, panic recovery, snapshot validation, dashboard request pulse, runtime maintenance banner, better registry error handling. | `ab14ba5`, `7dccf8c`, `0744410`, `cdf06ff`, `a42cba4`, `4ca2e3b`. | 4 | Medium | Port hardening pieces with tests. | This is less product-dependent than enterprise features and likely useful even if we do not adopt upstream's full registry direction. |
| Beacon and discovery improvements | Multi-beacon discovery, registry-discovered beacon filtering, public DNAT advertise address, dynamic peer discovery for beacon cluster. | `7d728ec`, `30e72f5`, `14c1e05`, `d54e0be`, `66e20b1`. | 4 | Medium | Review after route/rendezvous compatibility check. | Useful for scale and deployment flexibility; conflict risk comes from our rendezvous and relay routing changes. |
| Installer, updater, and release automation | Systemd restart policy, updater binary naming, fsync and size limits, self-exit/restart fixes, anonymous latest-tag resolution, Homebrew and release workflows. | `1ee4db7`, `f5c0a4f`, `e493845`, `723ddba`, `2ce7416`, `9c93127`, `2052ec9`, `202fab1`, `820e492`. | 4 | Medium | Port low-conflict operational fixes first. | Good value because many changes are isolated, but release workflow differences may not match our fork's versioning. |
| Integration and benchmark infrastructure | Docker and k8s integration suites, NAT/policy/webhook/topology tests, chaos helpers, daemon throughput benchmarks, CI timeout stabilization. | `149af97`, `6d0a1e3`, `b17db41`, `1f008be`, `29dd852`, `fc07ea1`, files under `tests/integration/` and `tests/bench_*`. | 4 | Medium | Import tests selectively as regression coverage. | Test infrastructure can guide integration and reveal regressions, but bulk importing may require adapting local harness assumptions. |
| Registry enterprise control plane | RBAC, audit trail, invite lifecycle, key expiry, IDP/JWKS validation, directory sync, provisioning, Prometheus metrics, webhook dispatch and DLQ. | `0e6b504`, `737b36d`, `92bd4d1`, `e77a7e7`, `b4d3a83`, `df8cf66`, `096af50`, `1bce0a5`, `daf2418`. | 3 | High | Product decision before integration. | Large surface area with API, persistence, and CLI implications. Some security fixes inside this area are worth extracting separately. |
| Task submit, service agents, and pubsub | Task execution opt-in, task lifecycle fixes, worker progress events, file-based results, pub/sub fan-out, service-agent examples and CLI result command. | `3349a55`, `b433e5f`, `91ed4f9`, `f5f4f11`, `e400693`, `8f34578`, `9dd4582`, `e9c6778`, `4a33c33`. | 3 | Medium | Compare against our current task and IPC direction. | Useful if we want upstream task semantics; otherwise cherry-pick bug fixes only. |
| SDKs and CGO bindings | Python SDK, Node SDK TypeScript bindings, CGO bindings, packaging, examples, publish workflows, SDK read-size hardening. | `20123c4`, `1b5b18d`, `77a4c95`, `06fc3e6`, paths under `sdk/python`, `sdk/node`, `sdk/cgo`. | 3 | Medium | Review if SDK compatibility or publishing matters now. | Valuable for ecosystem polish, but versioning and binary naming must match our fork. |
| Repo hygiene and governance | CODEOWNERS, security/governance docs, pull request template, dependabot, markdown lint, pre-commit config, SPDX/package hygiene. | `883d1e2`, `247cb2b`, files under `.github/`, `SECURITY.md`, `GOVERNANCE.md`, `.markdownlint*`, `.pre-commit-config.yaml`. | 3 | Low | Copy lightweight files if they fit our process. | Low-risk cleanup, but not urgent compared with reliability and security fixes. |
| Network blueprints and policy governance | Many shipped network configs, policy engine evolution, network provisioning CI, trust decay and open-data network blueprints. | `72f080a`, `06ff160`, `7a3a292`, `bc3a447`, `bb4a95b`, paths under `configs/networks/`. | 2 | Medium | Defer or extract schema/test improvements only. | Interesting product direction, but likely not critical unless we adopt upstream's network marketplace/governance model. |
| Trusted agents and skill injection | Trusted-agents list, node-id auto-accept, pilotctl trusted commands, automatic Pilot skill injection into agent tools. | `698c706`, `57d2dd5`, `2364372`, `f2560a6`, `e8f1035`, paths under `internal/trustedagents` and `pkg/skillinject`. | 2 | Medium | Defer unless this becomes a product goal. | Could create trust and onboarding implications. Some parts may be too opinionated for our fork. |
| Web, docs, blog, and SEO | Large Astro site expansion, many blog posts, plain docs pages, analytics, banners, sitemap, IETF docs and marketing pages. | `72041d9`, `f328e1f`, `5c06a06`, `d702b8d`, `134074a`, many paths under `web/` and `docs/`. | 1 | High | Ignore for now, except specific docs corrections. | Massive conflict surface with little direct runtime value. Cherry-pick only factual docs fixes such as hostname or CLI command corrections. |

## Suggested Integration Order

1. Port security hardening that is isolated and test-backed.
2. Port daemon reliability fixes one small behavior at a time, keeping upstream tests beside each port.
3. Review beacon/discovery and installer/updater fixes for low-conflict operational wins.
4. Import selected integration tests that exercise features we actually keep.
5. Revisit enterprise, task, SDK, and network-blueprint work after deciding product scope.
6. Leave web/blog/SEO out unless the website strategy changes.

## Conflict Notes

A dry merge simulation of `upstream/main` into our `main` reported 267 conflict records:

| Conflict type | Count |
| --- | ---: |
| add/add | 230 |
| content | 35 |
| modify/delete | 1 |
| rename/delete | 1 |

This makes a direct merge impractical. The safer path is targeted ports with tests and short-lived integration branches.

## Source Commands

The report was based on:

```sh
git log --format='%h %ad %s' --date=short main..upstream/main
git diff --name-only main...upstream/main
git diff --dirstat=files,0 main...upstream/main
git merge-tree --write-tree --name-only main upstream/main
```
