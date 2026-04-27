package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func (d *Daemon) sendRST(orig *protocol.Packet) {
	rst := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagRST,
		Protocol: protocol.ProtoStream,
		Src:      orig.Dst,
		Dst:      orig.Src,
		SrcPort:  orig.DstPort,
		DstPort:  orig.SrcPort,
	}
	d.tunnels.Send(orig.Src.Node, rst)
}

func (d *Daemon) queueAcceptedStream(conn *Connection, orig *protocol.Packet) bool {
	conn.Mu.Lock()
	alreadyQueued := !conn.AcceptQueuedAt.IsZero()
	localPort := conn.LocalPort
	remoteAddr := conn.RemoteAddr
	conn.Mu.Unlock()
	if alreadyQueued {
		return true
	}

	ln := d.ports.GetListener(localPort)
	if ln == nil {
		d.traceStream("accept.listener_missing", conn)
		d.abortConnection(conn)
		if orig != nil {
			d.sendRST(orig)
		}
		return false
	}

	select {
	case ln.AcceptCh <- conn:
		d.markConnAcceptQueued(conn)
		return true
	default:
		slog.Warn("accept queue full after stream established", "port", localPort, "src_addr", remoteAddr)
		d.traceStream("accept.full", conn)
		d.setConnState(conn, StateClosed, "accept queue full")
		d.removeConnection(conn, "accept queue full")
		if orig != nil {
			d.sendRST(orig)
		}
		return false
	}
}

// DialConnection initiates a connection to a remote address:port.
func (d *Daemon) DialConnection(dstAddr protocol.Addr, dstPort uint16) (*Connection, error) {
	// Reject self-dials before touching policy or allocating a
	// Connection. ensureTunnel below has the same guard; this is
	// belt-and-braces so a self-dial never leaks partial state into
	// ports.NewConnection either. (v1.9.0-jf.6)
	if dstAddr.Node == d.NodeID() {
		return nil, protocol.ErrDialToSelf
	}

	// Enforce outbound port policy: prevent dialing ports blocked by the network
	if !d.evaluatePortPolicy(policy.EventDial, dstAddr.Network, dstPort, dstAddr.Node, 0, "") {
		return nil, fmt.Errorf("port %d not allowed by network %d policy", dstPort, dstAddr.Network)
	}

	// Ensure we have a tunnel to the destination
	if err := d.ensureTunnel(dstAddr.Node); err != nil {
		return nil, err
	}

	localPort := d.ports.AllocEphemeralPort()
	conn := d.ports.NewConnection(localPort, dstAddr, dstPort)
	// Grab conn.Mu for the early field writes: NewConnection has
	// already registered the connection in the ports map, so any
	// concurrent sweep (PortManager.ResetKeepaliveForNode etc.) can
	// observe conn.State before we initialize it. Without the lock
	// the race detector flips under load from background tickers
	// (observed with the gossip Engine's 25 s loop).
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: dstAddr.Network, Node: d.NodeID()}
	conn.Mu.Unlock()
	d.setConnState(conn, StateSynSent, "dial syn sent")
	d.traceStream("syn.sent", conn, "new_state", StateSynSent.String())

	// Send SYN with our receive window
	syn := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      conn.LocalAddr,
		Dst:      dstAddr,
		SrcPort:  localPort,
		DstPort:  dstPort,
		Seq:      conn.SendSeq,
		Window:   conn.RecvWindow(),
	}

	if err := d.tunnels.Send(dstAddr.Node, syn); err != nil {
		d.removeConnection(conn, "syn send failed")
		return nil, fmt.Errorf("send SYN: %w", err)
	}
	conn.Mu.Lock()
	conn.SendSeq++
	conn.Mu.Unlock()

	// Wait for ESTABLISHED with SYN retransmission.
	// Phase 1: Direct connection (3 retries).
	// Phase 2: Relay through beacon if direct fails (3 more retries).
	retries := 0
	directRetries := DialDirectRetries
	maxRetries := DialMaxRetries
	relayActive := d.tunnels.IsRelayPeer(dstAddr.Node) // may already be relay from prior attempt
	if relayActive {
		directRetries = 0 // skip direct phase, go straight to relay
	}
	// v1.9.0-jf.12.1: skip phase-1 direct retries entirely when
	// outbound-turn-only is enabled. In that mode writeFrame routes
	// every send through the local TURN allocation (jf.11a / jf.11a.2)
	// — there is no real "direct UDP" being attempted, just the
	// 7-second cosmetic timer running out before phase-2 relay
	// semantics engage. Cutting straight to relay-tier RTOs (which
	// match Cloudflare TURN's 2-3× RTT profile) eliminates the
	// 7-second post-restart cosmetic stall on hide-ip peers
	// without changing any actual data-path behaviour.
	if d.config.OutboundTURNOnly {
		directRetries = 0
	}

	// v1.9.0-jf.14: Once-per-dial guard for the rendezvous lookup.
	// Set true after the lookup runs (success or failure) so we don't
	// hammer the rendezvous on every retry of a stuck peer.
	rendezvousQueried := false
	fallbackAttempted := false
	fallbackResult := "not_reached"

	// v1.9.0-jf.15.4: when directRetries=0 (set by jf.12.1's
	// outbound-turn-only shortcut OR by the already-relay-active
	// path), the original `retries == directRetries` gate at the
	// timer-fire site is dead code — retries is always >=1 after
	// the increment, so neither the rendezvous lookup nor the
	// TCP/relay-switch fallback ever fires. Compute the actual
	// trigger retry-count as max(directRetries, 1) so outbound-
	// turn-only peers do exercise the fallback path on the first
	// timer tick after the initial SYN, not silently never.
	fallbackTriggerAt := directRetries
	if fallbackTriggerAt < 1 {
		fallbackTriggerAt = 1
	}

	// v1.9.0-jf.11a.3: Race direct + relay concurrently. While the
	// main retry loop drives direct UDP retransmissions (phase 1),
	// a parallel goroutine re-transmits the same SYN through the
	// beacon relay with an RFC 8305-style 200 ms head-start. When
	// the cached direct endpoint is stale, the relay copy lands in
	// ~300 ms instead of waiting out the 7 s phase-1 exhaustion.
	// Whichever path elicits an authenticated reply first flips
	// viaRelay via updatePathDirect()/updatePathRelay() on ingress —
	// we deliberately do NOT call SetRelayPeer here, so a losing
	// relay goroutine can't poison future dials.
	//
	// Skipped when: (a) the peer is already relay-sticky (the main
	// loop's serial relay retries will drive it; no race needed);
	// (b) no beacon is configured (typical for -hide-ip peers that
	// route exclusively via TURN).
	raceStop := make(chan struct{})
	defer close(raceStop)
	if !relayActive && allowRacingBeaconRelay(dialFallbackPolicyInput{
		outboundTURNOnly: d.config.OutboundTURNOnly,
		hasBeacon:        d.config.BeaconAddr != "",
	}) {
		// Copy the SYN so the racing goroutine's Marshal is
		// race-free against the main loop's `syn.Seq = …` write.
		// Packet is a value-struct and SYN's Payload is nil, so a
		// shallow copy is safe. Capture under conn.Mu for clean
		// synchronization with the initial SendSeq++ above.
		conn.Mu.Lock()
		synForRelay := *syn
		conn.Mu.Unlock()
		go d.racingRelaySYN(dstAddr.Node, &synForRelay, raceStop)
	}
	// Initial RTO is path-aware (v1.9.0-jf.4). Relay-mode peers get a
	// larger initial budget because the beacon hop adds real RTT.
	rto := DialInitialRTO
	if relayActive {
		rto = DialRelayInitialRTO
	}
	timer := time.NewTimer(rto)
	defer timer.Stop()

	check := time.NewTicker(DialCheckInterval)
	defer check.Stop()

	for {
		select {
		case <-check.C:
			conn.Mu.Lock()
			st := conn.State
			conn.Mu.Unlock()
			if st == StateEstablished {
				d.startRetxLoop(conn)
				return conn, nil
			}
			if st == StateFinWait || st == StateCloseWait || st == StateTimeWait {
				d.traceStream("dial.closed", conn, "observed_state", st.String())
				conn.CloseRecvBuf()
				d.setConnState(conn, StateClosed, "dial observed closing connection")
				d.removeConnection(conn, "dial observed closing connection")
				return nil, protocol.ErrConnClosing
			}
			if st == StateClosed {
				return nil, protocol.ErrConnRefused
			}
		case <-timer.C:
			retries++

			// Switch fallback transport after direct UDP retries exhaust.
			// Prefer TCP direct-connect (lower latency than relay) if the
			// peer advertised a TCP endpoint; else fall back to relay.
			//
			// v1.9.0-jf.15.4: gate uses fallbackTriggerAt = max(directRetries, 1)
			// to handle directRetries==0 correctly (outbound-turn-only and
			// already-relay-active paths). The original `retries == directRetries`
			// gate was dead code in those modes since retries is always >=1
			// after the increment above. Once the block fires (relayActive=true
			// or TCP switched), subsequent ticks fall through unchanged.
			if retries == fallbackTriggerAt && !relayActive {
				fallbackAttempted = true
				fallback := planDialFallback(dialFallbackPolicyInput{
					outboundTURNOnly: d.config.OutboundTURNOnly,
					hasRendezvous:    d.rendezvousClient != nil,
					hasTCP:           d.tunnels.HasTCPEndpoint(dstAddr.Node),
					hasBeacon:        d.config.BeaconAddr != "",
				})
				// v1.9.0-jf.14: before falling back to TCP/relay,
				// consult the rendezvous service once per dial. The
				// most common cause of phase-1 timeout for hide-ip
				// peers is a stale cached TURN endpoint left over
				// from before the peer rotated. A fresh fetch from
				// the rendezvous unblocks the next retry without
				// burning the full relay-fallback budget.
				if fallback.queryRendezvous && !rendezvousQueried {
					rendezvousQueried = true
					fallbackResult = "rendezvous_empty"
					if fresh := d.rendezvousLookupForDial(dstAddr.Node); fresh != "" {
						if err := d.tunnels.AddPeerTURNEndpoint(dstAddr.Node, fresh); err != nil {
							slog.Debug("rendezvous fresh endpoint install failed",
								"node_id", dstAddr.Node, "addr", fresh, "error", err)
							fallbackResult = "rendezvous_install_failed"
						} else {
							slog.Info("rendezvous installed fresh turn endpoint, retrying dial",
								"node_id", dstAddr.Node, "addr", fresh)
							fallbackResult = "rendezvous_installed"
						}
					}
				}
				switched := false
				if fallback.tryTCP {
					dctx, cancel := context.WithTimeout(context.Background(), DialTCPFallbackTimeout)
					err := d.tunnels.DialTCPForPeer(dctx, dstAddr.Node)
					cancel()
					if err == nil {
						slog.Info("direct udp dial timed out, switched to tcp", "node_id", dstAddr.Node)
						switched = true
						fallbackResult = "tcp_switched"
						rto = DialInitialRTO
					} else {
						slog.Debug("tcp fallback dial failed", "node_id", dstAddr.Node, "error", err)
						if fallbackResult == "not_reached" {
							fallbackResult = "tcp_failed"
						}
					}
				}
				if !switched && fallback.switchToBeacon {
					slog.Info("direct dial timed out, switching to relay", "node_id", dstAddr.Node)
					d.tunnels.SetRelayPeer(dstAddr.Node, true)
					relayActive = true
					fallbackResult = "beacon_relay"
					// Reset backoff but use the larger relay-specific
					// initial RTO since beacon-relay RTT is 2-3× direct.
					rto = DialRelayInitialRTO
				}
				if !switched && !fallback.switchToBeacon && fallbackResult == "not_reached" {
					fallbackResult = "none_allowed"
				}
			}

			if retries > maxRetries {
				phase := classifyDialTimeout(retries, fallbackTriggerAt, relayActive, fallbackAttempted, rendezvousQueried, fallbackResult)
				d.traceStream("dial.timeout", conn,
					"retries", retries,
					"phase", phase,
					"fallback_trigger_at", fallbackTriggerAt,
					"fallback_attempted", fallbackAttempted,
					"fallback_result", fallbackResult,
					"rendezvous_queried", rendezvousQueried,
					"relay_active", relayActive,
				)
				d.removeConnection(conn, "dial timeout: "+phase)
				return nil, protocol.ErrDialTimeout
			}
			// Resend SYN (uses relay if relayActive)
			conn.Mu.Lock()
			syn.Seq = conn.SendSeq - 1
			conn.Mu.Unlock()
			d.tunnels.Send(dstAddr.Node, syn)
			rto = rto * 2 // exponential backoff
			if rto > DialMaxRTO {
				rto = DialMaxRTO
			}
			timer.Reset(rto)
		}
	}
}

func (d *Daemon) abortConnection(conn *Connection) {
	conn.CloseRecvBuf()
	d.setConnState(conn, StateClosed, "abort")
	conn.Mu.Lock()
	conn.LastActivity = time.Now()
	conn.Mu.Unlock()
	d.removeConnection(conn, "abort")
}

func classifyDialTimeout(retries, fallbackTriggerAt int, relayActive, fallbackAttempted, rendezvousQueried bool, fallbackResult string) string {
	switch {
	case retries <= fallbackTriggerAt:
		return "no_synack_initial"
	case relayActive:
		return "no_synack_relay"
	case fallbackResult == "tcp_switched":
		return "no_synack_tcp"
	case rendezvousQueried && fallbackResult == "rendezvous_installed":
		return "no_synack_after_rendezvous"
	case rendezvousQueried:
		return "no_synack_rendezvous_unresolved"
	case fallbackAttempted:
		return "no_synack_fallback_unavailable"
	default:
		return "no_synack"
	}
}

// racingRelaySYN re-transmits the SYN packet through the beacon relay
// in parallel with DialConnection's main direct-retry loop (v1.9.0-
// jf.11a.3). Waits DialRelayHeadStart first so direct wins
// unobstructed when reachable, then issues up to DialRelayRetries
// beacon-wrapped retransmissions with exponential backoff starting at
// DialRelayInitialRTO.
//
// The goroutine uses SendPacketViaBeacon, which does NOT mutate
// path.viaRelay — the peer's authenticated SYN-ACK reply will update
// the path state naturally via updatePathRelay()/updatePathDirect()
// on ingress. Exits immediately when stop is closed (DialConnection
// returning for any reason).
//
// Errors from SendPacketViaBeacon are swallowed: the goroutine is
// best-effort and must never take down the main dial. The caller
// observes success only through conn.State flipping to Established.
//
// The caller is responsible for passing a SYN pointer that is NOT
// shared with the main dial loop (e.g. a local copy taken under
// conn.Mu before this goroutine launches). Otherwise the main loop's
// `syn.Seq = …` writes would race with our Marshal.
func (d *Daemon) racingRelaySYN(nodeID uint32, syn *protocol.Packet, stop <-chan struct{}) {
	select {
	case <-stop:
		return
	case <-time.After(DialRelayHeadStart):
	}
	rto := DialRelayInitialRTO
	for i := 0; i < DialRelayRetries; i++ {
		_ = d.tunnels.SendPacketViaBeacon(nodeID, syn)
		select {
		case <-stop:
			return
		case <-time.After(rto):
		}
		rto = rto * 2
		if rto > DialMaxRTO {
			rto = DialMaxRTO
		}
	}
}

// NagleTimeout is the maximum time to buffer small writes before flushing.
const NagleTimeout = 40 * time.Millisecond

// DelayedACKTimeout is the max time to delay an ACK (RFC 1122 suggests 500ms max, we use 40ms).
const DelayedACKTimeout = 40 * time.Millisecond

// DelayedACKThreshold is the number of segments to receive before sending an ACK immediately.
const DelayedACKThreshold = 2

// SendData sends data over an established connection.
// Implements Nagle's algorithm: small writes are coalesced into MSS-sized
// segments unless NoDelay is set. Large writes (>= MSS) are sent immediately.
func (d *Daemon) SendData(conn *Connection, data []byte) error {
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateEstablished {
		return fmt.Errorf("connection not established")
	}

	// If Nagle is disabled (NoDelay), send everything immediately in segments
	if conn.NoDelay {
		return d.sendDataImmediate(conn, data)
	}

	conn.NagleMu.Lock()
	conn.NagleBuf = append(conn.NagleBuf, data...)
	conn.NagleMu.Unlock()

	return d.nagleFlush(conn)
}

// nagleFlush sends buffered data according to Nagle's algorithm:
// - Full MSS segments are always sent
// - Sub-MSS data is sent only if no unacknowledged data exists or timeout
func (d *Daemon) nagleFlush(conn *Connection) error {
	for {
		conn.NagleMu.Lock()
		if len(conn.NagleBuf) == 0 {
			conn.NagleMu.Unlock()
			return nil
		}

		// If we have at least MSS bytes, send a full segment
		if len(conn.NagleBuf) >= MaxSegmentSize {
			segment := make([]byte, MaxSegmentSize)
			copy(segment, conn.NagleBuf[:MaxSegmentSize])
			conn.NagleBuf = conn.NagleBuf[MaxSegmentSize:]
			conn.NagleMu.Unlock()

			if err := d.sendSegment(conn, segment); err != nil {
				return err
			}
			continue
		}

		// Sub-MSS data: check if we can send now (check under NagleMu)
		conn.RetxMu.Lock()
		hasUnacked := len(conn.Unacked) > 0
		conn.RetxMu.Unlock()

		if !hasUnacked {
			// No data in flight — send immediately (Nagle allows this)
			segment := make([]byte, len(conn.NagleBuf))
			copy(segment, conn.NagleBuf)
			conn.NagleBuf = conn.NagleBuf[:0]
			conn.NagleMu.Unlock()

			return d.sendSegment(conn, segment)
		}
		conn.NagleMu.Unlock()

		// Data in flight — wait for ACK or timeout
		nagleTimer := time.NewTimer(NagleTimeout)
		select {
		case <-conn.NagleCh:
			nagleTimer.Stop()
			// All data ACKed — flush now
		case <-nagleTimer.C:
			// Timeout — flush regardless
		case <-conn.RetxStop:
			nagleTimer.Stop()
			return protocol.ErrConnClosed
		}

		// Re-check under lock after waking
		conn.NagleMu.Lock()
		if len(conn.NagleBuf) == 0 {
			conn.NagleMu.Unlock()
			return nil
		}

		// Send whatever we have (might have reached MSS now)
		if len(conn.NagleBuf) >= MaxSegmentSize {
			conn.NagleMu.Unlock()
			continue // loop back to send full segments
		}

		segment := make([]byte, len(conn.NagleBuf))
		copy(segment, conn.NagleBuf)
		conn.NagleBuf = conn.NagleBuf[:0]
		conn.NagleMu.Unlock()

		return d.sendSegment(conn, segment)
	}
}

// sendDataImmediate sends data in MSS-sized segments without Nagle coalescing.
func (d *Daemon) sendDataImmediate(conn *Connection, data []byte) error {
	for offset := 0; offset < len(data); {
		end := offset + MaxSegmentSize
		if end > len(data) {
			end = len(data)
		}
		segment := data[offset:end]

		if err := d.sendSegment(conn, segment); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// sendSegment sends a single segment, waiting for the congestion window.
// Implements zero-window probing when the peer's receive window is 0.
func (d *Daemon) sendSegment(conn *Connection, data []byte) error {
	probeInterval := ZeroWinProbeInitial

	// Wait for effective window to have space
	probeTimer := time.NewTimer(probeInterval)
	defer probeTimer.Stop()
	for {
		conn.RetxMu.Lock()
		avail := conn.WindowAvailable()
		conn.RetxMu.Unlock()
		if avail {
			break
		}

		// Window full — wait for ACK to open it, with zero-window probing
		select {
		case <-conn.WindowCh:
			probeInterval = ZeroWinProbeInitial
			if !probeTimer.Stop() {
				select {
				case <-probeTimer.C:
				default:
				}
			}
			probeTimer.Reset(probeInterval)
		case <-conn.RetxStop:
			return protocol.ErrConnClosed
		case <-probeTimer.C:
			// Send zero-window probe (empty ACK) to trigger window update
			conn.Mu.Lock()
			probeSeq := conn.SendSeq
			probeAck := conn.RecvAck
			conn.Mu.Unlock()
			probe := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      conn.LocalAddr,
				Dst:      conn.RemoteAddr,
				SrcPort:  conn.LocalPort,
				DstPort:  conn.RemotePort,
				Seq:      probeSeq,
				Ack:      probeAck,
				Window:   conn.RecvWindow(),
			}
			d.tunnels.Send(conn.RemoteAddr.Node, probe)
			// Exponential backoff up to 30s
			probeInterval = probeInterval * 2
			if probeInterval > ZeroWinProbeMax {
				probeInterval = ZeroWinProbeMax
			}
			probeTimer.Reset(probeInterval)
		}
	}

	conn.Mu.Lock()
	seq := conn.SendSeq
	ack := conn.RecvAck
	conn.Mu.Unlock()
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      conn.LocalAddr,
		Dst:      conn.RemoteAddr,
		SrcPort:  conn.LocalPort,
		DstPort:  conn.RemotePort,
		Seq:      seq,
		Ack:      ack,
		Window:   conn.RecvWindow(),
		Payload:  data,
	}

	if err := d.tunnels.Send(conn.RemoteAddr.Node, pkt); err != nil {
		return err
	}
	conn.Mu.Lock()
	conn.SendSeq += uint32(len(data))
	conn.LastActivity = time.Now()
	conn.Stats.BytesSent += uint64(len(data))
	conn.Stats.SegsSent++
	conn.Mu.Unlock()
	conn.TrackSend(seq, data)

	// Cancel delayed ACK — this data packet piggybacks the ACK
	conn.AckMu.Lock()
	if conn.ACKTimer != nil {
		conn.ACKTimer.Stop()
		conn.ACKTimer = nil
	}
	conn.PendingACKs = 0
	conn.AckMu.Unlock()

	return nil
}

// startRetxLoop starts the retransmission goroutine for a connection.
func (d *Daemon) startRetxLoop(conn *Connection) {
	conn.RTO = InitialRTO
	conn.RetxStop = make(chan struct{})
	conn.RetxSend = func(pkt *protocol.Packet) {
		d.tunnels.Send(conn.RemoteAddr.Node, pkt)
	}
	go d.retxLoop(conn)
}

func (d *Daemon) retxLoop(conn *Connection) {
	ticker := time.NewTicker(RetxCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-conn.RetxStop:
			return
		case <-ticker.C:
			conn.Mu.Lock()
			st := conn.State
			conn.Mu.Unlock()
			if st == StateEstablished || st == StateFinWait {
				d.retransmitUnacked(conn)
			} else if st == StateClosed {
				// Connection abandoned (max retransmit) — clean up immediately
				conn.CloseRecvBuf()
				d.removeConnection(conn, "retransmit closed")
				return
			} else {
				// TIME_WAIT or other non-active state — stop retransmitting
				// Cleanup is handled by idleSweepLoop
				return
			}
		}
	}
}

func (d *Daemon) retransmitUnacked(conn *Connection) {
	conn.RetxMu.Lock()

	if len(conn.Unacked) == 0 {
		conn.RetxMu.Unlock()
		return
	}

	now := time.Now()

	// Only retransmit one segment per RTO period (like real TCP).
	if !conn.LastRetxTime.IsZero() && now.Sub(conn.LastRetxTime) < conn.RTO {
		conn.RetxMu.Unlock()
		return
	}

	// Find the first non-SACKed unacked segment that has timed out
	for _, e := range conn.Unacked {
		if e.sacked {
			continue
		}
		if now.Sub(e.sentAt) > conn.RTO {
			if e.attempts >= MaxRetxAttempts {
				// Too many retransmissions — abandon connection
				d.traceRetransmitFailure(conn, e, now)
				// Send RST to notify the remote peer
				rst := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagRST,
					Protocol: protocol.ProtoStream,
					Src:      conn.LocalAddr,
					Dst:      conn.RemoteAddr,
					SrcPort:  conn.LocalPort,
					DstPort:  conn.RemotePort,
				}
				if conn.RetxSend != nil {
					conn.RetxSend(rst)
				}
				conn.RetxMu.Unlock()
				d.setConnState(conn, StateClosed, "max retransmits")
				return
			}

			conn.Mu.Lock()
			sendSeq := conn.SendSeq
			conn.Mu.Unlock()

			isNewLossEvent := !conn.InRecovery
			if isNewLossEvent {
				// New loss event: reduce window, enter recovery
				conn.SSThresh = conn.CongWin / 2
				if conn.SSThresh < MaxSegmentSize {
					conn.SSThresh = MaxSegmentSize
				}
				conn.CongWin = InitialCongWin
				conn.InRecovery = true
				conn.RecoveryPoint = sendSeq

				// Double RTO for first timeout in this loss event
				conn.RTO = conn.RTO * 2
				if conn.RTO > 10*time.Second {
					conn.RTO = 10 * time.Second
				}
			}
			// During recovery, retransmit without further RTO doubling

			e.attempts++
			e.sentAt = now
			conn.Mu.Lock()
			conn.Stats.Retransmits++
			conn.Mu.Unlock()
			conn.LastRetxTime = now

			conn.Mu.Lock()
			recvAck := conn.RecvAck
			st := conn.State
			conn.Mu.Unlock()

			// FIN retransmit: when in FIN_WAIT, the tracked entry is a
			// FIN sentinel — resend with FlagFIN instead of data.
			if st == StateFinWait {
				pkt := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagFIN,
					Protocol: protocol.ProtoStream,
					Src:      conn.LocalAddr,
					Dst:      conn.RemoteAddr,
					SrcPort:  conn.LocalPort,
					DstPort:  conn.RemotePort,
					Seq:      e.seq,
				}
				if conn.RetxSend != nil {
					conn.RetxSend(pkt)
				}
				conn.RetxMu.Unlock()
				return
			}

			pkt := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      conn.LocalAddr,
				Dst:      conn.RemoteAddr,
				SrcPort:  conn.LocalPort,
				DstPort:  conn.RemotePort,
				Seq:      e.seq,
				Ack:      recvAck,
				Window:   conn.RecvWindow(),
				Payload:  e.data,
			}
			if conn.RetxSend != nil {
				conn.RetxSend(pkt)
			}
			conn.RetxMu.Unlock()
			return // only retransmit ONE segment per RTO
		}
		break // segments are ordered by time; if first hasn't timed out, none have
	}
	conn.RetxMu.Unlock()
}

// CloseConnection sends FIN and enters FIN_WAIT. The FIN is tracked in the
// retransmission buffer so it will be retried if lost — the existing retxLoop
// handles it. When FIN-ACK is received the connection moves to TIME_WAIT and
// is eventually reaped by idleSweepLoop.
func (d *Daemon) CloseConnection(conn *Connection) {
	conn.Mu.Lock()
	st := conn.State
	sendSeq := conn.SendSeq
	conn.Mu.Unlock()
	switch st {
	case StateEstablished:
		finData := []byte{0} // 1-byte sentinel so retxEntry has non-zero length
		fin := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagFIN,
			Protocol: protocol.ProtoStream,
			Src:      conn.LocalAddr,
			Dst:      conn.RemoteAddr,
			SrcPort:  conn.LocalPort,
			DstPort:  conn.RemotePort,
			Seq:      sendSeq,
		}
		d.tunnels.Send(conn.RemoteAddr.Node, fin)
		// Track FIN in retransmission buffer so the retxLoop retries it
		conn.TrackSend(sendSeq, finData)
		conn.Mu.Lock()
		conn.SendSeq++
		conn.Mu.Unlock()
	case StateFinWait, StateTimeWait, StateClosed:
		d.traceStream("close.ignored", conn, "observed_state", st.String())
		return
	}
	conn.CloseRecvBuf()
	conn.Mu.Lock()
	conn.LastActivity = time.Now()
	conn.Mu.Unlock()
	d.setConnState(conn, StateFinWait, "close requested")
}
