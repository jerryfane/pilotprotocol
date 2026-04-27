package daemon

import (
	"log/slog"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/policy"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func (d *Daemon) handleStreamPacket(pkt *protocol.Packet) {
	switch {
	case pkt.HasFlag(protocol.FlagSYN) && !pkt.HasFlag(protocol.FlagACK):
		d.handleStreamSYN(pkt)
	case pkt.HasFlag(protocol.FlagSYN) && pkt.HasFlag(protocol.FlagACK):
		d.handleStreamSYNACK(pkt)
	case pkt.HasFlag(protocol.FlagFIN):
		d.handleStreamFIN(pkt)
	case pkt.HasFlag(protocol.FlagRST):
		d.handleStreamRST(pkt)
	case pkt.HasFlag(protocol.FlagACK):
		d.handleStreamACK(pkt)
	}
}

func (d *Daemon) handleStreamSYN(pkt *protocol.Packet) {
	// SYN — incoming connection request
	if pkt.HasFlag(protocol.FlagSYN) && !pkt.HasFlag(protocol.FlagACK) {
		ln := d.ports.GetListener(pkt.DstPort)
		if ln == nil {
			// Nothing listening — send RST
			d.traceStreamPacket("syn.listener_missing", pkt.Src.Node, pkt.DstPort, pkt.SrcPort, "reason", "no listener")
			d.sendRST(pkt)
			return
		}

		// Check for retransmitted SYN (connection already exists for this 4-tuple)
		if existing := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort); existing != nil {
			d.traceStream("syn.duplicate", existing)
			// Resend SYN-ACK for the existing connection
			existing.Mu.Lock()
			eSeq := existing.SendSeq
			eAck := existing.RecvAck
			existing.Mu.Unlock()
			synack := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    protocol.FlagSYN | protocol.FlagACK,
				Protocol: protocol.ProtoStream,
				Src:      pkt.Dst,
				Dst:      pkt.Src,
				SrcPort:  pkt.DstPort,
				DstPort:  pkt.SrcPort,
				Seq:      eSeq - 1, // original SYN-ACK seq
				Ack:      eAck,
				Window:   existing.RecvWindow(),
			}
			if err := d.tunnels.Send(pkt.Src.Node, synack); err != nil {
				slog.Warn("resend SYN-ACK failed",
					"src_node", pkt.Src.Node,
					"src_addr", pkt.Src,
					"src_port", pkt.SrcPort,
					"dst_port", pkt.DstPort,
					"conn_id", existing.ID,
					"err", err)
			}
			d.traceStream("synack.resent", existing)
			return
		}

		// Trust gate: private nodes only accept SYN from trusted or same-network peers.
		// Runs before rate limiting so untrusted sources cannot waste rate-limit tokens.
		if !d.config.Public {
			srcNode := pkt.Src.Node
			trusted := d.handshakes.IsTrusted(srcNode)
			if !trusted && d.regConn != nil {
				// Fall back to registry trust check (covers admin-set trust pairs + shared networks)
				trusted, _ = d.regConn.CheckTrust(d.NodeID(), srcNode)
			}
			if !trusted {
				slog.Warn("SYN rejected: untrusted source", "src_node", srcNode, "src_addr", pkt.Src, "dst_port", pkt.DstPort)
				d.traceStreamPacket("syn.rejected", pkt.Src.Node, pkt.DstPort, pkt.SrcPort, "reason", "untrusted")
				d.webhook.Emit("syn.rejected", map[string]interface{}{
					"src_node_id": srcNode,
					"src_addr":    pkt.Src.String(),
					"dst_port":    pkt.DstPort,
				})
				return // silent drop — no RST to avoid leaking node existence
			}
		}

		// Network policy: reject SYN if port/peer is not allowed
		if !d.evaluatePortPolicy(policy.EventConnect, pkt.Dst.Network, pkt.DstPort, pkt.Src.Node, 0, "") {
			slog.Warn("SYN rejected: not allowed by network policy",
				"src_node", pkt.Src.Node, "dst_port", pkt.DstPort, "network", pkt.Dst.Network)
			d.traceStreamPacket("syn.rejected", pkt.Src.Node, pkt.DstPort, pkt.SrcPort, "reason", "policy")
			d.webhook.Emit("syn.port_rejected", map[string]interface{}{
				"src_node_id": pkt.Src.Node,
				"dst_port":    pkt.DstPort,
				"network":     pkt.Dst.Network,
			})
			return // silent drop — don't reveal policy to attacker
		}

		// SYN rate limiting
		if !d.allowSYN() {
			slog.Warn("SYN rate limit exceeded", "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.traceStreamPacket("syn.rejected", pkt.Src.Node, pkt.DstPort, pkt.SrcPort, "reason", "rate_limit")
			d.webhook.Emit("security.syn_rate_limited", map[string]interface{}{
				"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
			})
			return // silently drop — don't even RST (avoid amplification)
		}
		if !d.allowSYNFromSource(pkt.Src.Node) {
			slog.Warn("per-source SYN rate limit exceeded", "src_node", pkt.Src.Node, "src_port", pkt.SrcPort)
			d.traceStreamPacket("syn.rejected", pkt.Src.Node, pkt.DstPort, pkt.SrcPort, "reason", "source_rate_limit")
			return
		}

		// Check per-port connection limit
		if d.ports.ConnectionCountForPort(pkt.DstPort) >= d.config.maxConnectionsPerPort() {
			slog.Warn("max connections per port reached, rejecting SYN", "port", pkt.DstPort, "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.traceStreamPacket("syn.rejected", pkt.Src.Node, pkt.DstPort, pkt.SrcPort, "reason", "port_limit")
			d.sendRST(pkt)
			return
		}

		// Check global connection limit
		if d.ports.TotalActiveConnections() >= d.config.maxTotalConnections() {
			slog.Warn("max total connections reached, rejecting SYN", "src_addr", pkt.Src, "src_port", pkt.SrcPort)
			d.traceStreamPacket("syn.rejected", pkt.Src.Node, pkt.DstPort, pkt.SrcPort, "reason", "total_limit")
			d.sendRST(pkt)
			return
		}

		conn := d.ports.NewConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		conn.Mu.Lock()
		// Use the destination address from the SYN as our local address.
		// This ensures the correct network-specific address is used for
		// multi-network connections (e.g. 1:0001.0000.0003 instead of
		// the primary 0:0000.0000.0003).
		conn.LocalAddr = pkt.Dst
		conn.RecvAck = pkt.Seq + 1
		conn.ExpectedSeq = pkt.Seq + 1 // first data segment after SYN
		conn.Mu.Unlock()
		d.setConnState(conn, StateSynReceived, "syn received")
		d.traceStream("syn.recv", conn, "new_state", StateSynReceived.String())
		d.webhook.Emit("conn.syn_received", map[string]interface{}{
			"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort, "conn_id": conn.ID,
		})

		// Process peer's receive window from SYN (H9 fix: always update, including Window==0)
		conn.RetxMu.Lock()
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		conn.RetxMu.Unlock()

		// Send SYN-ACK with our receive window
		conn.Mu.Lock()
		synack := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagSYN | protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      pkt.Dst,
			Dst:      pkt.Src,
			SrcPort:  pkt.DstPort,
			DstPort:  pkt.SrcPort,
			Seq:      conn.SendSeq,
			Ack:      conn.RecvAck,
			Window:   conn.RecvWindow(),
		}
		if err := d.tunnels.Send(pkt.Src.Node, synack); err != nil {
			conn.Mu.Unlock()
			d.abortConnection(conn)
			slog.Warn("SYN-ACK send failed, closing half-open connection",
				"src_node", pkt.Src.Node,
				"src_addr", pkt.Src,
				"src_port", pkt.SrcPort,
				"dst_port", pkt.DstPort,
				"conn_id", conn.ID,
				"err", err)
			return
		}
		conn.SendSeq++
		conn.Mu.Unlock()
		d.traceStream("synack.sent", conn)
		return
	}
}

func (d *Daemon) handleStreamSYNACK(pkt *protocol.Packet) {
	// SYN-ACK — response to our dial
	if pkt.HasFlag(protocol.FlagSYN) && pkt.HasFlag(protocol.FlagACK) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn == nil {
			d.traceStreamPacket("synack.no_connection", pkt.Src.Node, pkt.DstPort, pkt.SrcPort)
			return
		}
		conn.Mu.Lock()
		if conn.State != StateSynSent {
			st := conn.State
			conn.Mu.Unlock()
			d.traceStream("synack.state_mismatch", conn, "observed_state", st.String())
			return
		}
		conn.RecvAck = pkt.Seq + 1
		sendSeq := conn.SendSeq
		recvAck := conn.RecvAck
		conn.Mu.Unlock()
		d.setConnState(conn, StateEstablished, "synack received")
		d.traceStream("synack.recv", conn)

		conn.RecvMu.Lock()
		conn.ExpectedSeq = pkt.Seq + 1 // first data segment after SYN-ACK
		conn.RecvMu.Unlock()

		// Process peer's receive window from SYN-ACK (H9 fix: always update)
		conn.RetxMu.Lock()
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		conn.RetxMu.Unlock()

		// Send ACK with our receive window
		ack := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      conn.LocalAddr,
			Dst:      pkt.Src,
			SrcPort:  pkt.DstPort,
			DstPort:  pkt.SrcPort,
			Seq:      sendSeq,
			Ack:      recvAck,
			Window:   conn.RecvWindow(),
		}
		d.tunnels.Send(pkt.Src.Node, ack)
		return
	}
}

func (d *Daemon) handleStreamFIN(pkt *protocol.Packet) {
	// FIN — remote close (or FIN-ACK acknowledging our FIN)
	if pkt.HasFlag(protocol.FlagFIN) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn != nil {
			conn.Mu.Lock()
			wasFinWait := conn.State == StateFinWait
			wasTimeWait := conn.State == StateTimeWait
			sendSeq := conn.SendSeq
			if !wasTimeWait {
				conn.LastActivity = time.Now()
				conn.KeepaliveUnacked = 0
			}
			conn.Mu.Unlock()

			if pkt.Ack > 0 {
				conn.RetxMu.Lock()
				conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
				conn.RetxMu.Unlock()
				d.processConnAck(conn, pkt.Ack, len(pkt.Payload) == 0, "fin")
			}

			if wasTimeWait {
				// Duplicate FIN after the close handshake is complete. ACK it
				// idempotently, but do not refresh LastActivity or emit another
				// transition; otherwise retransmitted FINs keep TIME_WAIT alive.
				ack := &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagACK,
					Protocol: protocol.ProtoStream,
					Src:      conn.LocalAddr,
					Dst:      pkt.Src,
					SrcPort:  pkt.DstPort,
					DstPort:  pkt.SrcPort,
					Seq:      sendSeq,
					Ack:      pkt.Seq + 1,
					Window:   conn.RecvWindow(),
				}
				d.tunnels.Send(pkt.Src.Node, ack)
				return
			}

			conn.CloseRecvBuf()
			conn.Mu.Lock()
			conn.LastActivity = time.Now()
			conn.KeepaliveUnacked = 0
			sendSeq = conn.SendSeq
			conn.Mu.Unlock()
			d.setConnState(conn, StateTimeWait, "fin received")
			d.traceStream("fin.recv", conn)
			// If we were in FIN_WAIT, this is a FIN-ACK — clear retx buffer
			if wasFinWait {
				conn.RetxMu.Lock()
				conn.Unacked = nil
				conn.RetxMu.Unlock()
			}
			if !wasTimeWait {
				d.webhook.Emit("conn.fin", map[string]interface{}{
					"remote_addr": pkt.Src.String(), "remote_port": pkt.SrcPort,
					"local_port": pkt.DstPort, "conn_id": conn.ID,
				})
			}
			// Connection will be reaped by idleSweepLoop after TimeWaitDuration

			flags := protocol.FlagFIN | protocol.FlagACK
			if wasFinWait {
				flags = protocol.FlagACK
			}
			// Send FIN-ACK for peer-initiated close. If we had already sent
			// our FIN, an ACK-only response avoids a FIN echo loop.
			finack := &protocol.Packet{
				Version:  protocol.Version,
				Flags:    flags,
				Protocol: protocol.ProtoStream,
				Src:      conn.LocalAddr,
				Dst:      pkt.Src,
				SrcPort:  pkt.DstPort,
				DstPort:  pkt.SrcPort,
				Seq:      sendSeq,
				Ack:      pkt.Seq + 1,
			}
			d.tunnels.Send(pkt.Src.Node, finack)
		} else {
			d.traceStreamPacket("fin.no_connection", pkt.Src.Node, pkt.DstPort, pkt.SrcPort)
		}
		return
	}
}

func (d *Daemon) handleStreamRST(pkt *protocol.Packet) {
	// RST
	if pkt.HasFlag(protocol.FlagRST) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn != nil {
			d.setConnState(conn, StateClosed, "rst received")
			d.traceStream("rst.recv", conn)
			conn.CloseRecvBuf()
			d.removeConnection(conn, "rst received")
			d.webhook.Emit("conn.rst", map[string]interface{}{
				"remote_addr": pkt.Src.String(), "remote_port": pkt.SrcPort,
				"local_port": pkt.DstPort, "conn_id": conn.ID,
			})
		} else {
			d.traceStreamPacket("rst.no_connection", pkt.Src.Node, pkt.DstPort, pkt.SrcPort)
		}
		return
	}
}

func (d *Daemon) handleStreamACK(pkt *protocol.Packet) {
	// ACK — pure ACK or data packet
	if pkt.HasFlag(protocol.FlagACK) {
		conn := d.ports.FindConnection(pkt.DstPort, pkt.Src, pkt.SrcPort)
		if conn == nil {
			d.traceStreamPacket("ack.no_connection", pkt.Src.Node, pkt.DstPort, pkt.SrcPort, "payload_len", len(pkt.Payload))
			return
		}

		conn.Mu.Lock()
		st := conn.State
		sendSeq := conn.SendSeq
		conn.Mu.Unlock()
		if st == StateSynReceived {
			if pkt.Ack < sendSeq {
				d.traceStream("synack.final_ack_stale", conn, "ack", pkt.Ack, "send_seq", sendSeq)
				return
			}
			d.setConnState(conn, StateEstablished, "final ack received")
			d.traceStream("synack.final_ack", conn)
			d.webhook.Emit("conn.established", map[string]interface{}{
				"src_addr": pkt.Src.String(), "src_port": pkt.SrcPort,
				"dst_port": pkt.DstPort, "conn_id": conn.ID,
			})
			d.startRetxLoop(conn)
			if !d.queueAcceptedStream(conn, pkt) {
				return
			}
		}

		conn.Mu.Lock()
		conn.LastActivity = time.Now()
		conn.KeepaliveUnacked = 0
		conn.Mu.Unlock()

		// Update peer's receive window (H9 fix: always update, honor Window==0)
		conn.RetxMu.Lock()
		conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
		conn.RetxMu.Unlock()

		// Process ACK for retransmission tracking
		// Only count as pure ACK for dup detection if no data payload
		if pkt.Ack > 0 {
			isPureACK := len(pkt.Payload) == 0
			d.processConnAck(conn, pkt.Ack, isPureACK, "packet")
		}

		// Check if payload is SACK info (not user data)
		if sackBlocks, ok := DecodeSACK(pkt.Payload); ok {
			conn.ProcessSACK(sackBlocks)
		} else if len(pkt.Payload) > 0 {
			conn.Mu.Lock()
			established := conn.State == StateEstablished
			if established {
				conn.LastActivity = time.Now()
				conn.Stats.BytesRecv += uint64(len(pkt.Payload))
				conn.Stats.SegsRecv++
			}
			conn.Mu.Unlock()
			if !established {
				return
			}
			// Deliver data using receive window (handles reordering)
			cumAck := conn.DeliverInOrder(pkt.Seq, pkt.Payload)
			conn.Mu.Lock()
			conn.RecvAck = cumAck
			conn.Mu.Unlock()

			// Check if we have out-of-order data — ACK immediately with SACK
			conn.RecvMu.Lock()
			hasOOO := len(conn.OOOBuf) > 0
			conn.RecvMu.Unlock()

			conn.AckMu.Lock()
			if hasOOO {
				// Immediate ACK with SACK blocks (trigger fast retransmit)
				conn.AckMu.Unlock()
				d.sendDelayedACK(conn)
			} else {
				// Delayed ACK: batch up to 2 segments or 40ms
				conn.PendingACKs++
				if conn.PendingACKs >= DelayedACKThreshold {
					conn.AckMu.Unlock()
					d.sendDelayedACK(conn)
				} else if conn.ACKTimer == nil {
					conn.ACKTimer = time.AfterFunc(DelayedACKTimeout, func() {
						d.sendDelayedACK(conn)
					})
					conn.AckMu.Unlock()
				} else {
					conn.AckMu.Unlock()
				}
			}
		}
	}
}

// sendDelayedACK sends a cumulative ACK for a connection, including SACK blocks if needed.
func (d *Daemon) sendDelayedACK(conn *Connection) {
	// Reset delayed ACK state
	conn.AckMu.Lock()
	if conn.ACKTimer != nil {
		conn.ACKTimer.Stop()
		conn.ACKTimer = nil
	}
	conn.PendingACKs = 0
	conn.AckMu.Unlock()

	conn.Mu.Lock()
	sendSeq := conn.SendSeq
	recvAck := conn.RecvAck
	conn.Mu.Unlock()

	ack := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      conn.LocalAddr,
		Dst:      conn.RemoteAddr,
		SrcPort:  conn.LocalPort,
		DstPort:  conn.RemotePort,
		Seq:      sendSeq,
		Ack:      recvAck,
		Window:   conn.RecvWindow(),
	}

	// Include SACK blocks if we have out-of-order segments
	conn.RecvMu.Lock()
	sackBlocks := conn.SACKBlocks()
	conn.RecvMu.Unlock()
	if len(sackBlocks) > 0 {
		ack.Payload = EncodeSACK(sackBlocks)
		conn.Mu.Lock()
		conn.Stats.SACKSent += uint64(len(sackBlocks))
		conn.Mu.Unlock()
	}

	d.tunnels.Send(conn.RemoteAddr.Node, ack)
}
