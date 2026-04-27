package daemon

import (
	"log/slog"
	"time"
)

func (d *Daemon) traceStream(event string, conn *Connection, attrs ...any) {
	if !d.config.TraceStreams || conn == nil {
		return
	}

	conn.Mu.Lock()
	state := conn.State
	localAddr := conn.LocalAddr.String()
	remoteAddr := conn.RemoteAddr.String()
	localPort := conn.LocalPort
	remotePort := conn.RemotePort
	lastActivity := conn.LastActivity
	createdAt := conn.CreatedAt
	recvLen := len(conn.RecvBuf)
	recvCap := cap(conn.RecvBuf)
	acceptQueued := !conn.AcceptQueuedAt.IsZero()
	accepted := !conn.AcceptedAt.IsZero()
	conn.Mu.Unlock()

	conn.RetxMu.Lock()
	unacked := len(conn.Unacked)
	inFlight := conn.BytesInFlight()
	conn.RetxMu.Unlock()

	ageMS := int64(0)
	if !createdAt.IsZero() {
		ageMS = time.Since(createdAt).Milliseconds()
	}
	lastActivityAgoMS := int64(0)
	if !lastActivity.IsZero() {
		lastActivityAgoMS = time.Since(lastActivity).Milliseconds()
	}

	base := []any{
		"conn_id", conn.ID,
		"peer_node", conn.RemoteAddr.Node,
		"local_addr", localAddr,
		"local_port", localPort,
		"remote_addr", remoteAddr,
		"remote_port", remotePort,
		"state", state.String(),
		"age_ms", ageMS,
		"last_activity_ago_ms", lastActivityAgoMS,
		"unacked", unacked,
		"in_flight", inFlight,
		"recv_buf_len", recvLen,
		"recv_buf_cap", recvCap,
		"accept_queued", acceptQueued,
		"accepted", accepted,
	}
	base = append(base, attrs...)
	slog.Info("stream."+event, base...)
}

func (d *Daemon) traceStreamTransition(conn *Connection, old, next ConnState, reason string) {
	if !d.config.TraceStreams || conn == nil {
		return
	}
	d.traceStream("transition", conn,
		"old_state", old.String(),
		"new_state", next.String(),
		"reason", reason,
	)
}

func (d *Daemon) setConnState(conn *Connection, next ConnState, reason string) {
	if conn == nil {
		return
	}
	conn.Mu.Lock()
	old := conn.State
	conn.State = next
	conn.Mu.Unlock()
	if old != next {
		d.traceStreamTransition(conn, old, next, reason)
	}
}

func (d *Daemon) markConnAcceptQueued(conn *Connection) {
	if conn == nil {
		return
	}
	conn.Mu.Lock()
	if conn.AcceptQueuedAt.IsZero() {
		conn.AcceptQueuedAt = time.Now()
	}
	conn.Mu.Unlock()
	d.traceStream("accept.queued", conn)
}

func (d *Daemon) markConnAccepted(conn *Connection) {
	if conn == nil {
		return
	}
	conn.Mu.Lock()
	if conn.AcceptedAt.IsZero() {
		conn.AcceptedAt = time.Now()
	}
	conn.Mu.Unlock()
	d.traceStream("accept.notified", conn)
}

func (d *Daemon) removeConnection(conn *Connection, reason string) {
	if conn == nil {
		return
	}
	d.traceStream("removed", conn, "reason", reason)
	d.ports.RemoveConnection(conn.ID)
}

func (d *Daemon) processConnAck(conn *Connection, ack uint32, pureACK bool, reason string) AckResult {
	res := conn.ProcessAck(ack, pureACK)
	if !d.config.TraceStreams {
		return res
	}
	attrs := []any{
		"reason", reason,
		"ack", res.Ack,
		"pure_ack", res.PureACK,
		"last_ack_before", res.BeforeLastAck,
		"last_ack_after", res.AfterLastAck,
		"unacked_before", res.BeforeUnacked,
		"unacked_after", res.AfterUnacked,
		"cleared", res.Cleared,
	}
	switch {
	case res.Stale:
		d.traceStream("ack.stale", conn, attrs...)
	case res.Duplicate:
		d.traceStream("ack.duplicate", conn, attrs...)
	case res.Cleared > 0:
		d.traceStream("ack.cleared", conn, attrs...)
	default:
		d.traceStream("ack.noop", conn, attrs...)
	}
	return res
}

func (d *Daemon) traceRetransmitFailure(conn *Connection, e *retxEntry, now time.Time) {
	if conn == nil || e == nil {
		return
	}

	conn.Mu.Lock()
	state := conn.State
	sendSeq := conn.SendSeq
	recvAck := conn.RecvAck
	lastActivity := conn.LastActivity
	conn.Mu.Unlock()

	unacked := len(conn.Unacked)
	inFlight := conn.BytesInFlight()
	rto := conn.RTO

	lastActivityAgoMS := int64(0)
	if !lastActivity.IsZero() {
		lastActivityAgoMS = now.Sub(lastActivity).Milliseconds()
	}

	slog.Error("max retransmits exceeded, sending RST",
		"conn_id", conn.ID,
		"peer_node", conn.RemoteAddr.Node,
		"local_addr", conn.LocalAddr.String(),
		"local_port", conn.LocalPort,
		"remote_addr", conn.RemoteAddr.String(),
		"remote_port", conn.RemotePort,
		"state", state.String(),
		"oldest_seq", e.seq,
		"oldest_len", len(e.data),
		"attempts", e.attempts,
		"oldest_age_ms", now.Sub(e.sentAt).Milliseconds(),
		"rto_ms", rto.Milliseconds(),
		"send_seq", sendSeq,
		"recv_ack", recvAck,
		"unacked", unacked,
		"in_flight", inFlight,
		"last_activity_ago_ms", lastActivityAgoMS,
	)
	if d.config.TraceStreams {
		slog.Info("stream.retransmit.max_exceeded",
			"conn_id", conn.ID,
			"peer_node", conn.RemoteAddr.Node,
			"local_addr", conn.LocalAddr.String(),
			"local_port", conn.LocalPort,
			"remote_addr", conn.RemoteAddr.String(),
			"remote_port", conn.RemotePort,
			"state", state.String(),
			"oldest_seq", e.seq,
			"oldest_len", len(e.data),
			"attempts", e.attempts,
			"oldest_age_ms", now.Sub(e.sentAt).Milliseconds(),
			"rto_ms", rto.Milliseconds(),
			"send_seq", sendSeq,
			"recv_ack", recvAck,
			"unacked", unacked,
			"in_flight", inFlight,
			"last_activity_ago_ms", lastActivityAgoMS,
		)
	}
}

func (d *Daemon) traceStreamPacket(event string, pktSrcNode uint32, localPort, remotePort uint16, attrs ...any) {
	if !d.config.TraceStreams {
		return
	}
	base := []any{
		"peer_node", pktSrcNode,
		"local_port", localPort,
		"remote_port", remotePort,
	}
	base = append(base, attrs...)
	slog.Info("stream."+event, base...)
}
