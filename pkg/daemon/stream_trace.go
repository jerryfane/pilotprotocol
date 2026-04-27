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

func (d *Daemon) removeConnection(conn *Connection, reason string) {
	if conn == nil {
		return
	}
	d.traceStream("removed", conn, "reason", reason)
	d.ports.RemoveConnection(conn.ID)
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
