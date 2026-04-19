// Package transport defines the pluggable byte-movement layer that sits
// underneath Pilot's tunnel encryption and peer framing. The abstraction
// lets the same Pilot wire format travel over different byte transports
// (UDP today, TCP next, QUIC/WebSocket/… later) without any code above
// the transport layer caring which one carried a given frame.
//
// Design notes:
//
//   - Transports are byte-movers. They do not understand tunnel
//     encryption, nodeIDs, beacon wrappers, or any Pilot protocol
//     semantics. They hand frames up to the caller, and the caller
//     parses headers and dispatches.
//
//   - Receive is channel-based. Every Transport's Listen starts a
//     goroutine that writes incoming frames onto a shared sink; a
//     single dispatcher in TunnelManager consumes that sink. Adding a
//     new transport is purely additive — the dispatcher sees frames
//     arriving from any transport via the same channel.
//
//   - Send is connection-oriented at the interface level even though
//     UDP is connectionless underneath. Dial returns a DialedConn that
//     the caller holds onto for subsequent sends to the same peer; for
//     UDP this is a trivial object that writes via the shared socket,
//     for TCP it's a real pooled connection. Uniform API, different
//     implementations.
//
//   - Endpoints are opaque. Each transport understands its own
//     endpoint format; callers use Endpoint.Network() to route and
//     Endpoint.String() for logs/serialization only. The wider daemon
//     does not depend on concrete UDP/TCP address types.
//
// Concurrency contract:
//
//   - Listen must be safe to call exactly once per Transport instance.
//     Subsequent Listens return an error.
//   - Dial must be safe to call concurrently. Implementations may
//     internally pool connections but that is not observable.
//   - Close must be idempotent and must unblock any in-flight Listen
//     goroutines by closing the underlying socket. The sink channel is
//     left open — the caller (TunnelManager) owns its lifecycle.
//   - DialedConn.Send must be safe to call concurrently. UDP's impl
//     is inherently threadsafe; TCP's impl serializes writes behind a
//     mutex.
package transport

import (
	"context"
	"net"
)

// Endpoint identifies a reachable peer location for a specific
// transport. Implementations of this interface are produced and
// consumed by a single transport; cross-transport comparisons are
// meaningless.
//
// The daemon treats Endpoints opaquely. The only operations callers
// perform are Network() (to route sends to the correct Transport) and
// String() (for logs and registry serialization round-trip).
type Endpoint interface {
	// Network returns the transport identifier that produced this
	// endpoint. Matches Transport.Name(): "udp", "tcp", "quic", ...
	// Used to route outbound sends to the matching transport.
	Network() string

	// String returns a stable human-readable form suitable for logs
	// and for registry serialization. For IP-based transports this is
	// "host:port"; other transports may format differently. The form
	// MUST round-trip through the transport's ParseEndpoint.
	String() string
}

// InboundFrame is the unit delivered by every Transport's Listen
// goroutine onto the shared sink channel. The Frame is the opaque byte
// slice Pilot's tunnel layer hands to handleEncrypted/handleKeyExchange/
// etc. The From endpoint identifies who sent it and on which transport.
type InboundFrame struct {
	// Frame is the raw bytes of a single Pilot wire frame. The buffer
	// is owned by the Transport until it lands on the sink; once
	// delivered, the caller owns it and may mutate or retain it.
	Frame []byte

	// From is the remote endpoint the frame arrived from. For UDP this
	// is the datagram's source address; for TCP it's the remote end of
	// the accepted connection.
	From Endpoint

	// Reply is a write-side handle to the specific connection the
	// frame arrived on. For connection-oriented transports (TCP) this
	// is the accepted socket — essential because a NAT'd peer that
	// dialled us inbound has no separately-listenable endpoint we
	// could Dial back to; replies must flow through the same
	// connection. For connectionless transports (UDP) it's a trivial
	// writer pointing at the source address via the shared socket.
	//
	// May be nil if a transport's Listen path can't synthesize a reply
	// channel (e.g. one-way datagram delivery where the source can't
	// be replied to directly).
	Reply DialedConn
}

// DialedConn is a write-side handle to a peer. For UDP it is a thin
// object that writes via the shared socket to a fixed destination
// address; for TCP it is a pooled persistent connection. Semantics
// intentionally match the common case ("I need to send some bytes to
// this peer; do the right thing") without exposing connection-oriented
// vs connectionless details.
//
// Receive is NOT symmetric with Send. Incoming frames always flow via
// the Transport's Listen sink channel, never out of DialedConn — so the
// same frame dispatcher handles both "peer I dialled sent me a reply"
// and "peer dialled me and sent something." DialedConn is write-only
// from the caller's perspective.
type DialedConn interface {
	// Send writes one Pilot frame to the peer. Blocks until the write
	// completes or fails. Safe to call concurrently from multiple
	// goroutines.
	Send(frame []byte) error

	// RemoteEndpoint returns the peer endpoint this Conn is connected
	// to. Stable for the lifetime of the Conn.
	RemoteEndpoint() Endpoint

	// Close tears down the connection. Must be idempotent. For UDP
	// (where the Conn does not own the socket) this is a no-op beyond
	// bookkeeping; for TCP it closes the underlying TCP connection and
	// removes it from any pool.
	Close() error
}

// Transport is a byte-movement layer between peers. One Transport
// instance per protocol per daemon; multiple transports coexist inside
// a single TunnelManager.
type Transport interface {
	// Name is the transport identifier, matching Endpoint.Network() on
	// endpoints produced by this transport. Must be stable across
	// process restarts so registry lookups resolve consistently
	// ("udp", "tcp", ...).
	Name() string

	// Listen binds the transport to addr and begins feeding received
	// frames onto sink. Returns once the listener is accepting; a
	// background goroutine owns the socket after that.
	//
	// Calling Listen more than once on a single Transport instance is
	// an error. sink is caller-owned and is NOT closed by the
	// transport; the caller should not close it either while the
	// transport is running.
	Listen(addr string, sink chan<- InboundFrame) error

	// LocalAddr returns the bound address after Listen has succeeded.
	// Returns nil if the transport is not listening (e.g. an outbound-
	// only dialler).
	LocalAddr() net.Addr

	// Dial acquires or reuses a DialedConn suitable for sending to ep.
	// For UDP this is effectively free (returns a trivial writer
	// pointing at the shared socket). For TCP this may open a new
	// connection or reuse a pooled one; respect ctx for cancellation
	// and timeout.
	//
	// The endpoint's Network() must match this Transport's Name();
	// callers enforce that before calling Dial.
	Dial(ctx context.Context, ep Endpoint) (DialedConn, error)

	// ParseEndpoint inflates a string form (as produced by
	// Endpoint.String()) back into a usable Endpoint for this
	// transport. Used by the TunnelManager when reading registry
	// payloads.
	ParseEndpoint(s string) (Endpoint, error)

	// Close shuts down the listener (if any) and invalidates any
	// DialedConn previously returned by Dial. Idempotent.
	Close() error
}
