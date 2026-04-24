// Package turncreds provides a credential-provider abstraction for
// TURN (RFC 8656) servers. Implementations mint and rotate the
// short-lived username/password pairs that TURN clients need to
// authenticate with a relay.
//
// Two concrete implementations live alongside this file:
//
//   - StaticProvider: long-lived credentials (e.g. for coturn with a
//     fixed shared-secret user). Never rotates, Get always returns the
//     same values.
//   - CloudflareProvider: short-lived credentials minted against the
//     Cloudflare Realtime TURN REST API. Refreshes in the background
//     at ttl/2.
//
// The abstraction is intentionally narrow (Get + Subscribe + Close) so
// downstream code (pkg/daemon/transport/turn.go) can rotate its pion
// TURN client on credential change without caring which backend
// minted them.
//
// This package has no dependency on pion/turn — it speaks HTTP only.
// That keeps the credential-minting code testable with httptest.Server
// rather than a full TURN server.
package turncreds

import (
	"context"
	"time"
)

// Credentials is a snapshot of the fields a TURN client needs to
// authenticate + connect to a relay. ExpiresAt is set by the
// provider; it's the provider's best knowledge of when the creds will
// stop working, not a server-attested value.
type Credentials struct {
	// ServerAddr is the TURN server's host:port, e.g.
	// "turn.cloudflare.com:3478". Does not include a URI scheme.
	ServerAddr string

	// Transport is the TURN client → server transport, one of
	// "udp", "tcp", or "tls" (TLS is TCP-wrapped TURNS).
	Transport string

	// Username / Password are the long-term credentials presented in
	// the TURN Allocate request. For short-lived Cloudflare creds,
	// Username is typically a Unix timestamp and Password is an
	// HMAC — but the Provider treats them as opaque.
	Username string
	Password string

	// ExpiresAt is the wall-clock time after which these creds will
	// no longer be accepted by the server. Zero value means "never
	// expires" (used by StaticProvider).
	ExpiresAt time.Time
}

// Provider is the abstraction transport/turn.go consumes. It has three
// responsibilities:
//
//  1. Get: return the currently valid Credentials. May block on a
//     network round-trip the first time; subsequent calls should hit
//     a cache until refresh.
//  2. Subscribe: deliver a new *Credentials value whenever the
//     provider rotates. The returned channel is shared across all
//     callers (not per-subscriber — there's exactly one channel).
//  3. Close: stop any background refresh goroutines and release
//     resources. Idempotent.
//
// Implementations must be safe for concurrent use. Get may be called
// from many goroutines simultaneously; Close may race with Get.
type Provider interface {
	// Get returns a pointer to the current Credentials. Callers must
	// not mutate the returned struct. If the provider has cached
	// valid creds, returns them without network I/O. Otherwise mints
	// new ones; network or HTTP errors surface here.
	//
	// The context bounds any network call. If ctx is canceled
	// during a mint, Get returns ctx.Err() (possibly wrapped).
	Get(ctx context.Context) (*Credentials, error)

	// Subscribe returns a buffered (size 1) channel that receives
	// the new *Credentials each time the provider rotates. Only the
	// most recent value is buffered — if a consumer is slow and a
	// second rotation happens, the first is dropped. Closed when
	// Close() is called. For StaticProvider this channel never
	// fires (there's nothing to rotate).
	//
	// All callers receive the same channel value; this is a
	// broadcast, not a fan-out. If you need multiple consumers, wrap
	// it yourself.
	Subscribe() <-chan *Credentials

	// Close stops background refresh work and closes the Subscribe
	// channel. Safe to call multiple times.
	Close() error
}

// validTransports is the set of Transport strings accepted by both
// StaticProvider and CloudflareProvider constructors. Kept private;
// transports are identified by string for wire-format stability
// (these values also appear in config JSON and in Entmoot's
// transport-ad payload).
var validTransports = map[string]struct{}{
	"udp": {},
	"tcp": {},
	"tls": {},
}

// isValidTransport returns true iff t is one of the three supported
// TURN client-to-server transports.
func isValidTransport(t string) bool {
	_, ok := validTransports[t]
	return ok
}
