package turncreds

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// StaticProvider returns the same long-lived credentials on every
// Get. Intended for coturn and other TURN servers with fixed
// username/password auth. There is no refresh loop and no rotation —
// Subscribe returns a channel that fires exactly once, at Close, when
// it is closed.
//
// Zero value is not usable; construct with NewStaticProvider.
type StaticProvider struct {
	creds *Credentials

	mu     sync.Mutex
	ch     chan *Credentials // never receives a value; closed at Close
	closed bool
}

// NewStaticProvider validates inputs and constructs a StaticProvider.
// All four fields must be non-empty and transport must be one of
// "udp", "tcp", or "tls".
func NewStaticProvider(server, transport, username, password string) (*StaticProvider, error) {
	if server == "" {
		return nil, errors.New("turncreds: static provider: server is required")
	}
	if transport == "" {
		return nil, errors.New("turncreds: static provider: transport is required")
	}
	if !isValidTransport(transport) {
		return nil, fmt.Errorf("turncreds: static provider: invalid transport %q (want udp|tcp|tls)", transport)
	}
	if username == "" {
		return nil, errors.New("turncreds: static provider: username is required")
	}
	if password == "" {
		return nil, errors.New("turncreds: static provider: password is required")
	}

	return &StaticProvider{
		creds: &Credentials{
			ServerAddr: server,
			Transport:  transport,
			Username:   username,
			Password:   password,
			// ExpiresAt zero = never expires.
		},
		ch: make(chan *Credentials, 1),
	}, nil
}

// Get returns the single immutable Credentials pointer. The same
// pointer is returned on every call; callers must not mutate it.
// ctx is accepted for interface compliance but never consulted —
// there is no network I/O.
func (p *StaticProvider) Get(ctx context.Context) (*Credentials, error) {
	return p.creds, nil
}

// Subscribe returns the broadcast channel. It never receives a value
// for a StaticProvider — it is closed when Close is called, which is
// the only signal consumers get. Useful as a lifecycle hook.
func (p *StaticProvider) Subscribe() <-chan *Credentials {
	return p.ch
}

// Close closes the Subscribe channel. Idempotent — calling multiple
// times is safe and returns nil.
func (p *StaticProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	close(p.ch)
	return nil
}
