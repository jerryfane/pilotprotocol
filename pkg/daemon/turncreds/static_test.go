package turncreds

import (
	"context"
	"testing"
	"time"
)

func TestStaticProvider_HappyPath(t *testing.T) {
	p, err := NewStaticProvider("turn.example.com:3478", "udp", "alice", "hunter2")
	if err != nil {
		t.Fatalf("NewStaticProvider: %v", err)
	}
	defer p.Close()

	creds, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if creds.ServerAddr != "turn.example.com:3478" {
		t.Errorf("ServerAddr = %q, want %q", creds.ServerAddr, "turn.example.com:3478")
	}
	if creds.Transport != "udp" {
		t.Errorf("Transport = %q, want %q", creds.Transport, "udp")
	}
	if creds.Username != "alice" {
		t.Errorf("Username = %q, want %q", creds.Username, "alice")
	}
	if creds.Password != "hunter2" {
		t.Errorf("Password = %q, want %q", creds.Password, "hunter2")
	}
	if !creds.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero", creds.ExpiresAt)
	}

	// Same pointer on repeat calls.
	creds2, _ := p.Get(context.Background())
	if creds != creds2 {
		t.Errorf("Get returned different pointer on second call")
	}
}

func TestStaticProvider_SubscribeDoesNotFire(t *testing.T) {
	p, err := NewStaticProvider("turn.example.com:3478", "tcp", "bob", "pw")
	if err != nil {
		t.Fatalf("NewStaticProvider: %v", err)
	}

	ch := p.Subscribe()

	// Should not receive anything in a short window.
	select {
	case <-ch:
		t.Errorf("Subscribe channel fired unexpectedly")
	case <-time.After(50 * time.Millisecond):
	}

	// Close closes the channel; the previously returned channel
	// should become readable (receiving zero value).
	if err := p.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case v, ok := <-ch:
		if ok {
			t.Errorf("Subscribe channel produced value on close: %v", v)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Subscribe channel did not close after Close()")
	}
}

func TestStaticProvider_CloseIdempotent(t *testing.T) {
	p, err := NewStaticProvider("turn.example.com:3478", "tls", "u", "p")
	if err != nil {
		t.Fatalf("NewStaticProvider: %v", err)
	}

	if err := p.Close(); err != nil {
		t.Errorf("Close #1: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close #2: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close #3: %v", err)
	}
}

func TestStaticProvider_ConstructorValidation(t *testing.T) {
	cases := []struct {
		name                        string
		server, transp, user, pass  string
	}{
		{"missing server", "", "udp", "u", "p"},
		{"missing transport", "s:1", "", "u", "p"},
		{"invalid transport", "s:1", "sctp", "u", "p"},
		{"missing username", "s:1", "udp", "", "p"},
		{"missing password", "s:1", "udp", "u", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewStaticProvider(tc.server, tc.transp, tc.user, tc.pass)
			if err == nil {
				p.Close()
				t.Errorf("expected error, got nil")
			}
		})
	}
}
