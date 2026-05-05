package daemon

import (
	"net"
	"testing"
	"time"
)

func TestEnsureTunnelOutboundTURNOnlyResolvesExistingPeerWithoutDestination(t *testing.T) {
	const peer uint32 = 45981
	d := &Daemon{
		config: Config{
			OutboundTURNOnly: true,
		},
		nodeID:  133053,
		tunnels: NewTunnelManager(),
		epCache: make(map[uint32]*endpointEntry),
		resolveCache: map[uint32]*resolveEntry{
			peer: {
				resp: map[string]interface{}{
					"real_addr": "203.0.113.7:37736",
				},
				cachedAt: time.Now(),
			},
		},
	}
	defer d.tunnels.Close()

	d.tunnels.mu.Lock()
	d.tunnels.getOrCreatePath(peer)
	d.tunnels.mu.Unlock()

	if d.tunnels.HasOutboundTURNOnlyDestination(peer) {
		t.Fatalf("fresh relay-only path unexpectedly has a strict-mode destination")
	}

	if err := d.ensureTunnel(peer); err != nil {
		t.Fatalf("ensureTunnel: %v", err)
	}

	d.tunnels.mu.RLock()
	got := d.tunnels.paths[peer].direct
	d.tunnels.mu.RUnlock()
	want := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 37736}
	if got == nil || !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("direct endpoint = %v, want %v", got, want)
	}
	if !d.tunnels.HasOutboundTURNOnlyDestination(peer) {
		t.Fatalf("resolved peer should now have a strict-mode destination")
	}
}

func TestResolveOutboundTURNOnlyDestinationUsesCachedResolveWithoutKeyExchange(t *testing.T) {
	const peer uint32 = 45982
	d := &Daemon{
		config: Config{
			OutboundTURNOnly: true,
		},
		nodeID:  133053,
		tunnels: NewTunnelManager(),
		epCache: make(map[uint32]*endpointEntry),
		resolveCache: map[uint32]*resolveEntry{
			peer: {
				resp: map[string]interface{}{
					"real_addr": "203.0.113.8:37737",
				},
				cachedAt: time.Now(),
			},
		},
	}
	defer d.tunnels.Close()

	d.tunnels.mu.Lock()
	d.tunnels.encrypt = true
	d.tunnels.mu.Unlock()

	if err := d.resolveOutboundTURNOnlyDestination(peer); err != nil {
		t.Fatalf("resolveOutboundTURNOnlyDestination: %v", err)
	}
	d.tunnels.mu.RLock()
	got := d.tunnels.paths[peer].direct
	d.tunnels.mu.RUnlock()
	d.tunnels.pendMu.Lock()
	pending := len(d.tunnels.pending[peer])
	d.tunnels.pendMu.Unlock()
	want := &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 37737}
	if got == nil || !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("direct endpoint = %v, want %v", got, want)
	}
	if pending != 0 {
		t.Fatalf("pending key exchange frames=%d, want 0", pending)
	}
}

func TestHasOutboundTURNOnlyDestination(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	const peer uint32 = 7

	if tm.HasOutboundTURNOnlyDestination(peer) {
		t.Fatalf("empty peer unexpectedly has strict-mode destination")
	}

	tm.mu.Lock()
	tm.getOrCreatePath(peer)
	tm.mu.Unlock()
	if tm.HasOutboundTURNOnlyDestination(peer) {
		t.Fatalf("path without direct endpoint unexpectedly has strict-mode destination")
	}

	tm.AddPeer(peer, &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 1004})
	if !tm.HasOutboundTURNOnlyDestination(peer) {
		t.Fatalf("direct endpoint should be a strict-mode destination")
	}
}
