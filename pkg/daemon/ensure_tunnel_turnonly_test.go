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

func TestResolveOutboundTURNOnlyDestinationPrefersPublicRegistryOverStaleTURN(t *testing.T) {
	const peer uint32 = 45983
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
					"real_addr": "203.0.113.9:37738",
				},
				cachedAt: time.Now(),
			},
		},
	}
	defer d.tunnels.Close()

	if err := d.tunnels.AddPeerTURNEndpoint(peer, "198.51.100.44:49152"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	stale := &stubDialedConn{network: "turn", remote: "198.51.100.44:49152"}
	d.tunnels.mu.Lock()
	d.tunnels.peerConns[peer] = stale
	d.tunnels.mu.Unlock()

	if err := d.resolveOutboundTURNOnlyDestination(peer); err != nil {
		t.Fatalf("resolveOutboundTURNOnlyDestination: %v", err)
	}
	if got := d.tunnels.PeerTURNEndpoint(peer); got != "" {
		t.Fatalf("PeerTURNEndpoint=%q, want cleared", got)
	}
	if stale.closes.Load() != 1 {
		t.Fatalf("stale TURN conn closes=%d, want 1", stale.closes.Load())
	}
	d.tunnels.mu.RLock()
	got := d.tunnels.paths[peer].direct
	_, cached := d.tunnels.peerConns[peer]
	d.tunnels.mu.RUnlock()
	want := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 37738}
	if got == nil || !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("direct endpoint = %v, want %v", got, want)
	}
	if cached {
		t.Fatalf("stale peer TURN conn still cached")
	}
}

func TestEnsureTunnelOutboundTURNOnlyRefreshesExistingDestination(t *testing.T) {
	const peer uint32 = 45984
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
					"real_addr": "203.0.113.10:37739",
				},
				cachedAt: time.Now(),
			},
		},
	}
	defer d.tunnels.Close()

	if err := d.tunnels.AddPeerTURNEndpoint(peer, "198.51.100.45:49152"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	d.tunnels.mu.Lock()
	d.tunnels.getOrCreatePath(peer)
	d.tunnels.mu.Unlock()

	if err := d.ensureTunnel(peer); err != nil {
		t.Fatalf("ensureTunnel: %v", err)
	}
	if got := d.tunnels.PeerTURNEndpoint(peer); got != "" {
		t.Fatalf("PeerTURNEndpoint=%q, want cleared", got)
	}
	d.tunnels.mu.RLock()
	got := d.tunnels.paths[peer].direct
	d.tunnels.mu.RUnlock()
	want := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 37739}
	if got == nil || !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("direct endpoint = %v, want %v", got, want)
	}
}

func TestEnsureTunnelOutboundTURNOnlyKeepsExistingDestinationOnRefreshFailure(t *testing.T) {
	const peer uint32 = 45985
	d := &Daemon{
		config: Config{
			OutboundTURNOnly: true,
		},
		nodeID:       133053,
		tunnels:      NewTunnelManager(),
		epCache:      make(map[uint32]*endpointEntry),
		resolveCache: make(map[uint32]*resolveEntry),
	}
	defer d.tunnels.Close()

	if err := d.tunnels.AddPeerTURNEndpoint(peer, "198.51.100.45:49152"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	if !d.tunnels.HasOutboundTURNOnlyDestination(peer) {
		t.Fatalf("peer TURN endpoint should be a strict-mode destination")
	}

	if err := d.ensureTunnel(peer); err != nil {
		t.Fatalf("ensureTunnel should keep existing destination after refresh failure: %v", err)
	}
	if got := d.tunnels.PeerTURNEndpoint(peer); got != "198.51.100.45:49152" {
		t.Fatalf("PeerTURNEndpoint=%q, want existing endpoint", got)
	}
}

func TestEnsureTunnelOutboundTURNOnlyKeepsExistingTURNWhenRegistryAddrMalformed(t *testing.T) {
	const peer uint32 = 45987
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
					"real_addr": "not-a-host-port",
				},
				cachedAt: time.Now(),
			},
		},
	}
	defer d.tunnels.Close()

	if err := d.tunnels.AddPeerTURNEndpoint(peer, "198.51.100.46:49152"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}

	if err := d.ensureTunnel(peer); err != nil {
		t.Fatalf("ensureTunnel should keep existing TURN endpoint after malformed registry addr: %v", err)
	}
	if got := d.tunnels.PeerTURNEndpoint(peer); got != "198.51.100.46:49152" {
		t.Fatalf("PeerTURNEndpoint=%q, want existing endpoint", got)
	}
}

func TestEnsureTunnelOutboundTURNOnlyFailsWithoutDestinationOnRefreshFailure(t *testing.T) {
	const peer uint32 = 45986
	d := &Daemon{
		config: Config{
			OutboundTURNOnly: true,
		},
		nodeID:       133053,
		tunnels:      NewTunnelManager(),
		epCache:      make(map[uint32]*endpointEntry),
		resolveCache: make(map[uint32]*resolveEntry),
	}
	defer d.tunnels.Close()

	if err := d.ensureTunnel(peer); err == nil {
		t.Fatalf("ensureTunnel succeeded without any strict-mode destination")
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
