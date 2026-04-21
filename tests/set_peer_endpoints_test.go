package tests

import (
	"errors"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// These tests cover the v1.9.0-jf.7 SetPeerEndpoints IPC command —
// a new driver → daemon call that lets application-layer transport-
// advertisement protocols (Entmoot v1.2.0 gossip in the motivating
// case) install TCP endpoints into the tunnel manager's peerTCP map
// from sources other than the central registry. Reuses
// TunnelManager.AddPeerTCPEndpoint verbatim. UDP endpoints are
// accepted on the wire but ignored by the daemon (advisory only —
// the existing dial path rediscovers them from registry / same-LAN
// probes).

// TestSetPeerEndpointsInstallsTCP verifies the happy path: a valid
// TCP endpoint installed via IPC lands in the tunnel manager's
// peerTCP map, visible via the exported HasTCPEndpoint helper.
func TestSetPeerEndpointsInstallsTCP(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	if a.Daemon.Tunnels().HasTCPEndpoint(b.Daemon.NodeID()) {
		t.Fatalf("pre: A must not yet have a TCP endpoint for B")
	}

	err := a.Driver.SetPeerEndpoints(b.Daemon.NodeID(), []driver.Endpoint{
		{Network: "tcp", Addr: "198.51.100.1:4443"},
	})
	if err != nil {
		t.Fatalf("SetPeerEndpoints: %v", err)
	}

	if !a.Daemon.Tunnels().HasTCPEndpoint(b.Daemon.NodeID()) {
		t.Fatalf("post: A must have a TCP endpoint for B after install")
	}
}

// TestSetPeerEndpointsIgnoresNonTCP asserts that UDP (and other non-
// "tcp") network entries are silently dropped rather than leaked into
// peerTCP under a wrong-network label.
func TestSetPeerEndpointsIgnoresNonTCP(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	err := a.Driver.SetPeerEndpoints(b.Daemon.NodeID(), []driver.Endpoint{
		{Network: "udp", Addr: "198.51.100.2:4443"},
	})
	if err != nil {
		t.Fatalf("SetPeerEndpoints: %v", err)
	}

	if a.Daemon.Tunnels().HasTCPEndpoint(b.Daemon.NodeID()) {
		t.Fatalf("UDP-only advertisement must not install a TCP endpoint")
	}
}

// TestSetPeerEndpointsRejectsSelf preserves the jf.6 ErrDialToSelf
// guard: an externally-sourced advertisement naming the local node
// must not be able to install a TCP endpoint that would later route
// a self-dial into the multi-homed same-LAN amplification bug.
func TestSetPeerEndpointsRejectsSelf(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	err := a.Driver.SetPeerEndpoints(a.Daemon.NodeID(), []driver.Endpoint{
		{Network: "tcp", Addr: "198.51.100.3:4443"},
	})
	if err == nil {
		t.Fatalf("SetPeerEndpoints(self): expected error, got nil")
	}
	// The IPC error surface turns the sentinel into a string; match
	// against ErrDialToSelf.Error() — mirrors how other driver-side
	// tests thread daemon errors through errors.Is-compatible checks.
	if !strings.Contains(err.Error(), protocol.ErrDialToSelf.Error()) {
		t.Fatalf("SetPeerEndpoints(self): got err=%v, want contains %q",
			err, protocol.ErrDialToSelf.Error())
	}
	if a.Daemon.Tunnels().HasTCPEndpoint(a.Daemon.NodeID()) {
		t.Fatalf("self-targeted install leaked a TCP endpoint despite the guard")
	}
	// Sanity: errors.Is on the local sentinel is unaffected.
	if errors.Is(err, protocol.ErrDialToSelf) {
		t.Logf("note: driver-layer err preserves errors.Is against ErrDialToSelf")
	}
}

// TestSetPeerEndpointsRoundTrip is the end-to-end sanity check: after
// installing a TCP endpoint for B via IPC, a subsequent dial from A
// to B's real UDP address still works on the local canary. The TCP
// endpoint is purely additive fallback info; it must not break the
// direct-UDP happy path that the rest of the Pilot test harness
// relies on.
func TestSetPeerEndpointsRoundTrip(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })
	b := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })

	// Install a bogus-but-well-formed TCP endpoint for B from A's POV.
	// The address is a TEST-NET-2 address that the test machine will
	// never actually reach; we're only asserting that the metadata
	// install doesn't poison the direct-UDP dial path.
	if err := a.Driver.SetPeerEndpoints(b.Daemon.NodeID(), []driver.Endpoint{
		{Network: "tcp", Addr: "198.51.100.4:4443"},
	}); err != nil {
		t.Fatalf("SetPeerEndpoints: %v", err)
	}
	if !a.Daemon.Tunnels().HasTCPEndpoint(b.Daemon.NodeID()) {
		t.Fatalf("endpoint install not visible post-SetPeerEndpoints")
	}

	// Direct UDP dial via echo port 7 — this is the same shape used
	// by gossip_integration_test.go and tunnel_encrypt_test.go. It
	// should succeed regardless of the bogus TCP fallback metadata.
	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), 7)
	if err != nil {
		t.Fatalf("post-install dial A→B:7 failed: %v", err)
	}
	conn.Close()
}
