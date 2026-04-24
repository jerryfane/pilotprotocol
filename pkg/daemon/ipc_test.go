package daemon

import (
	"encoding/binary"
	"testing"
)

// buildSetPeerEndpointsPayload constructs the wire-format payload for
// CmdSetPeerEndpoints. Mirrors parseSetPeerEndpoints:
//
//	node_id (4) | num_endpoints (1) | [network_len (1) | network | addr_len (1) | addr]*
func buildSetPeerEndpointsPayload(nodeID uint32, eps []peerEndpoint) []byte {
	out := make([]byte, 5)
	binary.BigEndian.PutUint32(out[0:4], nodeID)
	out[4] = byte(len(eps))
	for _, ep := range eps {
		out = append(out, byte(len(ep.network)))
		out = append(out, []byte(ep.network)...)
		out = append(out, byte(len(ep.addr)))
		out = append(out, []byte(ep.addr)...)
	}
	return out
}

// TestParseSetPeerEndpoints_TURN validates that the parser accepts a
// "turn" network entry alongside tcp/udp and preserves order. This is
// the layer the IPC server feeds into handleSetPeerEndpoints, which
// Part A2 routes to AddPeerTURNEndpoint.
func TestParseSetPeerEndpoints_TURN(t *testing.T) {
	eps := []peerEndpoint{
		{network: "tcp", addr: "1.2.3.4:4443"},
		{network: "turn", addr: "5.6.7.8:3478"},
		{network: "udp", addr: "9.10.11.12:37736"},
	}
	payload := buildSetPeerEndpointsPayload(42, eps)

	gotID, gotEps, err := parseSetPeerEndpoints(payload)
	if err != nil {
		t.Fatalf("parseSetPeerEndpoints: %v", err)
	}
	if gotID != 42 {
		t.Fatalf("nodeID=%d, want 42", gotID)
	}
	if len(gotEps) != 3 {
		t.Fatalf("len(eps)=%d, want 3", len(gotEps))
	}
	for i := range eps {
		if gotEps[i].network != eps[i].network {
			t.Errorf("eps[%d].network=%q, want %q", i, gotEps[i].network, eps[i].network)
		}
		if gotEps[i].addr != eps[i].addr {
			t.Errorf("eps[%d].addr=%q, want %q", i, gotEps[i].addr, eps[i].addr)
		}
	}
}

// TestAddPeerTURNEndpoint_ViaTunnelManager exercises the same call
// path handleSetPeerEndpoints takes for ep.network=="turn": parse the
// address, install into peerTURN, verify HasTURNEndpoint. We keep this
// in ipc_test.go (vs tunnel_path_test.go) so the "IPC routes turn
// endpoints correctly" invariant lives alongside the parser test.
func TestAddPeerTURNEndpoint_ViaTunnelManager(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	if err := tm.AddPeerTURNEndpoint(99, "203.0.113.7:3478"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	if !tm.HasTURNEndpoint(99) {
		t.Fatalf("HasTURNEndpoint should be true after install")
	}
	tm.mu.RLock()
	ep := tm.peerTURN[99]
	tm.mu.RUnlock()
	if ep == nil {
		t.Fatalf("peerTURN entry missing")
	}
	if ep.String() != "203.0.113.7:3478" {
		t.Fatalf("peerTURN addr=%q, want 203.0.113.7:3478", ep.String())
	}
}
