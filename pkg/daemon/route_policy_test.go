package daemon

import (
	"net"
	"testing"
)

func udpAddr(s string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panic(err)
	}
	return addr
}

func routeKinds(plan frameRoutePlan) []routeCandidateKind {
	out := make([]routeCandidateKind, 0, len(plan.candidates))
	for _, c := range plan.candidates {
		out = append(out, c.kind)
	}
	return out
}

func TestPlanFrameRoutes(t *testing.T) {
	direct := udpAddr("203.0.113.7:37736")

	tests := []struct {
		name       string
		in         frameRoutePolicyInput
		wantKinds  []routeCandidateKind
		failClosed bool
	}{
		{
			name: "outbound_turn_only_peer_turn_known_uses_cached_then_peer_turn_then_own_relay",
			in: frameRoutePolicyInput{
				outboundTURNOnly: true,
				hasLocalTURN:     true,
				hasPeerTURN:      true,
				cachedConnNet:    "turn",
				callerAddr:       direct,
			},
			wantKinds: []routeCandidateKind{
				routeCandidateCachedConn,
				routeCandidatePeerTURN,
				routeCandidateOwnTURNRelay,
			},
			failClosed: true,
		},
		{
			name: "outbound_turn_only_blocks_tcp_and_beacon_fallback",
			in: frameRoutePolicyInput{
				outboundTURNOnly: true,
				relay:            true,
				hasBeacon:        true,
				cachedConnNet:    "tcp",
				callerAddr:       direct,
			},
			wantKinds:  nil,
			failClosed: true,
		},
		{
			name: "peer_turn_suppresses_beacon_for_hide_ip",
			in: frameRoutePolicyInput{
				relay:       true,
				hasBeacon:   true,
				hasPeerTURN: true,
			},
			wantKinds: []routeCandidateKind{routeCandidatePeerTURN},
		},
		{
			name: "plain relay peer uses beacon",
			in: frameRoutePolicyInput{
				relay:     true,
				hasBeacon: true,
			},
			wantKinds: []routeCandidateKind{routeCandidateBeacon},
		},
		{
			name: "local_no_turn_peer_has_turn_direct_known",
			in: frameRoutePolicyInput{
				hasPeerTURN: true,
				callerAddr:  direct,
			},
			wantKinds: []routeCandidateKind{routeCandidateDirectUDP},
		},
		{
			name: "cached_turn_relay_failed_direct_available",
			in: frameRoutePolicyInput{
				hasPeerTURN:   true,
				cachedConnNet: "turn-relay",
				callerAddr:    direct,
			},
			wantKinds: []routeCandidateKind{routeCandidateDirectUDP},
		},
		{
			name: "local_turn_peer_has_turn_prefers_cached_then_peer_turn",
			in: frameRoutePolicyInput{
				hasLocalTURN:  true,
				hasPeerTURN:   true,
				cachedConnNet: "turn",
				callerAddr:    direct,
			},
			wantKinds: []routeCandidateKind{
				routeCandidateCachedConn,
				routeCandidatePeerTURN,
			},
		},
		{
			name: "normal_peer_uses_cached_then_direct",
			in: frameRoutePolicyInput{
				cachedConnNet: "tcp",
				pathDirect:    direct,
			},
			wantKinds: []routeCandidateKind{
				routeCandidateCachedConn,
				routeCandidateDirectUDP,
			},
		},
		{
			name: "outbound_turn_only_peer_no_turn_known_direct",
			in: frameRoutePolicyInput{
				outboundTURNOnly: true,
				hasLocalTURN:     true,
				pathDirect:       direct,
			},
			wantKinds:  []routeCandidateKind{routeCandidateOwnTURNRelay},
			failClosed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := planFrameRoutes(tt.in)
			if got.failClosed != tt.failClosed {
				t.Fatalf("failClosed=%v, want %v", got.failClosed, tt.failClosed)
			}
			gotKinds := routeKinds(got)
			if len(gotKinds) != len(tt.wantKinds) {
				t.Fatalf("kinds=%v, want %v", gotKinds, tt.wantKinds)
			}
			for i := range gotKinds {
				if gotKinds[i] != tt.wantKinds[i] {
					t.Fatalf("kinds=%v, want %v", gotKinds, tt.wantKinds)
				}
			}
		})
	}
}

func TestPlanDialFallback(t *testing.T) {
	tests := []struct {
		name string
		in   dialFallbackPolicyInput
		want dialFallbackDecision
	}{
		{
			name: "normal can use rendezvous tcp and beacon",
			in: dialFallbackPolicyInput{
				hasRendezvous: true,
				hasTCP:        true,
				hasBeacon:     true,
			},
			want: dialFallbackDecision{
				queryRendezvous: true,
				tryTCP:          true,
				switchToBeacon:  true,
			},
		},
		{
			name: "outbound turn only only allows rendezvous",
			in: dialFallbackPolicyInput{
				outboundTURNOnly: true,
				hasRendezvous:    true,
				hasTCP:           true,
				hasBeacon:        true,
			},
			want: dialFallbackDecision{
				queryRendezvous: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := planDialFallback(tt.in)
			if got != tt.want {
				t.Fatalf("decision=%+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAllowRacingBeaconRelay(t *testing.T) {
	if allowRacingBeaconRelay(dialFallbackPolicyInput{outboundTURNOnly: true, hasBeacon: true}) {
		t.Fatalf("outbound-turn-only must not race beacon relay")
	}
	if !allowRacingBeaconRelay(dialFallbackPolicyInput{hasBeacon: true}) {
		t.Fatalf("normal beacon-enabled dial should allow racing relay")
	}
}
