package daemon

import "net"

type routeCandidateKind int

const (
	routeCandidateBeacon routeCandidateKind = iota
	routeCandidateCachedConn
	routeCandidatePeerTURN
	routeCandidateOwnTURNRelay
	routeCandidateDirectUDP
)

type routeCandidate struct {
	kind routeCandidateKind
	tier int
	addr *net.UDPAddr
}

type frameRoutePolicyInput struct {
	outboundTURNOnly bool
	relay            bool
	hasBeacon        bool
	hasLocalTURN     bool
	hasPeerTURN      bool
	cachedConnNet    string
	callerAddr       *net.UDPAddr
	pathDirect       *net.UDPAddr
}

type frameRoutePlan struct {
	candidates []routeCandidate
	failClosed bool
}

func planFrameRoutes(in frameRoutePolicyInput) frameRoutePlan {
	udpAddr := preferredUDPAddr(in.callerAddr, in.pathDirect)
	var out frameRoutePlan

	if in.outboundTURNOnly {
		out.failClosed = true
		if isTURNNetwork(in.cachedConnNet) {
			out.candidates = append(out.candidates, routeCandidate{
				kind: routeCandidateCachedConn,
				tier: SendTierOutboundTurnOnlyCached,
			})
		}
		if in.hasLocalTURN && udpAddr != nil {
			out.candidates = append(out.candidates, routeCandidate{
				kind: routeCandidateOwnTURNRelay,
				tier: SendTierOutboundTurnOnlyOwnRelay,
				addr: udpAddr,
			})
		}
		if in.hasPeerTURN {
			out.candidates = append(out.candidates, routeCandidate{
				kind: routeCandidatePeerTURN,
				tier: SendTierOutboundTurnOnlyJF9,
			})
		}
		return out
	}

	if in.relay {
		if isTURNNetwork(in.cachedConnNet) {
			out.candidates = append(out.candidates, routeCandidate{
				kind: routeCandidateCachedConn,
				tier: SendTierCachedConn,
			})
		}
		if in.hasPeerTURN {
			out.candidates = append(out.candidates, routeCandidate{
				kind: routeCandidatePeerTURN,
				tier: SendTierJF9Fallback,
			})
			return out
		}
		if in.hasBeacon {
			out.candidates = append(out.candidates, routeCandidate{
				kind: routeCandidateBeacon,
				tier: SendTierBeaconRelay,
			})
			return out
		}
	}

	// Non-TURN daemons can get stuck behind a stale peer TURN route even
	// when a direct address is known. Prefer direct UDP in that mixed mode
	// until the peer is explicitly relay-marked; hide-IP peers use
	// outboundTURNOnly/local TURN and do not take this path.
	if !in.hasLocalTURN && in.hasPeerTURN && udpAddr != nil {
		out.candidates = append(out.candidates, routeCandidate{
			kind: routeCandidateDirectUDP,
			tier: SendTierDirectUDP,
			addr: udpAddr,
		})
		if in.cachedConnNet != "" && in.cachedConnNet != "udp" && !isTURNNetwork(in.cachedConnNet) {
			out.candidates = append(out.candidates, routeCandidate{
				kind: routeCandidateCachedConn,
				tier: SendTierCachedConn,
			})
		}
		return out
	}

	if in.cachedConnNet != "" && in.cachedConnNet != "udp" {
		out.candidates = append(out.candidates, routeCandidate{
			kind: routeCandidateCachedConn,
			tier: SendTierCachedConn,
		})
	}
	if !in.hasPeerTURN && udpAddr != nil {
		out.candidates = append(out.candidates, routeCandidate{
			kind: routeCandidateDirectUDP,
			tier: SendTierDirectUDP,
			addr: udpAddr,
		})
	}
	if in.hasPeerTURN {
		out.candidates = append(out.candidates, routeCandidate{
			kind: routeCandidatePeerTURN,
			tier: SendTierJF9Fallback,
		})
	}
	return out
}

func preferredUDPAddr(caller, pathDirect *net.UDPAddr) *net.UDPAddr {
	if caller != nil {
		return caller
	}
	return pathDirect
}

func isTURNNetwork(network string) bool {
	return network == "turn" || network == "turn-relay"
}

type dialFallbackPolicyInput struct {
	outboundTURNOnly bool
	hasRendezvous    bool
	hasTCP           bool
	hasBeacon        bool
}

type dialFallbackDecision struct {
	queryRendezvous bool
	tryTCP          bool
	switchToBeacon  bool
}

func planDialFallback(in dialFallbackPolicyInput) dialFallbackDecision {
	out := dialFallbackDecision{
		queryRendezvous: in.hasRendezvous,
	}
	if in.outboundTURNOnly {
		return out
	}
	out.tryTCP = in.hasTCP
	out.switchToBeacon = in.hasBeacon
	return out
}

func allowRacingBeaconRelay(in dialFallbackPolicyInput) bool {
	return !in.outboundTURNOnly && in.hasBeacon
}
