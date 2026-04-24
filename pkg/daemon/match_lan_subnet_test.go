package daemon

import "testing"

// The tests below pin the v1.9.0-jf.11a.5 same-LAN false-positive
// fix. Pre-jf.11a.5, matchLANSubnet returned a "same-LAN" hit any
// time two peers' RFC1918 LAN addresses shared a /24, even when
// the peers were on completely separate networks. Live evidence
// 2026-04-25: phobos (192.168.1.201/IT) and laptop
// (192.168.1.126/UAE) "matched" each other and stalled 7 s on a
// direct dial to a non-routable address. The fix requires both
// peers to share the same public IP (same NAT egress) before
// honoring the /24 collision.

func TestMatchLANSubnet_SamePublicIPMatches(t *testing.T) {
	ours := []string{"192.168.1.5:5000"}
	theirs := []interface{}{"192.168.1.10:5000"}
	got := matchLANSubnet(ours, theirs, "203.0.113.7:54321", "203.0.113.7:37736")
	if got != "192.168.1.10:5000" {
		t.Fatalf("matchLANSubnet = %q; want \"192.168.1.10:5000\" "+
			"(same /24 subnet, same public IP — true same-LAN match)", got)
	}
}

func TestMatchLANSubnet_DifferentPublicIPNoMatch(t *testing.T) {
	// The phobos<->laptop reproducer: both behind their own NATs
	// on default-router 192.168.1.0/24, but with different public
	// IPs (different countries). Pre-jf.11a.5 returned a match.
	// Post-fix returns "" — public IPs must match.
	ours := []string{"192.168.1.126:5000"}
	theirs := []interface{}{"192.168.1.201:5000"}
	got := matchLANSubnet(ours, theirs, "5.30.217.114:51619", "37.27.59.89:37736")
	if got != "" {
		t.Fatalf("matchLANSubnet = %q; want \"\" "+
			"(same RFC1918 /24 but different public IPs — peers are "+
			"on separate physical networks; treating them as same-LAN "+
			"is the very FP this fix targets)", got)
	}
}

func TestMatchLANSubnet_EmptyOurPublicSkips(t *testing.T) {
	// Without our own public IP we cannot run the precheck. Fail
	// closed: refuse the same-LAN shortcut. (Caller can recover
	// via the regular real-address path — direct UDP from the
	// registry-resolved IP.)
	ours := []string{"192.168.1.5:5000"}
	theirs := []interface{}{"192.168.1.10:5000"}
	got := matchLANSubnet(ours, theirs, "", "203.0.113.7:37736")
	if got != "" {
		t.Fatalf("matchLANSubnet with empty ourPublic = %q; want \"\" "+
			"(precheck must fail closed on missing data)", got)
	}
}

func TestMatchLANSubnet_EmptyTheirPublicSkips(t *testing.T) {
	// -hide-ip / -no-registry-endpoint peers register with
	// real_addr = "" (jf.11a.4). For those peers, same-LAN
	// reachability is moot — they route via TURN regardless.
	// Skip the shortcut.
	ours := []string{"192.168.1.5:5000"}
	theirs := []interface{}{"192.168.1.10:5000"}
	got := matchLANSubnet(ours, theirs, "203.0.113.7:54321", "")
	if got != "" {
		t.Fatalf("matchLANSubnet with empty theirPublic = %q; want \"\" "+
			"(hide-ip peers must skip the LAN shortcut)", got)
	}
}

func TestMatchLANSubnet_SamePublicIPDifferentSubnetNoMatch(t *testing.T) {
	// Same NAT egress but different RFC1918 subnets (e.g. one
	// peer on 10.0.0.0/24, another on 192.168.1.0/24 behind a
	// double-NAT). The /24 mismatch wins; no LAN shortcut.
	ours := []string{"10.0.0.5:5000"}
	theirs := []interface{}{"192.168.1.10:5000"}
	got := matchLANSubnet(ours, theirs, "203.0.113.7:54321", "203.0.113.7:37736")
	if got != "" {
		t.Fatalf("matchLANSubnet = %q; want \"\" "+
			"(public IP matches but /24 subnets differ — not same LAN)", got)
	}
}

func TestMatchLANSubnet_MalformedPublicAddrSkips(t *testing.T) {
	// Garbage public addresses fail to split host/port. Fail
	// closed rather than panic or accept.
	ours := []string{"192.168.1.5:5000"}
	theirs := []interface{}{"192.168.1.10:5000"}
	got := matchLANSubnet(ours, theirs, "garbage", "garbage")
	if got != "" {
		t.Fatalf("matchLANSubnet with malformed public = %q; want \"\"", got)
	}
}
