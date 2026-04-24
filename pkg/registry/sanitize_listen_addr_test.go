package registry

import "testing"

// TestSanitizeListenAddr_EmptyClientMeansNoEndpoint pins the v1.9.0-
// jf.11a.4 privacy fix: when a client registers with listen_addr="",
// the sanitizer must return "" (not backfill from the TCP source IP).
//
// Pre-jf.11a.4 behavior silently leaked the client's TCP source IP
// as node.RealAddr, defeating -no-registry-endpoint. A laptop in
// full -hide-ip mode would still expose its UAE residential IP to
// every peer that did a registry resolve — the very leak the flag
// exists to prevent.
func TestSanitizeListenAddr_EmptyClientMeansNoEndpoint(t *testing.T) {
	// Simulates a -hide-ip + -no-registry-endpoint daemon whose TCP
	// registration connection lands at the registry from its real
	// residential IP. The client supplies no listen_addr.
	got := sanitizeListenAddr("5.30.217.114:51619", "")
	if got != "" {
		t.Fatalf("sanitizeListenAddr(%q, %q) = %q; want \"\" "+
			"(empty clientAddr must NOT fall back to the TCP source — "+
			"that leaks the caller's real IP into node.RealAddr and "+
			"defeats -no-registry-endpoint)",
			"5.30.217.114:51619", "", got)
	}
}

// TestSanitizeListenAddr_ClientPortRespected confirms the
// pre-existing and still-correct behavior: when clientAddr is
// non-empty, the sanitizer keeps the IP from the TCP source (so a
// client can't spoof someone else's IP) but takes the port from the
// client (which may differ from the TCP source port, e.g. client
// listens on UDP:4000 but connected to us over a TCP ephemeral).
func TestSanitizeListenAddr_ClientPortRespected(t *testing.T) {
	got := sanitizeListenAddr("203.0.113.5:54321", "0.0.0.0:4000")
	want := "203.0.113.5:4000"
	if got != want {
		t.Fatalf("sanitizeListenAddr = %q; want %q "+
			"(IP from TCP source, port from client)", got, want)
	}
}

// TestSanitizeListenAddr_MalformedClientAddr: if the client sends a
// garbage listen_addr, fall back to the full TCP source. This keeps
// the legacy robustness: a misconfigured client still gets
// registered with its observed IP+port so peers can reach it.
// Not applicable when clientAddr is explicitly empty — that case is
// the privacy branch tested above.
func TestSanitizeListenAddr_MalformedClientAddr(t *testing.T) {
	got := sanitizeListenAddr("203.0.113.5:54321", "not-a-valid-addr")
	want := "203.0.113.5:54321"
	if got != want {
		t.Fatalf("sanitizeListenAddr with malformed client = %q; want %q "+
			"(fall back to full TCP source on parse failure)",
			got, want)
	}
}

// TestSanitizeListenAddr_IPv6ClientPort pins IPv6 host/port splitting
// works — guards against regressions that break bracketed-host
// handling in the pre-fix early-return path.
func TestSanitizeListenAddr_IPv6ClientPort(t *testing.T) {
	got := sanitizeListenAddr("[2001:db8::1]:54321", "[::]:4000")
	want := "[2001:db8::1]:4000"
	if got != want {
		t.Fatalf("sanitizeListenAddr IPv6 = %q; want %q", got, want)
	}
}
