package transport

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
)

// TestTURN_OnLocalAddrChange_FiresOnInitialAllocate locks the
// v1.9.0-jf.11b contract for fresh allocations: SetOnLocalAddrChange
// callback fires exactly once after Listen succeeds, with the
// pion-assigned relay address. This is what the daemon hooks to
// publish CmdNotify for the "turn_endpoint" topic so the very first
// subscriber learns the value the same instant pion does, without
// waiting for a polling tick.
func TestTURN_OnLocalAddrChange_FiresOnInitialAllocate(t *testing.T) {
	serverAddr, cleanup := turnTestServer(t, map[string]string{"u": "p"})
	defer cleanup()

	provider := newRotatingProvider(&turncreds.Credentials{
		ServerAddr: serverAddr,
		Transport:  "udp",
		Username:   "u",
		Password:   "p",
	})
	defer provider.Close()

	sink := make(chan InboundFrame, 8)
	tt := NewTURNTransport(provider, sink)
	defer tt.Close()

	got := make(chan string, 1)
	tt.SetOnLocalAddrChange(func(addr string) {
		select {
		case got <- addr:
		default:
		}
	})

	if err := tt.Listen("", sink); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	select {
	case addr := <-got:
		if addr == "" {
			t.Fatalf("callback fired with empty address; want pion-assigned relay addr")
		}
		// Sanity: returned addr should match LocalAddr().
		la := tt.LocalAddr()
		if la == nil || la.String() != addr {
			t.Fatalf("callback addr %q != LocalAddr() %v", addr, la)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("callback never fired after Listen")
	}
}

// TestTURN_OnLocalAddrChange_FiresOnRotation pins the post-rotation
// firing: when the rotationLoop swaps in a new pion client (e.g.
// credentials refreshed by the cloudflare provider), the callback
// must fire AGAIN with the new relay address. This is the steady-
// state Cloudflare-rotation scenario: pilot holds an allocation for
// hours, Cloudflare hands out fresh credentials, pion re-allocates
// to a new port, subscribers must see the new port within ~1 s of
// the swap.
func TestTURN_OnLocalAddrChange_FiresOnRotation(t *testing.T) {
	serverAddr, cleanup := turnTestServer(t, map[string]string{"u": "p", "u2": "p2"})
	defer cleanup()

	provider := newRotatingProvider(&turncreds.Credentials{
		ServerAddr: serverAddr,
		Transport:  "udp",
		Username:   "u",
		Password:   "p",
	})
	defer provider.Close()

	sink := make(chan InboundFrame, 8)
	tt := NewTURNTransport(provider, sink)
	defer tt.Close()

	var (
		mu      sync.Mutex
		seen    []string
		fireCnt atomic.Int32
	)
	tt.SetOnLocalAddrChange(func(addr string) {
		mu.Lock()
		seen = append(seen, addr)
		mu.Unlock()
		fireCnt.Add(1)
	})

	if err := tt.Listen("", sink); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	// Wait for initial Allocate callback.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && fireCnt.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if fireCnt.Load() != 1 {
		t.Fatalf("after Listen: fireCnt = %d, want 1", fireCnt.Load())
	}

	// Trigger a rotation. The rotatingProvider's subCh delivers
	// the new credentials to TURNTransport's rotationLoop, which
	// builds a new pion client and swaps it in.
	provider.Rotate(&turncreds.Credentials{
		ServerAddr: serverAddr,
		Transport:  "udp",
		Username:   "u2",
		Password:   "p2",
	})

	// Wait for the second callback. Rotation involves a real pion
	// allocation against the test server — give it generous slack.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && fireCnt.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if fireCnt.Load() < 2 {
		t.Fatalf("after Rotate: fireCnt = %d, want 2 (initial + rotation)",
			fireCnt.Load())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("seen addresses: %v; expected 2 entries", seen)
	}
	if seen[0] == seen[1] {
		// Pion's test server picks a fresh ephemeral on each
		// Allocate, so the two addresses MUST differ. If they
		// don't, the callback is being called twice with the
		// same value (would silently waste a transport_ad
		// re-emit).
		t.Fatalf("callback fired twice with same addr %q; expected new relay after rotation",
			seen[0])
	}
}
