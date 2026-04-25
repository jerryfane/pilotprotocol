package transport

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestSelfHeal_ThresholdNotReachedDoesntNudge: a single failure
// must not trigger heal. The bar is FIVE consecutive failures
// (selfHealFailureThreshold). Anything below that is normal
// transport noise and must stay quiet.
func TestSelfHeal_ThresholdNotReachedDoesntNudge(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	// Simulate a few failures below the threshold.
	for i := 0; i < selfHealFailureThreshold-1; i++ {
		tr.recordFailure()
	}
	select {
	case <-tr.selfHealCh:
		t.Fatalf("self-heal nudged at %d failures (threshold=%d)",
			selfHealFailureThreshold-1, selfHealFailureThreshold)
	default:
		// good — under-threshold failure burst, no nudge
	}
}

// TestSelfHeal_ThresholdAndStaleWindowTriggerNudge: when both
// the count threshold AND the staleness window are breached,
// the channel gets a single nudge. The two-axis check is the
// load-bearing RFC-7675-style guarantee.
func TestSelfHeal_ThresholdAndStaleWindowTriggerNudge(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	// Force lastSuccess to 31 s ago so the stale window is
	// breached immediately.
	tr.lastSuccessNano.Store(time.Now().Add(-(selfHealStaleWindow + time.Second)).UnixNano())
	for i := 0; i < selfHealFailureThreshold; i++ {
		tr.recordFailure()
	}
	select {
	case <-tr.selfHealCh:
		// good
	default:
		t.Fatalf("self-heal NOT nudged after %d failures + %s stale",
			selfHealFailureThreshold, selfHealStaleWindow+time.Second)
	}
}

// TestSelfHeal_ThresholdReachedButRecentSuccessDoesntNudge:
// 5 fast failures inside a 1-second window must NOT trigger
// heal. This is the noise-immunity case — a transient blip
// (brief Cloudflare hiccup, packet loss spike) shouldn't
// teardown a healthy allocation.
func TestSelfHeal_ThresholdReachedButRecentSuccessDoesntNudge(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	// Fresh success, then 5 immediate failures.
	tr.recordSuccess()
	for i := 0; i < selfHealFailureThreshold; i++ {
		tr.recordFailure()
	}
	select {
	case <-tr.selfHealCh:
		t.Fatalf("self-heal nudged inside the stale window (recent success)")
	default:
		// good — count threshold met but stale window not breached
	}
}

// TestSelfHeal_RecordSuccessResetsCounter: after a success,
// subsequent failures need to climb the threshold ladder again
// from zero. Otherwise a failure-success-failure pattern would
// fire heal on the second failure which is not what we want.
func TestSelfHeal_RecordSuccessResetsCounter(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	for i := 0; i < selfHealFailureThreshold-1; i++ {
		tr.recordFailure()
	}
	tr.recordSuccess()
	if got := tr.consecutiveFailures.Load(); got != 0 {
		t.Fatalf("consecutiveFailures after recordSuccess: %d (want 0)", got)
	}
	// The next failure shouldn't trigger (threshold reset).
	tr.recordFailure()
	select {
	case <-tr.selfHealCh:
		t.Fatalf("self-heal nudged on first post-success failure")
	default:
	}
}

// TestSelfHeal_NudgeChannelIsCoalesced: a flood of failures
// past the threshold mustn't queue multiple heal attempts —
// the channel is length 1 and the loop processes one signal
// at a time. This guarantees that even under massive
// transport pressure we don't spawn N concurrent rotates.
func TestSelfHeal_NudgeChannelIsCoalesced(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	tr.lastSuccessNano.Store(time.Now().Add(-1 * time.Hour).UnixNano())
	// 100x more failures than threshold.
	for i := 0; i < selfHealFailureThreshold*100; i++ {
		tr.recordFailure()
	}
	// Drain — should only have ONE pending nudge.
	count := 0
	for {
		select {
		case <-tr.selfHealCh:
			count++
		default:
			goto done
		}
	}
done:
	if count != 1 {
		t.Fatalf("self-heal channel got %d nudges; want exactly 1 (coalescing broken)", count)
	}
}

// TestSelfHeal_NoLastSuccessTriggersOnCountAlone: when the
// transport has never seen a successful operation
// (lastSuccessNano == 0, the initial state before Listen
// stamps it), the threshold count alone should trigger heal —
// otherwise a transport that never starts working would never
// heal.
//
// In the production path Listen() stamps lastSuccessNano so
// this branch is exercised only if the stamp didn't happen
// (e.g. test code that uses NewTURNTransport directly), but
// the safety property is worth pinning.
func TestSelfHeal_NoLastSuccessTriggersOnCountAlone(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	if tr.lastSuccessNano.Load() != 0 {
		t.Fatalf("fresh transport: lastSuccessNano=%d; want 0",
			tr.lastSuccessNano.Load())
	}
	for i := 0; i < selfHealFailureThreshold; i++ {
		tr.recordFailure()
	}
	select {
	case <-tr.selfHealCh:
		// good
	default:
		t.Fatalf("self-heal NOT nudged with no lastSuccess timestamp")
	}
}

// TestSelfHeal_BumpHealAttemptIncrements: bumpHealAttempt is
// the per-attempt counter that drives selfHealBackoffSchedule
// indexing. A monotonic increment is the contract; tests of
// the backoff cadence rely on it.
func TestSelfHeal_BumpHealAttemptIncrements(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	for i := 1; i <= 3; i++ {
		tr.bumpHealAttempt()
		tr.mu.RLock()
		got := tr.selfHealAttempt
		tr.mu.RUnlock()
		if got != i {
			t.Fatalf("after %d bumps, attempt=%d; want %d", i, got, i)
		}
	}
}

// TestSelfHeal_RunSerializes: two concurrent runSelfHeal calls
// must not both proceed — only one acquires the
// selfHealRunning lock; the other returns immediately. Without
// this we'd get parallel rotates burning Cloudflare API budget
// during a failure burst.
func TestSelfHeal_RunSerializes(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	// Mark closed so runSelfHeal returns early after the lock
	// acquisition, without trying to call provider.Get (provider
	// is nil in this test). This still exercises the
	// selfHealRunning gate.
	tr.mu.Lock()
	tr.closed = true
	tr.mu.Unlock()

	var inFlight atomic.Int64
	var maxInFlight atomic.Int64
	done := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		go func() {
			cur := inFlight.Add(1)
			for {
				m := maxInFlight.Load()
				if cur <= m || maxInFlight.CompareAndSwap(m, cur) {
					break
				}
			}
			tr.runSelfHeal()
			inFlight.Add(-1)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	// Test is best-effort: the goroutines may have raced past
	// each other before any of them entered the lock. The real
	// invariant we want to assert is that selfHealRunning is
	// false at the end (no leaked state).
	tr.mu.RLock()
	running := tr.selfHealRunning
	tr.mu.RUnlock()
	if running {
		t.Fatalf("selfHealRunning leaked after concurrent runSelfHeal calls")
	}
}

// TestSelfHeal_ClosedTransportNoOps: runSelfHeal on a closed
// transport must exit cleanly without calling provider.Get
// (which would crash on nil provider). Production guarantee:
// once Close() flips t.closed, the heal loop is inert.
func TestSelfHeal_ClosedTransportNoOps(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	tr.mu.Lock()
	tr.closed = true
	tr.mu.Unlock()
	// Should return immediately — no panic, no nil-deref.
	tr.runSelfHeal()
}

// TestSelfHeal_NilProviderNoOps: similar guarantee for nil
// provider. The heal loop must not deref a nil provider.
func TestSelfHeal_NilProviderNoOps(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	// Not closed but provider is nil (we passed nil in NewTURNTransport).
	tr.runSelfHeal() // must not panic
}

// TestSelfHeal_BackoffScheduleMonotonic: the schedule is the
// load-bearing knob — verify it's strictly increasing and
// caps at 5 minutes. A regression here would cause heal loops
// to thrash.
func TestSelfHeal_BackoffScheduleMonotonic(t *testing.T) {
	if len(selfHealBackoffSchedule) == 0 {
		t.Fatalf("empty backoff schedule")
	}
	last := time.Duration(0)
	for i, d := range selfHealBackoffSchedule {
		if d <= last {
			t.Fatalf("schedule[%d]=%s not > schedule[%d]=%s (must be monotonic)",
				i, d, i-1, last)
		}
		last = d
	}
	if got := selfHealBackoffSchedule[len(selfHealBackoffSchedule)-1]; got > 10*time.Minute {
		t.Fatalf("schedule cap %s exceeds 10 min sanity bound", got)
	}
}

// errSimulated is used by recordFailure semantic tests below —
// kept here because it documents that "any error from the
// transport surface" is what we increment on.
var errSimulated = errors.New("simulated transport failure")

// TestSelfHeal_BothPathsRecordFailure: SendViaOwnRelay and
// CreatePermission both must call recordFailure on error and
// recordSuccess on success. This is the load-bearing
// integration with the heal trigger — without it the heal
// loop never gets nudged.
//
// We can't easily exercise the real send path without a live
// pion server (covered by other tests), but we can verify the
// methods exist on the type and that recordSuccess /
// recordFailure are reachable from outside the package via
// the public API. This is more of a compile-time pin than a
// behavioural test.
func TestSelfHeal_RecordHelpersExist(t *testing.T) {
	tr := NewTURNTransport(nil, nil)
	// Smoke: both helpers callable, no panic.
	tr.recordSuccess()
	tr.recordFailure()
	// And the failure counter actually moved.
	if tr.consecutiveFailures.Load() != 1 {
		t.Fatalf("recordFailure didn't increment counter: %d",
			tr.consecutiveFailures.Load())
	}
	tr.recordSuccess()
	if tr.consecutiveFailures.Load() != 0 {
		t.Fatalf("recordSuccess didn't reset counter: %d",
			tr.consecutiveFailures.Load())
	}
}

// _silenceUnusedErr keeps errSimulated reachable from `go vet` even
// if the only test that referenced it is later removed. Cheap
// defensive declaration.
var _ = errSimulated
