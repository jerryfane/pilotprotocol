package daemon

import "testing"

func TestValidConnTransition(t *testing.T) {
	tests := []struct {
		name string
		old  ConnState
		next ConnState
		want bool
	}{
		{name: "dial opens", old: StateClosed, next: StateSynSent, want: true},
		{name: "passive opens", old: StateClosed, next: StateSynReceived, want: true},
		{name: "dial established", old: StateSynSent, next: StateEstablished, want: true},
		{name: "passive established", old: StateSynReceived, next: StateEstablished, want: true},
		{name: "established closes", old: StateEstablished, next: StateFinWait, want: true},
		{name: "time wait reaped", old: StateTimeWait, next: StateClosed, want: true},
		{name: "closed cannot jump established", old: StateClosed, next: StateEstablished, want: false},
		{name: "time wait cannot reopen", old: StateTimeWait, next: StateSynSent, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validConnTransition(tt.old, tt.next); got != tt.want {
				t.Fatalf("validConnTransition(%s, %s) = %v, want %v", tt.old, tt.next, got, tt.want)
			}
		})
	}
}

func TestClassifyDialTimeout(t *testing.T) {
	tests := []struct {
		name              string
		retries           int
		fallbackTriggerAt int
		relayActive       bool
		fallbackAttempted bool
		rendezvousQueried bool
		fallbackResult    string
		want              string
	}{
		{name: "initial synack timeout", retries: 1, fallbackTriggerAt: 2, want: "no_synack_initial"},
		{name: "relay timeout", retries: 7, fallbackTriggerAt: 3, relayActive: true, fallbackAttempted: true, fallbackResult: "beacon_relay", want: "no_synack_relay"},
		{name: "tcp switched timeout", retries: 7, fallbackTriggerAt: 3, fallbackAttempted: true, fallbackResult: "tcp_switched", want: "no_synack_tcp"},
		{name: "rendezvous installed timeout", retries: 7, fallbackTriggerAt: 3, fallbackAttempted: true, rendezvousQueried: true, fallbackResult: "rendezvous_installed", want: "no_synack_after_rendezvous"},
		{name: "rendezvous unresolved timeout", retries: 7, fallbackTriggerAt: 3, fallbackAttempted: true, rendezvousQueried: true, fallbackResult: "rendezvous_empty", want: "no_synack_rendezvous_unresolved"},
		{name: "fallback unavailable timeout", retries: 7, fallbackTriggerAt: 3, fallbackAttempted: true, fallbackResult: "none_allowed", want: "no_synack_fallback_unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyDialTimeout(tt.retries, tt.fallbackTriggerAt, tt.relayActive, tt.fallbackAttempted, tt.rendezvousQueried, tt.fallbackResult)
			if got != tt.want {
				t.Fatalf("classifyDialTimeout() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCloseConnectionDoesNotReopenTimeWait(t *testing.T) {
	d := New(Config{Email: "stream-close@example.com", Public: true, TraceStreams: true})
	conn := d.ports.NewConnection(1004, d.Addr(), 49152)
	conn.Mu.Lock()
	conn.State = StateTimeWait
	conn.Mu.Unlock()

	d.CloseConnection(conn)

	conn.Mu.Lock()
	got := conn.State
	conn.Mu.Unlock()
	if got != StateTimeWait {
		t.Fatalf("CloseConnection moved TIME_WAIT to %s, want TIME_WAIT", got)
	}
}
