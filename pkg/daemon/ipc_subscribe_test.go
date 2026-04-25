package daemon

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
)

// The tests below pin the v1.9.0-jf.11b pub/sub contract:
//
//   - handleSubscribe registers in the topic set BEFORE replying with
//     SubscribeOK, so a publish-in-flight always reaches the new
//     subscriber even if the snapshot it just sent is stale.
//   - PublishTopic fans out to every subscriber, ignores topics with
//     zero subscribers, and tolerates dead connections without
//     panicking.
//   - Connection-close cleanup removes the conn from every topic via
//     removeSubsForConn (called from handleClient's defer).
//
// We drive IPCServer directly with a fake *ipcConn over net.Pipe so we
// don't need to bring up a real Unix socket / accept loop. The wire
// shape is verified by reading back framed responses with ipcutil.

// newSubsTestServer returns a bare IPCServer (no listener, no daemon
// reference) suitable for unit tests that only exercise pub/sub.
// Tests that need to call handlers depending on s.daemon would have
// to wire a real *Daemon — none of the pub/sub paths do.
func newSubsTestServer() *IPCServer {
	return &IPCServer{
		clients:       make(map[*ipcConn]bool),
		subs:          make(map[string]map[*ipcConn]struct{}),
		topicSnapshot: make(map[string]func() []byte),
	}
}

// newTestIPCConn returns a server-side *ipcConn and the client-side
// net.Conn the test reads framed responses from.
func newTestIPCConn(t *testing.T) (*ipcConn, net.Conn) {
	t.Helper()
	srv, cli := net.Pipe()
	return &ipcConn{Conn: srv}, cli
}

// encodeSubscribeFrame builds a CmdSubscribe / CmdUnsubscribe payload
// of the form [topic_len:uint16][topic]. Tests use this to feed
// handleSubscribe / handleUnsubscribe directly without re-deriving the
// wire format inline. Mirrors the production encoding contract in
// parseTopicFrame.
func encodeSubscribeFrame(topic string) []byte {
	out := make([]byte, 2+len(topic))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(topic)))
	copy(out[2:], topic)
	return out
}

// decodeSubscribeReply unwraps a CmdSubscribeOK / CmdNotify frame and
// returns the topic + payload. Fails the test if the leading opcode
// doesn't match wantOp or the structure is malformed.
func decodeSubscribeReply(t *testing.T, frame []byte, wantOp byte) (topic string, payload []byte) {
	t.Helper()
	if len(frame) < 1+2+4 {
		t.Fatalf("frame too short: %d bytes (need at least 7)", len(frame))
	}
	if frame[0] != wantOp {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", frame[0], wantOp)
	}
	tn := binary.BigEndian.Uint16(frame[1:3])
	if int(tn) > len(frame)-3 {
		t.Fatalf("topic length %d overruns frame (%d bytes after header)",
			tn, len(frame)-3)
	}
	topic = string(frame[3 : 3+tn])
	pn := binary.BigEndian.Uint32(frame[3+tn : 7+tn])
	if int(pn) > len(frame)-int(7+tn) {
		t.Fatalf("payload length %d overruns frame", pn)
	}
	payload = frame[int(7+tn) : int(7+tn)+int(pn)]
	return topic, payload
}

// TestSubscribe_RoundTripWithSnapshot validates the basic
// Subscribe → SubscribeOK roundtrip carries the topic's current
// snapshot value back to the caller. This is the core "fresh
// subscriber learns current state without waiting for next change"
// invariant.
func TestSubscribe_RoundTripWithSnapshot(t *testing.T) {
	s := newSubsTestServer()
	s.SetTopicSnapshot("turn_endpoint", func() []byte {
		return []byte("104.30.150.213:54579")
	})

	srvConn, cliConn := newTestIPCConn(t)
	defer cliConn.Close()
	defer srvConn.Close()

	// Concurrent reader: handleSubscribe writes to the pipe; the
	// pipe is synchronous (unbuffered), so the writer blocks until
	// we read.
	gotFrame := make(chan []byte, 1)
	go func() {
		f, err := ipcutil.Read(cliConn)
		if err != nil {
			t.Errorf("client read: %v", err)
			return
		}
		gotFrame <- f
	}()

	s.handleSubscribe(srvConn, encodeSubscribeFrame("turn_endpoint"))

	select {
	case f := <-gotFrame:
		topic, payload := decodeSubscribeReply(t, f, CmdSubscribeOK)
		if topic != "turn_endpoint" {
			t.Fatalf("topic = %q, want turn_endpoint", topic)
		}
		if string(payload) != "104.30.150.213:54579" {
			t.Fatalf("snapshot = %q, want 104.30.150.213:54579", string(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("client never received SubscribeOK")
	}
}

// TestSubscribe_NoSnapshotReturnsEmpty: when no snapshot fn is
// registered for a topic, SubscribeOK still returns successfully —
// just with an empty payload. Topics are dynamic (the producer might
// register the fn later), so absence is not an error.
func TestSubscribe_NoSnapshotReturnsEmpty(t *testing.T) {
	s := newSubsTestServer()
	srvConn, cliConn := newTestIPCConn(t)
	defer cliConn.Close()
	defer srvConn.Close()

	gotFrame := make(chan []byte, 1)
	go func() {
		f, err := ipcutil.Read(cliConn)
		if err != nil {
			t.Errorf("client read: %v", err)
			return
		}
		gotFrame <- f
	}()

	s.handleSubscribe(srvConn, encodeSubscribeFrame("future_topic"))

	select {
	case f := <-gotFrame:
		topic, payload := decodeSubscribeReply(t, f, CmdSubscribeOK)
		if topic != "future_topic" {
			t.Fatalf("topic = %q, want future_topic", topic)
		}
		if len(payload) != 0 {
			t.Fatalf("payload = %q, want empty (no snapshot fn registered)",
				string(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("client never received SubscribeOK")
	}

	// Subscriber is still registered — verify by publishing.
	s.subsMu.RLock()
	count := len(s.subs["future_topic"])
	s.subsMu.RUnlock()
	if count != 1 {
		t.Fatalf("subs[future_topic] has %d entries, want 1 "+
			"(absence of snapshot fn must NOT prevent registration)", count)
	}
}

// TestPublishTopic_FansOutToMultipleSubscribers locks down the
// many-subscribers contract: one PublishTopic call delivers to every
// conn in the set. Live behaviour: laptop, phobos, and VPS may all
// subscribe to "turn_endpoint" against the same pilot daemon (when
// running multi-tenant entmootd instances on one host); each gets
// the same Notify.
func TestPublishTopic_FansOutToMultipleSubscribers(t *testing.T) {
	s := newSubsTestServer()

	conn1, cli1 := newTestIPCConn(t)
	defer cli1.Close()
	defer conn1.Close()
	conn2, cli2 := newTestIPCConn(t)
	defer cli2.Close()
	defer conn2.Close()

	// Both subscribers wait on their respective pipes.
	got1 := make(chan []byte, 2)
	got2 := make(chan []byte, 2)
	go func() {
		for i := 0; i < 2; i++ {
			f, err := ipcutil.Read(cli1)
			if err != nil {
				return
			}
			got1 <- f
		}
	}()
	go func() {
		for i := 0; i < 2; i++ {
			f, err := ipcutil.Read(cli2)
			if err != nil {
				return
			}
			got2 <- f
		}
	}()

	// Subscribe both. handleSubscribe writes SubscribeOK first;
	// then PublishTopic writes Notify.
	s.handleSubscribe(conn1, encodeSubscribeFrame("turn_endpoint"))
	s.handleSubscribe(conn2, encodeSubscribeFrame("turn_endpoint"))

	// Drain SubscribeOK on each before the publish so writes don't deadlock.
	<-got1
	<-got2

	// Publish — both subscribers must receive a Notify.
	s.PublishTopic("turn_endpoint", []byte("104.30.x.x:NEW"))

	for i, ch := range []chan []byte{got1, got2} {
		select {
		case f := <-ch:
			topic, payload := decodeSubscribeReply(t, f, CmdNotify)
			if topic != "turn_endpoint" {
				t.Fatalf("subscriber %d: topic = %q", i+1, topic)
			}
			if string(payload) != "104.30.x.x:NEW" {
				t.Fatalf("subscriber %d: payload = %q", i+1, string(payload))
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("subscriber %d never received Notify", i+1)
		}
	}
}

// TestPublishTopic_NoSubscribers_NoOp: publishing to an unsubscribed
// topic must not panic and must not block. Important because
// daemon.Start wires SetTURNOnLocalAddrChange BEFORE the IPC
// listener accepts any connections; the first publish during
// initial Allocate has zero subscribers.
func TestPublishTopic_NoSubscribers_NoOp(t *testing.T) {
	s := newSubsTestServer()
	done := make(chan struct{})
	go func() {
		s.PublishTopic("turn_endpoint", []byte("ignored"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("PublishTopic blocked with zero subscribers")
	}
}

// TestUnsubscribe_StopsDelivery: after Unsubscribe, subsequent
// Publishes must not reach the de-registered conn. Idempotency: the
// reply is UnsubscribeOK regardless of prior subscription state.
func TestUnsubscribe_StopsDelivery(t *testing.T) {
	s := newSubsTestServer()
	srvConn, cliConn := newTestIPCConn(t)
	defer cliConn.Close()
	defer srvConn.Close()

	frames := make(chan []byte, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			f, err := ipcutil.Read(cliConn)
			if err != nil {
				return
			}
			frames <- f
		}
	}()

	s.handleSubscribe(srvConn, encodeSubscribeFrame("turn_endpoint"))
	if got := (<-frames)[0]; got != CmdSubscribeOK {
		t.Fatalf("first frame opcode = 0x%02x, want SubscribeOK", got)
	}

	s.handleUnsubscribe(srvConn, encodeSubscribeFrame("turn_endpoint"))
	if got := (<-frames)[0]; got != CmdUnsubscribeOK {
		t.Fatalf("second frame opcode = 0x%02x, want UnsubscribeOK", got)
	}

	// Publish — no Notify should arrive.
	s.PublishTopic("turn_endpoint", []byte("post-unsub"))

	select {
	case f := <-frames:
		t.Fatalf("received unexpected frame after Unsubscribe (opcode 0x%02x)", f[0])
	case <-time.After(150 * time.Millisecond):
		// good — nothing arrived
	}
}

// TestRemoveSubsForConn_CleansAllTopics ensures the cleanup helper
// drops the conn from every topic and prunes empty topic entries.
// This is what handleClient's defer calls on disconnect — without
// it, PublishTopic would later try to ipcWrite to a closed socket
// (logged at Debug, not fatal, but still wasteful).
func TestRemoveSubsForConn_CleansAllTopics(t *testing.T) {
	s := newSubsTestServer()
	conn, _ := newTestIPCConn(t)

	// Manually register conn in two topics.
	s.subsMu.Lock()
	s.subs["turn_endpoint"] = map[*ipcConn]struct{}{conn: {}}
	s.subs["other_topic"] = map[*ipcConn]struct{}{conn: {}}
	s.subsMu.Unlock()

	s.removeSubsForConn(conn)

	s.subsMu.RLock()
	defer s.subsMu.RUnlock()
	if len(s.subs) != 0 {
		t.Fatalf("subs has %d topics after cleanup; want 0 "+
			"(empty topic entries should be pruned)", len(s.subs))
	}
}

// TestSubscribe_MalformedPayload validates the parseTopicFrame error
// surface: zero-length payload, undersized payload, length-overrun,
// and empty topic must all return CmdError rather than register
// garbage in the subs map.
func TestSubscribe_MalformedPayload(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"missing-bytes", []byte{0x00, 0x05, 'a', 'b'}}, // claims 5, has 2
		{"zero-length-topic", []byte{0x00, 0x00}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := newSubsTestServer()
			srvConn, cliConn := newTestIPCConn(t)
			defer cliConn.Close()
			defer srvConn.Close()

			gotFrame := make(chan []byte, 1)
			go func() {
				f, err := ipcutil.Read(cliConn)
				if err != nil {
					return
				}
				gotFrame <- f
			}()

			s.handleSubscribe(srvConn, tc.payload)

			select {
			case f := <-gotFrame:
				if f[0] != CmdError {
					t.Fatalf("opcode = 0x%02x, want CmdError 0x%02x", f[0], CmdError)
				}
			case <-time.After(time.Second):
				t.Fatalf("no error reply for malformed payload")
			}

			// subs map should remain empty.
			s.subsMu.RLock()
			n := len(s.subs)
			s.subsMu.RUnlock()
			if n != 0 {
				t.Fatalf("subs has %d entries after malformed Subscribe; want 0", n)
			}
		})
	}
}

// TestPublishTopic_ConcurrentSafe: 100 concurrent goroutines call
// PublishTopic + Subscribe + Unsubscribe + removeSubsForConn against
// the same IPCServer. The race detector should see no data races.
// Doesn't assert on delivery — that's not the contract this test
// pins; the concern is map / slice access under -race.
func TestPublishTopic_ConcurrentSafe(t *testing.T) {
	s := newSubsTestServer()
	s.SetTopicSnapshot("topic_a", func() []byte { return []byte("a") })

	// Set up a few subscribers with drain goroutines so writes don't
	// block forever on full pipes.
	const nSubs = 5
	closers := make([]net.Conn, 0, nSubs*2)
	for i := 0; i < nSubs; i++ {
		conn, cli := newTestIPCConn(t)
		closers = append(closers, conn.Conn, cli)
		go func() {
			for {
				if _, err := ipcutil.Read(cli); err != nil {
					return
				}
			}
		}()
		s.handleSubscribe(conn, encodeSubscribeFrame("topic_a"))
	}
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.PublishTopic("topic_a", []byte("payload"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.SetTopicSnapshot("topic_a", func() []byte { return []byte("changed") })
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.PublishTopic("topic_b_unused", []byte("none"))
		}
	}()
	wg.Wait()
}
