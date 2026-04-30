package driver

import (
	"encoding/binary"
	"io"
	"testing"
)

func TestRegisterRecvChAppliesPendingClose(t *testing.T) {
	c := &ipcClient{
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:  make(map[uint32][][]byte),
		pendClose: make(map[uint32]struct{}),
	}
	c.pendClose[42] = struct{}{}

	ch := c.registerRecvCh(42)
	if _, ok := <-ch; ok {
		t.Fatalf("registerRecvCh left channel open after pending CloseOK")
	}
	if _, ok := c.recvChs[42]; ok {
		t.Fatalf("closed conn registered in recvChs")
	}
}

func TestRegisterRecvChDrainsPendingRecvBeforePendingClose(t *testing.T) {
	c := &ipcClient{
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:  make(map[uint32][][]byte),
		pendClose: make(map[uint32]struct{}),
	}
	c.pendRecv[42] = [][]byte{[]byte("hello")}
	c.pendClose[42] = struct{}{}

	ch := c.registerRecvCh(42)
	if got, ok := <-ch; !ok || string(got) != "hello" {
		t.Fatalf("first recv = %q, %v; want hello, true", got, ok)
	}
	if _, ok := <-ch; ok {
		t.Fatalf("pending CloseOK did not close channel after draining data")
	}
	if _, ok := c.recvChs[42]; ok {
		t.Fatalf("closed conn registered in recvChs")
	}
}

func TestConnReadSeesPendingCloseAsEOF(t *testing.T) {
	c := &ipcClient{
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:  make(map[uint32][][]byte),
		pendClose: make(map[uint32]struct{}),
	}
	c.pendClose[42] = struct{}{}

	conn := &Conn{
		id:         42,
		ipc:        c,
		recvCh:     c.registerRecvCh(42),
		deadlineCh: make(chan struct{}),
	}
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read err = %v, want EOF", err)
	}
}

func TestSendResultFailureClosesActiveRecvCh(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}
	ch := c.registerRecvCh(42)

	c.handleSendResultFailure(42)

	if _, ok := <-ch; ok {
		t.Fatalf("send-result failure left recv channel open")
	}
	if _, ok := c.recvChs[42]; ok {
		t.Fatalf("send-result failure left recvCh registered")
	}
}

func TestSendResultFailureWithoutActiveRecvDoesNotBecomePendingClose(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}

	c.handleSendResultFailure(42)

	if _, ok := c.pendClose[42]; ok {
		t.Fatalf("send-result failure without active recvCh created pending close")
	}
	if _, ok := c.pendingRegister[42]; ok {
		t.Fatalf("send-result failure without active recvCh left pending registration")
	}

	ch := c.registerRecvCh(42)
	select {
	case _, ok := <-ch:
		t.Fatalf("send-result failure without active recvCh closed reused channel: ok=%v", ok)
	default:
	}
	if _, ok := c.recvChs[42]; !ok {
		t.Fatalf("reused conn ID was not registered after stale send-result failure")
	}
}

func TestDuplicateSendResultFailuresDoNotLeakPendingClose(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}
	ch := c.registerRecvCh(42)

	c.handleSendResultFailure(42)
	c.handleSendResultFailure(42)
	c.closeRecvCh(42)

	if _, ok := <-ch; ok {
		t.Fatalf("send-result failure left recv channel open")
	}
	if _, ok := c.pendClose[42]; ok {
		t.Fatalf("duplicate failure/close created pending close")
	}
	if _, ok := c.recvChs[42]; ok {
		t.Fatalf("duplicate failure/close left recvCh registered")
	}
}

func TestLateRecvAfterSendResultFailureIsDropped(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}
	ch := c.registerRecvCh(42)

	c.handleSendResultFailure(42)
	if _, ok := <-ch; ok {
		t.Fatalf("send-result failure left recv channel open")
	}

	c.handleRecvPayload(recvPayload(42, []byte("stale")))

	c.recvMu.Lock()
	if _, ok := c.recvChs[42]; ok {
		t.Fatalf("send-result failure left recvCh registered")
	}
	if _, ok := c.pendRecv[42]; ok {
		t.Fatalf("send-result failure left pending recv data")
	}
	if _, ok := c.pendingRegister[42]; ok {
		t.Fatalf("send-result failure left pending registration")
	}
	c.recvMu.Unlock()
}

func TestTruePreRegistrationCloseStillBecomesPendingClose(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}

	c.markPendingRegister(42)
	c.closeRecvCh(42)

	if _, ok := c.pendClose[42]; !ok {
		t.Fatalf("pre-registration CloseOK did not create pending close")
	}
	ch := c.registerRecvCh(42)
	if _, ok := <-ch; ok {
		t.Fatalf("pending CloseOK did not close registered channel")
	}
}

func TestUnknownCloseAndRecvWithoutPendingRegistrationAreDropped(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}

	c.closeRecvCh(42)
	c.handleRecvPayload(recvPayload(42, []byte("stale")))

	if _, ok := c.pendClose[42]; ok {
		t.Fatalf("unknown CloseOK created pending close without pending registration")
	}
	if _, ok := c.pendRecv[42]; ok {
		t.Fatalf("unknown Recv created pending recv without pending registration")
	}
	if _, ok := c.pendingRegister[42]; ok {
		t.Fatalf("unknown frames created pending registration")
	}
}

func TestPendingRegistrationBuffersRecvBeforeRegister(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}

	c.markPendingRegister(42)
	c.handleRecvPayload(recvPayload(42, []byte("hello")))

	ch := c.registerRecvCh(42)
	if got, ok := <-ch; !ok || string(got) != "hello" {
		t.Fatalf("pending recv = %q, %v; want hello, true", got, ok)
	}
	if _, ok := c.pendingRegister[42]; ok {
		t.Fatalf("registerRecvCh left pending registration")
	}
}

func TestUnregisterSuppressesLaterCloseAndAllowsReuse(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}
	ch := c.registerRecvCh(42)

	c.unregisterRecvCh(42)
	c.closeRecvCh(42)
	c.handleSendResultFailure(42)

	if _, ok := c.pendClose[42]; ok {
		t.Fatalf("post-unregister duplicate close created pending close")
	}
	select {
	case _, ok := <-ch:
		t.Fatalf("unregister closed/read old channel unexpectedly: ok=%v", ok)
	default:
	}

	reused := c.registerRecvCh(42)
	select {
	case _, ok := <-reused:
		t.Fatalf("closed marker poisoned reused conn ID: ok=%v", ok)
	default:
	}
	if _, ok := c.recvChs[42]; !ok {
		t.Fatalf("reused conn ID was not registered")
	}
}

func TestHighChurnClosesDoNotAccumulatePendingState(t *testing.T) {
	c := &ipcClient{
		recvChs:         make(map[uint32]chan []byte),
		pendRecv:        make(map[uint32][][]byte),
		pendClose:       make(map[uint32]struct{}),
		pendingRegister: make(map[uint32]struct{}),
	}

	for id := uint32(1); id <= 1000; id++ {
		ch := c.registerRecvCh(id)
		c.unregisterRecvCh(id)
		c.closeRecvCh(id)
		c.handleSendResultFailure(id)
		c.handleRecvPayload(recvPayload(id, []byte("late")))
		select {
		case _, ok := <-ch:
			t.Fatalf("unregister closed/read old channel unexpectedly for id %d: ok=%v", id, ok)
		default:
		}
	}

	if len(c.pendingRegister) != 0 {
		t.Fatalf("pendingRegister size = %d, want 0", len(c.pendingRegister))
	}
	if len(c.pendClose) != 0 {
		t.Fatalf("pendClose size = %d, want 0", len(c.pendClose))
	}
	if len(c.pendRecv) != 0 {
		t.Fatalf("pendRecv size = %d, want 0", len(c.pendRecv))
	}
}

func TestDecodeSendResultFormats(t *testing.T) {
	var legacy [6]byte
	binary.BigEndian.PutUint32(legacy[0:4], 42)
	binary.BigEndian.PutUint16(legacy[4:6], sendResultConnectionNotFound)
	connID, code, ok := decodeSendResult(legacy[:])
	if !ok || connID != 42 || code != sendResultConnectionNotFound {
		t.Fatalf("legacy decode = %d, %d, %v", connID, code, ok)
	}

	var trackedOK [14]byte
	binary.BigEndian.PutUint32(trackedOK[0:4], 42)
	binary.BigEndian.PutUint64(trackedOK[4:12], 1<<48)
	binary.BigEndian.PutUint16(trackedOK[12:14], sendResultOK)
	connID, code, ok = decodeTrackedSendResult(trackedOK[:])
	if !ok || connID != 42 || code != sendResultOK {
		t.Fatalf("tracked OK decode = %d, %d, %v", connID, code, ok)
	}

	var trackedFailure [14]byte
	binary.BigEndian.PutUint32(trackedFailure[0:4], 42)
	binary.BigEndian.PutUint64(trackedFailure[4:12], 1)
	binary.BigEndian.PutUint16(trackedFailure[12:14], sendResultConnectionNotFound)
	connID, code, ok = decodeTrackedSendResult(trackedFailure[:])
	if !ok || connID != 42 || code != sendResultConnectionNotFound {
		t.Fatalf("tracked failure decode = %d, %d, %v", connID, code, ok)
	}
}

func TestTrackedSendResultOKWithLargeSendIDDoesNotCloseRecvCh(t *testing.T) {
	c := &ipcClient{
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:  make(map[uint32][][]byte),
		pendClose: make(map[uint32]struct{}),
	}
	ch := c.registerRecvCh(42)

	payload := trackedSendResultPayload(42, 1<<48, sendResultOK)
	c.handleTrackedSendResultPayload(payload)

	select {
	case _, ok := <-ch:
		t.Fatalf("tracked OK closed/read recv channel unexpectedly: ok=%v", ok)
	default:
	}
	if _, ok := c.recvChs[42]; !ok {
		t.Fatalf("tracked OK unregistered recvCh")
	}
}

func TestTrackedSendResultFailureWithSmallSendIDClosesRecvCh(t *testing.T) {
	c := &ipcClient{
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:  make(map[uint32][][]byte),
		pendClose: make(map[uint32]struct{}),
	}
	ch := c.registerRecvCh(42)

	payload := trackedSendResultPayload(42, 1, sendResultConnectionNotFound)
	c.handleTrackedSendResultPayload(payload)

	if _, ok := <-ch; ok {
		t.Fatalf("tracked failure left recv channel open")
	}
	if _, ok := c.recvChs[42]; ok {
		t.Fatalf("tracked failure left recvCh registered")
	}
}

func trackedSendResultPayload(connID uint32, sendID uint64, code uint16) []byte {
	var payload [14]byte
	binary.BigEndian.PutUint32(payload[0:4], connID)
	binary.BigEndian.PutUint64(payload[4:12], sendID)
	binary.BigEndian.PutUint16(payload[12:14], code)
	return payload[:]
}

func recvPayload(connID uint32, data []byte) []byte {
	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload[0:4], connID)
	copy(payload[4:], data)
	return payload
}
