package daemon

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func TestIPCHandleSendFailureReturnsConnectionScopedError(t *testing.T) {
	d := New(Config{Email: "test@example.com"})
	s := &IPCServer{daemon: d}

	conn := d.ports.NewConnection(4000, protocol.Addr{Node: 99}, 1004)
	conn.Mu.Lock()
	conn.State = StateSynSent
	conn.Mu.Unlock()

	ipc := &ipcConn{Conn: &recordingConn{}}
	payload := make([]byte, 4+len("hello"))
	binary.BigEndian.PutUint32(payload[0:4], conn.ID)
	copy(payload[4:], "hello")

	s.handleSend(ipc, payload)

	if got := d.ports.GetConnection(conn.ID); got != nil {
		t.Fatalf("failed send left conn %d in port manager", conn.ID)
	}
	select {
	case _, ok := <-conn.RecvBuf:
		if ok {
			t.Fatalf("failed send left conn %d RecvBuf open", conn.ID)
		}
	default:
		t.Fatalf("failed send did not close conn %d RecvBuf", conn.ID)
	}

	assertSendResult(t, ipc.Conn.(*recordingConn), conn.ID, SendResultConnectionNotEstablished)
}

func TestIPCHandleSendMissingConnectionReturnsConnectionScopedErrorAndLegacyClose(t *testing.T) {
	d := New(Config{Email: "test@example.com"})
	s := &IPCServer{daemon: d}
	ipc := &ipcConn{Conn: &recordingConn{}}

	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], 12345)

	s.handleSend(ipc, payload[:])

	w := ipc.Conn.(*recordingConn)
	assertSendResult(t, w, 12345, SendResultConnectionNotFound)
	assertCloseOK(t, w, 12345)
}

func TestIPCHandleSendTrackedMissingConnectionReturnsTrackedError(t *testing.T) {
	d := New(Config{Email: "test@example.com"})
	s := &IPCServer{daemon: d}
	ipc := &ipcConn{Conn: &recordingConn{}}

	var payload [12]byte
	binary.BigEndian.PutUint32(payload[0:4], 12345)
	binary.BigEndian.PutUint64(payload[4:12], 67890)

	s.handleSendTracked(ipc, payload[:])

	assertTrackedSendResult(t, ipc.Conn.(*recordingConn), 12345, 67890, SendResultConnectionNotFound)
}

func assertSendResult(t *testing.T, w *recordingConn, wantID uint32, wantCode uint16) {
	t.Helper()
	msg, err := ipcutil.Read(&w.buf)
	if err != nil {
		t.Fatalf("read IPC reply: %v", err)
	}
	if len(msg) < 7 {
		t.Fatalf("reply length = %d, want at least 7", len(msg))
	}
	if msg[0] != CmdSendResult {
		t.Fatalf("reply command = 0x%02x, want CmdSendResult", msg[0])
	}
	if got := binary.BigEndian.Uint32(msg[1:5]); got != wantID {
		t.Fatalf("send-result conn_id = %d, want %d", got, wantID)
	}
	if got := binary.BigEndian.Uint16(msg[5:7]); got != wantCode {
		t.Fatalf("send-result code = %d, want %d (msg=%q)", got, wantCode, string(msg[7:]))
	}
}

func assertTrackedSendResult(t *testing.T, w *recordingConn, wantID uint32, wantSendID uint64, wantCode uint16) {
	t.Helper()
	msg, err := ipcutil.Read(&w.buf)
	if err != nil {
		t.Fatalf("read IPC reply: %v", err)
	}
	if len(msg) < 15 {
		t.Fatalf("reply length = %d, want at least 15", len(msg))
	}
	if msg[0] != CmdSendTrackedResult {
		t.Fatalf("reply command = 0x%02x, want CmdSendTrackedResult", msg[0])
	}
	if got := binary.BigEndian.Uint32(msg[1:5]); got != wantID {
		t.Fatalf("send-result conn_id = %d, want %d", got, wantID)
	}
	if got := binary.BigEndian.Uint64(msg[5:13]); got != wantSendID {
		t.Fatalf("send-result send_id = %d, want %d", got, wantSendID)
	}
	if got := binary.BigEndian.Uint16(msg[13:15]); got != wantCode {
		t.Fatalf("send-result code = %d, want %d (msg=%q)", got, wantCode, string(msg[15:]))
	}
}

func assertCloseOK(t *testing.T, w *recordingConn, wantID uint32) {
	t.Helper()
	msg, err := ipcutil.Read(&w.buf)
	if err != nil {
		t.Fatalf("read IPC close reply: %v", err)
	}
	if len(msg) != 5 {
		t.Fatalf("close reply length = %d, want 5", len(msg))
	}
	if msg[0] != CmdCloseOK {
		t.Fatalf("reply command = 0x%02x, want CmdCloseOK", msg[0])
	}
	if got := binary.BigEndian.Uint32(msg[1:5]); got != wantID {
		t.Fatalf("close conn_id = %d, want %d", got, wantID)
	}
}

type recordingConn struct {
	buf bytes.Buffer
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error)      { return c.buf.Write(p) }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
