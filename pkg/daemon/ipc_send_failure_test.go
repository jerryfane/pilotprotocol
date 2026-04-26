package daemon

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func TestIPCHandleSendFailureAbortsConn(t *testing.T) {
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

	w := ipc.Conn.(*recordingConn)
	if w.buf.Len() == 0 {
		t.Fatalf("handleSend did not emit an IPC error reply")
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
