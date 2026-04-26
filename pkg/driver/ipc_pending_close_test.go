package driver

import (
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
