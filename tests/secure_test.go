package tests

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/secure"
)

func TestSecureChannel(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	received := make(chan string, 1)
	ln, err := a.Driver.Listen(protocol.PortSecure)
	if err != nil {
		t.Fatalf("secure listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		sc, err := secure.Handshake(conn, true)
		if err != nil {
			t.Logf("secure handshake: %v", err)
			conn.Close()
			return
		}
		defer sc.Close()
		buf := make([]byte, 65535)
		n, err := sc.Read(buf)
		if err != nil {
			t.Logf("server read: %v", err)
			return
		}
		msg := string(buf[:n])
		received <- msg
		sc.Write([]byte("secure-echo: " + msg))
	}()

	// Secure client on B
	sc, err := secure.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("secure dial: %v", err)
	}
	defer sc.Close()
	t.Log("secure channel established")

	// Send encrypted message
	if _, err := sc.Write([]byte("hello secure world")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Server should receive plaintext
	select {
	case msg := <-received:
		if msg != "hello secure world" {
			t.Errorf("expected %q, got %q", "hello secure world", msg)
		}
		t.Logf("server received: %s", msg)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to receive message")
	}

	// Read encrypted reply
	buf := make([]byte, 65535)
	n, err := sc.Read(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	reply := string(buf[:n])
	if reply != "secure-echo: hello secure world" {
		t.Errorf("expected %q, got %q", "secure-echo: hello secure world", reply)
	}
	t.Logf("reply: %s", reply)
}
