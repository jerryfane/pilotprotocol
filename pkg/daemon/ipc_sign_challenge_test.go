package daemon

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	pilotcrypto "github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
)

func TestIPCSignChallengeSignsWithLocalIdentity(t *testing.T) {
	id, err := pilotcrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	d := New(Config{Email: "test@example.com"})
	d.identity = id
	d.nodeID = 45981
	s := &IPCServer{daemon: d}
	ipc := &ipcConn{Conn: &recordingConn{}}
	payload := []byte("entmoot.open_invite.redeem.v1:test")

	s.handleSignChallenge(ipc, payload)

	msg, err := ipcutil.Read(&ipc.Conn.(*recordingConn).buf)
	if err != nil {
		t.Fatalf("read IPC reply: %v", err)
	}
	if len(msg) < 2 || msg[0] != CmdSignChallengeOK {
		t.Fatalf("reply command/len = 0x%02x/%d, want CmdSignChallengeOK", msg[0], len(msg))
	}
	var out struct {
		NodeID    uint32 `json:"node_id"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(msg[1:], &out); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if out.NodeID != 45981 || out.PublicKey != pilotcrypto.EncodePublicKey(id.PublicKey) || !pilotcrypto.Verify(id.PublicKey, signChallengePayload(payload), sig) {
		t.Fatalf("bad sign_challenge reply: %+v", out)
	}
	if pilotcrypto.Verify(id.PublicKey, payload, sig) {
		t.Fatalf("sign_challenge signature verified against raw payload without domain separation")
	}
}

func TestDaemonCapabilitiesAdvertiseLookupAndSigning(t *testing.T) {
	caps := map[string]bool{}
	for _, cap := range daemonCapabilities() {
		caps[cap] = true
	}
	for _, want := range []string{
		"lookup_node",
		"sign_challenge",
		"stream_send_result",
		"stream_send_result_v2",
	} {
		if !caps[want] {
			t.Fatalf("daemonCapabilities missing %q: %v", want, daemonCapabilities())
		}
	}
}

func TestIPCLookupNodePrefersTrustedBinding(t *testing.T) {
	d := New(Config{Email: "test@example.com"})
	d.handshakes = NewHandshakeManager(d)
	d.handshakes.trusted[45981] = &TrustRecord{
		NodeID:    45981,
		PublicKey: "trusted-key",
	}
	s := &IPCServer{daemon: d}
	ipc := &ipcConn{Conn: &recordingConn{}}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 45981)

	s.handleLookupNode(ipc, payload)

	msg, err := ipcutil.Read(&ipc.Conn.(*recordingConn).buf)
	if err != nil {
		t.Fatalf("read IPC reply: %v", err)
	}
	if len(msg) < 2 || msg[0] != CmdLookupNodeOK {
		t.Fatalf("reply command/len = 0x%02x/%d, want CmdLookupNodeOK", msg[0], len(msg))
	}
	var out struct {
		NodeID    uint32 `json:"node_id"`
		PublicKey string `json:"public_key"`
		Source    string `json:"source"`
	}
	if err := json.Unmarshal(msg[1:], &out); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if out.NodeID != 45981 || out.PublicKey != "trusted-key" || out.Source != "trusted" {
		t.Fatalf("bad lookup_node reply: %+v", out)
	}
}
