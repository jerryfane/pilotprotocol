package gossip

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func sampleRecord() *GossipRecord {
	return &GossipRecord{
		NodeID:   42,
		RealAddr: "203.0.113.7:37736",
		Endpoints: []registry.NodeEndpoint{
			{Network: "tcp", Addr: "203.0.113.7:4443"},
			{Network: "udp", Addr: "203.0.113.7:37736"},
		},
		Hostname: "canary-hub",
		LastSeen: 1_700_000_000,
		PublicKey: make([]byte, 32), // filled in Sign or tests
	}
}

func TestCanonicalBytesDeterministic(t *testing.T) {
	r1 := sampleRecord()
	r2 := sampleRecord()
	// Intentionally shuffle endpoints in r2 — canonical form must sort them.
	r2.Endpoints = []registry.NodeEndpoint{
		{Network: "udp", Addr: "203.0.113.7:37736"},
		{Network: "tcp", Addr: "203.0.113.7:4443"},
	}
	if !bytes.Equal(canonicalBytes(r1), canonicalBytes(r2)) {
		t.Fatalf("canonicalBytes not stable under endpoint reorder")
	}
}

func TestCanonicalBytesChangesOnFieldFlip(t *testing.T) {
	r := sampleRecord()
	base := append([]byte(nil), canonicalBytes(r)...)

	flips := []func(*GossipRecord){
		func(r *GossipRecord) { r.NodeID++ },
		func(r *GossipRecord) { r.RealAddr = "203.0.113.7:37737" },
		func(r *GossipRecord) { r.Hostname = "canary-hub2" },
		func(r *GossipRecord) { r.LastSeen++ },
		func(r *GossipRecord) { r.Endpoints = append(r.Endpoints, registry.NodeEndpoint{Network: "quic", Addr: "203.0.113.7:4444"}) },
		func(r *GossipRecord) { r.PublicKey = append([]byte(nil), make([]byte, 32)...); r.PublicKey[0] = 1 },
	}
	for i, flip := range flips {
		rr := sampleRecord()
		flip(rr)
		if bytes.Equal(base, canonicalBytes(rr)) {
			t.Fatalf("flip %d produced identical canonical bytes", i)
		}
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	r := sampleRecord()
	r.PublicKey[0] = 0xab
	r.Signature = []byte{0x42, 0x43}

	data, err := MarshalRecord(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalRecord(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.NodeID != r.NodeID || got.RealAddr != r.RealAddr || got.Hostname != r.Hostname {
		t.Fatalf("scalar fields changed through round-trip: %+v", got)
	}
	if len(got.Endpoints) != len(r.Endpoints) {
		t.Fatalf("endpoints lost: want %d got %d", len(r.Endpoints), len(got.Endpoints))
	}
	if !bytes.Equal(got.PublicKey, r.PublicKey) {
		t.Fatalf("public key changed through round-trip")
	}
	if !bytes.Equal(got.Signature, r.Signature) {
		t.Fatalf("signature changed through round-trip")
	}
}

func TestMarshalDeltaAndSyncRoundTrip(t *testing.T) {
	sync := &GossipSync{Digests: []GossipDigest{{NodeID: 1, LastSeen: 100}, {NodeID: 2, LastSeen: 200}}}
	data, err := MarshalSync(sync)
	if err != nil {
		t.Fatalf("marshal sync: %v", err)
	}
	got, err := UnmarshalSync(data)
	if err != nil {
		t.Fatalf("unmarshal sync: %v", err)
	}
	if len(got.Digests) != 2 || got.Digests[0].NodeID != 1 || got.Digests[1].LastSeen != 200 {
		t.Fatalf("sync round-trip mismatch: %+v", got)
	}

	delta := &GossipDelta{Records: []GossipRecord{*sampleRecord()}, Missing: []uint32{7, 9}}
	data2, err := MarshalDelta(delta)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}
	d2, err := UnmarshalDelta(data2)
	if err != nil {
		t.Fatalf("unmarshal delta: %v", err)
	}
	if len(d2.Records) != 1 || len(d2.Missing) != 2 || d2.Missing[0] != 7 {
		t.Fatalf("delta round-trip mismatch: %+v", d2)
	}
}

func TestUnmarshalRecordRejectsGarbage(t *testing.T) {
	if _, err := UnmarshalRecord([]byte("not json")); err == nil {
		t.Fatalf("expected error on garbage input")
	}
}

// TestOmitEmptyShape guards against a regression where empty
// endpoints/hostname/signature bloat the wire form — we use
// `omitempty` tags for those and want to keep them.
func TestOmitEmptyShape(t *testing.T) {
	r := &GossipRecord{
		NodeID:    1,
		PublicKey: make([]byte, 32),
		RealAddr:  "1.2.3.4:5",
		LastSeen:  10,
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	for _, absent := range []string{"\"hostname\"", "\"signature\"", "\"endpoints\""} {
		if bytes.Contains(data, []byte(absent)) {
			t.Errorf("expected %q absent from encoded record, got %s", absent, s)
		}
	}
}
