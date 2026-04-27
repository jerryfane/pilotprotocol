package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/rendezvous"
)

// freshIdentity mirrors the helper in pkg/daemon/rendezvous; we
// keep a local copy here to avoid a test-import cycle.
func freshIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return &crypto.Identity{PublicKey: pub, PrivateKey: priv}
}

// newTestServer builds a Server backed by a temp bbolt file and
// wraps it in an httptest.Server that returns the URL the
// client side will hit. The fake-clock wired here is shared
// between the server's VerifyPUT path and the rate limiter so
// tests can advance time deterministically.
func newTestServer(t *testing.T) (*Server, *httptest.Server, *time.Time) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "store.db")
	srv, err := NewServer(dbPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	clock := time.Date(2026, 4, 25, 19, 30, 0, 0, time.UTC)
	srv.now = func() time.Time { return clock }
	httpSrv := httptest.NewServer(srv.Routes())
	t.Cleanup(httpSrv.Close)
	return srv, httpSrv, &clock
}

// putBlob is the test-side primitive for a raw HTTP PUT.
// Returns the response status code and body.
func putBlob(t *testing.T, base string, blob *rendezvous.AnnounceBlob) (int, string) {
	t.Helper()
	code, body, _ := putBlobResponse(t, base, blob)
	return code, body
}

func putBlobResponse(t *testing.T, base string, blob *rendezvous.AnnounceBlob) (int, string, http.Header) {
	t.Helper()
	body, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	url := fmt.Sprintf("%s/v1/announce/%d", base, blob.NodeID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody), resp.Header.Clone()
}

// TestServer_HealthEndpoint: trivial liveness probe.
func TestServer_HealthEndpoint(t *testing.T) {
	_, httpSrv, _ := newTestServer(t)
	resp, err := http.Get(httpSrv.URL + "/v1/health")
	if err != nil {
		t.Fatalf("GET /v1/health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

// TestServer_PUT_Then_GET: happy path. Sign a blob, PUT, GET,
// confirm the body round-trips byte-for-byte.
func TestServer_PUT_Then_GET(t *testing.T) {
	_, httpSrv, clockPtr := newTestServer(t)
	id := freshIdentity(t)
	blob, err := rendezvous.Sign(id, 45491, "104.30.150.206:49529", *clockPtr, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if code, body := putBlob(t, httpSrv.URL, blob); code != http.StatusNoContent {
		t.Fatalf("PUT status: %d body=%q", code, body)
	}
	resp, err := http.Get(fmt.Sprintf("%s/v1/announce/%d", httpSrv.URL, blob.NodeID))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status: %d", resp.StatusCode)
	}
	var got rendezvous.AnnounceBlob
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TURNEndpoint != blob.TURNEndpoint {
		t.Fatalf("endpoint: got %q want %q", got.TURNEndpoint, blob.TURNEndpoint)
	}
	if got.IssuedAt != blob.IssuedAt {
		t.Fatalf("issued_at: got %d want %d", got.IssuedAt, blob.IssuedAt)
	}
}

// TestServer_GET_NotFound: 404 for an unknown NodeID. The
// client treats this as ("", nil), so the status code matters.
func TestServer_GET_NotFound(t *testing.T) {
	_, httpSrv, _ := newTestServer(t)
	resp, err := http.Get(httpSrv.URL + "/v1/announce/99999")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

// TestServer_PUT_TOFU_Then_KeyConflict: the FIRST PUT for a
// NodeID binds its public key. A subsequent PUT signed by a
// different identity gets 409 Conflict — the load-bearing
// integrity check that prevents a server compromise from
// hijacking an existing peer's NodeID.
func TestServer_PUT_TOFU_Then_KeyConflict(t *testing.T) {
	srv, httpSrv, clockPtr := newTestServer(t)
	id1 := freshIdentity(t)
	id2 := freshIdentity(t)

	blob1, _ := rendezvous.Sign(id1, 100, "1.1.1.1:1111", *clockPtr, 5*time.Minute)
	if code, body := putBlob(t, httpSrv.URL, blob1); code != http.StatusNoContent {
		t.Fatalf("first PUT: %d body=%q", code, body)
	}

	// Need to step past the rate-limit window before the second
	// PUT — otherwise we'd see 429, not 409.
	*clockPtr = clockPtr.Add(2 * time.Minute)
	srv.now = func() time.Time { return *clockPtr }

	blob2, _ := rendezvous.Sign(id2, 100, "2.2.2.2:2222", *clockPtr, 5*time.Minute)
	code, body := putBlob(t, httpSrv.URL, blob2)
	if code != http.StatusConflict {
		t.Fatalf("second PUT (different key): status=%d body=%q (want 409)", code, body)
	}
}

// TestServer_PUT_PathBodyNodeIDMismatch: an attacker putting to
// /v1/announce/X with a body containing NodeID=Y must be
// rejected. Otherwise the path-keyed lookup and signature-keyed
// identity could disagree.
func TestServer_PUT_PathBodyNodeIDMismatch(t *testing.T) {
	_, httpSrv, clockPtr := newTestServer(t)
	id := freshIdentity(t)
	blob, _ := rendezvous.Sign(id, 1, "1.2.3.4:5", *clockPtr, 5*time.Minute)
	// PUT to /v1/announce/2 with body NodeID=1.
	url := fmt.Sprintf("%s/v1/announce/2", httpSrv.URL)
	body, _ := json.Marshal(blob)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d (want 400)", resp.StatusCode)
	}
}

// TestServer_PUT_BadSignature: a manually-mangled signature
// must fail VerifyPUT (server-side belt-and-suspenders even
// though clients also verify on Lookup).
func TestServer_PUT_BadSignature(t *testing.T) {
	_, httpSrv, clockPtr := newTestServer(t)
	id := freshIdentity(t)
	blob, _ := rendezvous.Sign(id, 1, "1.2.3.4:5", *clockPtr, 5*time.Minute)
	blob.Signature[0] ^= 0xFF
	code, body := putBlob(t, httpSrv.URL, blob)
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q (want 400)", code, body)
	}
}

// TestServer_PUT_RateLimit: two PUTs for the same NodeID
// within the rate-limit window — the second is 429.
func TestServer_PUT_RateLimit(t *testing.T) {
	srv, httpSrv, clockPtr := newTestServer(t)
	id := freshIdentity(t)

	blob, _ := rendezvous.Sign(id, 7, "1.1.1.1:1111", *clockPtr, 5*time.Minute)
	if code, body := putBlob(t, httpSrv.URL, blob); code != http.StatusNoContent {
		t.Fatalf("first PUT: %d body=%q", code, body)
	}
	// Bump the clock by 30 s — still under the 1-minute floor.
	*clockPtr = clockPtr.Add(30 * time.Second)
	srv.now = func() time.Time { return *clockPtr }
	blob2, _ := rendezvous.Sign(id, 7, "1.1.1.1:1112", *clockPtr, 5*time.Minute)
	code, body, header := putBlobResponse(t, httpSrv.URL, blob2)
	if code != http.StatusTooManyRequests {
		t.Fatalf("second PUT in window: status=%d body=%q (want 429)", code, body)
	}
	if got := header.Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After=%q, want 30", got)
	}
	// Step past the floor; third PUT accepted.
	*clockPtr = clockPtr.Add(31 * time.Second)
	srv.now = func() time.Time { return *clockPtr }
	blob3, _ := rendezvous.Sign(id, 7, "1.1.1.1:1113", *clockPtr, 5*time.Minute)
	code, body = putBlob(t, httpSrv.URL, blob3)
	if code != http.StatusNoContent {
		t.Fatalf("third PUT after window: status=%d body=%q (want 204)", code, body)
	}
}

// TestServer_PUT_MonotonicIssuedAt: a stale blob (older
// IssuedAt) silently keeps the existing newer record. The
// server returns 204 (the caller didn't do anything wrong),
// but the GET still serves the newer endpoint.
func TestServer_PUT_MonotonicIssuedAt(t *testing.T) {
	srv, httpSrv, clockPtr := newTestServer(t)
	id := freshIdentity(t)

	blobNew, _ := rendezvous.Sign(id, 1, "new.endpoint:1", *clockPtr, 5*time.Minute)
	if code, body := putBlob(t, httpSrv.URL, blobNew); code != http.StatusNoContent {
		t.Fatalf("PUT new: %d body=%q", code, body)
	}
	// Advance past rate-limit window then sign a blob with an
	// IssuedAt explicitly in the past.
	*clockPtr = clockPtr.Add(2 * time.Minute)
	srv.now = func() time.Time { return *clockPtr }
	stale := *blobNew
	stale.IssuedAt = blobNew.IssuedAt - int64(time.Minute/time.Millisecond)
	stale.ValidUntil = stale.IssuedAt + (5 * time.Minute).Milliseconds()
	stale.TURNEndpoint = "stale.endpoint:9"
	// Re-sign with the old IssuedAt so it passes VerifyPUT
	// shape checks (clock skew within tolerance because we
	// rolled the server clock forward).
	resigned, err := rendezvous.Sign(id, 1, "stale.endpoint:9",
		time.UnixMilli(stale.IssuedAt), 5*time.Minute)
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	// Server clock is now 2 min ahead of resigned.IssuedAt;
	// VerifyPUT skew tolerance is 5 min, so this is in-window.
	if code, body := putBlob(t, httpSrv.URL, resigned); code != http.StatusNoContent {
		t.Fatalf("PUT stale: %d body=%q", code, body)
	}
	// GET should still serve the newer endpoint.
	resp, err := http.Get(fmt.Sprintf("%s/v1/announce/1", httpSrv.URL))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var got rendezvous.AnnounceBlob
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.TURNEndpoint != "new.endpoint:1" {
		t.Fatalf("GET returned %q after stale PUT, want unchanged %q",
			got.TURNEndpoint, "new.endpoint:1")
	}
}

// TestServer_PUT_BodyTooLarge: requests with bodies above the
// cap are rejected without parsing the JSON. We can't easily
// check the LimitReader's truncation directly via the public
// API, so we rely on a body that *would* parse to test the
// behavior end-to-end with a giant junk field.
func TestServer_PUT_BodyTooLarge(t *testing.T) {
	_, httpSrv, _ := newTestServer(t)
	// Build a body bigger than maxBodyBytes.
	huge := bytes.Repeat([]byte("a"), maxBodyBytes+1024)
	url := fmt.Sprintf("%s/v1/announce/1", httpSrv.URL)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(huge))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d (want 400)", resp.StatusCode)
	}
}

// TestServer_BadMethod: anything other than PUT/GET on
// /v1/announce/* returns 405.
func TestServer_BadMethod(t *testing.T) {
	_, httpSrv, _ := newTestServer(t)
	url := fmt.Sprintf("%s/v1/announce/1", httpSrv.URL)
	req, _ := http.NewRequest(http.MethodPatch, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: %d (want 405)", resp.StatusCode)
	}
}

// TestServer_Persistence_AcrossOpen: write a blob, close the
// store, reopen it, GET — the blob is still there. Confirms
// bbolt durability behaves the way callers expect.
func TestServer_Persistence_AcrossOpen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
	srv, err := NewServer(dbPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clock := time.Date(2026, 4, 25, 19, 30, 0, 0, time.UTC)
	srv.now = func() time.Time { return clock }

	id := freshIdentity(t)
	blob, _ := rendezvous.Sign(id, 42, "1.2.3.4:5", clock, 5*time.Minute)
	if err := srv.storeBlob(blob); err != nil {
		t.Fatalf("storeBlob: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	srv2, err := NewServer(dbPath)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer srv2.Close()
	got, ok, err := srv2.loadBlob(42)
	if err != nil {
		t.Fatalf("loadBlob: %v", err)
	}
	if !ok || got.TURNEndpoint != "1.2.3.4:5" {
		t.Fatalf("after reopen: ok=%v ep=%q", ok, got.TURNEndpoint)
	}
}
