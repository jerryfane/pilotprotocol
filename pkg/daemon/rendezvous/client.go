package rendezvous

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// DefaultTimeout is the per-request HTTP deadline used by both
// Publish and Lookup. Picked to be generous enough for cross-
// continent TLS handshakes (~3-4 RTT) while still short enough
// that a slow rendezvous can't stall a cold-dial loop. Mirrors
// the 10s default in turncreds/cloudflare.go but a touch
// shorter — the rendezvous endpoint is supposed to be cheap.
const DefaultTimeout = 5 * time.Second

// DefaultPublishTTL is the validity window each daemon stamps
// onto its own blob on Publish. Capped server-side at
// MaxValidityWindow. Long enough that a peer who fetches once
// per cold dial doesn't need to refresh during a single dial
// attempt; short enough that a stale blob falls out of the
// store within the same window the TURN allocation itself
// rotates.
const DefaultPublishTTL = 30 * time.Minute

// Client is the daemon's handle to a Pkarr-style rendezvous
// service. Construct one per daemon at startup; all methods
// are safe for concurrent use.
//
// Zero-value Client is unusable. Use New().
type Client struct {
	// URL is the base URL of the rendezvous service, e.g.
	// "https://rendezvous.example.com" or
	// "http://localhost:8443". Trailing slash is OK; methods
	// strip it.
	URL string

	// HTTP is the http.Client used for every request. Tests
	// inject a custom client backed by httptest.Server.
	HTTP *http.Client

	// PublishTTL is the validity window stamped onto blobs in
	// Publish. Zero falls back to DefaultPublishTTL.
	PublishTTL time.Duration

	// Now returns the current wall time. Tests substitute a
	// fake clock to control IssuedAt deterministically.
	Now func() time.Time
}

// New constructs a Client pointing at url with sensible defaults
// (5 s HTTP timeout, real wall clock, 30 min publish TTL).
func New(url string) *Client {
	return &Client{
		URL:        strings.TrimRight(url, "/"),
		HTTP:       &http.Client{Timeout: DefaultTimeout},
		PublishTTL: DefaultPublishTTL,
		Now:        time.Now,
	}
}

// Publish signs a fresh AnnounceBlob for (nodeID, turnEndpoint)
// under id and PUTs it to the rendezvous. Idempotent; safe to
// call repeatedly with the same arguments. The server replaces
// any earlier blob for nodeID provided the IssuedAt is newer
// (and the public key matches the TOFU binding).
//
// Errors fall into three buckets the caller can safely log at
// Debug:
//   - input validation (bad TTL, missing identity)
//   - HTTP transport (connection refused, timeout, non-2xx)
//   - server-side rejection (4xx body explains why; we surface
//     the body as part of the error)
//
// None of those errors should kill the daemon — the rotation
// publish path is best-effort. The next rotation event (or the
// same one re-emitted on retry) will publish again.
func (c *Client) Publish(id *crypto.Identity, nodeID uint32, turnEndpoint string) error {
	if c == nil || c.URL == "" {
		return fmt.Errorf("rendezvous: no URL configured")
	}
	now := c.now()
	ttl := c.PublishTTL
	if ttl <= 0 {
		ttl = DefaultPublishTTL
	}
	blob, err := Sign(id, nodeID, turnEndpoint, now, ttl)
	if err != nil {
		return fmt.Errorf("rendezvous: sign: %w", err)
	}
	body, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("rendezvous: marshal: %w", err)
	}
	url := fmt.Sprintf("%s/v1/announce/%d", c.URL, nodeID)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rendezvous: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("rendezvous: PUT %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("rendezvous: PUT %s: status %d: %s",
			url, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	slog.Debug("rendezvous publish ok",
		"url", url, "node_id", nodeID, "turn_endpoint", turnEndpoint)
	return nil
}

// Lookup GETs the latest AnnounceBlob for nodeID, verifies its
// signature, validity window, and (if expectedPubkey is
// non-nil) its public-key binding, and returns the contained
// TURNEndpoint. Returns "" with no error when the rendezvous
// has no record for nodeID (404). Any verification failure
// returns a non-nil error and an empty endpoint — never trust
// a blob that didn't validate.
func (c *Client) Lookup(nodeID uint32, expectedPubkey ed25519.PublicKey) (string, error) {
	if c == nil || c.URL == "" {
		return "", fmt.Errorf("rendezvous: no URL configured")
	}
	url := fmt.Sprintf("%s/v1/announce/%d", c.URL, nodeID)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("rendezvous: request: %w", err)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return "", fmt.Errorf("rendezvous: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil // not an error — peer just hasn't published yet
	}
	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("rendezvous: GET %s: status %d: %s",
			url, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("rendezvous: read body: %w", err)
	}
	var blob AnnounceBlob
	if err := json.Unmarshal(body, &blob); err != nil {
		return "", fmt.Errorf("rendezvous: unmarshal: %w", err)
	}
	// Defense in depth: verify before trusting any field. Even
	// an honest server's storage corruption would surface here
	// rather than poisoning the daemon's path table.
	if err := blob.Verify(c.now(), nodeID, expectedPubkey); err != nil {
		return "", fmt.Errorf("rendezvous: verify: %w", err)
	}
	slog.Debug("rendezvous lookup ok",
		"url", url, "node_id", nodeID, "turn_endpoint", blob.TURNEndpoint)
	return blob.TURNEndpoint, nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: DefaultTimeout}
}

func (c *Client) timeout() time.Duration {
	if c.HTTP != nil && c.HTTP.Timeout > 0 {
		return c.HTTP.Timeout
	}
	return DefaultTimeout
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
