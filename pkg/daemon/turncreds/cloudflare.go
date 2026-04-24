package turncreds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Cloudflare defaults and bounds. Kept as unexported constants so
// behavior is observable only via the public API (CloudflareOptions).
const (
	cloudflareDefaultBaseURL  = "https://rtc.live.cloudflare.com"
	cloudflareDefaultTTL      = 1 * time.Hour
	cloudflareMinTTL          = 60 * time.Second
	cloudflareMaxTTL          = 48 * time.Hour
	cloudflareDefaultTimeout  = 10 * time.Second
	cloudflareDefaultTranspor = "udp"

	// cloudflareRefreshSafety is the slack subtracted from ExpiresAt
	// before we consider the cache stale on a Get. Keeps us from
	// serving creds the server is about to reject.
	cloudflareRefreshSafety = 60 * time.Second
)

// CloudflareOptions configures a CloudflareProvider. Only TokenID and
// APIToken are required.
type CloudflareOptions struct {
	// TokenID is the TURN Key ID displayed on the Cloudflare
	// Realtime dashboard. Not a secret; appears in the URL path.
	TokenID string

	// APIToken is the TURN Key's API Token (the secret). Sent in the
	// Authorization header as a Bearer token. Must NEVER appear in
	// log lines or error messages.
	APIToken string

	// TTL is how long each minted credential should be valid. The
	// Cloudflare API accepts 60s..48h. Defaults to 1h. The refresh
	// loop fires at TTL/2.
	TTL time.Duration

	// Transport is the TURN client → server transport encoded into
	// the URL picked from the API response. "udp" (default), "tcp",
	// or "tls".
	Transport string

	// HTTPClient, if non-nil, is used for all API calls. Tests
	// inject an httptest-backed client here. Defaults to a new
	// http.Client with a 10s timeout.
	HTTPClient *http.Client

	// BaseURL overrides the Cloudflare API host — tests point it at
	// an httptest.Server. Defaults to the production API.
	BaseURL string

	// Clock returns the current time. Tests substitute a fake to
	// control refresh cadence. Defaults to time.Now.
	Clock func() time.Time

	// backoffs is unexported; tests inject a short-circuited
	// sequence.
	backoffs []time.Duration

	// refreshInterval, if non-zero, overrides the TTL/2 refresh
	// cadence. Test-only escape hatch so the refresh loop fires
	// fast without violating the public TTL floor.
	refreshInterval time.Duration
}

// defaultBackoffs is the retry schedule on transient errors
// (network / 5xx). Three retries at 100ms, 400ms, 1.6s.
var defaultBackoffs = []time.Duration{
	100 * time.Millisecond,
	400 * time.Millisecond,
	1600 * time.Millisecond,
}

// CloudflareProvider mints and rotates short-lived TURN credentials
// via the Cloudflare Realtime TURN REST API. Thread-safe.
type CloudflareProvider struct {
	tokenID         string
	apiToken        string // secret — never log
	ttl             time.Duration
	transp          string
	baseURL         string
	client          *http.Client
	clock           func() time.Time
	backoffs        []time.Duration
	refreshInterval time.Duration

	mu        sync.Mutex
	cached    *Credentials
	subCh     chan *Credentials
	closeOnce sync.Once
	closed    bool
	cancel    context.CancelFunc
	done      chan struct{}
}

// cfICEServer mirrors one entry of the Cloudflare response
// iceServers array. Fields we don't need (e.g. urls for STUN-only
// entries) are still unmarshaled so we can iterate.
type cfICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// cfResponse is the top-level response body from
// generate-ice-servers.
type cfResponse struct {
	ICEServers []cfICEServer `json:"iceServers"`
}

// NewCloudflareProvider validates options, starts the background
// refresh loop, and returns a ready-to-use provider. The first Get
// will trigger an HTTP mint (the constructor does not itself call
// the API — that way constructor errors are purely config errors).
func NewCloudflareProvider(opts CloudflareOptions) (*CloudflareProvider, error) {
	if opts.TokenID == "" {
		return nil, errors.New("turncreds: cloudflare: TokenID is required")
	}
	if opts.APIToken == "" {
		return nil, errors.New("turncreds: cloudflare: APIToken is required")
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = cloudflareDefaultTTL
	}
	if ttl < cloudflareMinTTL {
		return nil, fmt.Errorf("turncreds: cloudflare: TTL %s below minimum %s", ttl, cloudflareMinTTL)
	}
	if ttl > cloudflareMaxTTL {
		return nil, fmt.Errorf("turncreds: cloudflare: TTL %s above maximum %s", ttl, cloudflareMaxTTL)
	}

	transp := opts.Transport
	if transp == "" {
		transp = cloudflareDefaultTranspor
	}
	if !isValidTransport(transp) {
		return nil, fmt.Errorf("turncreds: cloudflare: invalid transport %q (want udp|tcp|tls)", transp)
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = cloudflareDefaultBaseURL
	}
	// Normalize — strip trailing slash so URL joining is predictable.
	baseURL = strings.TrimRight(baseURL, "/")

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cloudflareDefaultTimeout}
	}

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	backoffs := opts.backoffs
	if backoffs == nil {
		backoffs = defaultBackoffs
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &CloudflareProvider{
		tokenID:         opts.TokenID,
		apiToken:        opts.APIToken,
		ttl:             ttl,
		transp:          transp,
		baseURL:         baseURL,
		client:          httpClient,
		clock:           clock,
		backoffs:        backoffs,
		refreshInterval: opts.refreshInterval,
		subCh:           make(chan *Credentials, 1),
		cancel:          cancel,
		done:            make(chan struct{}),
	}

	go p.refreshLoop(ctx)
	return p, nil
}

// Get returns cached credentials if they are still fresh
// (ExpiresAt - 60s > now), otherwise mints a new set. May block on
// up to ~2s of retry backoff plus per-request timeout.
func (p *CloudflareProvider) Get(ctx context.Context) (*Credentials, error) {
	p.mu.Lock()
	cached := p.cached
	p.mu.Unlock()

	if cached != nil {
		now := p.clock()
		if cached.ExpiresAt.After(now.Add(cloudflareRefreshSafety)) {
			return cached, nil
		}
	}

	creds, err := p.mint(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.cached = creds
	p.mu.Unlock()

	return creds, nil
}

// Subscribe returns the broadcast channel. Multiple callers share the
// same channel — this is a single-slot broadcast, not per-subscriber
// fan-out. The channel is closed by Close.
func (p *CloudflareProvider) Subscribe() <-chan *Credentials {
	return p.subCh
}

// Close stops the refresh goroutine and closes the Subscribe channel.
// Idempotent.
func (p *CloudflareProvider) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		p.cancel()
		<-p.done
		close(p.subCh)
	})
	return nil
}

// refreshLoop is the background goroutine that re-mints at TTL/2. It
// ticks on a timer rather than a ticker because the sleep interval
// depends on the last mint's timestamp — a missed tick pushes the
// next one out, not one fired back-to-back.
func (p *CloudflareProvider) refreshLoop(ctx context.Context) {
	defer close(p.done)

	interval := p.ttl / 2
	if p.refreshInterval > 0 {
		interval = p.refreshInterval
	}
	if interval <= 0 {
		interval = cloudflareMinTTL / 2
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			creds, err := p.mint(ctx)
			if err != nil {
				// Keep existing creds; log and retry on
				// next tick. Never log the API token.
				slog.Warn("turncreds: cloudflare refresh failed",
					"error", err,
					"token_id", p.tokenID,
				)
			} else {
				p.mu.Lock()
				p.cached = creds
				p.mu.Unlock()
				// Broadcast new creds. Non-blocking: if
				// the buffer is full (no listener drained
				// it), drop this update. A later refresh
				// will deliver the next value.
				select {
				case p.subCh <- creds:
				default:
				}
				slog.Info("turncreds: cloudflare credentials refreshed",
					"token_id", p.tokenID,
					"expires_at", creds.ExpiresAt,
				)
			}
			timer.Reset(interval)
		}
	}
}

// mint performs the HTTP call with retries. On terminal errors (4xx,
// parse failures) it returns immediately. On transient errors
// (network, 5xx) it retries according to p.backoffs. Never logs the
// API token; the returned error contains only status code + sanitized
// body snippets.
func (p *CloudflareProvider) mint(ctx context.Context) (*Credentials, error) {
	var lastErr error

	// Try once, then up to len(backoffs) retries.
	for attempt := 0; attempt <= len(p.backoffs); attempt++ {
		if attempt > 0 {
			// Sleep before retry, but respect ctx.
			d := p.backoffs[attempt-1]
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}

		creds, err, transient := p.mintOnce(ctx)
		if err == nil {
			return creds, nil
		}
		lastErr = err
		if !transient {
			return nil, err
		}
	}
	return nil, fmt.Errorf("turncreds: cloudflare: exhausted retries: %w", lastErr)
}

// mintOnce issues one HTTP request. Returns (creds, nil, false) on
// success, (nil, err, true) on transient failure (retriable),
// (nil, err, false) on terminal failure (do not retry).
func (p *CloudflareProvider) mintOnce(ctx context.Context) (*Credentials, error, bool) {
	endpoint := fmt.Sprintf("%s/v1/turn/keys/%s/credentials/generate-ice-servers",
		p.baseURL, url.PathEscape(p.tokenID))

	reqBody, err := json.Marshal(struct {
		TTL int `json:"ttl"`
	}{TTL: int(p.ttl.Seconds())})
	if err != nil {
		// Marshaling an int literal can't fail in practice, but
		// treat any error here as terminal.
		return nil, fmt.Errorf("turncreds: cloudflare: marshal request: %w", err), false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("turncreds: cloudflare: build request: %w", err), false
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	// Record the request timestamp BEFORE sending so ExpiresAt is
	// conservative — if the server takes 200ms to respond, we'd
	// rather expire 200ms early than 200ms late.
	mintedAt := p.clock()

	resp, err := p.client.Do(req)
	if err != nil {
		// Network error — retriable. Wrap without including the
		// token anywhere.
		if isTransientNetErr(err) {
			return nil, fmt.Errorf("turncreds: cloudflare: http request: %w", err), true
		}
		// Context cancellation is terminal.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("turncreds: cloudflare: http request: %w", err), false
		}
		return nil, fmt.Errorf("turncreds: cloudflare: http request: %w", err), true
	}
	defer resp.Body.Close()

	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if readErr != nil {
		return nil, fmt.Errorf("turncreds: cloudflare: read body: %w", readErr), true
	}

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("turncreds: cloudflare: server error %d: %s",
			resp.StatusCode, sanitizeBody(bodyBytes)), true
	}
	if resp.StatusCode >= 400 {
		hint := ""
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			hint = " (check api_token)"
		case http.StatusNotFound:
			hint = " (check token_id)"
		}
		return nil, fmt.Errorf("turncreds: cloudflare: client error %d%s: %s",
			resp.StatusCode, hint, sanitizeBody(bodyBytes)), false
	}

	var parsed cfResponse
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return nil, fmt.Errorf("turncreds: cloudflare: decode response: %w", err), false
	}

	creds, err := p.pickCredentials(parsed)
	if err != nil {
		return nil, err, false
	}
	creds.ExpiresAt = mintedAt.Add(p.ttl)
	return creds, nil, false
}

// pickCredentials walks the iceServers array, picks the first entry
// that carries credentials, then within its urls picks the first
// whose scheme/transport matches p.transp. Parses host:port from that
// URL.
func (p *CloudflareProvider) pickCredentials(r cfResponse) (*Credentials, error) {
	wantScheme, wantTransport := schemeAndTransport(p.transp)

	for _, s := range r.ICEServers {
		if s.Username == "" || s.Credential == "" {
			// STUN-only entries carry no creds — skip.
			continue
		}
		for _, u := range s.URLs {
			host, ok := parseTURNURL(u, wantScheme, wantTransport)
			if !ok {
				continue
			}
			return &Credentials{
				ServerAddr: host,
				Transport:  p.transp,
				Username:   s.Username,
				Password:   s.Credential,
			}, nil
		}
	}
	return nil, fmt.Errorf("turncreds: cloudflare: no %s URL in response", p.transp)
}

// schemeAndTransport maps the Credentials.Transport string onto the
// TURN URI scheme and query-param transport it implies:
//
//	udp → turn:...?transport=udp
//	tcp → turn:...?transport=tcp
//	tls → turns:...?transport=tcp (TURNS is always TCP-wrapped)
func schemeAndTransport(t string) (scheme, transportParam string) {
	switch t {
	case "udp":
		return "turn", "udp"
	case "tcp":
		return "turn", "tcp"
	case "tls":
		return "turns", "tcp"
	}
	return "", ""
}

// parseTURNURL inspects a single Cloudflare-supplied URL like
// "turn:turn.cloudflare.com:3478?transport=udp" and, if its scheme +
// transport query param match (wantScheme, wantTransport), returns
// the host:port portion.
//
// Accepts both "turn:host:port?transport=..." and
// "turn:host:port" (transport absent). Returns "", false on
// mismatch or malformed input.
func parseTURNURL(raw, wantScheme, wantTransport string) (string, bool) {
	// TURN URIs are not standard URLs (they use raw host:port, not
	// authority). Hand-parse rather than net/url.Parse, which is
	// lenient in unhelpful ways.
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return "", false
	}
	scheme := raw[:colon]
	if scheme != wantScheme {
		return "", false
	}
	rest := raw[colon+1:]

	// Split off query string.
	hostPort := rest
	query := ""
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		hostPort = rest[:q]
		query = rest[q+1:]
	}

	// Require host:port.
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		return "", false
	}

	// Check transport param.
	transport := ""
	if query != "" {
		for _, kv := range strings.Split(query, "&") {
			if strings.HasPrefix(kv, "transport=") {
				transport = kv[len("transport="):]
				break
			}
		}
	}
	if transport == "" {
		// No transport param: accept only if caller wants the
		// scheme's implicit default. For "turn" that's udp;
		// for "turns" that's tcp.
		switch scheme {
		case "turn":
			transport = "udp"
		case "turns":
			transport = "tcp"
		}
	}
	if transport != wantTransport {
		return "", false
	}
	return hostPort, true
}

// isTransientNetErr reports whether err from http.Client.Do looks
// like a retriable transport failure rather than an application
// error. Cast + Temporary() is deprecated but still the path of
// least surprise for the common cases (DNS, refused, reset).
func isTransientNetErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || true // treat any net.Error as retriable
	}
	return false
}

// sanitizeBody trims an error body for inclusion in a log line or
// error message. Cloudflare error bodies are short JSON; cap at 200
// bytes and collapse newlines.
func sanitizeBody(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
}
