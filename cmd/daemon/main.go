package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/config"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
)

var version = "dev"

func main() {
	// Subcommand dispatch. Must happen before flag.Parse() so subcommand
	// runners see their own args in os.Args[2:]. Only a couple of
	// subcommands exist; everything else falls through to the normal
	// daemon-start path.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "turn-setup":
			os.Exit(runTurnSetup(os.Args[2:]))
		case "turn-test":
			os.Exit(runTurnTest(os.Args[2:]))
		case "version":
			fmt.Println(version)
			os.Exit(0)
		}
	}

	configPath := flag.String("config", "", "path to config file (JSON)")
	registryAddr := flag.String("registry", "34.71.57.205:9000", "registry server address")
	beaconAddr := flag.String("beacon", "34.71.57.205:9001", "beacon server address")
	listenAddr := flag.String("listen", ":0", "UDP listen address for tunnel traffic")
	socketPath := flag.String("socket", "/tmp/pilot.sock", "Unix socket path for IPC")
	endpoint := flag.String("endpoint", "", "fixed public endpoint (host:port) — skips STUN (for cloud VMs with known IPs)")
	tcpListen := flag.String("tcp-listen", "", "optional TCP listen address for UDP-hostile peers (e.g. ':4443'; empty = disabled)")
	tcpEndpoint := flag.String("tcp-endpoint", "", "fixed public TCP endpoint (host:port) to advertise; empty = derive from -endpoint host + -tcp-listen port")
	encrypt := flag.Bool("encrypt", true, "enable tunnel-layer encryption (X25519 + AES-256-GCM)")
	registryTLS := flag.Bool("registry-tls", false, "use TLS for registry connection")
	registryFingerprint := flag.String("registry-fingerprint", "", "hex SHA-256 fingerprint of registry TLS certificate")
	identityPath := flag.String("identity", "", "path to persist Ed25519 identity (enables stable identity across restarts)")
	email := flag.String("email", "", "email address for account identification and key recovery")
	owner := flag.String("owner", "", "(deprecated: use -email) owner identifier for key rotation recovery")
	keepalive := flag.Duration("keepalive", 0, "keepalive probe interval (default 30s)")
	idleTimeout := flag.Duration("idle-timeout", 0, "idle connection timeout (default 120s)")
	synRate := flag.Int("syn-rate-limit", 0, "max SYN packets per second (default 100)")
	maxConnsPerPort := flag.Int("max-conns-per-port", 0, "max connections per port (default 1024)")
	maxConnsTotal := flag.Int("max-conns-total", 0, "max total connections (default 4096)")
	timeWait := flag.Duration("time-wait", 0, "TIME_WAIT duration (default 10s)")
	public := flag.Bool("public", false, "make this node's endpoint publicly visible (default: private)")
	hostname := flag.String("hostname", "", "hostname for discovery (lowercase alphanumeric + hyphens, max 63 chars)")
	noEcho := flag.Bool("no-echo", false, "disable built-in echo service (port 7)")
	noDataExchange := flag.Bool("no-dataexchange", false, "disable built-in data exchange service (port 1001)")
	noEventStream := flag.Bool("no-eventstream", false, "disable built-in event stream service (port 1002)")
	noTaskSubmit := flag.Bool("no-tasksubmit", false, "disable built-in task submit service (port 1003)")
	webhookURL := flag.String("webhook", "", "HTTP(S) endpoint for event notifications (empty = disabled)")
	adminToken := flag.String("admin-token", "", "admin token for network operations")
	networks := flag.String("networks", "", "comma-separated network IDs to auto-join at startup")
	trustAutoApprove := flag.Bool("trust-auto-approve", false, "automatically approve all incoming trust handshakes")
	noRegistryEndpoint := flag.Bool("no-registry-endpoint", false, "register identity only; do not publish UDP/TCP/LAN endpoints to the registry. Pair with -turn-provider for full hide-IP (peers reach us via TURN relay advertised out-of-band by the app layer; registry lookup returns 'endpoint unknown')")
	outboundTurnOnly := flag.Bool("outbound-turn-only", false, "route ALL outbound tunnel traffic through our own TURN allocation (requires -turn-provider). Symmetric hide-IP — peers see our TURN-assigned address, never our real IP. Mirrors WebRTC iceTransportPolicy='relay' (RFC 8828 Mode 3). Startup fails if -turn-provider is empty.")
	hideIP := flag.Bool("hide-ip", false, "full Pilot-layer IP privacy — preset for -no-registry-endpoint -outbound-turn-only. Requires -turn-provider. Sub-flags can be overridden individually (e.g. -hide-ip -no-registry-endpoint=false). Name intentionally matches Entmoot's app-layer -hide-ip for mental-model consistency; both layers should be set together for full privacy.")

	// TURN (RFC 8656) relay — optional client-side transport for peers
	// behind UDP-hostile NATs or running in hide-IP mode. Empty provider
	// = disabled. See pkg/daemon/turncreds for credential backends.
	peerKeepalive := flag.Duration("peer-keepalive", 0, `interval for per-peer tunnel keepalives (default 25s; set to a negative duration like -1s to disable). Sends one tiny encrypted control packet per authenticated peer to keep TURN allocation permissions (RFC 8656 §9, 5-min TTL) and NAT mappings fresh in both directions. Closes the post-rotation chicken-and-egg deadlock between peers behind TURN. (v1.9.0-jf.13)`)
	rendezvousURL := flag.String("rendezvous-url", "", `base URL of a Pkarr-style endpoint rendezvous service (e.g. "https://rendezvous.example.com"; empty = disabled). When set, the daemon publishes its TURN endpoint on every rotation and consults the rendezvous on cold-dial fallback to refresh stale cached endpoints. Composes with -hide-ip + -outbound-turn-only + -no-registry-endpoint to fix the cold-start bootstrap deadlock that survives jf.13 keepalive. See cmd/pilot-rendezvous for the companion server. (v1.9.0-jf.14)`)
	traceSends := flag.Bool("trace-sends", false, `emit one INFO log per writeFrame tier decision and per SendTo "queued pending key exchange" branch. High volume (~10 events/min/peer-pair in steady state, more during dial storms). Off by default; turn on for short-lived diagnostic windows. Per-tier counters in 'pilotctl info' are populated regardless. (v1.9.0-jf.15.2)`)
	traceStreams := flag.Bool("trace-streams", false, `emit INFO logs for virtual stream lifecycle events (SYN/SYN-ACK/ESTABLISHED/FIN/RST/IPC close/removal). High volume during dial storms; intended for short diagnostic windows when debugging port-level sessions such as Entmoot :1004.`)
	turnProvider := flag.String("turn-provider", "", `TURN credential provider ("" disables TURN; "static"=long-lived creds; "cloudflare"=short-lived Cloudflare Realtime TURN)`)
	turnServer := flag.String("turn-server", "", "TURN server host:port (required when -turn-provider=static)")
	turnTransport := flag.String("turn-transport", "udp", "TURN client→server transport: udp|tcp|tls")
	turnStaticUser := flag.String("turn-static-user", "", "TURN username (required when -turn-provider=static)")
	turnStaticPass := flag.String("turn-static-pass", "", "TURN password (required when -turn-provider=static; insecure — prefer `pilot-daemon turn-setup static`)")
	cloudflareTurnCredsFile := flag.String("cloudflare-turn-creds-file", defaultCloudflareTurnCredsFile(), "path to Cloudflare TURN credentials JSON (turn_token_id + api_token)")
	cloudflareTurnTTL := flag.Duration("cloudflare-turn-ttl", 1*time.Hour, "Cloudflare TURN credential TTL (60s ≤ value ≤ 48h)")

	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		config.ApplyToFlags(cfg)
	}

	logging.Setup(*logLevel, *logFormat)

	// v1.9.0-jf.11a: -hide-ip preset expands to -no-registry-endpoint +
	// -outbound-turn-only unless those sub-flags were explicitly set.
	// Explicit value wins (operator can compose, e.g.
	// `-hide-ip -no-registry-endpoint=false` to get outbound-turn-only
	// but keep registry publishing).
	if *hideIP {
		visited := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { visited[f.Name] = true })
		if !visited["no-registry-endpoint"] {
			*noRegistryEndpoint = true
		}
		if !visited["outbound-turn-only"] {
			*outboundTurnOnly = true
		}
	}

	turnProv := buildTURNProvider(
		*turnProvider,
		*turnServer,
		*turnTransport,
		*turnStaticUser,
		*turnStaticPass,
		*cloudflareTurnCredsFile,
		*cloudflareTurnTTL,
	)

	d := daemon.New(daemon.Config{
		RegistryAddr:          *registryAddr,
		BeaconAddr:            *beaconAddr,
		ListenAddr:            *listenAddr,
		SocketPath:            *socketPath,
		Endpoint:              *endpoint,
		TCPListenAddr:         *tcpListen,
		TCPEndpoint:           *tcpEndpoint,
		Encrypt:               *encrypt,
		RegistryTLS:           *registryTLS,
		RegistryFingerprint:   *registryFingerprint,
		IdentityPath:          *identityPath,
		Email:                 *email,
		Owner:                 *owner,
		KeepaliveInterval:     *keepalive,
		IdleTimeout:           *idleTimeout,
		SYNRateLimit:          *synRate,
		MaxConnectionsPerPort: *maxConnsPerPort,
		MaxTotalConnections:   *maxConnsTotal,
		TimeWaitDuration:      *timeWait,
		Public:                *public,
		Hostname:              *hostname,
		DisableEcho:           *noEcho,
		DisableDataExchange:   *noDataExchange,
		DisableEventStream:    *noEventStream,
		DisableTaskSubmit:     *noTaskSubmit,
		WebhookURL:            *webhookURL,
		AdminToken:            *adminToken,
		Networks:              parseNetworkIDs(*networks),
		Version:               version,
		TrustAutoApprove:      *trustAutoApprove,
		TURNProvider:          turnProv,
		NoRegistryEndpoint:    *noRegistryEndpoint,
		OutboundTURNOnly:      *outboundTurnOnly,
		PeerKeepaliveInterval: *peerKeepalive,
		RendezvousURL:         *rendezvousURL,
		TraceSends:            *traceSends,
		TraceStreams:          *traceStreams,
	})

	if err := d.Start(); err != nil {
		log.Fatalf("daemon start: %v", err)
	}

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("shutting down")
	d.Stop()
}

// defaultCloudflareTurnCredsFile returns the default path for the
// Cloudflare TURN credentials file, resolving "~/.pilot/..." against
// the current user's home. Falls back to a literal "~" expansion if
// os.UserHomeDir fails.
func defaultCloudflareTurnCredsFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "~/.pilot/cloudflare-turn.json"
	}
	return filepath.Join(home, ".pilot", "cloudflare-turn.json")
}

// cloudflareTurnCredsFile is the on-disk format for the Cloudflare
// TURN token: { "turn_token_id": "...", "api_token": "..." }.
type cloudflareTurnCredsFile struct {
	TurnTokenID string `json:"turn_token_id"`
	APIToken    string `json:"api_token"`
}

// buildTURNProvider constructs a turncreds.Provider from the
// -turn-provider family of flags. On any validation or file I/O error
// it calls log.Fatalf — the daemon should not start with a
// half-configured TURN backend.
func buildTURNProvider(
	kind, server, transport, staticUser, staticPass, cfFile string,
	cfTTL time.Duration,
) turncreds.Provider {
	switch kind {
	case "":
		return nil

	case "static":
		p, err := turncreds.NewStaticProvider(server, transport, staticUser, staticPass)
		if err != nil {
			log.Fatalf("turn-provider=static: %v", err)
		}
		if staticPass != "" {
			slog.Warn("turn-static-pass on command line is insecure; " +
				"prefer `pilot-daemon turn-setup static` which reads the password from stdin")
		}
		return p

	case "cloudflare":
		if cfFile == "" {
			log.Fatalf("turn-provider=cloudflare: -cloudflare-turn-creds-file is required")
		}
		data, err := os.ReadFile(cfFile)
		if err != nil {
			log.Fatalf("turn-provider=cloudflare: read %s: %v", cfFile, err)
		}
		var creds cloudflareTurnCredsFile
		if err := json.Unmarshal(data, &creds); err != nil {
			log.Fatalf("turn-provider=cloudflare: parse %s: %v", cfFile, err)
		}
		if creds.TurnTokenID == "" || creds.APIToken == "" {
			log.Fatalf("turn-provider=cloudflare: %s is missing turn_token_id or api_token", cfFile)
		}
		p, err := turncreds.NewCloudflareProvider(turncreds.CloudflareOptions{
			TokenID:   creds.TurnTokenID,
			APIToken:  creds.APIToken,
			TTL:       cfTTL,
			Transport: transport,
		})
		if err != nil {
			log.Fatalf("turn-provider=cloudflare: %v", err)
		}
		return p

	default:
		log.Fatalf(`turn-provider: unknown value %q (want "", "static", or "cloudflare")`, kind)
		return nil
	}
}

// parseNetworkIDs parses a comma-separated string of network IDs into a uint16 slice.
func parseNetworkIDs(s string) []uint16 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var ids []uint16
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			log.Printf("warning: invalid network ID %q: %v", p, err)
			continue
		}
		ids = append(ids, uint16(n))
	}
	return ids
}
