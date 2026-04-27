package tests

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// setClientSigner configures a registry client with a signer for the given identity.
// This is required for authenticated registry operations (H3 fix).
func setClientSigner(rc *registry.Client, id *crypto.Identity) {
	rc.SetSigner(func(challenge string) string {
		sig := id.Sign([]byte(challenge))
		return base64.StdEncoding.EncodeToString(sig)
	})
}

// resolveLocalAddr replaces wildcard hosts (::, 0.0.0.0, empty) with 127.0.0.1
// so that test daemons can actually connect to the local servers.
func resolveLocalAddr(addr net.Addr) string {
	s := addr.String()
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		return "127.0.0.1:" + port
	}
	return s
}

// TestAdminToken is the admin token used in tests for network creation.
const TestAdminToken = "test-admin-secret"

// TestEnv manages a complete Pilot Protocol test environment with
// OS-assigned ports and proper readiness signaling (no time.Sleep).
type TestEnv struct {
	t *testing.T

	Beacon   *beacon.Server
	Registry *registry.Server

	// Resolved addresses (only valid after Start)
	BeaconAddr   string
	RegistryAddr string
	AdminToken   string

	daemons []*daemon.Daemon
	drivers []*driver.Driver
	tmpDir  string
}

// DaemonInfo holds references for a started daemon and its driver.
type DaemonInfo struct {
	Daemon     *daemon.Daemon
	Driver     *driver.Driver
	SocketPath string
}

// NewTestEnv creates and starts a beacon + registry with OS-assigned ports.
// Call AddDaemon() to add daemons after creation.
func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()

	// Use /tmp for short socket paths — macOS limits unix socket paths to 104 bytes.
	// t.TempDir() paths include the full test name and can exceed this limit.
	tmpDir, err := os.MkdirTemp("/tmp", "w4-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	env := &TestEnv{
		t:      t,
		tmpDir: tmpDir,
	}

	// Start beacon on OS-assigned port
	env.Beacon = beacon.New()
	go env.Beacon.ListenAndServe("127.0.0.1:0")
	select {
	case <-env.Beacon.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon failed to start within 5s")
	}
	env.BeaconAddr = resolveLocalAddr(env.Beacon.Addr())

	// Start registry on OS-assigned port
	env.Registry = registry.New(env.BeaconAddr)
	env.Registry.SetAdminToken(TestAdminToken)
	env.AdminToken = TestAdminToken
	go env.Registry.ListenAndServe("127.0.0.1:0")
	select {
	case <-env.Registry.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start within 5s")
	}
	env.RegistryAddr = resolveLocalAddr(env.Registry.Addr())

	t.Cleanup(func() {
		env.Close()
	})

	return env
}

// AddDaemon starts a daemon connected to this environment's registry/beacon.
// Optional config overrides can be applied via the opts function.
func (env *TestEnv) AddDaemon(opts ...func(*daemon.Config)) *DaemonInfo {
	env.t.Helper()

	idx := len(env.daemons)
	sockPath := filepath.Join(env.tmpDir, fmt.Sprintf("daemon-%d.sock", idx))
	identityPath := filepath.Join(env.tmpDir, fmt.Sprintf("identity-%d.json", idx))

	cfg := daemon.Config{
		RegistryAddr:        env.RegistryAddr,
		BeaconAddr:          env.BeaconAddr,
		ListenAddr:          ":0",
		SocketPath:          sockPath,
		IdentityPath:        identityPath, // persist identity to avoid pubkey mismatch on restart
		Email:               fmt.Sprintf("test-%d@pilot.local", idx),
		Public:              true,                   // tests default to public for free connectivity
		WebhookHTTPTimeout:  500 * time.Millisecond, // fast webhook timeouts for tests
		WebhookRetryBackoff: 10 * time.Millisecond,  // fast retry backoff for tests
	}
	for _, fn := range opts {
		fn(&cfg)
	}

	d := daemon.New(cfg)
	if err := d.Start(); err != nil {
		env.t.Fatalf("daemon %d start: %v", idx, err)
	}
	env.daemons = append(env.daemons, d)

	drv := env.waitDriverReady(idx, sockPath, d.NodeID())
	env.drivers = append(env.drivers, drv)
	env.waitRegistryReady(idx, d.NodeID())

	return &DaemonInfo{Daemon: d, Driver: drv, SocketPath: sockPath}
}

// AddDaemonOnly starts a daemon without creating a driver (for tests that
// need to manage the driver lifecycle separately).
func (env *TestEnv) AddDaemonOnly(opts ...func(*daemon.Config)) (*daemon.Daemon, string) {
	env.t.Helper()

	idx := len(env.daemons)
	sockPath := filepath.Join(env.tmpDir, fmt.Sprintf("daemon-%d.sock", idx))
	identityPath := filepath.Join(env.tmpDir, fmt.Sprintf("identity-%d.json", idx))

	cfg := daemon.Config{
		RegistryAddr:        env.RegistryAddr,
		BeaconAddr:          env.BeaconAddr,
		ListenAddr:          ":0",
		SocketPath:          sockPath,
		IdentityPath:        identityPath, // persist identity to avoid pubkey mismatch on restart
		Email:               fmt.Sprintf("test-%d@pilot.local", idx),
		Public:              true,                   // tests default to public for free connectivity
		WebhookHTTPTimeout:  500 * time.Millisecond, // fast webhook timeouts for tests
		WebhookRetryBackoff: 10 * time.Millisecond,  // fast retry backoff for tests
	}
	for _, fn := range opts {
		fn(&cfg)
	}

	d := daemon.New(cfg)
	if err := d.Start(); err != nil {
		env.t.Fatalf("daemon %d start: %v", idx, err)
	}
	env.daemons = append(env.daemons, d)
	env.waitRegistryReady(idx, d.NodeID())

	return d, sockPath
}

func (env *TestEnv) waitDriverReady(idx int, sockPath string, nodeID uint32) *driver.Driver {
	env.t.Helper()

	var drv *driver.Driver
	if err := eventually(env.t, 5*time.Second, 20*time.Millisecond, fmt.Sprintf("daemon %d driver ready", idx), func() error {
		if drv != nil {
			drv.Close()
			drv = nil
		}
		var err error
		drv, err = driver.Connect(sockPath)
		if err != nil {
			return err
		}
		info, err := drv.Info()
		if err != nil {
			return err
		}
		got, ok := info["node_id"].(float64)
		if !ok || uint32(got) != nodeID {
			return fmt.Errorf("info node_id=%v, want %d", info["node_id"], nodeID)
		}
		return nil
	}); err != nil {
		env.t.Fatal(err)
	}
	return drv
}

func (env *TestEnv) waitRegistryReady(idx int, nodeID uint32) {
	env.t.Helper()

	if err := eventually(env.t, 5*time.Second, 20*time.Millisecond, fmt.Sprintf("daemon %d registry lookup", idx), func() error {
		rc, err := registry.Dial(env.RegistryAddr)
		if err != nil {
			return err
		}
		defer rc.Close()

		resp, err := rc.Lookup(nodeID)
		if err != nil {
			return err
		}
		if resp["error"] != nil {
			return fmt.Errorf("lookup node %d: %v", nodeID, resp["error"])
		}
		return nil
	}); err != nil {
		env.t.Fatal(err)
	}
}

func (env *TestEnv) DialAddrEventually(src *driver.Driver, dst protocol.Addr, port uint16) *driver.Conn {
	env.t.Helper()

	var conn *driver.Conn
	if err := eventually(env.t, 5*time.Second, 50*time.Millisecond, fmt.Sprintf("dial %s:%d", dst, port), func() error {
		var err error
		conn, err = src.DialAddr(dst, port)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		env.t.Fatal(err)
	}
	return conn
}

func eventually(t *testing.T, timeout, interval time.Duration, label string, fn func() error) error {
	t.Helper()

	deadline := time.Now().Add(timeout)
	if testDeadline, ok := t.Deadline(); ok {
		if until := time.Until(testDeadline) / 4; until > 0 && until < timeout {
			deadline = time.Now().Add(until)
		}
	}

	var lastErr error
	for {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not become ready within %s: %w", label, timeout, lastErr)
		}
		time.Sleep(interval)
	}
}

// SocketPath returns a unique socket path within the temp directory.
func (env *TestEnv) SocketPath(name string) string {
	return filepath.Join(env.tmpDir, name+".sock")
}

// Close stops all drivers, daemons, and servers.
func (env *TestEnv) Close() {
	for _, drv := range env.drivers {
		drv.Close()
	}
	for _, d := range env.daemons {
		d.Stop()
	}
	env.Beacon.Close()
	env.Registry.Close()

	// Remove the temp directory and all socket files
	os.RemoveAll(env.tmpDir)
}
