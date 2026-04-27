package pilot_dashboard

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/tests"
)

// TestRunDashboardWithSeed is a manual test that starts a local rendezvous server,
// seeds it with test data, and keeps it running for manual dashboard inspection.
//
// Run with:
//
//	PILOT_MANUAL_DASHBOARD=1 go test -v -run TestRunDashboardWithSeed -timeout=0 ./tests/pilot_dashboard
//
// The dashboard will be available on an ephemeral localhost port printed by the
// test.
// Press Ctrl+C to stop the server.
func TestRunDashboardWithSeed(t *testing.T) {
	if os.Getenv("PILOT_MANUAL_DASHBOARD") != "1" {
		t.Skip("manual dashboard test; set PILOT_MANUAL_DASHBOARD=1 to run")
	}
	if testing.Short() {
		t.Skip("skipping manual dashboard test in short mode")
	}

	log.Println("Starting rendezvous server with dashboard...")

	// Create test environment with dashboard enabled
	env := tests.NewTestEnv(t)

	// Start dashboard on the registry
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dashboard listen: %v", err)
	}
	dashboardAddr := ln.Addr().String()
	srv := &http.Server{Handler: env.Registry.DashboardHandler()}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	waitDashboardReady(t, dashboardAddr, errCh)

	// Seed the registry with test data
	log.Println("\nSeeding registry with test data...")
	if err := SeedRegistry(env.RegistryAddr); err != nil {
		t.Fatalf("failed to seed registry: %v", err)
	}

	// Print access information
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Printf("✅ Dashboard is running!\n\n")
	fmt.Printf("   Dashboard URL:  http://%s\n", dashboardAddr)
	fmt.Printf("   Registry Addr:  %s\n", env.RegistryAddr)
	fmt.Printf("   Beacon Addr:    %s\n\n", env.BeaconAddr)
	fmt.Println("   Press Ctrl+C to stop the server")
	fmt.Println(strings.Repeat("=", 70) + "\n")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\nShutting down...")
}

func waitDashboardReady(t *testing.T, addr string, errCh <-chan error) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	url := "http://" + addr + "/api/stats"
	for {
		select {
		case err := <-errCh:
			t.Fatalf("dashboard serve: %v", err)
		case <-deadline:
			t.Fatalf("dashboard did not become ready at %s", url)
		case <-tick.C:
			resp, err := http.Get(url)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
}
