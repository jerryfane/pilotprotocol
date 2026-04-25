package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
)

var version = "dev"

func main() {
	listen := flag.String("listen", ":8443",
		"HTTP listen address (e.g. :8443). For TLS, run behind Caddy/Cloudflare/Tailscale-Funnel; this server speaks plain HTTP.")
	dbPath := flag.String("db", "/var/lib/pilot-rendezvous/store.db",
		"path to bbolt database (parent dir must exist)")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		_, _ = os.Stdout.WriteString(version + "\n")
		os.Exit(0)
	}
	logging.Setup(*logLevel, *logFormat)

	srv, err := NewServer(*dbPath)
	if err != nil {
		log.Fatalf("init server: %v", err)
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("pilot-rendezvous listening", "addr", *listen, "db", *dbPath, "version", version)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("shutdown signal", "signal", sig.String())
	case err := <-errCh:
		if err != nil {
			log.Fatalf("server error: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		slog.Warn("http shutdown", "error", err)
	}
}
