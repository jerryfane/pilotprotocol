package tests

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func startTestDashboard(t *testing.T, r *registry.Server) string {
	t.Helper()
	srv := httptest.NewServer(r.DashboardHandler())
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}
