package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPilotUpdateRepoDefaultsToOfficial(t *testing.T) {
	if got := pilotUpdateRepo(nil, t.TempDir()); got != "TeoSlayer/pilotprotocol" {
		t.Fatalf("pilotUpdateRepo default = %q, want TeoSlayer/pilotprotocol", got)
	}
}

func TestPilotUpdateRepoUsesInstallMarker(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".pilot-repo"), []byte("jerryfane/pilotprotocol\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := pilotUpdateRepo(nil, dir); got != "jerryfane/pilotprotocol" {
		t.Fatalf("pilotUpdateRepo marker = %q, want jerryfane/pilotprotocol", got)
	}
}

func TestPilotUpdateRepoEmptyOrUnreadableMarkerFallsBack(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".pilot-repo"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		if got := pilotUpdateRepo(nil, dir); got != "TeoSlayer/pilotprotocol" {
			t.Fatalf("pilotUpdateRepo empty marker = %q, want TeoSlayer/pilotprotocol", got)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, ".pilot-repo"), 0755); err != nil {
			t.Fatal(err)
		}
		if got := pilotUpdateRepo(nil, dir); got != "TeoSlayer/pilotprotocol" {
			t.Fatalf("pilotUpdateRepo unreadable marker = %q, want TeoSlayer/pilotprotocol", got)
		}
	})
}

func TestPilotUpdateRepoFlagOverridesDefault(t *testing.T) {
	flags, pos := parseFlags([]string{"--repo", "example/pilot"})
	if len(pos) != 0 {
		t.Fatalf("positional args = %v, want none", pos)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".pilot-repo"), []byte("jerryfane/pilotprotocol\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := pilotUpdateRepo(flags, dir); got != "example/pilot" {
		t.Fatalf("pilotUpdateRepo override = %q, want example/pilot", got)
	}
}
