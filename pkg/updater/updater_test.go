package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input   string
		want    Semver
		wantErr bool
	}{
		{"v1.2.3", Semver{1, 2, 3}, false},
		{"1.2.3", Semver{1, 2, 3}, false},
		{"v0.0.1", Semver{0, 0, 1}, false},
		{"v10.20.30", Semver{10, 20, 30}, false},
		{"v1.2.3-dirty", Semver{1, 2, 3}, false},
		{"v1.6.2-rc1", Semver{1, 6, 2}, false},
		{"", Semver{}, true},
		{"v1.2", Semver{}, true},
		{"v1.2.x", Semver{}, true},
		{"abc", Semver{}, true},
		{"v1.2.3.4", Semver{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSemver(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSemver(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ParseSemver(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSemverNewerThan(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"v1.2.4", "v1.2.3", true},
		{"v1.3.0", "v1.2.9", true},
		{"v2.0.0", "v1.9.9", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.3", "v1.2.4", false},
		{"v1.2.3", "v1.3.0", false},
		{"v1.2.3", "v2.0.0", false},
		{"v0.0.1", "v0.0.0", true},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s>%s", tt.a, tt.b)
		t.Run(name, func(t *testing.T) {
			a, _ := ParseSemver(tt.a)
			b, _ := ParseSemver(tt.b)
			if got := a.NewerThan(b); got != tt.want {
				t.Fatalf("%s.NewerThan(%s) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestReleaseVersionNewerThanPreservesSuffixes(t *testing.T) {
	tests := []struct {
		target  string
		current string
		want    bool
	}{
		{"v1.9.0-jf.15.3", "v1.9.0-jf.15.2", true},
		{"v1.9.0-jf.15.3", "v1.9.0", true},
		{"v1.9.0-jf.15", "v1.9.0-jf.11b", true},
		{"v1.9.0-jf.11b", "v1.9.0-jf.11a", true},
		{"v1.9.0-rc.2", "v1.9.0-rc.1", true},
		{"v1.9.0", "v1.9.0-rc.1", true},
		{"v1.9.0+build.2", "v1.9.0+build.1", false},
		{"v1.9.0", "v1.9.0-jf.15.3", false},
		{"v1.9.0-jf.15.2", "v1.9.0-jf.15.3", false},
	}
	for _, tt := range tests {
		t.Run(tt.target+"_over_"+tt.current, func(t *testing.T) {
			target, err := parseReleaseVersion(tt.target)
			if err != nil {
				t.Fatalf("target parse: %v", err)
			}
			current, err := parseReleaseVersion(tt.current)
			if err != nil {
				t.Fatalf("current parse: %v", err)
			}
			if got := target.NewerThan(current); got != tt.want {
				t.Fatalf("%s newer than %s = %v, want %v", tt.target, tt.current, got, tt.want)
			}
		})
	}
}

func TestReleaseUpdateAvailableExplicitTagUsesFullTag(t *testing.T) {
	current, err := parseReleaseVersion("v1.9.0-jf.15.2")
	if err != nil {
		t.Fatal(err)
	}
	target, err := parseReleaseVersion("v1.9.0-jf.15.3")
	if err != nil {
		t.Fatal(err)
	}
	if !releaseUpdateAvailable(current, "v1.9.0-jf.15.2", target, "v1.9.0-jf.15.3", true) {
		t.Fatalf("explicit tag should update when only suffix differs")
	}
	if releaseUpdateAvailable(current, "v1.9.0-jf.15.2", current, "v1.9.0-jf.15.2", true) {
		t.Fatalf("explicit tag should not update to same full tag")
	}
}

func TestResolveRepoPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".pilot-repo"), []byte("jerryfane/pilotprotocol\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveRepo(dir, "example/pilot"); got != "example/pilot" {
		t.Fatalf("explicit repo = %q, want example/pilot", got)
	}
	if got := ResolveRepo(dir, ""); got != "jerryfane/pilotprotocol" {
		t.Fatalf("marker repo = %q, want jerryfane/pilotprotocol", got)
	}
	if got := ResolveRepo(t.TempDir(), ""); got != DefaultRepo {
		t.Fatalf("fallback repo = %q, want %q", got, DefaultRepo)
	}
}

func TestResolveRepoIgnoresEmptyOrUnreadableMarker(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".pilot-repo"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		if got := ResolveRepo(dir, ""); got != DefaultRepo {
			t.Fatalf("empty marker repo = %q, want %q", got, DefaultRepo)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, ".pilot-repo"), 0755); err != nil {
			t.Fatal(err)
		}
		if got := ResolveRepo(dir, ""); got != DefaultRepo {
			t.Fatalf("unreadable marker repo = %q, want %q", got, DefaultRepo)
		}
	})
}

func TestSemverString(t *testing.T) {
	v := Semver{1, 6, 3}
	if s := v.String(); s != "v1.6.3" {
		t.Fatalf("String() = %q, want %q", s, "v1.6.3")
	}
}

func TestGitHubReleaseByTagURLEscapesTagPathSegment(t *testing.T) {
	got := githubReleaseByTagURL("test/repo", "release/v1.2.3")
	want := "https://api.github.com/repos/test/repo/releases/tags/release%2Fv1.2.3"
	if got != want {
		t.Fatalf("githubReleaseByTagURL = %q, want %q", got, want)
	}

	got = githubReleaseByTagURL("test/repo", "v1.2.3")
	want = "https://api.github.com/repos/test/repo/releases/tags/v1.2.3"
	if got != want {
		t.Fatalf("githubReleaseByTagURL normal tag = %q, want %q", got, want)
	}
}

func TestVerifyChecksum(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file.
	content := []byte("hello world\n")
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	os.WriteFile(archivePath, content, 0644)

	// Compute its SHA256.
	h := sha256.Sum256(content)
	correctHash := fmt.Sprintf("%x", h)

	// Write correct checksums file.
	correctChecksums := filepath.Join(tmpDir, "checksums-ok.txt")
	os.WriteFile(correctChecksums, []byte(correctHash+"  test.tar.gz\n"), 0644)

	// Write incorrect checksums file.
	badChecksums := filepath.Join(tmpDir, "checksums-bad.txt")
	os.WriteFile(badChecksums, []byte("0000000000000000000000000000000000000000000000000000000000000000  test.tar.gz\n"), 0644)

	// Write checksums file missing our archive.
	missingChecksums := filepath.Join(tmpDir, "checksums-missing.txt")
	os.WriteFile(missingChecksums, []byte(correctHash+"  other.tar.gz\n"), 0644)

	t.Run("correct", func(t *testing.T) {
		if err := VerifyChecksum(archivePath, "test.tar.gz", correctChecksums); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		err := VerifyChecksum(archivePath, "test.tar.gz", badChecksums)
		if err == nil {
			t.Fatal("expected error for mismatched checksum")
		}
	})

	t.Run("missing_entry", func(t *testing.T) {
		err := VerifyChecksum(archivePath, "test.tar.gz", missingChecksums)
		if err == nil {
			t.Fatal("expected error for missing entry")
		}
	})
}

func TestExtractTarGz(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a tar.gz with two files.
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	createTestTarGz(t, archivePath, map[string]string{
		"daemon":   "daemon-binary-content",
		"pilotctl": "pilotctl-binary-content",
	})

	// Extract.
	destDir := filepath.Join(tmpDir, "extracted")
	os.MkdirAll(destDir, 0755)
	if err := extractTarGz(archivePath, destDir); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}

	// Verify files.
	for _, name := range []string{"daemon", "pilotctl"} {
		data, err := os.ReadFile(filepath.Join(destDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		expected := name + "-binary-content"
		if string(data) != expected {
			t.Fatalf("%s content = %q, want %q", name, string(data), expected)
		}
		info, _ := os.Stat(filepath.Join(destDir, name))
		if info.Mode().Perm() != 0755 {
			t.Fatalf("%s permissions = %o, want 0755", name, info.Mode().Perm())
		}
	}
}

func TestCheckOnce_AlreadyUpToDate(t *testing.T) {
	tmpDir := t.TempDir()

	// Write version file indicating v1.6.3.
	os.WriteFile(filepath.Join(tmpDir, ".pilot-version"), []byte("v1.6.3\n"), 0644)
	// Create dummy daemon binary.
	os.WriteFile(filepath.Join(tmpDir, "daemon"), []byte("#!/bin/sh\necho v1.6.3"), 0755)

	// Mock GitHub API returning v1.6.3 as latest.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(GitHubRelease{
			TagName: "v1.6.3",
			Assets:  []GitHubAsset{},
		})
	}))
	defer srv.Close()

	u := &Updater{
		config: Config{
			Repo:       "test/repo",
			InstallDir: tmpDir,
		},
		client: srv.Client(),
		stopCh: make(chan struct{}),
	}
	// Override the fetch to use our test server.
	// We'll test via the exported interface instead.
	release, err := func() (*GitHubRelease, error) {
		resp, err := u.client.Get(srv.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var rel GitHubRelease
		json.NewDecoder(resp.Body).Decode(&rel)
		return &rel, nil
	}()
	if err != nil {
		t.Fatal(err)
	}

	latest, _ := ParseSemver(release.TagName)
	current, _ := ParseSemver("v1.6.3")
	if latest.NewerThan(current) {
		t.Fatal("v1.6.3 should not be newer than v1.6.3")
	}
}

func TestCheckOnce_NewVersionAvailable(t *testing.T) {
	tmpDir := t.TempDir()

	// Current version is v1.6.2.
	os.WriteFile(filepath.Join(tmpDir, ".pilot-version"), []byte("v1.6.2\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "daemon"), []byte("dummy"), 0755)

	// Create a test archive for the update.
	archiveDir := t.TempDir()
	archiveName := fmt.Sprintf("pilot-%s-%s.tar.gz", "linux", "amd64")
	archivePath := filepath.Join(archiveDir, archiveName)
	createTestTarGz(t, archivePath, map[string]string{
		"daemon":   "new-daemon-v1.6.3",
		"pilotctl": "new-pilotctl-v1.6.3",
	})
	archiveContent, _ := os.ReadFile(archivePath)
	archiveHash := sha256.Sum256(archiveContent)
	checksumsContent := fmt.Sprintf("%x  %s\n", archiveHash, archiveName)

	// Mock GitHub API.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/test/repo/releases/latest":
			json.NewEncoder(w).Encode(GitHubRelease{
				TagName: "v1.6.3",
				Assets: []GitHubAsset{
					{Name: archiveName, BrowserDownloadURL: "http://" + r.Host + "/download/" + archiveName},
					{Name: "checksums.txt", BrowserDownloadURL: "http://" + r.Host + "/download/checksums.txt"},
				},
			})
		case r.URL.Path == "/download/"+archiveName:
			w.Write(archiveContent)
		case r.URL.Path == "/download/checksums.txt":
			w.Write([]byte(checksumsContent))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Verify the mock returns a newer version.
	resp, _ := srv.Client().Get(srv.URL + "/repos/test/repo/releases/latest")
	var rel GitHubRelease
	json.NewDecoder(resp.Body).Decode(&rel)
	resp.Body.Close()

	latest, _ := ParseSemver(rel.TagName)
	current, _ := ParseSemver("v1.6.2")
	if !latest.NewerThan(current) {
		t.Fatal("v1.6.3 should be newer than v1.6.2")
	}
}

func TestReplaceBinary(t *testing.T) {
	tmpDir := t.TempDir()

	// Create source and destination.
	src := filepath.Join(tmpDir, "new-bin")
	dst := filepath.Join(tmpDir, "bin")
	os.WriteFile(src, []byte("new content"), 0755)
	os.WriteFile(dst, []byte("old content"), 0755)

	if err := replaceBinary(src, dst); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(dst)
	if string(data) != "new content" {
		t.Fatalf("got %q, want %q", string(data), "new content")
	}
}

func TestCurrentVersionFallsBackToDaemonVersion(t *testing.T) {
	tmpDir := t.TempDir()
	daemon := filepath.Join(tmpDir, "pilot-daemon")
	if err := os.WriteFile(daemon, []byte("#!/bin/sh\necho pilot-daemon v1.2.3\n"), 0755); err != nil {
		t.Fatal(err)
	}
	u := &Updater{config: Config{InstallDir: tmpDir}}
	got, err := u.currentVersion()
	if err != nil {
		t.Fatalf("currentVersion: %v", err)
	}
	if got.String() != "v1.2.3" {
		t.Fatalf("currentVersion = %s, want v1.2.3", got.String())
	}
}

func TestReleaseAvailabilityAllowsDevCurrentVersion(t *testing.T) {
	current, latest, available, err := releaseAvailability("dev", "v1.6.3", false)
	if err != nil {
		t.Fatalf("releaseAvailability: %v", err)
	}
	if current != "dev" {
		t.Fatalf("current version = %q, want dev", current)
	}
	if latest != "v1.6.3" {
		t.Fatalf("latest version = %q, want v1.6.3", latest)
	}
	if !available {
		t.Fatalf("dev current version should update to release")
	}
}

func TestApplyUpdate_SkipsServerBinaries(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "linux")
	defer restore()

	tmpDir := t.TempDir()
	installDir := filepath.Join(tmpDir, "bin")
	os.MkdirAll(installDir, 0755)

	// Seed existing binaries (client + server).
	os.WriteFile(filepath.Join(installDir, "daemon"), []byte("old-daemon"), 0755)
	os.WriteFile(filepath.Join(installDir, "gateway"), []byte("old-gateway"), 0755)
	os.WriteFile(filepath.Join(installDir, "updater"), []byte("old-updater"), 0755)
	os.WriteFile(filepath.Join(installDir, "registry"), []byte("old-registry"), 0755)
	os.WriteFile(filepath.Join(installDir, "beacon"), []byte("old-beacon"), 0755)
	os.WriteFile(filepath.Join(installDir, ".pilot-version"), []byte("v1.0.0\n"), 0644)

	// Build an archive with both client and server binaries.
	archiveDir := t.TempDir()
	archiveName := fmt.Sprintf("pilot-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	archivePath := filepath.Join(archiveDir, archiveName)
	createTestTarGz(t, archivePath, map[string]string{
		"daemon":     "new-daemon",
		"pilotctl":   "new-pilotctl",
		"gateway":    "new-gateway",
		"updater":    "new-updater",
		"registry":   "new-registry",
		"beacon":     "new-beacon",
		"rendezvous": "new-rendezvous",
		"nameserver": "new-nameserver",
	})
	archiveContent, _ := os.ReadFile(archivePath)
	archiveHash := sha256.Sum256(archiveContent)
	checksumsContent := fmt.Sprintf("%x  %s\n", archiveHash, archiveName)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/" + archiveName:
			w.Write(archiveContent)
		case "/download/checksums.txt":
			w.Write([]byte(checksumsContent))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u := &Updater{
		config: Config{Repo: "test/repo", InstallDir: installDir},
		client: srv.Client(),
		stopCh: make(chan struct{}),
	}

	release := &GitHubRelease{
		TagName: "v1.1.0",
		Assets: []GitHubAsset{
			{Name: archiveName, BrowserDownloadURL: srv.URL + "/download/" + archiveName},
			{Name: "checksums.txt", BrowserDownloadURL: srv.URL + "/download/checksums.txt"},
		},
	}

	if _, err := u.applyUpdate(release); err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}
	repoData, err := os.ReadFile(filepath.Join(installDir, ".pilot-repo"))
	if err != nil {
		t.Fatalf("read .pilot-repo: %v", err)
	}
	if string(repoData) != "test/repo\n" {
		t.Fatalf(".pilot-repo = %q, want test/repo", string(repoData))
	}

	// Client binaries should be updated.
	for _, name := range []string{"daemon", "pilotctl", "gateway", "updater"} {
		data, err := os.ReadFile(filepath.Join(installDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(data) != "new-"+name {
			t.Errorf("%s = %q, want %q", name, string(data), "new-"+name)
		}
	}

	// Server binaries should NOT be updated.
	for _, name := range []string{"registry", "beacon"} {
		data, err := os.ReadFile(filepath.Join(installDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(data) != "old-"+name {
			t.Errorf("%s = %q, want %q (should be unchanged)", name, string(data), "old-"+name)
		}
	}

	// Server binaries not previously present should NOT be created.
	for _, name := range []string{"rendezvous", "nameserver"} {
		if _, err := os.Stat(filepath.Join(installDir, name)); err == nil {
			t.Errorf("%s should not have been created", name)
		}
	}
}

func TestInstalledPathForPrefersInstallerNames(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pilot-daemon"), []byte("daemon"), 0755); err != nil {
		t.Fatal(err)
	}
	u := &Updater{config: Config{InstallDir: dir}}
	tests := map[string]string{
		"daemon":   "pilot-daemon",
		"gateway":  "pilot-gateway",
		"updater":  "pilot-updater",
		"pilotctl": "pilotctl",
	}
	for archiveName, wantBase := range tests {
		got, err := u.installedPathFor(archiveName)
		if err != nil {
			t.Fatalf("installedPathFor(%s): %v", archiveName, err)
		}
		if filepath.Base(got) != wantBase {
			t.Fatalf("installedPathFor(%s) = %s, want %s", archiveName, filepath.Base(got), wantBase)
		}
	}
}

func TestInstalledPathForPrefersPrefixedNamesInMixedInstall(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"pilot-daemon", "pilot-gateway", "pilot-updater", "daemon", "gateway", "updater"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	u := &Updater{config: Config{InstallDir: dir}}
	tests := map[string]string{
		"daemon":  "pilot-daemon",
		"gateway": "pilot-gateway",
		"updater": "pilot-updater",
	}
	for archiveName, wantBase := range tests {
		got, err := u.installedPathFor(archiveName)
		if err != nil {
			t.Fatalf("installedPathFor(%s): %v", archiveName, err)
		}
		if filepath.Base(got) != wantBase {
			t.Fatalf("installedPathFor(%s) = %s, want %s", archiveName, filepath.Base(got), wantBase)
		}
	}
}

func TestInstalledPathForKeepsLegacyUnprefixedNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"daemon", "gateway", "updater"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	u := &Updater{config: Config{InstallDir: dir}}
	tests := map[string]string{
		"daemon":  "daemon",
		"gateway": "gateway",
		"updater": "updater",
	}
	for archiveName, wantBase := range tests {
		got, err := u.installedPathFor(archiveName)
		if err != nil {
			t.Fatalf("installedPathFor(%s): %v", archiveName, err)
		}
		if filepath.Base(got) != wantBase {
			t.Fatalf("installedPathFor(%s) = %s, want %s", archiveName, filepath.Base(got), wantBase)
		}
	}
}

func TestPrepareUpdatedBinaryDarwinRunsCodesign(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "darwin")
	defer restore()
	var commands []string
	updaterRunCommand = func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil
	}
	if err := prepareUpdatedBinary("/tmp/pilot-daemon"); err != nil {
		t.Fatalf("prepareUpdatedBinary: %v", err)
	}
	if err := clearInstallDirXattrs("/tmp/pilot-bin"); err != nil {
		t.Fatalf("clearInstallDirXattrs: %v", err)
	}
	want := "[codesign --force --sign - /tmp/pilot-daemon xattr -cr /tmp/pilot-bin]"
	if fmt.Sprint(commands) != want {
		t.Fatalf("commands = %v, want %s", commands, want)
	}
}

func TestApplyUpdateDarwinCodesignFailureDoesNotReplaceBinary(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "darwin")
	defer restore()
	updaterRunCommand = func(name string, args ...string) error {
		if name == "codesign" {
			return os.ErrPermission
		}
		return nil
	}

	tmpDir := t.TempDir()
	installDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "daemon"), []byte("old-daemon"), 0755); err != nil {
		t.Fatal(err)
	}

	release, client := testUpdaterReleaseServer(t, map[string]string{"daemon": "new-daemon"})
	u := &Updater{
		config: Config{InstallDir: installDir},
		client: client,
		stopCh: make(chan struct{}),
	}
	if _, err := u.applyUpdate(release); err == nil {
		t.Fatalf("applyUpdate succeeded despite codesign failure")
	}
	data, err := os.ReadFile(filepath.Join(installDir, "daemon"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old-daemon" {
		t.Fatalf("daemon = %q, want old-daemon", string(data))
	}
}

func TestApplyUpdateDarwinXattrFailureWarns(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "darwin")
	defer restore()
	updaterRunCommand = func(name string, args ...string) error {
		if name == "xattr" {
			return os.ErrPermission
		}
		return nil
	}

	tmpDir := t.TempDir()
	installDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "daemon"), []byte("old-daemon"), 0755); err != nil {
		t.Fatal(err)
	}

	release, client := testUpdaterReleaseServer(t, map[string]string{"daemon": "new-daemon"})
	u := &Updater{
		config: Config{InstallDir: installDir},
		client: client,
		stopCh: make(chan struct{}),
	}
	result, err := u.applyUpdate(release)
	if err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}
	if len(result.warnings) != 1 || !strings.Contains(result.warnings[0], "quarantine") {
		t.Fatalf("warnings = %v, want quarantine warning", result.warnings)
	}
	data, err := os.ReadFile(filepath.Join(installDir, "daemon"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new-daemon" {
		t.Fatalf("daemon = %q, want new-daemon", string(data))
	}
}

func TestRestartDaemonUsesSystemdWhenAvailable(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "linux")
	defer restore()
	var commands []string
	updaterLookPath = func(name string) (string, error) {
		if name != "systemctl" {
			t.Fatalf("unexpected lookpath %s", name)
		}
		return "/bin/systemctl", nil
	}
	updaterRunCommand = func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil
	}
	u := &Updater{}
	got := u.restartDaemonAfterUpdate([]int{123})
	if !got.handled || len(got.warnings) != 0 {
		t.Fatalf("restart = %+v, want handled", got)
	}
	want := "[systemctl is-active --quiet pilot-daemon.service systemctl restart pilot-daemon.service]"
	if fmt.Sprint(commands) != want {
		t.Fatalf("commands = %v, want %s", commands, want)
	}
}

func TestRestartDaemonLinuxFallbackSignalsButRequiresManualStart(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "linux")
	defer restore()
	updaterLookPath = func(string) (string, error) { return "", os.ErrNotExist }
	var signaled []int
	updaterSignalProcess = func(pid int, sig syscall.Signal) error {
		if sig != syscall.SIGTERM {
			t.Fatalf("signal = %v, want SIGTERM", sig)
		}
		signaled = append(signaled, pid)
		return nil
	}
	u := &Updater{}
	got := u.restartDaemonAfterUpdate([]int{123})
	if got.handled || len(got.warnings) == 0 {
		t.Fatalf("restart = %+v, want warning/manual restart", got)
	}
	if fmt.Sprint(signaled) != "[123]" {
		t.Fatalf("signaled = %v, want [123]", signaled)
	}
}

func TestRestartDaemonLinuxNoPIDRequiresManualRestart(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "linux")
	defer restore()
	updaterLookPath = func(string) (string, error) { return "", os.ErrNotExist }
	u := &Updater{}
	got := u.restartDaemonAfterUpdate(nil)
	if got.handled {
		t.Fatalf("restart = %+v, want manual restart required", got)
	}
	if len(got.warnings) != 1 || !strings.Contains(got.warnings[0], "no running Pilot daemon") {
		t.Fatalf("warnings = %v, want no daemon warning", got.warnings)
	}
}

func TestRestartDaemonDarwinUsesLaunchctl(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "darwin")
	defer restore()
	updaterLookPath = func(name string) (string, error) {
		if name != "launchctl" {
			t.Fatalf("unexpected lookpath %s", name)
		}
		return "/bin/launchctl", nil
	}
	var command string
	updaterRunCommand = func(name string, args ...string) error {
		command = name + " " + strings.Join(args, " ")
		return nil
	}
	u := &Updater{}
	got := u.restartDaemonAfterUpdate(nil)
	if !got.handled || len(got.warnings) != 0 {
		t.Fatalf("restart = %+v, want handled", got)
	}
	if !strings.Contains(command, "launchctl kickstart -k gui/") ||
		!strings.Contains(command, "/com.vulturelabs.pilot-daemon") {
		t.Fatalf("command = %q, want launchctl kickstart daemon label", command)
	}
}

func TestRestartDaemonSignalsAfterSystemdRestartFailureWhenRestartAlways(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "linux")
	defer restore()
	updaterLookPath = func(string) (string, error) { return "/bin/systemctl", nil }
	var commands []string
	updaterRunCommand = func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "restart" {
			return os.ErrPermission
		}
		return nil
	}
	updaterRunCommandOutput = func(name string, args ...string) ([]byte, error) {
		if name != "systemctl" || fmt.Sprint(args) != "[show pilot-daemon.service -p Restart --value]" {
			t.Fatalf("unexpected output command: %s %v", name, args)
		}
		return []byte("always\n"), nil
	}
	var signaled []int
	updaterSignalProcess = func(pid int, sig syscall.Signal) error {
		if sig != syscall.SIGTERM {
			t.Fatalf("signal = %v, want SIGTERM", sig)
		}
		signaled = append(signaled, pid)
		return nil
	}
	u := &Updater{}
	got := u.restartDaemonAfterUpdate([]int{321})
	if got.handled {
		t.Fatalf("restart = %+v, want manual restart required", got)
	}
	if len(got.warnings) != 2 {
		t.Fatalf("warnings = %v, want systemctl and fallback warnings", got.warnings)
	}
	if !strings.Contains(got.warnings[0], "systemctl restart") {
		t.Fatalf("first warning = %q, want systemctl warning", got.warnings[0])
	}
	if !strings.Contains(got.warnings[1], "pilot-daemon was signaled") {
		t.Fatalf("second warning = %q, want signal warning", got.warnings[1])
	}
	if fmt.Sprint(signaled) != "[321]" {
		t.Fatalf("signaled = %v, want [321]", signaled)
	}
	wantCommands := "[systemctl is-active --quiet pilot-daemon.service systemctl restart pilot-daemon.service]"
	if fmt.Sprint(commands) != wantCommands {
		t.Fatalf("commands = %v, want %s", commands, wantCommands)
	}
}

func TestRestartDaemonDoesNotSignalAfterSystemdRestartFailureWhenRestartOnFailure(t *testing.T) {
	restore := stubUpdaterRestartEnvironment(t, "linux")
	defer restore()
	updaterLookPath = func(string) (string, error) { return "/bin/systemctl", nil }
	var commands []string
	updaterRunCommand = func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "restart" {
			return os.ErrPermission
		}
		return nil
	}
	updaterRunCommandOutput = func(name string, args ...string) ([]byte, error) {
		if name != "systemctl" || fmt.Sprint(args) != "[show pilot-daemon.service -p Restart --value]" {
			t.Fatalf("unexpected output command: %s %v", name, args)
		}
		return []byte("on-failure\n"), nil
	}
	var signaled []int
	updaterSignalProcess = func(pid int, sig syscall.Signal) error {
		signaled = append(signaled, pid)
		return nil
	}
	u := &Updater{}
	got := u.restartDaemonAfterUpdate([]int{321})
	if got.handled {
		t.Fatalf("restart = %+v, want manual restart required", got)
	}
	if len(got.warnings) != 2 {
		t.Fatalf("warnings = %v, want systemctl and manual restart warnings", got.warnings)
	}
	if !strings.Contains(got.warnings[0], "systemctl restart") {
		t.Fatalf("first warning = %q, want systemctl warning", got.warnings[0])
	}
	if !strings.Contains(got.warnings[1], "restart Pilot manually") {
		t.Fatalf("second warning = %q, want manual restart warning", got.warnings[1])
	}
	if len(signaled) != 0 {
		t.Fatalf("signaled = %v, want none", signaled)
	}
	wantCommands := "[systemctl is-active --quiet pilot-daemon.service systemctl restart pilot-daemon.service]"
	if fmt.Sprint(commands) != wantCommands {
		t.Fatalf("commands = %v, want %s", commands, wantCommands)
	}
}

func TestFindUpdaterDaemonProcessIDsDetectsDaemonModes(t *testing.T) {
	oldReadDir := updaterReadDir
	oldReadFile := updaterReadFile
	oldReadlink := updaterReadlink
	oldGetpid := updaterGetpid
	defer func() {
		updaterReadDir = oldReadDir
		updaterReadFile = oldReadFile
		updaterReadlink = oldReadlink
		updaterGetpid = oldGetpid
	}()

	daemonPath := "/opt/pilot/pilot-daemon"
	pilotctlPath := "/opt/pilot/pilotctl"
	updaterGetpid = func() int { return 999 }
	updaterReadDir = func(path string) ([]os.DirEntry, error) {
		if path != "/proc" {
			t.Fatalf("read dir = %q, want /proc", path)
		}
		return []os.DirEntry{
			fakeDirEntry{name: "101", dir: true},
			fakeDirEntry{name: "202", dir: true},
			fakeDirEntry{name: "303", dir: true},
			fakeDirEntry{name: "404", dir: true},
			fakeDirEntry{name: "999", dir: true},
			fakeDirEntry{name: "not-a-pid", dir: true},
		}, nil
	}
	updaterReadlink = func(path string) (string, error) {
		switch path {
		case "/proc/101/exe":
			return daemonPath, nil
		case "/proc/202/exe", "/proc/303/exe", "/proc/404/exe", "/proc/999/exe":
			return pilotctlPath, nil
		case "/proc/not-a-pid/exe":
			return pilotctlPath, nil
		default:
			return "", os.ErrNotExist
		}
	}
	updaterReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/202/cmdline":
			return []byte("pilotctl\x00_daemon-run\x00--socket\x00/tmp/pilot.sock\x00"), nil
		case "/proc/303/cmdline":
			return []byte("pilotctl\x00update\x00--restart\x00"), nil
		case "/proc/404/cmdline":
			return []byte("pilotctl\x00daemon\x00status\x00"), nil
		case "/proc/999/cmdline":
			return []byte("pilotctl\x00_daemon-run\x00"), nil
		default:
			return nil, os.ErrNotExist
		}
	}

	got := findUpdaterDaemonProcessIDs(daemonPath, pilotctlPath)
	if fmt.Sprint(got) != "[101 202]" {
		t.Fatalf("pids = %v, want [101 202]", got)
	}
}

func TestIsUpdaterPilotctlDaemonProcess(t *testing.T) {
	oldReadFile := updaterReadFile
	defer func() { updaterReadFile = oldReadFile }()

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "daemon run", data: []byte("pilotctl\x00_daemon-run\x00--listen\x00:0\x00"), want: true},
		{name: "update", data: []byte("pilotctl\x00update\x00--restart\x00"), want: false},
		{name: "daemon status", data: []byte("pilotctl\x00daemon\x00status\x00"), want: false},
		{name: "empty", data: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updaterReadFile = func(string) ([]byte, error) {
				return tt.data, nil
			}
			if got := isUpdaterPilotctlDaemonProcess("/proc/1/cmdline"); got != tt.want {
				t.Fatalf("isUpdaterPilotctlDaemonProcess = %v, want %v", got, tt.want)
			}
		})
	}
}

func stubUpdaterRestartEnvironment(t *testing.T, goos string) func() {
	t.Helper()
	oldGOOS := updaterRuntimeGOOS
	oldSignal := updaterSignalProcess
	oldLookPath := updaterLookPath
	oldReadDir := updaterReadDir
	oldReadFile := updaterReadFile
	oldReadlink := updaterReadlink
	oldGetpid := updaterGetpid
	oldRun := updaterRunCommand
	oldOutput := updaterRunCommandOutput
	updaterRuntimeGOOS = goos
	return func() {
		updaterRuntimeGOOS = oldGOOS
		updaterSignalProcess = oldSignal
		updaterLookPath = oldLookPath
		updaterReadDir = oldReadDir
		updaterReadFile = oldReadFile
		updaterReadlink = oldReadlink
		updaterGetpid = oldGetpid
		updaterRunCommand = oldRun
		updaterRunCommandOutput = oldOutput
	}
}

type fakeDirEntry struct {
	name string
	dir  bool
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return f.dir }
func (f fakeDirEntry) Type() os.FileMode          { return 0 }
func (f fakeDirEntry) Info() (os.FileInfo, error) { return nil, os.ErrNotExist }

func testUpdaterReleaseServer(t *testing.T, files map[string]string) (*GitHubRelease, *http.Client) {
	t.Helper()
	archiveDir := t.TempDir()
	archiveName := fmt.Sprintf("pilot-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	archivePath := filepath.Join(archiveDir, archiveName)
	createTestTarGz(t, archivePath, files)
	archiveContent, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archiveHash := sha256.Sum256(archiveContent)
	checksumsContent := fmt.Sprintf("%x  %s\n", archiveHash, archiveName)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/" + archiveName:
			w.Write(archiveContent)
		case "/download/checksums.txt":
			w.Write([]byte(checksumsContent))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	return &GitHubRelease{
		TagName: "v1.1.0",
		Assets: []GitHubAsset{
			{Name: archiveName, BrowserDownloadURL: srv.URL + "/download/" + archiveName},
			{Name: "checksums.txt", BrowserDownloadURL: srv.URL + "/download/checksums.txt"},
		},
	}, srv.Client()
}

// createTestTarGz creates a tar.gz archive with the given file name→content map.
func createTestTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
}
