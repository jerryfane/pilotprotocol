package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config holds the updater configuration.
type Config struct {
	CheckInterval time.Duration
	Repo          string // "owner/repo"
	InstallDir    string
	Version       string // updater's own version (used for user-agent)
	Tag           string // explicit tag to install; empty = latest release
	Prerelease    bool   // when true, use the newest release including prereleases
	Restart       bool   // signal daemon restart after applying an update
}

// Updater periodically checks GitHub Releases for new versions and optionally applies them.
type Updater struct {
	config Config
	client *http.Client
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// GitHubRelease represents a subset of the GitHub release API response.
type GitHubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []GitHubAsset `json:"assets"`
}

// GitHubAsset represents a release asset.
type GitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type releaseVersion struct {
	major      int
	minor      int
	patch      int
	prerelease []string
}

type applyResult struct {
	restartHandled bool
	warnings       []string
}

type restartResult struct {
	handled  bool
	warnings []string
}

const (
	DefaultRepo  = "TeoSlayer/pilotprotocol"
	repoFileName = ".pilot-repo"
)

// Result describes one update check/apply attempt.
type Result struct {
	CurrentVersion  string   `json:"current_version"`
	LatestVersion   string   `json:"latest_version"`
	Updated         bool     `json:"updated"`
	UpdateAvailable bool     `json:"update_available"`
	Asset           string   `json:"asset,omitempty"`
	InstallDir      string   `json:"install_dir"`
	RestartRequired bool     `json:"restart_required"`
	Warnings        []string `json:"warnings,omitempty"`
}

var updaterRuntimeGOOS = runtime.GOOS
var updaterSignalProcess = syscall.Kill
var updaterLookPath = exec.LookPath
var updaterReadDir = os.ReadDir
var updaterReadFile = os.ReadFile
var updaterReadlink = os.Readlink
var updaterGetpid = os.Getpid
var updaterRunCommand = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
var updaterRunCommandOutput = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// New creates a new Updater.
func New(cfg Config) *Updater {
	return &Updater{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		stopCh: make(chan struct{}),
	}
}

// Start begins the periodic check loop.
func (u *Updater) Start() {
	u.wg.Add(1)
	go u.checkLoop()
}

// Stop signals the check loop to stop and waits for it to finish.
func (u *Updater) Stop() {
	close(u.stopCh)
	u.wg.Wait()
}

func (u *Updater) checkLoop() {
	defer u.wg.Done()

	// Run once immediately on start.
	u.checkOnce()

	ticker := time.NewTicker(u.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Add 0-30s jitter to avoid thundering herd.
			jitter := time.Duration(rand.Int63n(int64(30 * time.Second)))
			select {
			case <-time.After(jitter):
			case <-u.stopCh:
				return
			}
			u.checkOnce()
		case <-u.stopCh:
			return
		}
	}
}

func (u *Updater) checkOnce() {
	slog.Debug("checking for updates")

	result, err := u.CheckAndApply()
	if err != nil {
		slog.Error("failed to update", "error", err)
		return
	}
	slog.Info("version check", "current", result.CurrentVersion, "latest", result.LatestVersion)
	if !result.UpdateAvailable {
		slog.Debug("already up to date")
		return
	}
	for _, warning := range result.Warnings {
		slog.Warn("update warning", "warning", warning)
	}
	slog.Info("update applied successfully", "version", result.LatestVersion)
}

// Check reports whether an update is available without mutating the install.
func (u *Updater) Check() (*Result, error) {
	return u.check(false)
}

// CheckAndApply applies the newest available update when one exists.
func (u *Updater) CheckAndApply() (*Result, error) {
	return u.check(true)
}

func (u *Updater) check(apply bool) (*Result, error) {
	u.config.Repo = ResolveRepo(u.config.InstallDir, u.config.Repo)
	release, err := u.fetchSelectedRelease()
	if err != nil {
		return nil, fmt.Errorf("fetch release: %w", err)
	}
	currentTag, err := u.currentTag()
	if err != nil {
		return nil, fmt.Errorf("current version: %w", err)
	}
	currentVersion, latestVersion, updateAvailable, err := releaseAvailability(currentTag, release.TagName, u.config.Tag != "")
	if err != nil {
		return nil, fmt.Errorf("parse release tag %q: %w", release.TagName, err)
	}
	assetName := u.archiveName()
	result := &Result{
		CurrentVersion:  currentVersion,
		LatestVersion:   latestVersion,
		UpdateAvailable: updateAvailable,
		Asset:           assetName,
		InstallDir:      u.config.InstallDir,
	}
	if !result.UpdateAvailable {
		return result, nil
	}
	if apply {
		applyResult, err := u.applyUpdate(release)
		if err != nil {
			return nil, err
		}
		result.Updated = true
		result.RestartRequired = true
		if u.config.Restart && applyResult.restartHandled {
			result.RestartRequired = false
		}
		result.Warnings = append(result.Warnings, applyResult.warnings...)
	}
	return result, nil
}

func ResolveRepo(installDir, explicit string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return explicit
	}
	if installDir != "" {
		data, err := os.ReadFile(filepath.Join(installDir, repoFileName))
		if err == nil {
			repo := strings.TrimSpace(string(data))
			if repo != "" {
				return repo
			}
		}
	}
	return DefaultRepo
}

func (u *Updater) fetchSelectedRelease() (*GitHubRelease, error) {
	if u.config.Tag != "" {
		return u.fetchReleaseByTag(u.config.Tag)
	}
	if u.config.Prerelease {
		releases, err := u.fetchReleases()
		if err != nil {
			return nil, err
		}
		if len(releases) == 0 {
			return nil, fmt.Errorf("no releases found")
		}
		return &releases[0], nil
	}
	return u.fetchLatestRelease()
}

func (u *Updater) fetchLatestRelease() (*GitHubRelease, error) {
	return u.fetchReleaseURL(fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.config.Repo))
}

func (u *Updater) fetchReleaseByTag(tag string) (*GitHubRelease, error) {
	return u.fetchReleaseURL(githubReleaseByTagURL(u.config.Repo, tag))
}

func (u *Updater) fetchReleaseURL(url string) (*GitHubRelease, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if u.config.Version != "" {
		req.Header.Set("User-Agent", "pilot-updater/"+u.config.Version)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &release, nil
}

func githubReleaseByTagURL(repo, tag string) string {
	return fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, url.PathEscape(tag))
}

func (u *Updater) fetchReleases() ([]GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=1", u.config.Repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if u.config.Version != "" {
		req.Header.Set("User-Agent", "pilot-updater/"+u.config.Version)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}
	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return releases, nil
}

func (u *Updater) currentVersion() (Semver, error) {
	tag, err := u.currentTag()
	if err != nil {
		return Semver{}, err
	}
	return ParseSemver(tag)
}

func (u *Updater) currentTag() (string, error) {
	daemonPath, err := u.installedPathFor("daemon")
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(daemonPath); err != nil {
		return "", fmt.Errorf("daemon binary not found at %s: %w", daemonPath, err)
	}

	// Read the version file we write after each update.
	versionFile := filepath.Join(u.config.InstallDir, ".pilot-version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		out, runErr := exec.Command(daemonPath, "-version").CombinedOutput()
		if runErr != nil {
			return "", fmt.Errorf("no version file at %s (%v) and daemon -version failed: %w", versionFile, err, runErr)
		}
		fields := strings.Fields(string(out))
		if len(fields) == 0 {
			return "", fmt.Errorf("daemon -version returned no version")
		}
		return normalizeReleaseTag(fields[len(fields)-1]), nil
	}
	return normalizeReleaseTag(string(data)), nil
}

func (u *Updater) applyUpdate(release *GitHubRelease) (*applyResult, error) {
	result := &applyResult{}
	archiveName := u.archiveName()
	var archiveURL, checksumsURL string

	for _, a := range release.Assets {
		switch a.Name {
		case archiveName:
			archiveURL = a.BrowserDownloadURL
		case "checksums.txt":
			checksumsURL = a.BrowserDownloadURL
		}
	}

	if archiveURL == "" {
		return nil, fmt.Errorf("no asset %q in release %s", archiveName, release.TagName)
	}
	if checksumsURL == "" {
		return nil, fmt.Errorf("release %s has no checksums.txt", release.TagName)
	}

	tmpDir, err := os.MkdirTemp("", "pilot-update-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download archive.
	archivePath := filepath.Join(tmpDir, archiveName)
	if err := u.downloadFile(archiveURL, archivePath); err != nil {
		return nil, fmt.Errorf("download archive: %w", err)
	}

	checksumsPath := filepath.Join(tmpDir, "checksums.txt")
	if err := u.downloadFile(checksumsURL, checksumsPath); err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}
	if err := VerifyChecksum(archivePath, archiveName, checksumsPath); err != nil {
		return nil, fmt.Errorf("checksum verification failed: %w", err)
	}
	slog.Info("checksum verified", "archive", archiveName)

	// Extract to staging directory.
	stagingDir := filepath.Join(tmpDir, "staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}
	if err := extractTarGz(archivePath, stagingDir); err != nil {
		return nil, fmt.Errorf("extract archive: %w", err)
	}

	// Only replace client binaries — server binaries (registry, beacon,
	// rendezvous, nameserver) are managed separately.
	clientBins := map[string]bool{
		"daemon":   true,
		"pilotctl": true,
		"gateway":  true,
		"updater":  true,
	}

	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return nil, fmt.Errorf("read staging dir: %w", err)
	}
	var daemonPIDs []int
	if u.config.Restart && updaterRuntimeGOOS == "linux" {
		daemonPath, daemonErr := u.installedPathFor("daemon")
		pilotctlPath, pilotctlErr := u.installedPathFor("pilotctl")
		if daemonErr == nil && pilotctlErr == nil {
			daemonPIDs = findUpdaterDaemonProcessIDs(daemonPath, pilotctlPath)
		}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !clientBins[entry.Name()] {
			slog.Debug("skipping server binary", "name", entry.Name())
			continue
		}
		src := filepath.Join(stagingDir, entry.Name())
		dst, err := u.installedPathFor(entry.Name())
		if err != nil {
			return nil, err
		}
		if err := prepareUpdatedBinary(src); err != nil {
			return nil, fmt.Errorf("prepare %s: %w", entry.Name(), err)
		}
		if err := replaceBinary(src, dst); err != nil {
			return nil, fmt.Errorf("replace %s: %w", entry.Name(), err)
		}
		slog.Info("replaced binary", "name", entry.Name())
	}
	if err := clearInstallDirXattrs(u.config.InstallDir); err != nil {
		result.warnings = append(result.warnings, fmt.Sprintf("failed to clear macOS quarantine attributes: %v", err))
	}

	// Write version file for future comparison.
	versionFile := filepath.Join(u.config.InstallDir, ".pilot-version")
	if err := os.WriteFile(versionFile, []byte(release.TagName+"\n"), 0644); err != nil {
		slog.Warn("failed to write version file", "error", err)
	}
	repoFile := filepath.Join(u.config.InstallDir, repoFileName)
	if err := os.WriteFile(repoFile, []byte(u.config.Repo+"\n"), 0644); err != nil {
		slog.Warn("failed to write repo file", "error", err)
	}

	if u.config.Restart {
		restartResult := u.restartDaemonAfterUpdate(daemonPIDs)
		result.restartHandled = restartResult.handled
		result.warnings = append(result.warnings, restartResult.warnings...)
	}

	return result, nil
}

func (u *Updater) downloadFile(url, dst string) error {
	resp, err := u.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

// VerifyChecksum checks the SHA256 of archivePath against the checksums file.
func VerifyChecksum(archivePath, archiveName, checksumsPath string) error {
	// Read checksums file.
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}

	// Find the line for our archive.
	var expectedHash string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "hash  filename" or "hash filename"
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == archiveName {
			expectedHash = parts[0]
			break
		}
	}
	if expectedHash == "" {
		return fmt.Errorf("no checksum found for %s", archiveName)
	}

	// Compute actual hash.
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}

func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		// Only extract regular files, skip directories and symlinks.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Sanitize path — prevent directory traversal.
		name := filepath.Base(hdr.Name)
		if name == "." || name == ".." {
			continue
		}

		dst := filepath.Join(destDir, name)
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return fmt.Errorf("write %s: %w", name, err)
		}
		out.Close()
	}
	return nil
}

func prepareUpdatedBinary(path string) error {
	if updaterRuntimeGOOS != "darwin" {
		return nil
	}
	return updaterRunCommand("codesign", "--force", "--sign", "-", path)
}

func clearInstallDirXattrs(dir string) error {
	if updaterRuntimeGOOS != "darwin" {
		return nil
	}
	return updaterRunCommand("xattr", "-cr", dir)
}

func replaceBinary(src, dst string) error {
	backup := dst + ".bak"
	_ = os.Remove(backup)
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, backup); err != nil {
			return err
		}
	}
	srcFile, err := os.Open(src)
	if err != nil {
		_ = os.Rename(backup, dst)
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		_ = os.Rename(backup, dst)
		return err
	}
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		_ = dstFile.Close()
		_ = os.Remove(dst)
		_ = os.Rename(backup, dst)
		return err
	}
	if err := dstFile.Close(); err != nil {
		_ = os.Remove(dst)
		_ = os.Rename(backup, dst)
		return err
	}
	if err := os.Chmod(dst, 0755); err != nil {
		_ = os.Remove(dst)
		_ = os.Rename(backup, dst)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func (u *Updater) restartDaemonAfterUpdate(preUpdatePIDs []int) restartResult {
	switch updaterRuntimeGOOS {
	case "linux":
		var warnings []string
		if _, err := updaterLookPath("systemctl"); err == nil {
			if updaterRunCommand("systemctl", "is-active", "--quiet", "pilot-daemon.service") == nil {
				if err := updaterRunCommand("systemctl", "restart", "pilot-daemon.service"); err == nil {
					return restartResult{handled: true}
				} else {
					warnings = append(warnings, fmt.Sprintf("systemctl restart pilot-daemon.service failed: %v", err))
					if systemdRestartPolicy("pilot-daemon.service") != "always" {
						warnings = append(warnings, "restart Pilot manually")
						return restartResult{warnings: warnings}
					}
				}
			}
		}
		if len(preUpdatePIDs) == 0 {
			warnings = append(warnings, "no running Pilot daemon process found; restart Pilot manually if it was running")
			return restartResult{warnings: warnings}
		}
		for _, pid := range preUpdatePIDs {
			if err := updaterSignalProcess(pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
				warnings = append(warnings, fmt.Sprintf("failed to signal pilot-daemon pid %d: %v; restart Pilot manually", pid, err))
				return restartResult{warnings: warnings}
			}
		}
		warnings = append(warnings, "pilot-daemon was signaled after update; start it manually if it is not service-managed")
		return restartResult{warnings: warnings}
	case "darwin":
		if _, err := updaterLookPath("launchctl"); err == nil {
			label := fmt.Sprintf("gui/%d/com.vulturelabs.pilot-daemon", os.Getuid())
			if err := updaterRunCommand("launchctl", "kickstart", "-k", label); err == nil {
				return restartResult{handled: true}
			} else {
				return restartResult{
					warnings: []string{fmt.Sprintf("launchctl restart failed: %v; restart Pilot manually", err)},
				}
			}
		}
		return restartResult{
			warnings: []string{"launchctl is unavailable; restart Pilot manually"},
		}
	default:
		return restartResult{
			warnings: []string{fmt.Sprintf("restart is not supported on %s; restart Pilot manually", updaterRuntimeGOOS)},
		}
	}
}

func systemdRestartPolicy(service string) string {
	if _, err := updaterLookPath("systemctl"); err != nil {
		return ""
	}
	data, err := updaterRunCommandOutput("systemctl", "show", service, "-p", "Restart", "--value")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func findUpdaterDaemonProcessIDs(daemonPath, pilotctlPath string) []int {
	entries, err := updaterReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := 0
		fmt.Sscanf(entry.Name(), "%d", &pid)
		if pid <= 0 || pid == updaterGetpid() {
			continue
		}
		exe, err := updaterReadlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}
		cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
		switch exe {
		case daemonPath:
			pids = append(pids, pid)
		case pilotctlPath:
			if isUpdaterPilotctlDaemonProcess(cmdlinePath) {
				pids = append(pids, pid)
			}
		}
	}
	return pids
}

func isUpdaterPilotctlDaemonProcess(cmdlinePath string) bool {
	data, err := updaterReadFile(cmdlinePath)
	if err != nil || len(data) == 0 {
		return false
	}
	for _, arg := range splitUpdaterProcCmdline(data) {
		if arg == "_daemon-run" {
			return true
		}
	}
	return false
}

func splitUpdaterProcCmdline(data []byte) []string {
	parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (u *Updater) archiveName() string {
	return fmt.Sprintf("pilot-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

func (u *Updater) installedPathFor(archiveName string) (string, error) {
	if u.config.InstallDir == "" {
		return "", fmt.Errorf("install dir is required")
	}
	candidates := map[string][]string{
		"daemon":   {"pilot-daemon", "daemon"},
		"gateway":  {"pilot-gateway", "gateway"},
		"updater":  {"pilot-updater", "updater"},
		"pilotctl": {"pilotctl"},
	}
	names, ok := candidates[archiveName]
	if !ok {
		return "", fmt.Errorf("unsupported update binary %q", archiveName)
	}
	for _, name := range names {
		path := filepath.Join(u.config.InstallDir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return filepath.Join(u.config.InstallDir, names[0]), nil
}
