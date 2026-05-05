package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TeoSlayer/pilotprotocol/pkg/updater"
)

func cmdUpdate(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) != 0 {
		fatalCode("invalid_argument", "usage: pilotctl update [--check] [--restart] [--repo owner/repo] [--tag vX.Y.Z] [--prerelease] [--install-dir DIR]")
	}

	installDir := flagString(flags, "install-dir", "")
	if installDir == "" {
		installDir = defaultUpdateInstallDir(configDir(), "pilotctl")
	}
	repo := pilotUpdateRepo(flags, installDir)
	u := updater.New(updater.Config{
		Repo:       repo,
		InstallDir: installDir,
		Version:    version,
		Tag:        flagString(flags, "tag", ""),
		Prerelease: flagBool(flags, "prerelease"),
		Restart:    flagBool(flags, "restart"),
	})

	var (
		result *updater.Result
		err    error
	)
	if flagBool(flags, "check") {
		result, err = u.Check()
	} else {
		result, err = u.CheckAndApply()
	}
	if err != nil {
		fatalCode("update_failed", "%v", err)
	}
	if jsonOutput {
		output(result)
		return
	}
	if !result.UpdateAvailable {
		fmt.Printf("Pilot is up to date (%s)\n", result.CurrentVersion)
		return
	}
	if flagBool(flags, "check") {
		fmt.Printf("Pilot update available: %s -> %s\n", result.CurrentVersion, result.LatestVersion)
		fmt.Printf("Run: pilotctl update --restart\n")
		return
	}
	fmt.Printf("Updated Pilot: %s -> %s\n", result.CurrentVersion, result.LatestVersion)
	for _, warning := range result.Warnings {
		fmt.Printf("Warning: %s\n", warning)
	}
	if result.RestartRequired {
		fmt.Println("Restart required: run `pilotctl daemon stop && pilotctl daemon start` or rerun with --restart next time.")
	}
}

func pilotUpdateRepo(flags map[string]string, installDir string) string {
	return updater.ResolveRepo(installDir, flagString(flags, "repo", ""))
}

func defaultUpdateInstallDir(homeDir, binaryName string) string {
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		if filepath.Base(exe) == binaryName {
			return filepath.Dir(exe)
		}
	}
	return filepath.Join(homeDir, "bin")
}
