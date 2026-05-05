package updater

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Semver represents a parsed semantic version.
type Semver struct {
	Major int
	Minor int
	Patch int
}

var forkSuffixTokenRE = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

// ParseSemver parses a version string like "v1.2.3" or "1.2.3" or "v1.2.3-dirty".
// It strips the "v" prefix and any suffix after a hyphen.
func ParseSemver(s string) (Semver, error) {
	s = strings.TrimPrefix(s, "v")
	// Strip anything after hyphen (e.g. "-dirty", "-rc1")
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Semver{}, fmt.Errorf("invalid semver: %q", s)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return Semver{}, fmt.Errorf("invalid major: %w", err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return Semver{}, fmt.Errorf("invalid minor: %w", err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return Semver{}, fmt.Errorf("invalid patch: %w", err)
	}
	return Semver{Major: major, Minor: minor, Patch: patch}, nil
}

// NewerThan returns true if v is strictly newer than other.
func (v Semver) NewerThan(other Semver) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch > other.Patch
}

// String returns the version as "vMAJOR.MINOR.PATCH".
func (v Semver) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func normalizeReleaseTag(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if s == "dev" {
		return s
	}
	if !strings.HasPrefix(s, "v") {
		return "v" + s
	}
	return s
}

func parseReleaseVersion(s string) (releaseVersion, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	var prerelease []string
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		prerelease = strings.Split(s[idx+1:], ".")
		s = s[:idx]
	}
	base, err := ParseSemver(s)
	if err != nil {
		return releaseVersion{}, err
	}
	return releaseVersion{
		major:      base.Major,
		minor:      base.Minor,
		patch:      base.Patch,
		prerelease: prerelease,
	}, nil
}

func releaseUpdateAvailable(current releaseVersion, currentTag string, target releaseVersion, targetTag string, explicitTag bool) bool {
	if explicitTag {
		return normalizeReleaseTag(currentTag) != normalizeReleaseTag(targetTag)
	}
	return target.NewerThan(current)
}

func releaseAvailability(currentTag, releaseTag string, explicitTag bool) (string, string, bool, error) {
	latest, err := parseReleaseVersion(releaseTag)
	if err != nil {
		return "", "", false, err
	}
	normalizedCurrent := normalizeReleaseTag(currentTag)
	normalizedLatest := normalizeReleaseTag(releaseTag)
	current, currentErr := parseReleaseVersion(normalizedCurrent)
	if currentErr != nil {
		return normalizedCurrent, normalizedLatest, true, nil
	}
	return normalizedCurrent, normalizedLatest, releaseUpdateAvailable(current, normalizedCurrent, latest, releaseTag, explicitTag), nil
}

func (v releaseVersion) NewerThan(other releaseVersion) bool {
	if v.major != other.major {
		return v.major > other.major
	}
	if v.minor != other.minor {
		return v.minor > other.minor
	}
	if v.patch != other.patch {
		return v.patch > other.patch
	}
	if cmp, ok := compareForkSuffix(v.prerelease, other.prerelease); ok {
		return cmp > 0
	}
	return comparePrerelease(v.prerelease, other.prerelease) > 0
}

func compareForkSuffix(a, b []string) (int, bool) {
	aIsJF := len(a) > 0 && a[0] == "jf"
	bIsJF := len(b) > 0 && b[0] == "jf"
	if !aIsJF && !bIsJF {
		return 0, false
	}
	if aIsJF && !bIsJF {
		return 1, true
	}
	if !aIsJF && bIsJF {
		return -1, true
	}
	return compareForkSuffixParts(a[1:], b[1:]), true
}

func compareForkSuffixParts(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		cmp := compareForkTokenList(forkSuffixTokens(a[i]), forkSuffixTokens(b[i]))
		if cmp != 0 {
			return cmp
		}
	}
	if len(a) > len(b) {
		return 1
	}
	if len(a) < len(b) {
		return -1
	}
	return 0
}

func forkSuffixTokens(s string) []string {
	tokens := forkSuffixTokenRE.FindAllString(s, -1)
	if len(tokens) == 0 {
		return []string{s}
	}
	return tokens
}

func compareForkTokenList(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		cmp := compareForkToken(a[i], b[i])
		if cmp != 0 {
			return cmp
		}
	}
	if len(a) > len(b) {
		return 1
	}
	if len(a) < len(b) {
		return -1
	}
	return 0
}

func compareForkToken(a, b string) int {
	aNum, aErr := strconv.Atoi(a)
	bNum, bErr := strconv.Atoi(b)
	aIsNum := aErr == nil
	bIsNum := bErr == nil
	switch {
	case aIsNum && bIsNum:
		if aNum > bNum {
			return 1
		}
		if aNum < bNum {
			return -1
		}
		return 0
	case aIsNum:
		return 1
	case bIsNum:
		return -1
	default:
		if a > b {
			return 1
		}
		if a < b {
			return -1
		}
		return 0
	}
}

func comparePrerelease(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		cmp := comparePrereleaseIdentifier(a[i], b[i])
		if cmp != 0 {
			return cmp
		}
	}
	if len(a) > len(b) {
		return 1
	}
	if len(a) < len(b) {
		return -1
	}
	return 0
}

func comparePrereleaseIdentifier(a, b string) int {
	aNum, aErr := strconv.Atoi(a)
	bNum, bErr := strconv.Atoi(b)
	aIsNum := aErr == nil
	bIsNum := bErr == nil
	switch {
	case aIsNum && bIsNum:
		if aNum > bNum {
			return 1
		}
		if aNum < bNum {
			return -1
		}
		return 0
	case aIsNum:
		return -1
	case bIsNum:
		return 1
	default:
		if a > b {
			return 1
		}
		if a < b {
			return -1
		}
		return 0
	}
}
