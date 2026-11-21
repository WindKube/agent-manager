package pkgspec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// ErrSemver means a version string cannot be stored in a form that orders
// correctly.
var ErrSemver = errors.New("version is not a usable semver")

// NormaliseSemver turns a manifest `version` or upstream ref into the string
// stored in `version.semver`. One spelling per release keeps
// `unique (package_id, semver)` meaningful, so build metadata is dropped.
func NormaliseSemver(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty", ErrSemver)
	}
	// Refs arrive as `refs/tags/v1.3.0` from some forges, `v1.3.0` from most.
	trimmed = strings.TrimPrefix(trimmed, "refs/tags/")

	// Date tags and floating tags like `v1` parse yet name no release.
	core := strings.TrimPrefix(trimmed, "v")
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	if !strings.Contains(core, ".") {
		return "", fmt.Errorf("%w: %q names no minor version, so it is a tag rather than a release", ErrSemver, raw)
	}

	version, err := semver.NewVersion(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrSemver, raw, err)
	}

	out := fmt.Sprintf("%d.%d.%d", version.Major(), version.Minor(), version.Patch())
	if pre := version.Prerelease(); pre != "" {
		out += "-" + pre
	}
	return out, nil
}

func IsSemver(raw string) bool {
	_, err := NormaliseSemver(raw)
	return err == nil
}
