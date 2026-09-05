package pkgspec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// ErrSemver means a version string cannot be stored in a form that orders
// correctly: a non-semver version from an upstream tag is normalised or
// rejected at registration, never stored in a form that breaks ordering.
var ErrSemver = errors.New("version is not a usable semver")

// NormaliseSemver turns a manifest `version` or an upstream ref into the
// exact string stored in `version.semver`. Normalised, not merely validated:
// `v1.3.0` and `1.3` both name a real release and must reach the catalog as
// one spelling, or two registrations of the same version would not collide
// on `unique (package_id, semver)`. Build metadata is dropped since semver
// says it does not affect precedence — keeping it would let `1.3.0+a` and
// `1.3.0+b` exist as distinct versions with identical precedence.
func NormaliseSemver(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty", ErrSemver)
	}
	// Refs arrive as `refs/tags/v1.3.0` from some forges, `v1.3.0` from most.
	trimmed = strings.TrimPrefix(trimmed, "refs/tags/")

	// Checked before parsing: a date tag like `2026-08-27` or floating tag
	// `v1` both parse "successfully" yet name no release.
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
