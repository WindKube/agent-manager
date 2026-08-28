package pkgspec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// ErrSemver means a version string cannot be stored in a form that orders
// correctly. The spec's edge case: "a non-semver version string from an upstream
// tag is normalised or rejected at registration, never stored in a form that
// breaks ordering."
var ErrSemver = errors.New("version is not a usable semver")

// NormaliseSemver turns a manifest `version` or an upstream ref into the exact
// string stored in `version.semver`.
//
// Normalised, not merely validated: `v1.3.0` and `1.3` both name a real release
// and both must reach the catalog as one spelling, or two registrations of the
// same version would not collide on `unique (package_id, semver)` and FR-007's
// immutability rule would have a hole in it.
//
// Build metadata is dropped rather than stored: semver says it does not affect
// precedence, so keeping it would let `1.3.0+a` and `1.3.0+b` both exist as
// distinct versions with identical precedence — two rows the ordering cannot
// separate.
func NormaliseSemver(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty", ErrSemver)
	}
	// Refs arrive as `refs/tags/v1.3.0` from some forges and as `v1.3.0` from
	// most. Neither is a semver, and both name one.
	trimmed = strings.TrimPrefix(trimmed, "refs/tags/")

	// At least major.minor is required, and this check has to happen before
	// parsing because the parser is lenient in a way that matters here: a date tag
	// `2026-08-27` parses as major 2026 with prerelease `08-27`, and a floating tag
	// `v1` parses as 1.0.0. Both would then be stored as versions that order
	// plausibly and mean nothing. Neither names a release.
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

// IsSemver reports whether raw normalises.
func IsSemver(raw string) bool {
	_, err := NormaliseSemver(raw)
	return err == nil
}
