package plan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The expectations here are hand-derived from Semantic Versioning 2.0.0 §10 and
// §11 — build metadata ignored, prerelease lower than release, numeric
// identifiers compared numerically and ranked below alphanumeric ones — and not
// from running this code.
func TestVersionsAreOrderedBySemverPrecedenceAndNotLexicographically(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		from string
		to   string
		want Direction
	}{
		{"a patch bump moves up", "2.4.0", "2.4.1", DirectionUp},
		{"a minor bump across a digit boundary moves up", "1.9.0", "1.10.0", DirectionUp},
		{"the same bump read backwards moves down", "1.10.0", "1.9.0", DirectionDown},
		{"a major bump moves up", "1.999.999", "2.0.0", DirectionUp},
		{"identical versions are the same version", "2.4.1", "2.4.1", DirectionSame},

		// Semver §11.3: a prerelease has LOWER precedence than the release.
		{"leaving a prerelease moves up", "1.0.0-rc.1", "1.0.0", DirectionUp},
		{"entering a prerelease moves down", "1.0.0", "1.0.0-rc.1", DirectionDown},

		// Semver §11.4's own worked example, adjacent pair by adjacent pair.
		{"alpha to alpha.1 moves up", "1.0.0-alpha", "1.0.0-alpha.1", DirectionUp},
		{"alpha.1 to alpha.beta moves up because numeric ranks below alphanumeric", "1.0.0-alpha.1", "1.0.0-alpha.beta", DirectionUp},
		{"alpha.beta to beta moves up", "1.0.0-alpha.beta", "1.0.0-beta", DirectionUp},
		{"beta to beta.2 moves up", "1.0.0-beta", "1.0.0-beta.2", DirectionUp},
		{"beta.2 to beta.11 moves up, numerically", "1.0.0-beta.2", "1.0.0-beta.11", DirectionUp},
		{"beta.11 to rc.1 moves up", "1.0.0-beta.11", "1.0.0-rc.1", DirectionUp},

		// §10: build metadata is ignored for precedence, so there is no
		// direction to report even though the strings differ.
		{"build metadata alone gives no direction", "1.2.3", "1.2.3+build.7", DirectionUnknown},
		{"a padded core gives no direction", "1.0", "1.0.0", DirectionUnknown},

		// Not semver at all. Numeric-segment comparison still gets the two
		// common cases right.
		{"a date-shaped version orders by its segments", "2024-01-15", "2024-02-01", DirectionUp},
		{"a four-segment version orders by its last segment", "1.2.3.4", "1.2.3.5", DirectionUp},

		// A documented quirk rather than a claim: §11.4.3 puts every
		// alphanumeric field above every numeric one, and applying that to
		// something that is not semver makes "v2" outrank "2".
		{"a v-prefix outranks a bare number, which is semver's rule misapplied", "v2", "2", DirectionDown},

		{"an empty installed version is an add, not a comparison", "", "1.0.0", DirectionNone},
		{"an empty locked version is not orderable", "1.0.0", "", DirectionUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, DirectionOf(nil, tc.from, tc.to),
				"%s -> %s", tc.from, tc.to)
		})
	}
}

// The negative control for the case above it: prove that the naive comparison
// really would get these wrong, so the numeric handling is doing work rather
// than agreeing with a shortcut.
func TestLexicographicComparisonWouldGetTheseBackwards(t *testing.T) {
	t.Parallel()

	pairs := [][2]string{
		{"1.9.0", "1.10.0"},
		{"1.0.0-beta.2", "1.0.0-beta.11"},
		{"1.0.0-rc.1", "1.0.0"},
	}
	for _, p := range pairs {
		t.Run(fmt.Sprintf("%s to %s", p[0], p[1]), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, DirectionUp, DirectionOf(nil, p[0], p[1]))
			require.Positive(t, strings.Compare(p[0], p[1]),
				"a string comparison calls this a downgrade, which is the whole reason CompareVersions exists")
		})
	}
}

func TestTheSemverExampleChainIsStrictlyIncreasing(t *testing.T) {
	t.Parallel()

	// Semver 2.0.0 §11.4's example, verbatim.
	chain := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
	}
	for i := range chain {
		for j := range chain {
			sign, ok := CompareVersions(chain[i], chain[j])
			require.True(t, ok || i == j, "%s vs %s must be orderable", chain[i], chain[j])
			switch {
			case i < j:
				require.Negative(t, sign, "%s must precede %s", chain[i], chain[j])
			case i > j:
				require.Positive(t, sign, "%s must follow %s", chain[i], chain[j])
			default:
				require.Zero(t, sign)
			}
		}
	}
}

func TestAnOversizedNumericSegmentIsNotOrderedRatherThanTruncated(t *testing.T) {
	t.Parallel()

	// 21 digits overflows uint64. Truncating would invent an ordering; treating
	// the field as alphanumeric at least does not claim one that is wrong in a
	// silent direction.
	huge := "1." + strings.Repeat("9", 21) + ".0"
	sign, ok := CompareVersions(huge, "1.0.0")
	require.True(t, ok)
	require.Positive(t, sign, "an alphanumeric field outranks a numeric one, which is the honest fallback")
}

func TestACustomComparerReplacesTheDefaultEntirely(t *testing.T) {
	t.Parallel()

	// The shape a Masterminds/semver comparer would have. Proves the seam is
	// real: nothing else in the package reaches for CompareVersions.
	alwaysDown := func(string, string) (int, bool) { return 1, true }
	require.Equal(t, DirectionDown, DirectionOf(alwaysDown, "1.0.0", "9.9.9"))
	require.Equal(t, DirectionUp, DirectionOf(nil, "1.0.0", "9.9.9"))

	declines := func(string, string) (int, bool) { return 0, false }
	require.Equal(t, DirectionUnknown, DirectionOf(declines, "1.0.0", "9.9.9"))

	// A nil comparer never asks about an add, so a comparer that panics is
	// never reached for one.
	panics := func(string, string) (int, bool) { panic("must not be consulted for an add") }
	require.Equal(t, DirectionNone, DirectionOf(panics, "", "1.0.0"))
}
