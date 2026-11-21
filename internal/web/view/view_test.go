package view_test

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/view"
)

// The tests read the design file directly rather than transcribing its strings, so they cannot agree with themselves.
const designFile = "../../../docs/design/agent-manager.dc.html"

// designRow takes the manifest name from the id's second segment, since the design's `key` field is a shorter handle.
var designRow = regexp.MustCompile(`id: '[^/']+/([^']+)', name: '([^']+)'`)

// TestTitleReproducesTheDesignsNamesExceptWhereNoDerivationCould pins how far deriving a title from the manifest
// name gets. The unrecoverable list is a ratchet: acronyms cannot be derived, and a new entry means a regression.
func TestTitleReproducesTheDesignsNamesExceptWhereNoDerivationCould(t *testing.T) {
	unrecoverable := map[string]string{
		"pii-redactor":        "the acronym PII",
		"adr-writer":          "the acronym ADR",
		"aws-cost-explainer":  "the acronym AWS",
		"k8s-incident-triage": "k8s is an abbreviation of a word the name never spells",
	}

	rows := designRow.FindAllStringSubmatch(readDesign(t), -1)
	require.Len(t, rows, 10, "the design's ten packages")

	for _, row := range rows {
		name, want := row[1], row[2]
		t.Run(name, func(t *testing.T) {
			got := view.Title(name)
			if reason, known := unrecoverable[name]; known {
				require.NotEqualf(t, want, got,
					"%s is listed as underivable because of %s, but Title now returns it — "+
						"delete the entry rather than keeping a stale excuse", name, reason)
				return
			}
			require.Equal(t, want, got)
		})
	}
}

// TestTitleIsSafeOnNamesTheHubDidNotChoose runs the derivation over untrusted manifest names that break a naive
// implementation.
func TestTitleIsSafeOnNamesTheHubDidNotChoose(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"a single word is capitalised", "redactor", "Redactor"},
		{"underscores separate words like hyphens do", "pii_redactor", "Pii Redactor"},
		{"an empty name stays empty", "", ""},
		{"a name of separators alone is returned unchanged", "---", "---"},
		{"repeated separators do not produce empty words", "a--b", "A B"},
		{"leading and trailing separators are dropped", "-redactor-", "Redactor"},
		{"a digit-leading word is left alone", "3d-viewer", "3d Viewer"},
		{"an already-capitalised word is not lowercased", "PII-redactor", "PII Redactor"},
		{"a multi-byte first rune is not cut in half", "ölschutz-tool", "Ölschutz Tool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, view.Title(tc.in))
		})
	}
}

// TestRelativeSaysEveryPhraseTheDesignsUpdatedColumnShows sweeps two years of ages and checks every phrase the
// design uses is reachable.
func TestRelativeSaysEveryPhraseTheDesignsUpdatedColumnShows(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	reachable := map[string]bool{}
	for hours := range 2 * 365 * 24 {
		reachable[view.Relative(now.Add(-time.Duration(hours)*time.Hour), now)] = true
	}

	updated := regexp.MustCompile(`updated: '([^']+)'`).FindAllStringSubmatch(readDesign(t), -1)
	require.NotEmpty(t, updated)
	for _, match := range updated {
		require.Truef(t, reachable[match[1]],
			"the design's Updated column shows %q and no age produces it", match[1])
	}
}

func TestRelativeRoundsDownAtEveryBoundaryItCrosses(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) string { return view.Relative(now.Add(-d), now) }

	require.Equal(t, "just now", ago(-time.Hour),
		"a future timestamp is clock skew between the hub and a publisher, not a negative age")
	require.Equal(t, "just now", ago(59*time.Second))
	require.Equal(t, "1 minute ago", ago(time.Minute))
	require.Equal(t, "59 minutes ago", ago(59*time.Minute+59*time.Second))
	require.Equal(t, "1 hour ago", ago(time.Hour))
	require.Equal(t, "23 hours ago", ago(23*time.Hour+59*time.Minute))
	// 24 to 48 hours is "yesterday", which a naive days-since implementation drops.
	require.Equal(t, "yesterday", ago(24*time.Hour))
	require.Equal(t, "yesterday", ago(47*time.Hour))
	require.Equal(t, "2 days ago", ago(48*time.Hour))
	require.Equal(t, "6 days ago", ago(6*24*time.Hour))
	require.Equal(t, "1 week ago", ago(7*24*time.Hour))
	require.Equal(t, "4 weeks ago", ago(29*24*time.Hour))
	require.Equal(t, "1 month ago", ago(30*24*time.Hour))
	require.Equal(t, "12 months ago", ago(364*24*time.Hour))
	require.Equal(t, "1 year ago", ago(365*24*time.Hour))
}

func readDesign(t *testing.T) string {
	t.Helper()

	source, err := os.ReadFile(designFile)
	require.NoError(t, err, "the design is the reference for this package's rendering")
	return string(source)
}
