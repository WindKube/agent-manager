package view_test

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/view"
)

// The design file is the other side of both checks in here. Transcribing its
// strings into this file would make the test agree with itself: what is being
// asserted is that a derivation over the REAL schema's columns can reproduce the
// REAL design's rendering, and the interesting answer is where it cannot.
const designFile = "../../../docs/design/agent-manager.dc.html"

// designRow pulls `id: 'example/pii-redactor'` and `name: 'PII Redactor'` out of
// one package literal. The id's second segment is the manifest name — the `key`
// field is not, `security-kit` stands for `security-review-kit` — so the name is
// taken from the id rather than from the shorter handle beside it.
var designRow = regexp.MustCompile(`id: '[^/']+/([^']+)', name: '([^']+)'`)

// TestTitleReproducesTheDesignsNamesExceptWhereNoDerivationCould measures the
// gap between a derived heading and the one the design draws.
//
// `package` has no display-name column and Agent Plugins 1.0.0 has no title
// field, so the catalog's heading is derived from the manifest name. This pins
// how far that gets: six of the design's ten names come back exactly, and the
// four that do not are all the same failure — an acronym or an abbreviation that
// the lowercase name does not record. `pii-redactor` cannot become "PII
// Redactor" without a table of acronyms, and a table of acronyms is a display
// name column with extra steps.
//
// The list below is a ratchet, not a wish. A fifth entry appearing in it means
// the derivation regressed on a name it used to get right.
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

// TestTitleIsSafeOnNamesTheHubDidNotChoose runs the derivation over names an
// archive can carry rather than over the ten the design happens to use.
//
// The manifest is untrusted input (constitution principle III) and its `name` is
// whatever the archive said, so this runs over the shapes that break a naive
// implementation rather than over the ten well-behaved names above. The
// multi-byte case is the one that used to corrupt output: slicing word[:1] cuts
// a UTF-8 sequence in half and the browser renders U+FFFD.
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

// TestRelativeSaysEveryPhraseTheDesignsUpdatedColumnShows checks the vocabulary
// in both directions.
//
// The api returns an instant and the design shows a phrase, so the risk is a
// phrase the design uses that no age can produce — "yesterday" is the one a
// naive days-since implementation silently drops. Sweeping an hour at a time up
// to two years and collecting what comes out is the independent half: the design
// supplies the expected vocabulary, this supplies the reachable one.
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
	// The gap a days-since implementation loses: 24 to 48 hours is a word, not a
	// number, and the design shows that word.
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
