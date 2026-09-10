package commands

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/blob"
	"agent-manager/internal/fetch"
	"agent-manager/internal/store/models"
)

// validRegistration is a Registration that passes every check normalise makes
// other than the one on Publisher, so each test below isolates that one.
func validRegistration(publisher string) Registration {
	return Registration{
		Source:    fetch.SourceUpload,
		Archive:   []byte("x"),
		Publisher: publisher,
		Name:      "widget",
		Version:   "1.0.0",
	}
}

func TestNormaliseAcceptsAOneSegmentPublisherAndDerivesItsNamespace(t *testing.T) {
	for _, tc := range []struct {
		publisher, wantNamespace string
	}{
		{"community", "community"},
		{"community/platform", "community"},
	} {
		t.Run(tc.publisher, func(t *testing.T) {
			out, err := validRegistration(tc.publisher).normalise()
			require.NoError(t, err)
			require.Equal(t, tc.wantNamespace, out.Namespace)
			require.Equal(t, tc.publisher, out.Publisher)
		})
	}
}

// A publisher must be exactly one or two non-empty segments: a namespace on
// its own, or a namespace and a team. Anything else is refused before it ever
// reaches the schema's own check constraint.
func TestNormaliseRefusesAPublisherThatIsNotOneOrTwoNonEmptySegments(t *testing.T) {
	for _, publisher := range []string{
		"",      // no publisher at all
		"/team", // empty namespace
		"team/", // empty team
		"a/b/c", // three segments
		"/",     // only slashes
		"//",    // only slashes
	} {
		t.Run("rejects "+publisher, func(t *testing.T) {
			_, err := validRegistration(publisher).normalise()
			require.ErrorIs(t, err, ErrRegistration)
		})
	}
}

func TestNormaliseTrimsDedupesAndSortsTags(t *testing.T) {
	in := validRegistration("community")
	in.Tags = []string{" terraform ", "aws", "terraform", ""}

	out, err := in.normalise()
	require.NoError(t, err)
	require.Equal(t, []string{"aws", "terraform"}, out.Tags)
}

func TestNormaliseAcceptsAnEmptyTagsFieldUnchanged(t *testing.T) {
	out, err := validRegistration("community").normalise()
	require.NoError(t, err)
	require.Empty(t, out.Tags)
}

func TestNormaliseRefusesMoreThanMaxTagCountDistinctTags(t *testing.T) {
	in := validRegistration("community")
	tags := make([]string, MaxTagCount+1)
	for i := range tags {
		tags[i] = fmt.Sprintf("tag%d", i)
	}
	in.Tags = tags

	_, err := in.normalise()
	require.ErrorIs(t, err, ErrRegistration)
	require.ErrorContains(t, err, fmt.Sprintf("at most %d tags", MaxTagCount))
}

// A repeated tag dedupes away before the count is checked, so it never trips
// the refusal above.
func TestNormaliseDoesNotCountADuplicateTagTwice(t *testing.T) {
	in := validRegistration("community")
	tags := make([]string, MaxTagCount+1)
	for i := range tags {
		tags[i] = "terraform"
	}
	in.Tags = tags

	out, err := in.normalise()
	require.NoError(t, err)
	require.Equal(t, []string{"terraform"}, out.Tags)
}

func TestNormaliseRefusesATagOverMaxTagLength(t *testing.T) {
	in := validRegistration("community")
	in.Tags = []string{strings.Repeat("a", MaxTagLength+1)}

	_, err := in.normalise()
	require.ErrorIs(t, err, ErrRegistration)
	require.ErrorContains(t, err, "not a valid tag")
}

func TestNormaliseRefusesATagWithACharacterTheFacetCannotRender(t *testing.T) {
	for _, tag := range []string{"has space", "comma,d", "slash/ed", "quote\"d", "-leading-hyphen"} {
		t.Run(tag, func(t *testing.T) {
			in := validRegistration("community")
			in.Tags = []string{tag}

			_, err := in.normalise()
			require.ErrorIs(t, err, ErrRegistration)
			require.ErrorContains(t, err, "not a valid tag")
		})
	}
}

// conflictMessage is a pure function of the row's own columns: a version never
// fetched, one the scanner flagged or rejected, and one simply published all
// have to read differently, and this is the one place that distinction is made.
func TestConflictMessageNamesTheStateBlockingRegistration(t *testing.T) {
	ref := blob.VersionRef{Namespace: "acme", Name: "widget", Semver: "1.2.3"}

	cases := []struct {
		name    string
		version *models.Version
		want    []string
		reject  []string
	}{
		{
			name:    "a version whose fetch never landed does not claim to be published",
			version: &models.Version{Verdict: models.VerdictScanning, Visible: false, Digest: nil},
			want:    []string{"acme/widget@1.2.3", "fetch has not finished"},
			reject:  []string{"already published"},
		},
		{
			name:    "a published version still awaiting scan reads as published",
			version: &models.Version{Verdict: models.VerdictScanning, Visible: true, Digest: []byte{0xab}},
			want:    []string{"acme/widget@1.2.3", "already published", "immutable"},
		},
		{
			name:    "a clean published version reads as published",
			version: &models.Version{Verdict: models.VerdictClean, Visible: true, Digest: []byte{0xab}},
			want:    []string{"acme/widget@1.2.3", "already published", "immutable"},
		},
		{
			name:    "a flagged version names the scanner's verdict",
			version: &models.Version{Verdict: models.VerdictFlagged, Visible: true, Digest: []byte{0xab}},
			want:    []string{"acme/widget@1.2.3", "flagged", "immutable"},
		},
		{
			name:    "a rejected version names the scanner's verdict",
			version: &models.Version{Verdict: models.VerdictRejected, Visible: true, Digest: []byte{0xab}},
			want:    []string{"acme/widget@1.2.3", "rejected", "immutable"},
		},
		{
			name:    "the race the insert-time catch loses has no row left to describe",
			version: nil,
			want:    []string{"acme/widget@1.2.3", "immutable"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := conflictMessage(ref, tc.version)
			for _, want := range tc.want {
				require.Contains(t, got, want)
			}
			for _, reject := range tc.reject {
				require.NotContains(t, got, reject)
			}
		})
	}
}
