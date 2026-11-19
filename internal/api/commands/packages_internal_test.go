package commands

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/fetch"
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
