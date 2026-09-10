package commands

import (
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
