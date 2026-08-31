package commands

// The invariant the Scanner screen was contradicting: an acceptance this product
// records ALWAYS lapses.
//
// `expires_at` is nullable, the column predates the requirement, and nothing here
// writes a null one — which is a sentence in a comment until something asserts it.
// It was worth asserting: six places in internal/web told reviewers that leaving
// the expiry field blank granted an override that never lapses, and blank is
// exactly the input this function turns into thirty days.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEveryAcceptedOverrideGetsALifetimeWhateverWasAskedFor(t *testing.T) {
	for _, days := range []int{0, -1, -365, 1, 12, 30, 365, 366, 10_000} {
		got := Decision{Days: days}.normalise().Days

		require.GreaterOrEqualf(t, got, 1,
			"%d days normalised to %d. An override with no lifetime is a permanent exception "+
				"recorded by accident, and the screen would render its empty expiry as a "+
				"guarantee nobody granted", days, got)
		require.LessOrEqualf(t, got, MaxOverrideDays,
			"%d days normalised to %d, past the bound the published contract states", days, got)
	}

	require.Equal(t, DefaultOverrideDays, Decision{}.normalise().Days,
		"an unstated lifetime is the default, not forever. contract/governance.go says "+
			"\"never unlimited\" and internal/web mirrors this number to say so on the form")
}
