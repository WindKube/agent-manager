package commands

// An override this product records always lapses: blank expiry input becomes
// the default lifetime, never "forever".

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
