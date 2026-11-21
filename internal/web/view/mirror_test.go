package view_test

// The web role mirrors some of the api's bounds; a drifted mirror makes the screen state a rule the api does
// not apply. Tests may import internal/api even though the web role may not: archcheck only checks non-test code.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/web/view"
)

func TestTheOverrideBoundsThisRoleStatesAreTheOnesTheApiApplies(t *testing.T) {
	require.Equal(t, commands.DefaultOverrideDays, view.DefaultOverrideDays,
		"the screen tells a reviewer what a blank expiry field means. If that number is not "+
			"the one the api writes, the screen is lying about a governance decision")
	require.Equal(t, commands.MaxOverrideDays, view.MaxOverrideDays,
		"the screen bounds the field so a reviewer is not told to retype a number after "+
			"choosing it. A mirror wider than the api's turns that into a refusal instead")

	require.Equal(t, "30", view.DefaultOverrideDaysText(),
		"the printed form of the default must be the default")
}

func TestTheTagsFieldThisRoleBoundsHoldsEveryTagTheApiAccepts(t *testing.T) {
	require.Equal(t, commands.MaxTagCount*(commands.MaxTagLength+1), view.MaxTagsFieldLength,
		"the modal has one comma-separated tags input, so its maxlength has to hold the "+
			"longest registration the api would accept. A narrower mirror refuses what the "+
			"api would have taken, at the keyboard, with no message")
}
