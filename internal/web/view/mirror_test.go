package view_test

// The web role mirrors two of the api's bounds so a reviewer is told the rule
// before they break it rather than after. A mirror that drifts is worse than no
// mirror: the screen then states a rule the api does not apply, and the reviewer
// believes the screen.
//
// That is not hypothetical here. This file exists because the screen told
// reviewers "leave the expiry blank and the override does not lapse" while
// commands.normalise() turned a blank into 30 days and the published contract said
// "never unlimited" — six places on this side, none of them wrong about anything a
// test was checking, because the only test in the area asserted the TRANSPORT (the
// field is omitted) rather than the OUTCOME. Omitting the field is exactly what
// makes the api apply its default.
//
// internal/web may not import internal/api — internal/archcheck refuses it, and
// for good reason. A TEST may: archcheck loads the non-test packages, and what is
// forbidden is the web role LINKING the api's code, not a test comparing two
// numbers that have to agree.

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
