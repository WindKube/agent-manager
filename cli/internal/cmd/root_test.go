package cmd_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/cmd"
	"github.com/WindKube/agent-manager/cli/internal/hub"
)

// The refusal hub.New composes names a flag by string. If root.go registered a
// different literal, the error would tell a user to pass a flag amctl does not
// have — the kind of defect no compiler and no happy-path test can see, because
// each half is individually correct. Both sides are asserted here so neither can
// be renamed alone.
func TestThePlaintextFlagIsTheOneTheRefusalNames(t *testing.T) {
	root, _ := cmd.NewRootCmd(io.Discard, io.Discard)

	require.NotNil(t, root.PersistentFlags().Lookup(hub.PlaintextFlagName),
		"hub.New's refusal names --%s and nothing registers it", hub.PlaintextFlagName)

	_, err := hub.New(hub.Config{URL: "http://hub.example.com", Token: "t"})
	require.ErrorIs(t, err, hub.ErrInsecureHub)
	require.Contains(t, err.Error(), hub.PlaintextFlagName,
		"the refusal must name the flag that answers it")
}

// The flag exists to be typed deliberately, so it must not have a one-letter
// shorthand that a person could hit by accident next to -v.
func TestThePlaintextFlagHasNoShorthand(t *testing.T) {
	root, _ := cmd.NewRootCmd(io.Discard, io.Discard)
	require.Empty(t, root.PersistentFlags().Lookup(hub.PlaintextFlagName).Shorthand)
}
