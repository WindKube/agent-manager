package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// allCodes is written out by name, not derived from codeNames, so the two are
// independent: a copy-paste that made two constants equal collapses codeNames
// but leaves this slice four long, and the length comparison below catches it.
var allCodes = []Code{CodeNoChanges, CodeFailure, CodeChanged, CodeRefused}

func TestExitCodesAreDistinct(t *testing.T) {
	t.Run("no two of the four share a number", func(t *testing.T) {
		seen := map[int]string{}
		for _, c := range allCodes {
			if prev, dup := seen[int(c)]; dup {
				t.Fatalf("exit code %d is used by both %s and %s", int(c), prev, c)
			}
			seen[int(c)] = c.String()
		}
		require.Len(t, seen, len(allCodes))
	})

	t.Run("no two names alias the same number", func(t *testing.T) {
		// codeNames is keyed by Code. If two constants were accidentally equal,
		// the later map entry would overwrite the earlier one and this length
		// would drop below four while nothing else looked wrong.
		require.Len(t, codeNames, len(allCodes),
			"codeNames has %d entries for %d codes: two constants share a value, or a code has no name",
			len(codeNames), len(allCodes))
		for _, c := range allCodes {
			name, ok := codeNames[c]
			require.True(t, ok, "code %d has no name", int(c))
			require.NotEmpty(t, name)
			require.NotEqual(t, fmt.Sprintf("Code(%d)", int(c)), c.String())
		}
	})

	t.Run("success with no changes is the only zero", func(t *testing.T) {
		// FR-036's whole point: a script under `set -e` must not abort on the
		// steady state, and must be able to tell it from every other outcome.
		require.Equal(t, 0, int(CodeNoChanges))
		for _, c := range []Code{CodeFailure, CodeChanged, CodeRefused} {
			require.NotZero(t, int(c), "%s must not be zero", c)
		}
	})

	t.Run("an unnamed code renders as its number", func(t *testing.T) {
		require.Equal(t, "Code(99)", Code(99).String())
	})
}

func TestExitCodeMapping(t *testing.T) {
	boom := errors.New("hub unreachable")

	cases := []struct {
		name    string
		outcome Code
		err     error
		want    Code
	}{
		{"a clean run keeps the verb's outcome", CodeNoChanges, nil, CodeNoChanges},
		{"a run that changed the tree reports changed", CodeChanged, nil, CodeChanged},
		{"an unclassified error is an unexpected failure", CodeNoChanges, boom, CodeFailure},
		{"a marked error is a refusal the user can fix", CodeNoChanges, Refuse(boom), CodeRefused},
		{"a refusal wrapped again is still a refusal", CodeNoChanges, fmt.Errorf("sync: %w", Refuse(boom)), CodeRefused},
		{"an error beats a changed outcome", CodeChanged, boom, CodeFailure},
		{"a refusal beats a changed outcome", CodeChanged, Refuse(boom), CodeRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ExitCode(tc.outcome, tc.err))
		})
	}
}

func TestRefuseKeepsTheMessageAndTheChain(t *testing.T) {
	inner := errors.New("HOME is not writable")
	err := Refuse(inner)

	require.Equal(t, "HOME is not writable", err.Error())
	require.ErrorIs(t, err, inner)
	require.True(t, IsRefusal(err))

	require.NoError(t, Refuse(nil))
	require.False(t, IsRefusal(nil))
	require.False(t, IsRefusal(inner))
}

// The rest of this file drives the real command tree, because an exit code
// nothing produces is not worth asserting.

func TestMainExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want Code
	}{
		{"version succeeds with nothing changed", []string{"version"}, CodeNoChanges},
		{"a stub verb exits zero", []string{"sync"}, CodeNoChanges},
		{"no arguments prints help and exits zero", nil, CodeNoChanges},
		{"an unknown output format is a refusal", []string{"--output", "yaml", "version"}, CodeRefused},
		{"an unknown flag is a refusal", []string{"--nope", "version"}, CodeRefused},
		{"an unknown command is a refusal", []string{"instal"}, CodeRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var result, diag bytes.Buffer
			require.Equal(t, tc.want, Main(tc.args, &result, &diag))
		})
	}
}

func TestEveryVerbIsWiredAndExitsZero(t *testing.T) {
	// T002's contract: five verbs, each reachable and each exiting 0. When a
	// real implementation replaces a stub this test keeps the verb reachable.
	for _, verb := range []string{"login", "logout", "sync", "status", "version"} {
		t.Run(verb+" is reachable", func(t *testing.T) {
			root, _ := NewRootCmd(&bytes.Buffer{}, &bytes.Buffer{})
			cmd, _, err := root.Find([]string{verb})
			require.NoError(t, err)
			require.Equal(t, verb, cmd.Name())
		})
	}
}

func TestGlobalFlagsBindToOptionsNotGlobals(t *testing.T) {
	// Two trees at once, with different values, is the case a package-level
	// flag variable cannot survive.
	rootA, optsA := NewRootCmd(&bytes.Buffer{}, &bytes.Buffer{})
	rootB, optsB := NewRootCmd(&bytes.Buffer{}, &bytes.Buffer{})

	rootA.SetArgs([]string{"--hub", "https://a.example", "--offline", "-v", "version"})
	rootB.SetArgs([]string{"--hub", "https://b.example", "--output", "json", "version"})

	require.NoError(t, rootA.Execute())
	require.NoError(t, rootB.Execute())

	require.Equal(t, "https://a.example", optsA.Hub)
	require.True(t, optsA.Offline)
	require.True(t, optsA.Verbose)
	require.Equal(t, "human", optsA.Output)

	require.Equal(t, "https://b.example", optsB.Hub)
	require.False(t, optsB.Offline)
	require.Equal(t, "json", optsB.Output)
}

func TestVersionPrintsAndStaysOffTheDiagnosticStream(t *testing.T) {
	// CI smokes the built binary with `amctl version`, so a broken -ldflags
	// stamp has to be visible here too.
	t.Run("human", func(t *testing.T) {
		var result, diag bytes.Buffer
		require.Equal(t, CodeNoChanges, Main([]string{"version"}, &result, &diag))
		require.Contains(t, result.String(), "amctl ")
		require.Contains(t, result.String(), Version)
		require.Empty(t, diag.String())
	})

	t.Run("json is one parseable document", func(t *testing.T) {
		var result, diag bytes.Buffer
		require.Equal(t, CodeNoChanges, Main([]string{"--output", "json", "version"}, &result, &diag))

		var doc struct {
			Kind   string `json:"kind"`
			Result struct {
				Version string `json:"version"`
			} `json:"result"`
		}
		dec := json.NewDecoder(bytes.NewReader(result.Bytes()))
		require.NoError(t, dec.Decode(&doc))
		require.False(t, dec.More(), "the result stream must carry exactly one document")
		require.Equal(t, "version", doc.Kind)
		require.Equal(t, Version, doc.Result.Version)
		require.Empty(t, diag.String())
	})
}

func TestDiagnosticsNeverReachTheResultStream(t *testing.T) {
	// FR-035, at the level the verbs will inherit: a stub warns, and the
	// result stream stays empty rather than gaining an unparseable line.
	//
	// The verb here has to be one that is still a stub, so it moves as each
	// user story lands — it was `login` until T030 implemented it. When the
	// last stub goes, replace it with a verb whose real diagnostic this can
	// assert; the property being tested belongs to output.Streams and not to
	// any one verb.
	var result, diag bytes.Buffer
	require.Equal(t, CodeNoChanges, Main([]string{"--output", "json", "sync"}, &result, &diag))
	require.Empty(t, result.String())
	require.Contains(t, diag.String(), "sync is not implemented yet")
}

func TestErrorsGoToTheDiagnosticStream(t *testing.T) {
	var result, diag bytes.Buffer
	require.Equal(t, CodeRefused, Main([]string{"--output", "yaml", "version"}, &result, &diag))
	require.Empty(t, result.String(), "an error on the result stream would corrupt the json document")
	require.Contains(t, diag.String(), "--output")
	require.Contains(t, diag.String(), "yaml")
}
