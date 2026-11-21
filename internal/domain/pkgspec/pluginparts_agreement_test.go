package pkgspec_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/pluginparts"

	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
)

// The hub shows a plugin's components and the CLI installs them, from two
// readers; this keeps them naming the same components in the same places.
const sharedFixture = "../../../cli/pluginparts/testdata/kit"

type componentKey struct {
	Kind, Name, Where string
}

func TestHubSurfacesAndCLIComponentsAgreeOnTheSharedFixture(t *testing.T) {
	tree := bundle.New()
	require.NoError(t, filepath.WalkDir(sharedFixture, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(sharedFixture, p)
		return tree.Add(filepath.ToSlash(rel), bundle.FileMode, data)
	}))
	hub := pkgspec.ReadSurfaces(tree)
	require.Empty(t, hub.Unreadable)

	cli, err := pluginparts.Read(os.DirFS(sharedFixture))
	require.NoError(t, err)
	require.Empty(t, cli.Problems)

	var hubKeys, cliKeys []componentKey
	for _, s := range hub.Servers {
		hubKeys = append(hubKeys, componentKey{"server", s.Name, s.Transport + " " + s.Location()})
	}
	for _, h := range hub.Hooks {
		hubKeys = append(hubKeys, componentKey{"hook", h.Event + "/" + h.Matcher, h.Type + " " + h.Command})
	}
	for _, p := range hub.Prompts {
		hubKeys = append(hubKeys, componentKey{string(p.Kind), p.Name, p.Path})
	}

	for _, s := range cli.Servers {
		cliKeys = append(cliKeys, componentKey{"server", s.Name, string(s.Transport) + " " + s.Source})
	}
	for _, h := range cli.Hooks {
		for _, e := range h.Entries {
			cliKeys = append(cliKeys, componentKey{"hook", h.Event + "/" + h.Matcher, e.Type + " " + e.Command})
		}
	}
	for _, s := range cli.Skills {
		cliKeys = append(cliKeys, componentKey{string(pkgspec.ComponentSkill), s.Name, s.Dir + "/" + pluginparts.SkillFile})
	}
	for _, p := range cli.Agents {
		cliKeys = append(cliKeys, componentKey{string(pkgspec.ComponentAgent), p.Name, p.Path})
	}
	for _, p := range cli.Commands {
		cliKeys = append(cliKeys, componentKey{string(pkgspec.ComponentCommand), p.Name, p.Path})
	}

	require.ElementsMatch(t, hubKeys, cliKeys)
	require.Len(t, cliKeys, 12)
}
