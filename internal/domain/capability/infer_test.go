package capability_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/domain/capability"
)

// Inputs are hand-built so these tests exercise Infer, not the scanner's
// reading of a bundle.

func script(name string, args ...string) capability.Command {
	return capability.Command{File: "scripts/digest.sh", Line: 41, Name: name, Args: args}
}

func rowFor(t *testing.T, rows []capability.Capability, name string) capability.Capability {
	t.Helper()

	for _, row := range rows {
		if row.Name == name {
			return row
		}
	}
	require.Failf(t, "missing capability", "no %q in %+v", name, rows)
	return capability.Capability{}
}

func names(rows []capability.Capability) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Name)
	}
	return out
}

func TestNetworkIsInferredFromCommandsAndInstructionURLs(t *testing.T) {
	for _, tc := range []struct {
		name       string
		artefacts  capability.Artefacts
		wantHosts  []string
		wantLevel  capability.Level
		indefinite bool
	}{
		{
			name: "a literal host in a curl is an allowlistable target",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("curl", "-sS", "https://collect.hexley-metrics.io/v1/ping"),
			}},
			wantHosts: []string{"collect.hexley-metrics.io"},
			wantLevel: capability.LevelAllowlisted,
		},
		{
			name: "a URL in an instruction file counts even with no script at all",
			artefacts: capability.Artefacts{URLs: []capability.URL{
				{File: "SKILL.md", Line: 12, Raw: "https://api.github.com/repos/org/repo"},
			}},
			wantHosts: []string{"api.github.com"},
			wantLevel: capability.LevelAllowlisted,
		},
		{
			name: "a host behind an expansion cannot be named, so the whole row is Review",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("curl", "https://$HOST/collect"),
			}},
			wantLevel:  capability.LevelReview,
			indefinite: true,
		},
		{
			name: "one unresolvable target contaminates an otherwise definite list",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("curl", "https://slack.com/api/chat"),
				script("curl", "$ENDPOINT"),
			}},
			wantHosts:  []string{"slack.com"},
			wantLevel:  capability.LevelReview,
			indefinite: true,
		},
		{
			name: "a package manager with no host is network reach with an indefinite target",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("npm", "i", "-g", "@octoflow/notes-cli"),
			}},
			wantLevel:  capability.LevelReview,
			indefinite: true,
		},
		{
			name: "the cloud metadata endpoint is Review however literal it is",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("curl", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
			}},
			wantHosts: []string{"169.254.169.254"},
			wantLevel: capability.LevelReview,
		},
		{
			name: "an scp destination names its host",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("scp", "report.txt", "deploy@files.example.dev:/srv/drop/"),
			}},
			wantHosts: []string{"files.example.dev"},
			wantLevel: capability.LevelAllowlisted,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := rowFor(t, capability.Infer(tc.artefacts), capability.Network)
			require.Equal(t, tc.wantLevel, row.Level)
			require.Equal(t, tc.indefinite, row.Indefinite)
			if tc.wantHosts == nil {
				require.Empty(t, row.Detail)
				return
			}
			require.Equal(t, tc.wantHosts, row.Detail)
		})
	}
}

func TestARemoteDestinationIsNotAFilesystemTarget(t *testing.T) {
	rows := capability.Infer(capability.Artefacts{Commands: []capability.Command{
		script("scp", "report.txt", "deploy@files.example.dev:/srv/drop/"),
	}})

	require.Equal(t, []string{"files.example.dev"}, rowFor(t, rows, capability.Network).Detail)
	require.NotContains(t, names(rows), capability.FilesystemWrite)
	require.Equal(t, []string{"report.txt"}, rowFor(t, rows, capability.FilesystemRead).Detail)
}

func TestNetworkIsNeverScoped(t *testing.T) {
	for _, artefacts := range []capability.Artefacts{
		{Commands: []capability.Command{script("curl", "https://slack.com/api")}},
		{URLs: []capability.URL{{Raw: "https://example.dev/doc"}}},
		{Commands: []capability.Command{script("git", "clone", "https://github.com/org/repo")}},
	} {
		row := rowFor(t, capability.Infer(artefacts), capability.Network)
		require.NotEqual(t, capability.LevelScoped, row.Level)
	}
}

func TestABareWordIsNotAHost(t *testing.T) {
	rows := capability.Infer(capability.Artefacts{Commands: []capability.Command{
		{File: "scripts/build.sh", Line: 3, Name: "echo", Args: []string{"building", "the", "thing"}},
	}})
	for _, row := range rows {
		require.NotEqual(t, capability.Network, row.Name,
			"a command with no host and no URL produced network reach: %+v", row)
	}
}

func TestFilesystemScopeIsGradedByWhereTheTargetsAre(t *testing.T) {
	for _, tc := range []struct {
		name      string
		artefacts capability.Artefacts
		which     string
		wantLevel capability.Level
		wantPaths []string
	}{
		{
			name: "reads confined to the package tree are Scoped",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("cat", "references/guardrails.md"),
			}},
			which:     capability.FilesystemRead,
			wantLevel: capability.LevelScoped,
			wantPaths: []string{"references/guardrails.md"},
		},
		{
			name: "a definite path outside the tree is Allowlisted, not Review",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("cat", "/usr/share/dict/words"),
			}},
			which:     capability.FilesystemRead,
			wantLevel: capability.LevelAllowlisted,
			wantPaths: []string{"/usr/share/dict/words"},
		},
		{
			name: "a credential file is Review",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("cat", "~/.aws/credentials"),
			}},
			which:     capability.FilesystemRead,
			wantLevel: capability.LevelReview,
			wantPaths: []string{"~/.aws/credentials"},
		},
		{
			name: "a recursive glob is Review however definite it looks",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				{Name: "tee", Args: []string{"**/report.md"}},
			}},
			which:     capability.FilesystemWrite,
			wantLevel: capability.LevelReview,
			wantPaths: []string{"**/report.md"},
		},
		{
			name: "a path that climbs out of the package root is Review",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				{Name: "cp", Args: []string{"scripts/hook.sh", "../../etc/profile.d/hook.sh"}},
			}},
			which:     capability.FilesystemWrite,
			wantLevel: capability.LevelReview,
			wantPaths: []string{"../../etc/profile.d/hook.sh"},
		},
		{
			name: "a redirection is a write target",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				{Name: "echo", Args: []string{"done"},
					Redirects: []capability.Redirect{{Path: "out/report.md", Write: true}}},
			}},
			which:     capability.FilesystemWrite,
			wantLevel: capability.LevelScoped,
			wantPaths: []string{"out/report.md"},
		},
		{
			name: "a dynamic target cannot be graded, so it is Review",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("cat", "$HOME/.config/thing.toml"),
			}},
			which:     capability.FilesystemRead,
			wantLevel: capability.LevelReview,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := rowFor(t, capability.Infer(tc.artefacts), tc.which)
			require.Equal(t, tc.wantLevel, row.Level)
			if tc.wantPaths != nil {
				require.Equal(t, tc.wantPaths, row.Detail)
			}
		})
	}
}

func TestATransferCommandReadsItsSourcesAndWritesItsDestination(t *testing.T) {
	rows := capability.Infer(capability.Artefacts{Commands: []capability.Command{
		{Name: "cp", Args: []string{"-r", "templates/base", "/opt/agent/templates"}},
	}})

	require.Equal(t, []string{"templates/base"}, rowFor(t, rows, capability.FilesystemRead).Detail)
	require.Equal(t, []string{"/opt/agent/templates"}, rowFor(t, rows, capability.FilesystemWrite).Detail)
}

func TestSedWritesOnlyInPlace(t *testing.T) {
	read := capability.Infer(capability.Artefacts{Commands: []capability.Command{
		script("sed", "s/a/b/", "notes.md"),
	}})
	require.Equal(t, []string{"notes.md"}, rowFor(t, read, capability.FilesystemRead).Detail)
	require.NotContains(t, names(read), capability.FilesystemWrite)

	write := capability.Infer(capability.Artefacts{Commands: []capability.Command{
		script("sed", "-i", "s/a/b/", "notes.md"),
	}})
	require.Equal(t, []string{"notes.md"}, rowFor(t, write, capability.FilesystemWrite).Detail)
	require.NotContains(t, names(write), capability.FilesystemRead)
}

func TestAShellCapabilityIsNeverBelowReview(t *testing.T) {
	t.Run("the most harmless command imaginable still grades Review", func(t *testing.T) {
		rows := capability.Infer(capability.Artefacts{Commands: []capability.Command{
			{File: "scripts/noop.sh", Line: 1, Name: "true"},
		}})
		require.Equal(t, capability.LevelReview, rowFor(t, rows, capability.Shell).Level)
	})

	t.Run("a script the parser yielded no commands from is still a shell capability", func(t *testing.T) {
		rows := capability.Infer(capability.Artefacts{Files: []capability.File{
			{Path: "scripts/postinstall.sh", Class: capability.ClassScript},
		}})
		require.Equal(t, capability.LevelReview, rowFor(t, rows, capability.Shell).Level)
	})

	t.Run("a package with no script and no command has no shell capability at all", func(t *testing.T) {
		rows := capability.Infer(capability.Artefacts{Files: []capability.File{
			{Path: "SKILL.md", Class: capability.ClassInstruction},
		}})
		require.Empty(t, rows)
	})
}

func TestInferenceIsDeterministicAndOrderedByTheCapabilityVocabulary(t *testing.T) {
	artefacts := capability.Artefacts{
		Files: []capability.File{{Path: "scripts/digest.sh", Class: capability.ClassScript}},
		Commands: []capability.Command{
			script("curl", "https://slack.com/api/chat"),
			script("tee", "out/digest.md"),
			script("cat", "references/notes.md"),
			script("curl", "https://slack.com/api/chat"),
		},
	}

	first := capability.Infer(artefacts)
	require.Equal(t, []string{
		capability.Network, capability.FilesystemRead, capability.FilesystemWrite, capability.Shell,
	}, names(first))
	require.Equal(t, []string{"slack.com"}, rowFor(t, first, capability.Network).Detail,
		"a host named twice is one target")
	require.Equal(t, first, capability.Infer(artefacts))
}

// Targets come from an untrusted bundle, so the bundle must not choose how
// many are stored.
func TestTheTargetListIsCappedAndSaysSoWhenItTruncates(t *testing.T) {
	commands := make([]capability.Command, 0, 200)
	for i := range 200 {
		commands = append(commands, script("curl", "https://host-"+string(rune('a'+i%26))+
			string(rune('a'+i/26))+".example.dev/x"))
	}

	row := rowFor(t, capability.Infer(capability.Artefacts{Commands: commands}), capability.Network)
	require.Len(t, row.Detail, 64)
	require.True(t, row.Indefinite, "a truncated list must never read as the whole list")
	require.Equal(t, capability.LevelReview, row.Level)
}
