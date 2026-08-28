package capability_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/domain/capability"
)

// The inference (T056, FR-018). Every input below is hand-built: the scanner
// that will produce these artefacts does not exist yet (US4), and a test written
// against its output would be testing the scanner's reading of a bundle rather
// than this package's reading of a command.

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
			// FR-018 names instruction files alongside the shell AST: an instruction
			// telling an agent to fetch something is network reach too.
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
			// The one that matters: a definite list plus one unresolvable target is
			// not a definite list, and grading it Allowlisted would let a reviewer
			// accept a set that is not the whole set.
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
			// `npm i -g @octoflow/notes-cli` — the design's f3 finding. The registry
			// it contacts appears nowhere in the command, so recording no target
			// would render as a network capability that reaches nothing.
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

// A remote destination is a network target and not a local write scope. Filing
// `deploy@files.example.dev:/srv/drop/` under filesystem.write would describe
// the wrong risk on the wrong panel, and would also claim the package writes to
// a directory that does not exist on the machine running it.
func TestARemoteDestinationIsNotAFilesystemTarget(t *testing.T) {
	rows := capability.Infer(capability.Artefacts{Commands: []capability.Command{
		script("scp", "report.txt", "deploy@files.example.dev:/srv/drop/"),
	}})

	require.Equal(t, []string{"files.example.dev"}, rowFor(t, rows, capability.Network).Detail)
	require.NotContains(t, names(rows), capability.FilesystemWrite)
	require.Equal(t, []string{"report.txt"}, rowFor(t, rows, capability.FilesystemRead).Detail)
}

// A host is outside the package by definition, so Scoped is not a grade the
// network capability can reach. This is a property of the model rather than a
// threshold that happened not to be crossed, so it is asserted directly.
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

// The false positive worth guarding: a bare word is not a host. `git clone repo`
// must not produce network reach to a machine called `repo`, and `grep TODO
// notes` must not either.
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
			// The design's f2 finding, expressed as a capability rather than as a
			// manifest field that cannot exist.
			name: "a credential file is Review",
			artefacts: capability.Artefacts{Commands: []capability.Command{
				script("cat", "~/.aws/credentials"),
			}},
			which:     capability.FilesystemRead,
			wantLevel: capability.LevelReview,
			wantPaths: []string{"~/.aws/credentials"},
		},
		{
			// The design's f4 finding: write access to the whole workspace where a
			// report directory would be enough.
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

// `cp a b` reads a and writes b. Getting the direction wrong would file every
// copy's source as a write target, which is the difference between "reads the
// hook script it ships" and "writes to /etc".
func TestATransferCommandReadsItsSourcesAndWritesItsDestination(t *testing.T) {
	rows := capability.Infer(capability.Artefacts{Commands: []capability.Command{
		{Name: "cp", Args: []string{"-r", "templates/base", "/opt/agent/templates"}},
	}})

	require.Equal(t, []string{"templates/base"}, rowFor(t, rows, capability.FilesystemRead).Detail)
	require.Equal(t, []string{"/opt/agent/templates"}, rowFor(t, rows, capability.FilesystemWrite).Detail)
}

// sed is the one command whose direction is a flag, and it is common enough in
// postinstall scripts that reading it as a read either way would hide a write.
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

// FR-018, the one absolute in this file.
func TestAShellCapabilityIsNeverBelowReview(t *testing.T) {
	t.Run("the most harmless command imaginable still grades Review", func(t *testing.T) {
		rows := capability.Infer(capability.Artefacts{Commands: []capability.Command{
			{File: "scripts/noop.sh", Line: 1, Name: "true"},
		}})
		require.Equal(t, capability.LevelReview, rowFor(t, rows, capability.Shell).Level)
	})

	t.Run("a script the parser yielded no commands from is still a shell capability", func(t *testing.T) {
		// The blind spot that matters: an empty or unparseable script would
		// otherwise be graded clean by the absence of evidence.
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

// The whole point of the R1 inversion: nothing in the manifest can reach the
// inferred set. Infer takes no manifest, so this asserts the only thing left to
// assert — that the artefacts alone decide, and identical bytes give identical
// rows however they were assembled.
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

// The targets come from an untrusted bundle and land in a jsonb column and on a
// page, so their number is not the bundle's to choose.
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
