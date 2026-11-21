package plan

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

const (
	home       = "/home/dev"
	skillsRoot = home + "/.claude/skills"
	hubURL     = "https://hub.example.com"
)

// dg is a well-formed lockfile digest; distinct seeds give distinct digests.
func dg(seed int) string { return fmt.Sprintf("sha256:%064x", seed) }

func mustDigest(t *testing.T, seed int) record.Digest {
	t.Helper()
	d, err := record.ParseDigest(dg(seed))
	require.NoError(t, err)
	return d
}

// claudeCodeTarget routes namespace/name to <root>/<namespace>-<name> through
// the real layout validation.
func claudeCodeTarget(root string) Target {
	return Target{
		Name: record.TargetClaudeCode,
		Dest: func(id string, kind record.Kind) (string, error) {
			if kind != record.KindSkill {
				return "", fmt.Errorf("claude-code supports skills only, not %s: %w", kind, layout.ErrKindUnsupported)
			}
			ns, name, ok := strings.Cut(id, "/")
			if !ok || ns == "" || name == "" {
				return "", fmt.Errorf("entry id %q is not exactly two non-empty segments", id)
			}
			dir := ns + "-" + name
			if err := layout.ValidateClaudeCodeSkillDirName(dir); err != nil {
				return "", err
			}
			return filepath.Join(root, dir), nil
		},
	}
}

// nameOnlyTarget drops the namespace, so a package named `synced` reaches
// claude-code's reserved directory.
func nameOnlyTarget(root string) Target {
	return Target{
		Name: record.TargetClaudeCode,
		Dest: func(id string, _ record.Kind) (string, error) {
			_, name, _ := strings.Cut(id, "/")
			if err := layout.ValidateClaudeCodeSkillDirName(name); err != nil {
				return "", err
			}
			return filepath.Join(root, name), nil
		},
	}
}

// codexTarget is a synthetic target this build knows but cannot write.
func codexTarget(t *testing.T) Target {
	t.Helper()
	return Target{Name: record.TargetCodex, Err: fmt.Errorf("codex: %w", layout.ErrR2Unresolved)}
}

// withdrawnTarget is known but deliberately unimplemented, reported rather
// than refused; the sentinel comes from the real registry.
func withdrawnTarget(t *testing.T) Target {
	t.Helper()
	reg, err := layout.NewRegistry(layout.Config{HomeDir: home})
	require.NoError(t, err)
	_, err = reg.Resolve("agents-md")
	require.ErrorIs(t, err, layout.ErrWithdrawnTarget)
	return Target{Name: "agents-md", Withdrawn: err}
}

func lf(slug string, targets []string, entries ...hub.LockfileEntry) *hub.Lockfile {
	tg := make([]hub.LockfileTargets, 0, len(targets))
	for _, name := range targets {
		tg = append(tg, hub.LockfileTargets(name))
	}
	if entries == nil {
		entries = []hub.LockfileEntry{}
	}
	return &hub.Lockfile{
		SchemaVersion: "1.0.0",
		Profile:       hub.LockfileProfile{Slug: slug, Name: slug},
		Revision:      7,
		ResolvedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Gate:          "block",
		Entries:       entries,
		Skipped:       []hub.LockfileSkip{},
		Targets:       tg,
	}
}

func skill(id, version string, digestSeed int) hub.LockfileEntry {
	return hub.LockfileEntry{
		Id:         id,
		Kind:       hub.Skill,
		Version:    version,
		Digest:     dg(digestSeed),
		ObjectKey:  "bundles/" + id + "/" + version + "/bundle.tar.zst",
		Resolution: "pinned",
		Verdict:    "clean",
	}
}

func plugin(id, version string, digestSeed int) hub.LockfileEntry {
	e := skill(id, version, digestSeed)
	e.Kind = hub.Plugin
	return e
}

type installedEntry struct {
	id          string
	version     string
	digestSeed  int
	target      record.Target
	dest        string
	fingerprint bool
}

func rec(t *testing.T, profiles map[string][]installedEntry) *record.Record {
	t.Helper()
	r := record.New(hubURL)
	for slug, entries := range profiles {
		p := record.Profile{
			Slug:        slug,
			Revision:    6,
			InstalledAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Targets:     []record.Target{record.TargetClaudeCode},
		}
		for _, e := range entries {
			target := e.target
			if target == "" {
				target = record.TargetClaudeCode
			}
			dest := e.dest
			if dest == "" {
				ns, name, _ := strings.Cut(e.id, "/")
				dest = filepath.Join(skillsRoot, ns+"-"+name)
			}
			entry := record.Entry{
				ID:      e.id,
				Version: e.version,
				Digest:  mustDigest(t, e.digestSeed),
				Kind:    record.KindSkill,
				Target:  target,
				Dest:    dest,
			}
			if e.fingerprint {
				entry.Fingerprint = record.Fingerprint{
					Algo:  record.FingerprintAlgo,
					Files: map[string]record.FileMark{"SKILL.md": {SHA256: strings.Repeat("b", 64), Size: 12, Mode: 0o644, Kind: record.FileKindRegular}},
				}
			}
			p.Entries = append(p.Entries, entry)
		}
		r.SetProfile(p)
	}
	return r
}

func changeLines(cs []Change) []string {
	if len(cs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cs))
	for i := range cs {
		c := &cs[i]
		from := "none"
		if c.From != nil {
			from = c.From.Version
		}
		out = append(out, fmt.Sprintf("%s %s %s %s %s->%s dir=%s", c.Target, c.ID, c.Profile, c.Op, from, c.Version, orDash(string(c.Direction))))
	}
	return out
}

func removeLines(rs []Removal) []string {
	if len(rs) == 0 {
		return nil
	}
	out := make([]string, 0, len(rs))
	for i := range rs {
		r := &rs[i]
		out = append(out, fmt.Sprintf("%s %s %s %s disk=%t", r.Target, r.ID, r.Profile, r.Reason, r.RemovesFromDisk()))
	}
	return out
}

func conflictLines(cs []Conflict) []string {
	if len(cs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cs))
	for i := range cs {
		out = append(out, fmt.Sprintf("%s %s %s", cs[i].Kind, orDash(cs[i].ID), orDash(string(cs[i].Target))))
	}
	return out
}

func skipLines(ss []Skip) []string {
	if len(ss) == 0 {
		return nil
	}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, fmt.Sprintf("%s %s %s %s known=%t would=%s",
			s.Profile, s.ID, orDash(string(s.Target)), s.Reason, s.Recognised, orDash(s.WouldHaveResolvedTo)))
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type want struct {
	add       []string
	upgrade   []string
	downgrade []string
	unchanged []string
	remove    []string
	conflicts []string
	skipped   []string
}

func (w want) check(t *testing.T, p Plan) {
	t.Helper()
	require.Equal(t, w.add, changeLines(p.Add), "Add")
	require.Equal(t, w.upgrade, changeLines(p.Upgrade), "Upgrade")
	require.Equal(t, w.downgrade, changeLines(p.Downgrade), "Downgrade")
	require.Equal(t, w.unchanged, changeLines(p.Unchanged), "Unchanged")
	require.Equal(t, w.remove, removeLines(p.Remove), "Remove")
	require.Equal(t, w.conflicts, conflictLines(p.Conflicts), "Conflicts")
	require.Equal(t, w.skipped, skipLines(p.Skipped), "Skipped")
}

func TestEveryTransitionBetweenTheLockfileAndTheRecord(t *testing.T) {
	t.Parallel()

	cc := claudeCodeTarget(skillsRoot)

	cases := []struct {
		name      string
		lockfiles []*hub.Lockfile
		record    *record.Record
		targets   []Target
		want      want
	}{
		{
			name:      "a package absent from the machine is added",
			lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1))},
			record:    nil,
			targets:   []Target{cc},
			want: want{
				add: []string{"claude-code acme/code-review base add none->2.4.1 dir=-"},
			},
		},
		{
			name:      "a version the hub moved forward is an upgrade",
			lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/code-review", "1.10.0", 2))},
			record:    rec(t, map[string][]installedEntry{"base": {{id: "acme/code-review", version: "1.9.0", digestSeed: 1}}}),
			targets:   []Target{cc},
			want: want{
				// Lexicographic comparison gets 1.9.0 -> 1.10.0 backwards.
				upgrade: []string{"claude-code acme/code-review base upgrade 1.9.0->1.10.0 dir=up"},
			},
		},
		{
			name:      "a version the hub moved backward is a downgrade, not an upgrade with a minus sign",
			lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/code-review", "1.9.0", 1))},
			record:    rec(t, map[string][]installedEntry{"base": {{id: "acme/code-review", version: "1.10.0", digestSeed: 2}}}),
			targets:   []Target{cc},
			want: want{
				downgrade: []string{"claude-code acme/code-review base downgrade 1.10.0->1.9.0 dir=down"},
			},
		},
		{
			name:      "an entry at the locked version and digest is unchanged and appears nowhere else",
			lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1))},
			record:    rec(t, map[string][]installedEntry{"base": {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}}}),
			targets:   []Target{cc},
			want: want{
				unchanged: []string{"claude-code acme/code-review base unchanged 2.4.1->2.4.1 dir=same"},
			},
		},
		{
			name:      "the same version republished with different bytes is a replace, not an upgrade",
			lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 9))},
			record:    rec(t, map[string][]installedEntry{"base": {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}}}),
			targets:   []Target{cc},
			want: want{
				upgrade: []string{"claude-code acme/code-review base replace 2.4.1->2.4.1 dir=same"},
			},
		},
		{
			name:      "a package that left the profile is removed",
			lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1))},
			record: rec(t, map[string][]installedEntry{"base": {
				{id: "acme/code-review", version: "2.4.1", digestSeed: 1},
				{id: "acme/legacy-helper", version: "0.3.0", digestSeed: 4},
			}}),
			targets: []Target{cc},
			want: want{
				unchanged: []string{"claude-code acme/code-review base unchanged 2.4.1->2.4.1 dir=same"},
				remove:    []string{"claude-code acme/legacy-helper base no-longer-in-profile disk=true"},
			},
		},
		{
			name:      "a target the profile disabled has everything the CLI wrote under it removed",
			lockfiles: []*hub.Lockfile{lf("base", []string{}, skill("acme/code-review", "2.4.1", 1))},
			record:    rec(t, map[string][]installedEntry{"base": {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}}}),
			targets:   []Target{cc},
			want: want{
				remove: []string{"claude-code acme/code-review base target-disabled disk=true"},
			},
		},
		{
			name: "two profiles resolving one package to two versions is refused before anything is written",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1)),
				lf("web", []string{"claude-code"}, skill("acme/code-review", "2.3.0", 5)),
			},
			record:  nil,
			targets: []Target{cc},
			want: want{
				add: []string{
					"claude-code acme/code-review base add none->2.4.1 dir=-",
					"claude-code acme/code-review web add none->2.3.0 dir=-",
				},
				conflicts: []string{"version-split acme/code-review -"},
			},
		},
		{
			name: "two profiles agreeing on the version but not the digest is the same one-directory-two-contents refusal",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1)),
				lf("web", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 2)),
			},
			record:  nil,
			targets: []Target{cc},
			want: want{
				add: []string{
					"claude-code acme/code-review base add none->2.4.1 dir=-",
					"claude-code acme/code-review web add none->2.4.1 dir=-",
				},
				conflicts: []string{"version-split acme/code-review -"},
			},
		},
		{
			name: "two profiles at one version share the directory, so one dropping it removes nothing from disk",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}),
				lf("web", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1)),
			},
			record: rec(t, map[string][]installedEntry{
				"base": {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}},
				"web":  {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}},
			}),
			targets: []Target{cc},
			want: want{
				unchanged: []string{"claude-code acme/code-review web unchanged 2.4.1->2.4.1 dir=same"},
				remove:    []string{"claude-code acme/code-review base no-longer-in-profile disk=false"},
			},
		},
		{
			name: "a target this build cannot write is skipped, not reported as disabled and not refused",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code", "codex"}, skill("acme/code-review", "2.4.1", 1)),
			},
			record:  nil,
			targets: []Target{cc, codexTarget(t)},
			want: want{
				add:     []string{"claude-code acme/code-review base add none->2.4.1 dir=-"},
				skipped: []string{"base acme/code-review codex target-unwritable known=true would=-"},
			},
		},
		{
			name: "a withdrawn target is reported rather than refused, and the writable one still installs",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code", "agents-md"}, skill("acme/code-review", "2.4.1", 1)),
			},
			record:  nil,
			targets: []Target{cc, withdrawnTarget(t)},
			want: want{
				add: []string{"claude-code acme/code-review base add none->2.4.1 dir=-"},
			},
		},
		{
			name: "a profile whose every target is withdrawn is refused, or it would install nothing and exit 0",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"agents-md"}, skill("acme/code-review", "2.4.1", 1)),
			},
			record:  nil,
			targets: []Target{cc, withdrawnTarget(t)},
			want: want{
				conflicts: []string{"no-writable-target - -"},
			},
		},
		{
			name: "a target this build has never heard of is refused rather than ignored",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code", "agents-md"}, skill("acme/code-review", "2.4.1", 1)),
			},
			record:  nil,
			targets: []Target{cc},
			want: want{
				add:       []string{"claude-code acme/code-review base add none->2.4.1 dir=-"},
				conflicts: []string{"target-unknown - agents-md"},
			},
		},
		{
			name: "an id that is not exactly two segments is refused, never joined or truncated",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, skill("acme", "2.4.1", 1), skill("a/b/c", "1.0.0", 2)),
			},
			record:  nil,
			targets: []Target{cc},
			want: want{
				conflicts: []string{
					"unroutable-entry a/b/c claude-code",
					"unroutable-entry acme claude-code",
				},
			},
		},
		{
			name: "a plugin is skipped by a skills-only target rather than installed somewhere hopeful",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, plugin("acme/big-plugin", "1.0.0", 3)),
			},
			record:  nil,
			targets: []Target{cc},
			want: want{
				skipped: []string{"base acme/big-plugin claude-code entry-kind-not-installable known=true would=-"},
			},
		},
		{
			name: "a package named synced is refused because claude-code would never load it",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, skill("acme/synced", "1.0.0", 3)),
			},
			record:  nil,
			targets: []Target{nameOnlyTarget(skillsRoot)},
			want: want{
				conflicts: []string{"unroutable-entry acme/synced claude-code"},
			},
		},
		{
			name: "two different packages routed to one directory is refused",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, skill("acme/tools", "1.0.0", 1), skill("beta/tools", "1.0.0", 2)),
			},
			record:  nil,
			targets: []Target{nameOnlyTarget(skillsRoot)},
			want: want{
				add: []string{
					"claude-code acme/tools base add none->1.0.0 dir=-",
					"claude-code beta/tools base add none->1.0.0 dir=-",
				},
				conflicts: []string{"destination-collision - claude-code"},
			},
		},
		{
			name: "two ids differing only by case collide, because APFS folds them into one directory",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, skill("Acme/tools", "1.0.0", 1), skill("acme/tools", "1.0.0", 2)),
			},
			record:  nil,
			targets: []Target{cc},
			want: want{
				add: []string{
					"claude-code Acme/tools base add none->1.0.0 dir=-",
					"claude-code acme/tools base add none->1.0.0 dir=-",
				},
				conflicts: []string{"destination-collision - claude-code"},
			},
		},
		{
			name: "a destination that moved is removed at the old path and added at the new one",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1)),
			},
			record: rec(t, map[string][]installedEntry{"base": {{
				id: "acme/code-review", version: "2.4.1", digestSeed: 1,
				dest: skillsRoot + "/code-review",
			}}}),
			targets: []Target{cc},
			want: want{
				add:    []string{"claude-code acme/code-review base add none->2.4.1 dir=-"},
				remove: []string{"claude-code acme/code-review base relocated disk=true"},
			},
		},
		{
			name: "a package still in the profile but no longer routable is a skip, not a removal",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, plugin("acme/code-review", "3.0.0", 8)),
			},
			record:  rec(t, map[string][]installedEntry{"base": {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}}}),
			targets: []Target{cc},
			want: want{
				skipped: []string{"base acme/code-review claude-code entry-kind-not-installable known=true would=-"},
			},
		},
		{
			name: "a profile the caller did not ask about is left entirely alone",
			lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1)),
			},
			record: rec(t, map[string][]installedEntry{
				"base":  {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}},
				"other": {{id: "acme/legacy-helper", version: "0.3.0", digestSeed: 4}},
			}),
			targets: []Target{cc},
			want: want{
				unchanged: []string{"claude-code acme/code-review base unchanged 2.4.1->2.4.1 dir=same"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := Compute(Inputs{Lockfiles: tc.lockfiles, Record: tc.record, Targets: tc.targets})
			require.NoError(t, err)
			tc.want.check(t, p)
		})
	}
}

func TestEverySkippedEntryIsReportedWithTheHubsOwnReason(t *testing.T) {
	t.Parallel()

	require.Len(t, KnownSkipReasons(), 6,
		"lockfile.schema.json freezes six skip reasons; a seventh needs a decision, not a quiet append")

	// Compared against the generated client, so a typo in the hand-typed list
	// can't reclassify a real reason as unknown.
	for _, reason := range KnownSkipReasons() {
		require.True(t, hub.LockfileSkipReason(reason).Valid(),
			"%q is not a value the generated client recognises", reason)
		require.True(t, IsKnownSkipReason(reason))
	}
	require.False(t, hub.LockfileSkipReason("not-a-reason").Valid(),
		"the generated Valid() must actually reject something, or the loop above proves nothing")
	require.False(t, IsKnownSkipReason("not-a-reason"))

	l := lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1))
	detail := "SH-NET-002 in postinstall.sh"
	would := "1.9.0"
	future := "some-reason-this-build-has-never-heard-of"
	l.Skipped = []hub.LockfileSkip{
		{Id: "acme/legacy-helper", Reason: hub.LockfileSkipReason(SkipFlaggedAwaitingApproval), Detail: &detail, WouldHaveResolvedTo: &would},
		{Id: "acme/from-the-future", Reason: hub.LockfileSkipReason(future)},
	}

	p, err := Compute(Inputs{Lockfiles: []*hub.Lockfile{l}, Targets: []Target{claudeCodeTarget(skillsRoot)}})
	require.NoError(t, err)

	require.Equal(t, []string{
		"base acme/from-the-future - " + future + " known=false would=-",
		"base acme/legacy-helper - flagged-awaiting-approval known=true would=1.9.0",
	}, skipLines(p.Skipped))

	// The unknown reason must survive byte for byte.
	require.Equal(t, future, p.Skipped[0].Reason)
	require.False(t, p.Skipped[0].Recognised)
	require.Equal(t, detail, p.Skipped[1].Detail)

	// A skip is a report, not an action.
	require.Equal(t, 1, p.ChangeCount())
}

func TestTheChangeSetDoesNotDependOnTheVersionComparer(t *testing.T) {
	t.Parallel()

	lockfiles := []*hub.Lockfile{lf("base", []string{"claude-code"},
		skill("acme/code-review", "1.10.0", 2),
		skill("acme/lint-guard", "0.9.0", 3),
		skill("acme/new-thing", "1.0.0", 4),
	)}
	r := rec(t, map[string][]installedEntry{"base": {
		{id: "acme/code-review", version: "1.9.0", digestSeed: 1},
		{id: "acme/lint-guard", version: "1.4.0", digestSeed: 5},
		{id: "acme/gone", version: "1.0.0", digestSeed: 6},
	}})
	targets := []Target{claudeCodeTarget(skillsRoot)}

	inverted := func(a, b string) (int, bool) {
		sign, ok := CompareVersions(a, b)
		return -sign, ok
	}
	nonsense := func(string, string) (int, bool) { return 0, false }

	honest, err := Compute(Inputs{Lockfiles: lockfiles, Record: r, Targets: targets})
	require.NoError(t, err)
	backwards, err := Compute(Inputs{Lockfiles: lockfiles, Record: r, Targets: targets, Compare: inverted})
	require.NoError(t, err)
	silent, err := Compute(Inputs{Lockfiles: lockfiles, Record: r, Targets: targets, Compare: nonsense})
	require.NoError(t, err)

	key := func(p Plan) []string {
		out := []string{}
		for _, c := range p.Writes() {
			out = append(out, fmt.Sprintf("write %s %s %s %s", c.Target, c.ID, c.Version, c.Dest))
		}
		for _, rm := range p.Remove {
			out = append(out, fmt.Sprintf("remove %s %s %s", rm.Target, rm.ID, rm.Dest))
		}
		for _, c := range p.Unchanged {
			out = append(out, fmt.Sprintf("keep %s %s %s", c.Target, c.ID, c.Dest))
		}
		return out
	}
	require.Equal(t, key(honest), key(backwards))
	require.Equal(t, key(honest), key(silent))

	// The labels did move, so the assertion above is not vacuous.
	require.Equal(t, []string{"claude-code acme/code-review base upgrade 1.9.0->1.10.0 dir=up"}, changeLines(honest.Upgrade))
	require.Equal(t, []string{"claude-code acme/lint-guard base downgrade 1.4.0->0.9.0 dir=down"}, changeLines(honest.Downgrade))
	require.Equal(t, []string{"claude-code acme/lint-guard base upgrade 1.4.0->0.9.0 dir=up"}, changeLines(backwards.Upgrade))
	require.Equal(t, []string{"claude-code acme/code-review base downgrade 1.9.0->1.10.0 dir=down"}, changeLines(backwards.Downgrade))
	require.Empty(t, silent.Downgrade)
	require.Equal(t, []string{
		"claude-code acme/code-review base replace 1.9.0->1.10.0 dir=unknown",
		"claude-code acme/lint-guard base replace 1.4.0->0.9.0 dir=unknown",
	}, changeLines(silent.Upgrade))
}

func TestThePlanIsInAStableOrderWhateverOrderTheInputsArriveIn(t *testing.T) {
	t.Parallel()

	entries := []hub.LockfileEntry{
		skill("zeta/one", "1.0.0", 10),
		skill("acme/two", "2.0.0", 11),
		skill("acme/one", "3.0.0", 12),
		skill("beta/one", "4.0.0", 13),
	}
	build := func(seed uint64) Inputs {
		rng := rand.New(rand.NewPCG(seed, seed))
		shuffled := append([]hub.LockfileEntry(nil), entries...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		half := len(shuffled) / 2
		lockfiles := []*hub.Lockfile{
			lf("web", []string{"claude-code"}, shuffled[:half]...),
			lf("base", []string{"claude-code"}, shuffled[half:]...),
		}
		rng.Shuffle(len(lockfiles), func(i, j int) { lockfiles[i], lockfiles[j] = lockfiles[j], lockfiles[i] })
		return Inputs{
			Lockfiles: lockfiles,
			Record:    rec(t, map[string][]installedEntry{"base": {{id: "acme/dropped", version: "1.0.0", digestSeed: 20}}}),
			Targets:   []Target{claudeCodeTarget(skillsRoot)},
		}
	}

	first, err := Compute(build(1))
	require.NoError(t, err)
	for seed := uint64(2); seed < 12; seed++ {
		again, err := Compute(build(seed))
		require.NoError(t, err)
		require.Equal(t, idOrder(first.Add), idOrder(again.Add))
		require.Equal(t, removeLines(first.Remove), removeLines(again.Remove))
	}

	// Target, then package id, then profile slug, whatever the seed.
	require.Equal(t, []string{
		"claude-code acme/one 3.0.0",
		"claude-code acme/two 2.0.0",
		"claude-code beta/one 4.0.0",
		"claude-code zeta/one 1.0.0",
	}, idOrder(first.Add))
}

func idOrder(cs []Change) []string {
	out := make([]string, 0, len(cs))
	for i := range cs {
		out = append(out, fmt.Sprintf("%s %s %s", cs[i].Target, cs[i].ID, cs[i].Version))
	}
	return out
}

// TestAnUnwritableTargetWithNoOtherWritableTargetStillRefuses: a profile with
// no writable target must refuse rather than install nothing and exit 0.
func TestAnUnwritableTargetWithNoOtherWritableTargetStillRefuses(t *testing.T) {
	t.Parallel()

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{
			lf("base", []string{"codex"}, skill("acme/code-review", "2.4.1", 1)),
			lf("web", []string{"codex"}, skill("acme/code-review", "2.4.1", 1)),
		},
		Targets: []Target{claudeCodeTarget(skillsRoot), codexTarget(t)},
	})
	require.NoError(t, err)
	require.True(t, p.Refuses())
	require.Len(t, p.Conflicts, 2, "one no-writable-target conflict per profile")
	require.Equal(t, ConflictNoWritableTarget, p.Conflicts[0].Kind)
	require.Equal(t, ConflictNoWritableTarget, p.Conflicts[1].Kind)

	require.Zero(t, p.ChangeCount())
	require.False(t, p.IsNoOp())

	// A refused plan still reports what it would have skipped.
	require.Len(t, p.Skipped, 2)
	for _, sk := range p.Skipped {
		require.Equal(t, record.TargetCodex, sk.Target)
		require.Equal(t, SkipTargetUnwritable, sk.Reason)
	}
}

func TestAnUnwritableTargetIsSkippedWhenAnotherTargetCanStillWrite(t *testing.T) {
	t.Parallel()

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{
			lf("base", []string{"claude-code", "codex"}, skill("acme/code-review", "2.4.1", 1)),
		},
		Targets: []Target{claudeCodeTarget(skillsRoot), codexTarget(t)},
	})
	require.NoError(t, err)
	require.False(t, p.Refuses())
	require.Len(t, p.Add, 1)
	require.Equal(t, record.TargetClaudeCode, p.Add[0].Target, "claude-code still installs")

	require.Len(t, p.Skipped, 1)
	sk := p.Skipped[0]
	require.Equal(t, "base", sk.Profile)
	require.Equal(t, "acme/code-review", sk.ID)
	require.Equal(t, record.TargetCodex, sk.Target)
	require.Equal(t, SkipTargetUnwritable, sk.Reason)
	require.True(t, sk.Recognised)
	require.Contains(t, sk.Detail, layout.ErrR2Unresolved.Error())
}

func TestAnUnwritableTargetIsNotTheSameOutcomeAsADisabledOne(t *testing.T) {
	t.Parallel()

	installed := rec(t, map[string][]installedEntry{"base": {{
		id: "acme/code-review", version: "2.4.1", digestSeed: 1,
		target: record.TargetCodex, dest: home + "/.agents/skills/acme-code-review",
	}}})

	disabled, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1))},
		Record:    installed,
		Targets:   []Target{claudeCodeTarget(skillsRoot), codexTarget(t)},
	})
	require.NoError(t, err)
	require.False(t, disabled.Refuses(), "turning a target off is a normal outcome")
	require.Equal(t, []string{"codex acme/code-review base target-disabled disk=true"}, removeLines(disabled.Remove))

	stillEnabled, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code", "codex"}, skill("acme/code-review", "2.4.1", 1))},
		Record:    installed,
		Targets:   []Target{claudeCodeTarget(skillsRoot), codexTarget(t)},
	})
	require.NoError(t, err)
	require.False(t, stillEnabled.Refuses(), "a target this build cannot write must not refuse a profile whose other target still can")
	require.Empty(t, stillEnabled.Remove,
		"a target the profile still enables must not be reported as disabled, and nothing may be removed under a target this build cannot route")
	require.Len(t, stillEnabled.Skipped, 1, "the still-enabled but unwritable target is reported rather than silently dropped")
	require.Equal(t, record.TargetCodex, stillEnabled.Skipped[0].Target)
	require.Equal(t, SkipTargetUnwritable, stillEnabled.Skipped[0].Reason)
}

func TestAnUnsupportedEntryKindIsSkippedRatherThanBlockingItsSiblings(t *testing.T) {
	t.Parallel()

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{
			lf("base", []string{"claude-code"},
				skill("acme/one", "1.0.0", 1),
				skill("acme/two", "1.0.0", 2),
				plugin("acme/three", "1.0.0", 3),
			),
		},
		Targets: []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.False(t, p.Refuses(), "one unsupported entry kind must not refuse the plan")
	require.Empty(t, p.Conflicts)
	require.Equal(t, []string{"acme/one", "acme/two"}, idsOf(p.Add))

	require.Len(t, p.Skipped, 1)
	sk := p.Skipped[0]
	require.Equal(t, "base", sk.Profile)
	require.Equal(t, "acme/three", sk.ID)
	require.Equal(t, record.TargetClaudeCode, sk.Target)
	require.Equal(t, SkipEntryKindUnsupported, sk.Reason)
	require.True(t, sk.Recognised)
	require.Contains(t, sk.Detail, layout.ErrKindUnsupported.Error())
}

func idsOf(cs []Change) []string {
	out := make([]string, 0, len(cs))
	for i := range cs {
		out = append(out, cs[i].ID)
	}
	return out
}

func TestFR012NamesBothProfilesAndBothVersionsAndWhatIsInstalled(t *testing.T) {
	t.Parallel()

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{
			lf("web", []string{"claude-code"}, skill("acme/code-review", "2.3.0", 5)),
			lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1)),
		},
		Record: rec(t, map[string][]installedEntry{
			"base": {{id: "acme/code-review", version: "2.0.0", digestSeed: 7}},
		}),
		Targets: []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.Len(t, p.Conflicts, 1)

	c := p.Conflicts[0]
	require.Equal(t, ConflictVersionSplit, c.Kind)
	require.Equal(t, []Claim{
		{Profile: "base", Target: record.TargetClaudeCode, ID: "acme/code-review", Version: "2.4.1"},
		{Profile: "web", Target: record.TargetClaudeCode, ID: "acme/code-review", Version: "2.3.0"},
	}, c.Claims)
	require.Equal(t, []Claim{
		{Profile: "base", Target: record.TargetClaudeCode, ID: "acme/code-review", Version: "2.0.0"},
	}, c.Installed, "record.ByID supplies what the machine has now; it cannot decide the conflict")

	msg := c.String()
	for _, must := range []string{"base", "web", "2.4.1", "2.3.0", "acme/code-review"} {
		require.Contains(t, msg, must)
	}
}

// TestVersionSplitAgainstAProfileNotInThisRunStillRefuses: syncing profile B
// alone must still refuse a version split against profile A's recorded row.
func TestVersionSplitAgainstAProfileNotInThisRunStillRefuses(t *testing.T) {
	t.Parallel()

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{
			lf("example/platform-engineer", []string{"claude-code"}, skill("example/adr-writer", "3.0.2", 1)),
		},
		Record: rec(t, map[string][]installedEntry{
			"e2e/smoke": {{id: "example/adr-writer", version: "3.1.0", digestSeed: 9}},
		}),
		Targets: []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.Len(t, p.Conflicts, 1)
	require.True(t, p.Refuses(), "a version split must refuse the run, not install over the other profile")

	c := p.Conflicts[0]
	require.Equal(t, ConflictVersionSplit, c.Kind)
	require.Equal(t, []Claim{
		{Profile: "e2e/smoke", Target: record.TargetClaudeCode, ID: "example/adr-writer", Version: "3.1.0"},
		{Profile: "example/platform-engineer", Target: record.TargetClaudeCode, ID: "example/adr-writer", Version: "3.0.2"},
	}, c.Claims)

	msg := c.String()
	for _, must := range []string{"e2e/smoke", "example/platform-engineer", "3.1.0", "3.0.2"} {
		require.Contains(t, msg, must)
	}
}

func TestRemovalPathsAreTwoLiteralNamesAndNeverAPattern(t *testing.T) {
	t.Parallel()

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"})},
		Record: rec(t, map[string][]installedEntry{"base": {
			{id: "acme/code-review", version: "2.4.1", digestSeed: 1, fingerprint: true},
			{id: "acme/legacy-helper", version: "0.3.0", digestSeed: 4},
		}}),
		Targets: []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.Len(t, p.Remove, 2)

	for _, r := range p.Remove {
		require.Equal(t, []string{r.Dest, r.Dest + record.AsideSuffix}, r.Paths)
		for _, path := range r.Paths {
			require.NotContains(t, path, "*", "a glob is how you delete somebody's hand-written skill")
			require.True(t, strings.HasPrefix(path, skillsRoot+"/"))
		}
	}

	// No fingerprint means unverifiable, not unmodified; apply does the refusing.
	byID := map[string]Removal{}
	for _, r := range p.Remove {
		byID[r.ID] = r
	}
	require.True(t, byID["acme/code-review"].Fingerprinted)
	require.False(t, byID["acme/legacy-helper"].Fingerprinted)
}

func TestASharedDirectoryIsNotRemovedWhileAnotherProfileStillWantsIt(t *testing.T) {
	t.Parallel()

	t.Run("the surviving claim comes from the record", func(t *testing.T) {
		t.Parallel()
		p, err := Compute(Inputs{
			// `other` is not being synced, so its record row stands.
			Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"})},
			Record: rec(t, map[string][]installedEntry{
				"base":  {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}},
				"other": {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}},
			}),
			Targets: []Target{claudeCodeTarget(skillsRoot)},
		})
		require.NoError(t, err)
		require.Len(t, p.Remove, 1)
		require.False(t, p.Remove[0].RemovesFromDisk())
		require.Equal(t, []Claim{{
			Profile: "other", Target: record.TargetClaudeCode, ID: "acme/code-review", Version: "2.4.1",
		}}, p.Remove[0].RetainedBy)
	})

	t.Run("both claimants dropping it does remove it", func(t *testing.T) {
		t.Parallel()
		p, err := Compute(Inputs{
			Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}), lf("other", []string{"claude-code"})},
			Record: rec(t, map[string][]installedEntry{
				"base":  {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}},
				"other": {{id: "acme/code-review", version: "2.4.1", digestSeed: 1}},
			}),
			Targets: []Target{claudeCodeTarget(skillsRoot)},
		})
		require.NoError(t, err)
		require.Len(t, p.Remove, 2)
		for _, r := range p.Remove {
			require.True(t, r.RemovesFromDisk(), "no claim survives, so the directory goes")
		}
	})
}

func TestTheSecondRunOfAnUnchangedProfilePlansNothing(t *testing.T) {
	t.Parallel()

	lockfiles := []*hub.Lockfile{lf("base", []string{"claude-code"},
		skill("acme/code-review", "2.4.1", 1),
		skill("acme/lint-guard", "1.0.0", 2),
	)}
	p, err := Compute(Inputs{
		Lockfiles: lockfiles,
		Record: rec(t, map[string][]installedEntry{"base": {
			{id: "acme/code-review", version: "2.4.1", digestSeed: 1},
			{id: "acme/lint-guard", version: "1.0.0", digestSeed: 2},
		}}),
		Targets: []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.Zero(t, p.ChangeCount(), "nothing to write means nothing is written")
	require.True(t, p.IsNoOp())
	require.Len(t, p.Unchanged, 2, "and every entry is accounted for, rather than merely absent")
}

func TestMalformedInputsAreACallerBugAndNotAConflict(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   Inputs
		msg  string
	}{
		{
			name: "a nil lockfile",
			in:   Inputs{Lockfiles: []*hub.Lockfile{nil}},
			msg:  "a nil lockfile",
		},
		{
			name: "one profile given twice",
			in: Inputs{Lockfiles: []*hub.Lockfile{
				lf("base", []string{"claude-code"}), lf("base", []string{"claude-code"}),
			}},
			msg: "profile base given twice",
		},
		{
			name: "a target with no name",
			in:   Inputs{Targets: []Target{{Dest: func(string, record.Kind) (string, error) { return "/x", nil }}}},
			msg:  "a target has no name",
		},
		{
			name: "a target with neither a resolver nor an error",
			in:   Inputs{Targets: []Target{{Name: record.TargetClaudeCode}}},
			msg:  "neither a destination resolver nor an error",
		},
		{
			name: "the same target twice",
			in: Inputs{Targets: []Target{
				claudeCodeTarget(skillsRoot), claudeCodeTarget(skillsRoot),
			}},
			msg: "target claude-code given twice",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Compute(tc.in)
			require.ErrorIs(t, err, ErrInputs)
			require.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestAMalformedDigestIsRefusedRatherThanCarriedAsAString(t *testing.T) {
	t.Parallel()

	e := skill("acme/code-review", "2.4.1", 1)
	e.Digest = "sha-256=AAAA"

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, e)},
		Targets:   []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"unroutable-entry acme/code-review claude-code"}, conflictLines(p.Conflicts))
	require.Empty(t, p.Add)
}

func TestTheSignatureIsNeverPresentedAsAPass(t *testing.T) {
	t.Parallel()

	ref := "sigstore:acme/code-review@2.4.1"
	no := false
	e := skill("acme/code-review", "2.4.1", 1)
	e.Signature = &hub.LockfileSignature{Ref: &ref, Verified: &no}

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, e)},
		Targets:   []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.Len(t, p.Add, 1)
	require.NotNil(t, p.Add[0].Signature)
	require.Equal(t, ref, p.Add[0].Signature.Ref)
	require.False(t, p.Add[0].Signature.Verified,
		"false until Sigstore verification ships, and a false value is not a pass")
}

func TestComputeTouchesNothingItWasNotGiven(t *testing.T) {
	t.Parallel()

	// Same inputs give the same plan, and the inputs are not mutated.
	l := lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1))
	r := rec(t, map[string][]installedEntry{"base": {{id: "acme/code-review", version: "2.3.0", digestSeed: 5}}})

	before := fmt.Sprintf("%+v|%+v", *l, *r)
	p1, err := Compute(Inputs{Lockfiles: []*hub.Lockfile{l}, Record: r, Targets: []Target{claudeCodeTarget(skillsRoot)}})
	require.NoError(t, err)
	p2, err := Compute(Inputs{Lockfiles: []*hub.Lockfile{l}, Record: r, Targets: []Target{claudeCodeTarget(skillsRoot)}})
	require.NoError(t, err)

	require.Equal(t, before, fmt.Sprintf("%+v|%+v", *l, *r), "Compute must not mutate its inputs")
	require.Equal(t, changeLines(p1.Upgrade), changeLines(p2.Upgrade))
	require.Equal(t, p1.Add[:0:0], p2.Add[:0:0])
}

func TestConflictErrorIsNilWhenThereIsNothingToRefuse(t *testing.T) {
	t.Parallel()

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/code-review", "2.4.1", 1))},
		Targets:   []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.NoError(t, p.ConflictError())
	require.False(t, p.Refuses())

	missing := errors.New("sentinel")
	require.NotErrorIs(t, p.ConflictError(), missing)
}

// TestCaseFoldedDestinationsAreRefusedAgainstTheRealLayout: ids differing only
// by namespace case are one directory on APFS. The Place calls are asserted to
// succeed first, or a layout refusal would make this vacuous.
func TestCaseFoldedDestinationsAreRefusedAgainstTheRealLayout(t *testing.T) {
	t.Parallel()

	reg, err := layout.NewRegistry(layout.Config{HomeDir: home})
	require.NoError(t, err)
	cc, err := reg.Resolve(record.TargetClaudeCode)
	require.NoError(t, err)

	upper, err := cc.Place(layout.Request{ID: "Acme/x", Kind: record.KindSkill})
	require.NoError(t, err, "layout accepts an uppercase namespace; that is the premise of this test")
	lower, err := cc.Place(layout.Request{ID: "acme/x", Kind: record.KindSkill})
	require.NoError(t, err)
	require.NotEqual(t, upper.Dest, lower.Dest, "the two paths differ as strings")
	require.Equal(t, strings.ToLower(upper.Dest), strings.ToLower(lower.Dest),
		"and are the same directory once the filesystem folds them")

	target := Target{Name: record.TargetClaudeCode, Dest: func(id string, kind record.Kind) (string, error) {
		p, perr := cc.Place(layout.Request{ID: id, Kind: kind})
		if perr != nil {
			return "", perr
		}
		return p.Dest, nil
	}}

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"},
			skill("Acme/x", "1.0.0", 1), skill("acme/x", "1.0.0", 2))},
		Targets: []Target{target},
	})
	require.NoError(t, err)
	require.True(t, p.Refuses(), "the plan must refuse rather than install both")
	require.Len(t, p.Conflicts, 1)
	require.Equal(t, ConflictDestCollision, p.Conflicts[0].Kind)
	require.ElementsMatch(t, []string{"Acme/x", "acme/x"}, distinctIDs(p.Conflicts[0].Claims))
}

// TestARemovalIsRetainedAgainstACaseFoldedInstall: a recorded removal and a
// desired install differing only by case are one directory on APFS, which
// destCollisions cannot see.
func TestARemovalIsRetainedAgainstACaseFoldedInstall(t *testing.T) {
	t.Parallel()

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{
			// `dropped` no longer lists Acme/x, so its recorded row is removed.
			lf("dropped", []string{"claude-code"}),
			// `keeps` installs acme/x, which folds onto the same directory.
			lf("keeps", []string{"claude-code"}, skill("acme/x", "1.0.0", 2)),
		},
		Record: rec(t, map[string][]installedEntry{"dropped": {{
			id: "Acme/x", version: "1.0.0", digestSeed: 1, dest: skillsRoot + "/Acme-x",
		}}}),
		Targets: []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.False(t, p.Refuses())

	require.Len(t, p.Remove, 1)
	rm := p.Remove[0]
	require.Equal(t, skillsRoot+"/Acme-x", rm.Dest)
	require.NotEmpty(t, rm.RetainedBy,
		"the record row goes, but the directory is another entry's live install and must not be unlinked")
	require.Equal(t, "acme/x", rm.RetainedBy[0].ID)
}

func openCodeTarget(root string, servedBy ...record.Target) Target {
	return Target{
		Name:     record.TargetOpenCode,
		ServedBy: servedBy,
		Dest: func(id string, _ record.Kind) (string, error) {
			ns, name, _ := strings.Cut(id, "/")
			return filepath.Join(root, ns+"--"+name), nil
		},
	}
}

func TestASkillOpenCodeAlreadyLoadsFromAnotherTargetIsNotPlacedTwice(t *testing.T) {
	t.Parallel()
	targets := []Target{claudeCodeTarget(skillsRoot), openCodeTarget(home+"/.config/opencode/skills", record.TargetClaudeCode)}

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code", "opencode"},
			skill("acme/review", "1.0.0", 1), plugin("acme/kit", "1.0.0", 2))},
		Targets: targets,
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"claude-code acme/review base add none->1.0.0 dir=-",
		"opencode acme/kit base add none->1.0.0 dir=-",
	}, changeLines(p.Add), "a plugin decides per component, so it is still planned for opencode")
	var served []Skip
	for _, sk := range p.Skipped {
		if sk.Reason == SkipServedBySharedRoot {
			served = append(served, sk)
		}
	}
	require.Len(t, served, 1)
	require.Equal(t, "acme/review", served[0].ID)
	require.Equal(t, record.TargetOpenCode, served[0].Target)
	require.Contains(t, served[0].Detail, "claude-code")

	alone, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"opencode"}, skill("acme/review", "1.0.0", 1))},
		Targets:   targets,
	})
	require.NoError(t, err)
	require.Len(t, alone.Add, 1, "without the serving target in the profile, opencode gets its own copy")
	require.Empty(t, alone.Skipped)
}

func TestAPartiallyDeliveredEntryIsReplayedAtTheSameVersion(t *testing.T) {
	t.Parallel()
	r := rec(t, map[string][]installedEntry{"base": {{id: "acme/review", version: "1.0.0", digestSeed: 1, fingerprint: true}}})
	r.Profiles[0].Entries[0].Partial = true

	p, err := Compute(Inputs{
		Lockfiles: []*hub.Lockfile{lf("base", []string{"claude-code"}, skill("acme/review", "1.0.0", 1))},
		Record:    r,
		Targets:   []Target{claudeCodeTarget(skillsRoot)},
	})
	require.NoError(t, err)
	require.Empty(t, p.Unchanged)
	require.Len(t, p.Upgrade, 1)
	require.Equal(t, OpReplace, p.Upgrade[0].Op)
}
