// T042's tests. What is asserted here is the ORDER and the REFUSALS, because
// those are the two things a reader cannot recover from apply.go by inspection:
// that the record is written after the swap and per entry, that a run killed in
// the window between them converges, and that every destination amctl did not
// write is refused rather than replaced.
//
// Staging and swapping themselves are stage_test.go's and swap_test.go's; this
// file only asserts that they are called in the right order with the right
// arguments.

package apply

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/cache"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

const (
	applyHub     = "https://hub.apply.example"
	applyProfile = "platform"
)

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

type applyLog struct {
	warns  []string
	debugs []string
}

func (l *applyLog) Warnf(format string, args ...any) {
	l.warns = append(l.warns, fmt.Sprintf(format, args...))
}

func (l *applyLog) Debugf(format string, args ...any) {
	l.debugs = append(l.debugs, fmt.Sprintf(format, args...))
}

func (l *applyLog) warnedAbout(t *testing.T, substr string) bool {
	t.Helper()
	for _, w := range l.warns {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// applyBundles is a BundleSource over a table keyed by `id@version`, plus an
// optional hook that runs before each hand-over so a test can observe the
// state of the tree at that moment.
type applyBundles struct {
	byRef  map[string][]byte
	before func(c plan.Change)
	fail   map[string]error
}

func (b *applyBundles) Bundle(_ context.Context, c plan.Change) ([]byte, error) {
	if b.before != nil {
		b.before(c)
	}
	key := c.ID + "@" + c.Version
	if err := b.fail[key]; err != nil {
		return nil, err
	}
	bundle, ok := b.byRef[key]
	if !ok {
		return nil, fmt.Errorf("no bundle fixture for %s", key)
	}
	return bundle, nil
}

type applyFixture struct {
	home    string
	skills  string
	recPath string
	rec     *record.Record
	log     *applyLog
	bundles *applyBundles
	now     time.Time
}

func newApplyFixture(t *testing.T) *applyFixture {
	t.Helper()
	home := t.TempDir()
	return &applyFixture{
		home:    home,
		skills:  filepath.Join(home, ".claude", "skills"),
		recPath: filepath.Join(home, ".agent-manager", "hub", record.FileName),
		rec:     record.New(applyHub),
		log:     &applyLog{},
		bundles: &applyBundles{byRef: map[string][]byte{}, fail: map[string]error{}},
		now:     time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
	}
}

func (f *applyFixture) dest(dirName string) string { return filepath.Join(f.skills, dirName) }

// add registers a bundle for id@version and returns the change that installs it.
func (f *applyFixture) add(t *testing.T, id, version string, bundle []byte) plan.Change {
	t.Helper()
	d, err := record.ParseDigest(cache.Compute(bundle).Lockfile())
	require.NoError(t, err)
	f.bundles.byRef[id+"@"+version] = bundle

	pkg, err := layout.ParsePackageID(id)
	require.NoError(t, err)
	return plan.Change{
		Op:      plan.OpAdd,
		Profile: applyProfile,
		Target:  record.TargetClaudeCode,
		ID:      id,
		Kind:    record.KindSkill,
		Dest:    f.dest(pkg.DirName()),
		Version: version,
		Digest:  d,
	}
}

func (f *applyFixture) applier(t *testing.T, mutate ...func(*Config)) *Applier {
	t.Helper()
	home, err := OpenHome(f.home)
	require.NoError(t, err)
	t.Cleanup(func() {})

	cfg := Config{
		Home:       home,
		Record:     f.rec,
		RecordPath: f.recPath,
		Profiles:   []ProfileState{{Slug: applyProfile, Revision: 7, Targets: []record.Target{record.TargetClaudeCode}}},
		Bundles:    f.bundles,
		Log:        f.log,
		Now:        func() time.Time { return f.now },
	}
	for _, m := range mutate {
		m(&cfg)
	}
	a, err := New(cfg)
	require.NoError(t, err)
	return a
}

func planOf(changes ...plan.Change) plan.Plan {
	p := plan.Plan{}
	for i := range changes {
		c := changes[i]
		switch c.Op {
		case plan.OpAdd:
			p.Add = append(p.Add, c)
		case plan.OpDowngrade:
			p.Downgrade = append(p.Downgrade, c)
		case plan.OpUnchanged:
			p.Unchanged = append(p.Unchanged, c)
		default:
			p.Upgrade = append(p.Upgrade, c)
		}
	}
	return p
}

// loadedRecord is the record as it exists ON DISK, which is the only copy that
// matters for a crash: the in-memory one dies with the process.
func loadedRecord(t *testing.T, f *applyFixture) *record.Record {
	t.Helper()
	rec, err := record.Load(f.recPath, applyHub)
	require.NoError(t, err)
	return rec
}

// ---------------------------------------------------------------------------
// the happy path, and what it must leave on disk
// ---------------------------------------------------------------------------

func TestApplyInstallsAnEntryAndRecordsIt(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))

	res, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)
	require.Len(t, res.Installed, 1)
	require.Empty(t, res.Failed)

	body, err := os.ReadFile(filepath.Join(c.Dest, "SKILL.md"))
	require.NoError(t, err)
	require.Equal(t, "---\nname: lint-go\n---\nthe body\n", string(body))

	rec := loadedRecord(t, f)
	prof, ok := rec.ProfileBySlug(applyProfile)
	require.True(t, ok)
	require.Equal(t, 7, prof.Revision, "the resolved revision is recorded, never `head` (FR-013)")
	require.Equal(t, []record.Target{record.TargetClaudeCode}, prof.Targets)
	require.Len(t, prof.Entries, 1)
	require.Equal(t, c.Dest, prof.Entries[0].Dest)
	require.Equal(t, "1.4.0", prof.Entries[0].Version)
	require.Equal(t, c.Digest, prof.Entries[0].Digest)
}

// TestApplyWritesTheProvenanceMarkerBesideTheEntryFile is FR-022: the directory
// says which package and version it holds with no hub and no network.
func TestApplyWritesTheProvenanceMarkerBesideTheEntryFile(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	b, err := os.ReadFile(filepath.Join(c.Dest, layout.MarkerFileName))
	require.NoError(t, err)
	m, err := layout.ParseMarker(b)
	require.NoError(t, err)
	require.Equal(t, layout.Marker{
		SchemaVersion: layout.MarkerSchemaVersion,
		ID:            "acme/lint-go",
		Version:       "1.4.0",
		Kind:          record.KindSkill,
		Target:        record.TargetClaudeCode,
		Digest:        c.Digest,
	}, m)

	skill, err := os.ReadFile(filepath.Join(c.Dest, "SKILL.md"))
	require.NoError(t, err)
	require.NotContains(t, string(skill), "agent-manager",
		"SKILL.md is never stamped: it would rewrite bytes verified by digest and break R4's fingerprint")
}

// TestApplyLeavesNoStagingDirectoryBehind — the staging root is shared between
// entries under one parent, so it is pruned once at the end and only when empty.
func TestApplyLeavesNoStagingDirectoryBehind(t *testing.T) {
	f := newApplyFixture(t)
	one := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	two := f.add(t, "other/lint-go", "2.0.0", skillBundle(t))

	_, err := f.applier(t).Apply(context.Background(), planOf(one, two))
	require.NoError(t, err)
	require.NoDirExists(t, layout.StagingRoot(one.Dest))
	require.DirExists(t, one.Dest)
	require.DirExists(t, two.Dest)
	require.NotEqual(t, one.Dest, two.Dest,
		"two publishers sharing a package name install to distinct directories (FR-023)")
}

// ---------------------------------------------------------------------------
// the order: swap, then record, per entry
// ---------------------------------------------------------------------------

// orderProbe is a Fingerprinter whose Modes call happens exactly in the window
// between the swap and the record write, which is where the ordering is
// observable at all.
type orderProbe struct {
	t       *testing.T
	f       *applyFixture
	seen    []string
	hashErr error
}

func (p *orderProbe) Hash(staged *Staged) (record.Fingerprint, error) {
	if p.hashErr != nil {
		return record.Fingerprint{}, p.hashErr
	}
	files := map[string]record.FileMark{}
	for _, name := range staged.Files {
		files[name] = record.FileMark{
			SHA256: strings.Repeat("a", 64), Size: 1, Mode: 0o644, Kind: record.FileKindRegular,
		}
	}
	// The staged tree is still staged and the destination is untouched.
	require.DirExists(p.t, staged.Path, "content is hashed from the staged tree, before the swap")
	return record.Fingerprint{Algo: record.FingerprintAlgo, Files: files}, nil
}

func (p *orderProbe) Modes(dest string, fp record.Fingerprint) (record.Fingerprint, error) {
	p.seen = append(p.seen, dest)
	require.DirExists(p.t, dest, "Modes runs after the swap: the entry is already installed")

	onDisk, err := record.Load(p.f.recPath, applyHub)
	require.NoError(p.t, err)
	refs := onDisk.Refs()
	for i := range refs {
		require.NotEqual(p.t, dest, refs[i].Entry.Dest,
			"the record must not yet mention %s: a record written before the swap describes a tree that does not exist", dest)
	}
	return fp, nil
}

func TestApplyWritesTheRecordAfterTheSwapAndPerEntry(t *testing.T) {
	f := newApplyFixture(t)
	one := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	two := f.add(t, "beta/fmt-go", "0.9.1", skillBundle(t))

	probe := &orderProbe{t: t, f: f}
	// The second entry's fetch asserts the FIRST entry is already recorded,
	// which is what makes the per-entry claim different from a single write at
	// the end.
	f.bundles.before = func(c plan.Change) {
		if c.ID != two.ID {
			return
		}
		onDisk, err := record.Load(f.recPath, applyHub)
		require.NoError(t, err)
		require.Len(t, onDisk.ByID(one.ID), 1,
			"entry one must be recorded before entry two is staged, or a crash here loses it")
	}

	res, err := f.applier(t, func(c *Config) { c.Fingerprints = probe }).Apply(context.Background(), planOf(one, two))
	require.NoError(t, err)
	require.Len(t, res.Installed, 2)
	require.ElementsMatch(t, []string{one.Dest, two.Dest}, probe.seen)
	require.Equal(t, 2, res.RecordWrites, "one record write per entry, and none wasted at the end")
}

// TestApplyFailsTheEntryWhenItsFingerprintCannotBeTaken — a fingerprint taken
// before the swap is the only chance to have one, so failing to take it fails
// the entry rather than installing something FR-029 can never protect.
func TestApplyFailsTheEntryWhenItsFingerprintCannotBeTaken(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	boom := errors.New("cannot read the staged tree")

	res, err := f.applier(t, func(cfg *Config) {
		cfg.Fingerprints = &orderProbe{t: t, f: f, hashErr: boom}
	}).Apply(context.Background(), planOf(c))

	require.Error(t, err)
	require.ErrorIs(t, err, boom)
	require.Empty(t, res.Installed)
	require.NoDirExists(t, c.Dest, "nothing reaches the destination when staging fails")
	require.NoDirExists(t, layout.StagingRoot(c.Dest), "the staged tree is discarded")
	require.NoFileExists(t, f.recPath, "no record is written for an entry that did not land")
}

// ---------------------------------------------------------------------------
// convergence after a crash between the swap and the record write (T046's case)
// ---------------------------------------------------------------------------

func TestApplyAdoptsItsOwnLeftoverFromAnInterruptedRun(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	// Simulate the process dying between the swap and the record write: the
	// tree is there, the record row is not.
	require.NoError(t, os.RemoveAll(filepath.Dir(f.recPath)))
	f.rec = record.New(applyHub)

	res, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err, "the re-run must converge, not refuse its own leftover")
	require.Len(t, res.Installed, 1)
	require.True(t, f.log.warnedAbout(t, "interrupted between the install and the record write"))
	require.Len(t, loadedRecord(t, f).ByID(c.ID), 1, "the record row is restored")
}

// TestApplyRefusesAnUnrecordedDestinationWithoutAMarker is the negative control
// for the test above: with the marker gone, the same directory is somebody
// else's work and is refused. It is what proves the adoption above is doing its
// job through the marker and not through "the directory happens to be there".
func TestApplyRefusesAnUnrecordedDestinationWithoutAMarker(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(filepath.Dir(f.recPath)))
	f.rec = record.New(applyHub)
	require.NoError(t, os.Remove(filepath.Join(c.Dest, layout.MarkerFileName)))
	handwritten := filepath.Join(c.Dest, "SKILL.md")
	require.NoError(t, os.WriteFile(handwritten, []byte("mine, not amctl's\n"), 0o644))

	res, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnrecorded)
	require.Empty(t, res.Installed)
	require.Len(t, res.Refusals(), 1)
	require.Empty(t, res.Failures(), "an unrecorded destination is a refusal the user can fix, not a crash")

	body, err := os.ReadFile(handwritten)
	require.NoError(t, err)
	require.Equal(t, "mine, not amctl's\n", string(body), "FR-028: the file amctl did not write survives byte-identical")
}

func TestApplyRefusesAMarkerForADifferentPackage(t *testing.T) {
	f := newApplyFixture(t)
	mine := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(mine))
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(filepath.Dir(f.recPath)))
	f.rec = record.New(applyHub)

	// A change for a DIFFERENT id whose destination happens to be the same
	// directory. The marker names acme/lint-go, so it is not this entry's
	// leftover and the overwrite is refused.
	other := mine
	other.ID = "beta/fmt-go"
	f.bundles.byRef[other.ID+"@"+other.Version] = f.bundles.byRef[mine.ID+"@"+mine.Version]

	_, err = f.applier(t).Apply(context.Background(), planOf(other))
	require.ErrorIs(t, err, ErrUnrecorded)
}

// ---------------------------------------------------------------------------
// the three refusals, and --force naming what it destroys
// ---------------------------------------------------------------------------

func TestApplyRefusesASymlinkAtTheDestination(t *testing.T) {
	if err := os.Symlink("target", filepath.Join(t.TempDir(), "probe")); err != nil {
		t.Skipf("unprivileged symlinks unavailable on %s: %v", os.Getenv("GOOS"), err)
	}
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))

	elsewhere := filepath.Join(f.home, "elsewhere")
	require.NoError(t, os.MkdirAll(elsewhere, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(elsewhere, "SKILL.md"), []byte("not amctl's\n"), 0o644))
	require.NoError(t, os.MkdirAll(f.skills, 0o755))
	require.NoError(t, os.Symlink(elsewhere, c.Dest))

	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.ErrorIs(t, err, ErrUnrecorded)
	require.Contains(t, err.Error(), "is a symlink")

	link, err := os.Readlink(c.Dest)
	require.NoError(t, err)
	require.Equal(t, elsewhere, link, "the link is untouched by a refusal")

	// --force replaces the LINK and leaves what it pointed at alone: writing
	// through it is how amctl would write outside the home without ever
	// constructing a path outside it.
	res, err := f.applier(t, func(cfg *Config) { cfg.Force = true }).Apply(context.Background(), planOf(c))
	require.NoError(t, err)
	require.Len(t, res.Installed, 1)
	require.True(t, f.log.warnedAbout(t, "--force is replacing the symlink"),
		"--force must name the link it destroys")

	info, err := os.Lstat(c.Dest)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Zero(t, info.Mode()&fs.ModeSymlink)
	body, err := os.ReadFile(filepath.Join(elsewhere, "SKILL.md"))
	require.NoError(t, err)
	require.Equal(t, "not amctl's\n", string(body), "nothing was written through the link")
}

// stubVerifier is T049's seam, stubbed.
type stubVerifier struct {
	changed []string
	err     error
	asked   []string
}

func (v *stubVerifier) Modifications(e record.Entry) ([]string, error) {
	v.asked = append(v.asked, e.Dest)
	return v.changed, v.err
}

func TestApplyRefusesToOverwriteAnEntryItCannotVerify(t *testing.T) {
	base := skillBundle(t)
	next := packBundle(t, file("SKILL.md", "---\nname: lint-go\n---\nversion two\n"))

	cases := []struct {
		name          string
		fingerprinted bool
		verifier      *stubVerifier
		wantErr       error
		wantNamed     string
	}{
		{
			name:          "an entry recorded before install fingerprints existed is unverifiable",
			fingerprinted: false,
			wantErr:       ErrUnverifiable,
			wantNamed:     "could not be verified",
		},
		{
			name:          "a fingerprint this build has no verifier for is unverifiable",
			fingerprinted: true,
			wantErr:       ErrUnverifiable,
			wantNamed:     "without verifying it",
		},
		{
			name:          "a verifier that cannot answer is unverifiable, never unmodified",
			fingerprinted: true,
			verifier:      &stubVerifier{err: errors.New("the record's algorithm is not this build's")},
			wantErr:       ErrUnverifiable,
			wantNamed:     "could not be verified",
		},
		{
			name:          "a modified entry is preserved and reported per file",
			fingerprinted: true,
			verifier:      &stubVerifier{changed: []string{"SKILL.md", "references/style.md"}},
			wantErr:       ErrModified,
			wantNamed:     "destroying 2 modified path(s)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplyFixture(t)
			c := f.add(t, "acme/lint-go", "1.4.0", base)
			_, err := f.applier(t).Apply(context.Background(), planOf(c))
			require.NoError(t, err)

			upgrade := f.add(t, "acme/lint-go", "1.5.0", next)
			upgrade.Op = plan.OpUpgrade
			upgrade.From = &plan.Installed{Version: "1.4.0", Digest: c.Digest, Fingerprinted: tc.fingerprinted}

			opts := func(cfg *Config) {
				if tc.verifier != nil {
					cfg.Verifier = tc.verifier
				}
			}
			_, err = f.applier(t, opts).Apply(context.Background(), planOf(upgrade))
			require.ErrorIs(t, err, tc.wantErr)
			require.Contains(t, err.Error(), "--force")

			body, rerr := os.ReadFile(filepath.Join(c.Dest, "SKILL.md"))
			require.NoError(t, rerr)
			require.Equal(t, "---\nname: lint-go\n---\nthe body\n", string(body),
				"the installed version is preserved by a refusal")

			forced := func(cfg *Config) {
				opts(cfg)
				cfg.Force = true
			}
			res, ferr := f.applier(t, forced).Apply(context.Background(), planOf(upgrade))
			require.NoError(t, ferr)
			require.Len(t, res.Installed, 1)
			require.True(t, f.log.warnedAbout(t, tc.wantNamed),
				"--force must name what it destroys; warnings were %q", f.log.warns)

			body, rerr = os.ReadFile(filepath.Join(c.Dest, "SKILL.md"))
			require.NoError(t, rerr)
			require.Equal(t, "---\nname: lint-go\n---\nversion two\n", string(body))
		})
	}
}

func TestApplyUpgradesAnEntryAVerifierReportsUnmodified(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	next := packBundle(t, file("SKILL.md", "---\nname: lint-go\n---\nversion two\n"))
	upgrade := f.add(t, "acme/lint-go", "1.5.0", next)
	upgrade.Op = plan.OpUpgrade
	upgrade.From = &plan.Installed{Version: "1.4.0", Digest: c.Digest, Fingerprinted: true}

	v := &stubVerifier{}
	res, err := f.applier(t, func(cfg *Config) { cfg.Verifier = v }).Apply(context.Background(), planOf(upgrade))
	require.NoError(t, err)
	require.Len(t, res.Installed, 1)
	require.Equal(t, []string{c.Dest}, v.asked, "the verifier is asked about the installed entry, by its recorded destination")
	require.NoDirExists(t, c.Dest+AsideSuffix, "the aside is gone after a clean swap")

	rec := loadedRecord(t, f)
	require.Len(t, rec.ByID(c.ID), 1, "an upgrade replaces the row rather than adding a second one")
	require.Equal(t, "1.5.0", rec.ByID(c.ID)[0].Entry.Version)
}

func TestApplyReinstallsWhenTheRecordClaimsAnEntryThatIsGone(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)
	require.NoError(t, os.RemoveAll(c.Dest))

	same := c
	same.Op = plan.OpUpgrade
	same.From = &plan.Installed{Version: "1.4.0", Digest: c.Digest, Fingerprinted: true}

	// No verifier is wired, and it does not matter: nothing is at the
	// destination, so there is nothing to destroy and nothing to verify.
	res, err := f.applier(t).Apply(context.Background(), planOf(same))
	require.NoError(t, err)
	require.Len(t, res.Installed, 1)
	require.True(t, f.log.warnedAbout(t, "but nothing is there; re-installing"))
	require.DirExists(t, c.Dest)
}

// ---------------------------------------------------------------------------
// the run-wide refusals
// ---------------------------------------------------------------------------

// TestApplyRefusesAPlanWithConflictsBeforeStagingAByte covers FR-012, FR-023
// and R2's unwritable target together, because all three arrive as a
// plan.Conflict and the requirement is the same for each: refuse BEFORE writing.
func TestApplyRefusesAPlanWithConflictsBeforeStagingAByte(t *testing.T) {
	r2 := fmt.Errorf("codex: %w", layout.ErrR2Unresolved)
	cases := []struct {
		name string
		conf plan.Conflict
		want error
	}{
		{
			name: "two profiles resolving one package to two versions",
			conf: plan.Conflict{
				Kind:   plan.ConflictVersionSplit,
				ID:     "acme/lint-go",
				Target: record.TargetClaudeCode,
				Claims: []plan.Claim{
					{Profile: "a", Target: record.TargetClaudeCode, ID: "acme/lint-go", Version: "1.4.0"},
					{Profile: "b", Target: record.TargetClaudeCode, ID: "acme/lint-go", Version: "2.0.0"},
				},
			},
		},
		{
			name: "a target this build cannot write",
			conf: plan.Conflict{Kind: plan.ConflictTargetUnwritable, Target: record.TargetCodex, Err: r2},
			want: layout.ErrR2Unresolved,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplyFixture(t)
			c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
			p := planOf(c)
			p.Conflicts = []plan.Conflict{tc.conf}

			res, err := f.applier(t).Apply(context.Background(), p)
			require.Error(t, err)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want,
					"a lockfile naming an unwritable target must surface the gate's error, not skip silently")
			}
			require.Empty(t, res.Installed)
			require.NoDirExists(t, f.skills, "not one directory is created when the plan refuses")
			require.NoFileExists(t, f.recPath)
		})
	}
}

func TestApplyRefusesAPlanForAProfileItWasNotToldAbout(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	c.Profile = "unknown"

	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.ErrorIs(t, err, ErrConfig)
	require.NoDirExists(t, f.skills)
}

func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	home, err := OpenHome(t.TempDir())
	require.NoError(t, err)
	full := Config{Home: home, Record: record.New(applyHub), RecordPath: "/tmp/x", Bundles: &applyBundles{}}

	cases := map[string]func(*Config){
		"no home":        func(c *Config) { c.Home = nil },
		"no record":      func(c *Config) { c.Record = nil },
		"no record path": func(c *Config) { c.RecordPath = "" },
		"no bundles":     func(c *Config) { c.Bundles = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := full
			mutate(&cfg)
			_, nerr := New(cfg)
			require.ErrorIs(t, nerr, ErrConfig)
		})
	}
	_, err = New(full)
	require.NoError(t, err)
}

func TestApplyRefusesAnUnresolvedRevision(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	a := f.applier(t, func(cfg *Config) {
		cfg.Profiles = []ProfileState{{Slug: applyProfile, Revision: 0}}
	})
	_, err := a.Apply(context.Background(), planOf(c))
	require.ErrorIs(t, err, ErrConfig)
	require.Contains(t, err.Error(), "head")
}

// ---------------------------------------------------------------------------
// partial syncs, removals, idempotence
// ---------------------------------------------------------------------------

// TestApplyReportsWhichEntriesLandedWhenOneFails is plan.md's Risks
// requirement: a sync that fails at one entry says which others landed and
// still exits non-zero.
func TestApplyReportsWhichEntriesLandedWhenOneFails(t *testing.T) {
	f := newApplyFixture(t)
	one := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	two := f.add(t, "beta/fmt-go", "0.9.1", skillBundle(t))
	three := f.add(t, "gamma/vet-go", "3.1.0", skillBundle(t))

	boom := errors.New("the hub served 500")
	f.bundles.fail[two.ID+"@"+two.Version] = boom

	res, err := f.applier(t).Apply(context.Background(), planOf(one, two, three))
	require.Error(t, err)
	require.ErrorIs(t, err, boom)

	landed := make([]string, 0, len(res.Installed))
	for _, i := range res.Installed {
		landed = append(landed, i.Change.ID)
	}
	sort.Strings(landed)
	require.Equal(t, []string{"acme/lint-go", "gamma/vet-go"}, landed,
		"a failure at one entry must not abandon the entries after it")
	require.Len(t, res.Failed, 1)
	require.Equal(t, two.ID, res.Failed[0].Change.ID)
	require.False(t, res.Failed[0].Refusal, "a hub failure is not a refusal the user can fix")
	require.NoDirExists(t, two.Dest)
	require.Len(t, loadedRecord(t, f).Refs(), 2, "the record claims exactly what is on disk")
}

// TestApplyRefusesToReportARemovalItCannotPerform — the whole point of the
// Pruner seam. A build with no pruner must not exit 0 having removed nothing.
func TestApplyRefusesToReportARemovalItCannotPerform(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	p := plan.Plan{Remove: []plan.Removal{{
		Profile: applyProfile, Target: record.TargetClaudeCode, ID: c.ID, Kind: record.KindSkill,
		Version: c.Version, Dest: c.Dest, Reason: plan.RemoveLeftProfile,
		Paths: []string{c.Dest, c.Dest + AsideSuffix},
	}}}

	res, err := f.applier(t).Apply(context.Background(), p)
	require.ErrorIs(t, err, ErrPruneUnavailable)
	require.Len(t, res.Failed, 1)
	require.DirExists(t, c.Dest, "the entry is still installed, which is exactly what the error says")
	require.Len(t, loadedRecord(t, f).Refs(), 1,
		"the record row is KEPT: dropping it before the files would make them unremovable (FR-028)")
}

type stubPruner struct {
	removed []string
	err     error
}

func (p *stubPruner) Remove(_ context.Context, r plan.Removal) (bool, error) {
	if p.err != nil {
		return false, p.err
	}
	p.removed = append(p.removed, r.Dest)
	return true, os.RemoveAll(r.Dest)
}

func TestApplyDropsTheRecordRowOnlyAfterAPrunerRemovedTheFiles(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	removal := plan.Removal{
		Profile: applyProfile, Target: record.TargetClaudeCode, ID: c.ID, Kind: record.KindSkill,
		Version: c.Version, Dest: c.Dest, Reason: plan.RemoveLeftProfile,
	}
	pruner := &stubPruner{}
	res, err := f.applier(t, func(cfg *Config) { cfg.Pruner = pruner }).
		Apply(context.Background(), plan.Plan{Remove: []plan.Removal{removal}})
	require.NoError(t, err)
	require.Equal(t, []string{c.Dest}, pruner.removed)
	require.Len(t, res.Removed, 1)
	require.Empty(t, loadedRecord(t, f).Refs())

	// And when the pruner fails, the row stays.
	f2 := newApplyFixture(t)
	c2 := f2.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err = f2.applier(t).Apply(context.Background(), planOf(c2))
	require.NoError(t, err)
	removal.Dest = c2.Dest
	failing := &stubPruner{err: errors.New("permission denied")}
	_, err = f2.applier(t, func(cfg *Config) { cfg.Pruner = failing }).
		Apply(context.Background(), plan.Plan{Remove: []plan.Removal{removal}})
	require.Error(t, err)
	require.Len(t, loadedRecord(t, f2).Refs(), 1)
	require.DirExists(t, c2.Dest)
}

func TestApplyDropsARetainedRowWithoutTouchingTheFiles(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	removal := plan.Removal{
		Profile: applyProfile, Target: record.TargetClaudeCode, ID: c.ID, Kind: record.KindSkill,
		Version: c.Version, Dest: c.Dest, Reason: plan.RemoveLeftProfile,
		RetainedBy: []plan.Claim{{Profile: "other", Target: record.TargetClaudeCode, ID: c.ID, Version: c.Version}},
	}
	res, err := f.applier(t).Apply(context.Background(), plan.Plan{Remove: []plan.Removal{removal}})
	require.NoError(t, err, "another profile still claims the destination; no pruner is needed")
	require.Len(t, res.Retained, 1)
	require.DirExists(t, c.Dest, "the directory another profile still wants is untouched")
	require.Empty(t, loadedRecord(t, f).ByID(c.ID))
}

// TestApplyWritesNothingOnAnUnchangedRun is apply's half of FR-025, asserted by
// mtime across the whole tree rather than by what the Result claims.
func TestApplyWritesNothingOnAnUnchangedRun(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	before := treeSnapshot(t, f.home)

	unchanged := c
	unchanged.Op = plan.OpUnchanged
	unchanged.From = &plan.Installed{Version: c.Version, Digest: c.Digest, Fingerprinted: true}
	res, err := f.applier(t).Apply(context.Background(), planOf(unchanged))
	require.NoError(t, err)
	require.Empty(t, res.Installed)
	require.Len(t, res.Unchanged, 1)
	require.Zero(t, res.RecordWrites, "state.json must not be rewritten by a run that changed nothing")

	require.Equal(t, before, treeSnapshot(t, f.home),
		"a second run against an unchanged hub makes no filesystem modification (FR-025)")
}

// treeSnapshot is every path under root with the metadata a modification would
// move: mode, size and mtime. It is deliberately NOT the CLI's own report of
// what it did.
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		out[filepath.ToSlash(rel)] = fmt.Sprintf("mode=%v size=%d mtime=%d",
			info.Mode(), info.Size(), info.ModTime().UnixNano())
		return nil
	}))
	return out
}

func TestApplyStopsOnACancelledContext(t *testing.T) {
	f := newApplyFixture(t)
	one := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	two := f.add(t, "beta/fmt-go", "0.9.1", skillBundle(t))

	ctx, cancel := context.WithCancel(context.Background())
	f.bundles.before = func(c plan.Change) {
		if c.ID == one.ID {
			cancel()
		}
	}
	res, err := f.applier(t).Apply(ctx, planOf(one, two))
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, res.Installed, 0, "the entry whose fetch was cancelled did not land")
	require.NoDirExists(t, two.Dest, "and the run stops rather than continuing to the next entry")
}
