// These tests assert ordering and refusals: the record is written after each
// swap, a run killed between the two converges, and every destination amctl
// did not write is refused rather than replaced.

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

// applyBundles is a BundleSource keyed by `id@version`, with an optional hook
// run before each hand-over to observe the tree.
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

// loadedRecord reads the record from disk, the only copy that survives a crash.
func loadedRecord(t *testing.T, f *applyFixture) *record.Record {
	t.Helper()
	rec, err := record.Load(f.recPath, applyHub)
	require.NoError(t, err)
	return rec
}

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
	require.Equal(t, 7, prof.Revision, "the resolved revision is recorded, never `head`")
	require.Equal(t, []record.Target{record.TargetClaudeCode}, prof.Targets)
	require.Len(t, prof.Entries, 1)
	require.Equal(t, c.Dest, prof.Entries[0].Dest)
	require.Equal(t, "1.4.0", prof.Entries[0].Version)
	require.Equal(t, c.Digest, prof.Entries[0].Digest)
}

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
		"two publishers sharing a package name install to distinct directories")
}

// orderProbe observes the tree from Modes, which runs between the swap and the
// record write.
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
	// The second entry's fetch asserts the first is already recorded.
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

// TestApplyStopsWritingWhenTheCallerSaysItNoLongerOwnsTheTree covers a lock
// holder declared stale mid-run: it must stop, and entries already landed must
// stay recorded.
func TestApplyStopsWritingWhenTheCallerSaysItNoLongerOwnsTheTree(t *testing.T) {
	f := newApplyFixture(t)
	first := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	second := f.add(t, "acme/doc-gen", "2.0.0", skillBundle(t))

	reclaimed := errors.New("another amctl reclaimed the lock")
	seen := 0
	res, err := f.applier(t, func(cfg *Config) {
		cfg.Continue = func() error {
			seen++
			if seen > 1 {
				return reclaimed
			}
			return nil
		}
	}).Apply(context.Background(), planOf(first, second))

	require.Error(t, err)
	require.ErrorIs(t, err, reclaimed)
	require.Len(t, res.Installed, 1, "the entry that landed before the lock went stays installed")
	require.Len(t, res.Failed, 1)
	require.Empty(t, res.Refusals(), "losing the lock is not the user's to fix with --force")

	// The first entry is on disk with its record row.
	rec := loadedRecord(t, f)
	installed := res.Installed[0].Change
	require.Len(t, rec.ByID(installed.ID), 1)
	require.DirExists(t, installed.Dest)
	require.NoDirExists(t, res.Failed[0].Change.Dest, "the abandoned entry was never staged")
}

// leftoverAsideFixture installs 1.4.0, then upgrades to 1.5.0 with step 5's
// RemoveAll obstructed, leaving an `.amctl-old` beside the destination.
func leftoverAsideFixture(t *testing.T, f *applyFixture) (upgrade plan.Change, aside string) {
	t.Helper()
	a := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(a))
	require.NoError(t, err)

	blocked := filepath.Join(a.Dest, "references")
	require.NoError(t, os.Chmod(blocked, 0o500))

	b := f.add(t, "acme/lint-go", "1.5.0", skillBundle(t))
	b.Op = plan.OpUpgrade
	b.From = &plan.Installed{Version: "1.4.0", Digest: a.Digest}

	res, err := f.applier(t, func(cfg *Config) { cfg.Force = true }).Apply(context.Background(), planOf(b))
	require.NoError(t, err, "a failed step 5 must not fail an install that landed")
	aside = b.Dest + AsideSuffix
	require.DirExists(t, aside, "the premise: step 5 really did fail and left the aside behind")
	require.Equal(t, []string{aside}, res.Leftovers)
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(aside, "references"), 0o700) })

	return b, aside
}

// TestAConvergedRunSweepsAnAsideAnEarlierSwapCouldNotRemove: an Unchanged
// entry never runs Swap again, so only the sweep can remove its aside.
func TestAConvergedRunSweepsAnAsideAnEarlierSwapCouldNotRemove(t *testing.T) {
	f := newApplyFixture(t)
	b, aside := leftoverAsideFixture(t, f)

	require.NoError(t, os.Chmod(filepath.Join(aside, "references"), 0o700))

	converged := b
	converged.Op = plan.OpUnchanged
	converged.From = &plan.Installed{Version: "1.5.0", Digest: b.Digest}

	res, err := f.applier(t).Apply(context.Background(), planOf(converged))
	require.NoError(t, err)
	require.Empty(t, res.Installed, "the premise: this run writes nothing, so nothing calls Swap")
	require.Empty(t, res.Leftovers)
	require.NoDirExists(t, aside, "the aside must be swept by a run that had no change for the entry")
	require.DirExists(t, b.Dest, "and the live install is untouched")
}

func TestASweepReportsAnAsideItStillCannotRemove(t *testing.T) {
	f := newApplyFixture(t)
	b, aside := leftoverAsideFixture(t, f)

	converged := b
	converged.Op = plan.OpUnchanged
	converged.From = &plan.Installed{Version: "1.5.0", Digest: b.Digest}

	res, err := f.applier(t).Apply(context.Background(), planOf(converged))
	require.NoError(t, err, "a leftover is reported, never a failed entry")
	require.Equal(t, []string{aside}, res.Leftovers)
	require.True(t, f.log.warnedAbout(t, "safe to delete by hand"),
		"the operator has to be told which path to remove, or the entry is stuck forever")
}

// TestTheSweepNeverRemovesAnAsideWhoseDestinationIsAbsent: after a crash
// between Swap steps 2 and 3 the aside is the only copy. Apply re-installs the
// vanished entry and Swap reclaims the aside; res.Reclaimed proves it was not
// simply re-extracted after the copy was deleted.
func TestTheSweepNeverRemovesAnAsideWhoseDestinationIsAbsent(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	aside := c.Dest + AsideSuffix
	require.NoError(t, os.Rename(c.Dest, aside))

	converged := c
	converged.Op = plan.OpUnchanged
	converged.From = &plan.Installed{Version: "1.4.0", Digest: c.Digest}

	res, err := f.applier(t).Apply(context.Background(), planOf(converged))
	require.NoError(t, err)
	require.Empty(t, res.Leftovers, "an aside that is the only copy is not a leftover")

	require.Len(t, res.Installed, 1,
		"the destination the record claims is absent, so this run must not report itself converged")
	require.True(t, res.Installed[0].Swap.Reclaimed,
		"the aside held the only complete copy: step 1 must have RECLAIMED it by renaming it back, "+
			"not discarded it and re-extracted over the gap")

	require.DirExists(t, c.Dest, "the only complete copy of the entry must survive, at the destination")
	require.FileExists(t, filepath.Join(c.Dest, "SKILL.md"))
	require.NoDirExists(t, aside, "and nothing is left stranded at the aside path")
}

func TestApplyAdoptsItsOwnLeftoverFromAnInterruptedRun(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	// Simulate dying between the swap and the record write.
	require.NoError(t, os.RemoveAll(filepath.Dir(f.recPath)))
	f.rec = record.New(applyHub)

	res, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err, "the re-run must converge, not refuse its own leftover")
	require.Len(t, res.Installed, 1)
	require.True(t, f.log.warnedAbout(t, "interrupted between the install and the record write"))
	require.Len(t, loadedRecord(t, f).ByID(c.ID), 1, "the record row is restored")
}

// TestApplyAdoptsAnotherProfilesShareOfADestinationWithoutTheInterruptedWarning:
// a second profile sharing the same install is ordinary sharing, not a crash.
func TestApplyAdoptsAnotherProfilesShareOfADestinationWithoutTheInterruptedWarning(t *testing.T) {
	f := newApplyFixture(t)
	c := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	other := c
	other.Profile = "other-profile"

	res, err := f.applier(t, func(cfg *Config) {
		cfg.Profiles = append(cfg.Profiles, ProfileState{
			Slug: other.Profile, Revision: 1, Targets: []record.Target{record.TargetClaudeCode},
		})
	}).Apply(context.Background(), planOf(other))
	require.NoError(t, err, "an agreeing second profile must be adopted, not refused")
	require.Len(t, res.Installed, 1)
	require.False(t, f.log.warnedAbout(t, "interrupted between the install and the record write"),
		"this is ordinary sharing between two profiles, not a crash recovery")

	refs := loadedRecord(t, f).ByID(c.ID)
	require.Len(t, refs, 2, "both profiles now claim the entry")
}

// republishFixture leaves the state of a republish killed between swap and
// record write: tree and marker at the new digest, record at the old. It
// returns the OpReplace change that reconciles it.
func republishFixture(t *testing.T, f *applyFixture) plan.Change {
	t.Helper()
	first := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(first))
	require.NoError(t, err)

	republished := packBundle(t,
		file("SKILL.md", "---\nname: lint-go\n---\nthe body, republished\n"),
		file("references/style.md", "a reference\n"),
	)
	newDigest, derr := record.ParseDigest(cache.Compute(republished).Lockfile())
	require.NoError(t, derr)
	require.NotEqual(t, first.Digest, newDigest, "the republish must actually change the bytes")
	f.bundles.byRef["acme/lint-go@1.4.0"] = republished

	c := first
	c.Op = plan.OpReplace
	c.Digest = newDigest
	c.From = &plan.Installed{Version: "1.4.0", Digest: first.Digest}

	_, err = f.applier(t, func(cfg *Config) { cfg.Force = true }).Apply(context.Background(), planOf(c))
	require.NoError(t, err)

	rec := loadedRecord(t, f)
	prof, ok := rec.ProfileBySlug(applyProfile)
	require.True(t, ok)
	require.Len(t, prof.Entries, 1)
	prof.Entries[0].Digest = first.Digest
	rec.SetProfile(prof)
	_, serr := record.Save(f.recPath, rec)
	require.NoError(t, serr)
	f.rec = rec
	f.log.warns = nil

	return c
}

// TestApplyAdoptsItsOwnLeftoverFromAnInterruptedRepublish covers OpReplace,
// where From.Version equals the version being installed.
func TestApplyAdoptsItsOwnLeftoverFromAnInterruptedRepublish(t *testing.T) {
	f := newApplyFixture(t)
	c := republishFixture(t, f)

	res, err := f.applier(t).Apply(context.Background(), planOf(c))
	require.NoError(t, err, "a republish killed between the swap and the record write must converge without --force")
	require.Len(t, res.Installed, 1)
	require.Empty(t, res.Failed)
	require.True(t, f.log.warnedAbout(t, "interrupted between the install and the record write"))
	require.True(t, f.log.warnedAbout(t, "at digest "+c.From.Digest.Lockfile()),
		"the warning must name the digest, because both versions read 1.4.0")

	rec := loadedRecord(t, f)
	refs := rec.ByID(c.ID)
	require.Len(t, refs, 1)
	require.Equal(t, c.Digest, refs[0].Entry.Digest, "the record is caught up to what is on disk")
}

// TestApplyDoesNotAdoptAMarkerWhoseDigestIsNotTheChanges: adopting on a
// version match alone would silence verifyUnmodified for every upgrade.
func TestApplyDoesNotAdoptAMarkerWhoseDigestIsNotTheChanges(t *testing.T) {
	f := newApplyFixture(t)
	c := republishFixture(t, f)

	// The plan now wants a third set of bytes at the same version.
	third := packBundle(t,
		file("SKILL.md", "---\nname: lint-go\n---\nthe body, republished twice\n"),
		file("references/style.md", "a reference\n"),
	)
	thirdDigest, derr := record.ParseDigest(cache.Compute(third).Lockfile())
	require.NoError(t, derr)
	require.NotEqual(t, c.Digest, thirdDigest)
	f.bundles.byRef["acme/lint-go@1.4.0"] = third

	want := c
	want.Digest = thirdDigest

	res, err := f.applier(t).Apply(context.Background(), planOf(want))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnverifiable,
		"the tree is not this change's install, so it goes back through verifyUnmodified")
	require.Empty(t, res.Installed)
	require.Len(t, res.Refusals(), 1)
}

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
	require.Equal(t, "mine, not amctl's\n", string(body), "the file amctl did not write survives byte-identical")
}

func TestApplyRefusesAMarkerForADifferentPackage(t *testing.T) {
	f := newApplyFixture(t)
	mine := f.add(t, "acme/lint-go", "1.4.0", skillBundle(t))
	_, err := f.applier(t).Apply(context.Background(), planOf(mine))
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(filepath.Dir(f.recPath)))
	f.rec = record.New(applyHub)

	// A different id at the same directory: the marker is not this entry's.
	other := mine
	other.ID = "beta/fmt-go"
	f.bundles.byRef[other.ID+"@"+other.Version] = f.bundles.byRef[mine.ID+"@"+mine.Version]

	_, err = f.applier(t).Apply(context.Background(), planOf(other))
	require.ErrorIs(t, err, ErrUnrecorded)
}

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

	// --force replaces the link and leaves what it pointed at alone.
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

	// No verifier is needed: nothing is at the destination.
	res, err := f.applier(t).Apply(context.Background(), planOf(same))
	require.NoError(t, err)
	require.Len(t, res.Installed, 1)
	require.True(t, f.log.warnedAbout(t, "but nothing is there; re-installing"))
	require.DirExists(t, c.Dest)
}

// TestApplyRefusesAPlanWithConflictsBeforeStagingAByte covers every conflict
// kind, since each must refuse before writing.
func TestApplyRefusesAPlanWithConflictsBeforeStagingAByte(t *testing.T) {
	unknown := fmt.Errorf("target agents-md: %w", layout.ErrUnknownTarget)
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
			name: "a target this build has never heard of",
			conf: plan.Conflict{Kind: plan.ConflictTargetUnknown, Target: "agents-md", Err: unknown},
			want: layout.ErrUnknownTarget,
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
		"the record row is KEPT: dropping it before the files would make them unremovable")
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

// TestApplyWritesNothingOnAnUnchangedRun checks mtimes across the tree rather
// than trusting the Result.
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
		"a second run against an unchanged hub makes no filesystem modification")
}

// treeSnapshot is every path under root with its mode, size and mtime.
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
