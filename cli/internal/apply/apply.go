package apply

// This file executes a plan.Plan, per entry: contain -> guard -> fetch ->
// stage -> hash -> SWAP -> RECORD, in that order and never batched at the
// end, so a crash mid-run converges: a swap with no record yet is recognised
// by amctl's own provenance marker and adopted, not refused as a stranger's
// file. Download, versioning, destinations, removal and hashing belong to
// other seams; this file only writes what those already decided.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ErrOutsideHome marks a destination whose resolved path is outside Home; see Home.
var ErrOutsideHome = errors.New("destination resolves outside the invoking user's home")

// ErrUnrecorded marks a destination amctl's record does not claim.
var ErrUnrecorded = errors.New("destination exists and is not in amctl's installation record")

// ErrModified marks an amctl destination changed since it was installed.
var ErrModified = errors.New("destination has been modified since it was installed")

// ErrUnverifiable is the fail-closed case: no fingerprint, or no verifier for
// the one recorded.
var ErrUnverifiable = errors.New("destination cannot be verified as unmodified")

// ErrPruneUnavailable marks a planned removal with no Pruner wired.
var ErrPruneUnavailable = errors.New("this build cannot execute a removal")

// ErrConfig marks an Applier that cannot be constructed.
var ErrConfig = errors.New("invalid apply configuration")

type Logger interface {
	Warnf(format string, args ...any)
	Debugf(format string, args ...any)
}

// BundleSource supplies bytes already hashed to Change.Digest by internal/hub.
type BundleSource interface {
	Bundle(ctx context.Context, c plan.Change) ([]byte, error)
}

// Fingerprinter hashes the staged tree before the swap (Hash) and lstats
// the written entry after it (Modes), since the umask changes the mode.
type Fingerprinter interface {
	Hash(staged *Staged) (record.Fingerprint, error)
	Modes(dest string, fp record.Fingerprint) (record.Fingerprint, error)
}

// Verifier reports paths that differ from the record; empty is the only
// verdict permitting an overwrite.
type Verifier interface {
	Modifications(e record.Entry) ([]string, error)
}

// Pruner executes one planned removal and reports whether it removed anything.
type Pruner interface {
	Remove(ctx context.Context, r plan.Removal) (bool, error)
}

// ProfileState is what the record needs about a profile beyond the plan.
type ProfileState struct {
	Slug     string
	Revision int
	Targets  []record.Target
}

// Config builds an Applier; Home, Record, RecordPath, Bundles required.
type Config struct {
	Home       *Home
	Record     *record.Record
	RecordPath string
	Profiles   []ProfileState
	Bundles    BundleSource

	Fingerprints Fingerprinter
	Verifier     Verifier
	Pruner       Pruner
	Log          Logger

	Force bool // overrides symlink/unrecorded/unverified refusals, always naming what it destroys

	Now func() time.Time // stamps Profile.InstalledAt on change; defaults to time.Now

	// Continue is asked before each entry whether this run still owns the
	// lock, so a heartbeat-declared-stale holder stops before two Swaps
	// race one entry. Nil means "always".
	Continue func() error
}

type Applier struct {
	cfg Config
}

func New(cfg Config) (*Applier, error) {
	switch {
	case cfg.Home == nil:
		return nil, fmt.Errorf("%w: no home was opened, so FR-020 containment could not be checked", ErrConfig)
	case cfg.Record == nil:
		return nil, fmt.Errorf("%w: no installation record; an absent record is record.New(hub), never nil", ErrConfig)
	case cfg.RecordPath == "":
		return nil, fmt.Errorf("%w: no installation record path", ErrConfig)
	case cfg.Bundles == nil:
		return nil, fmt.Errorf("%w: no bundle source", ErrConfig)
	}
	if cfg.Log == nil {
		cfg.Log = discardLog{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Applier{cfg: cfg}, nil
}

type discardLog struct{}

func (discardLog) Warnf(string, ...any)  {}
func (discardLog) Debugf(string, ...any) {}

type Installed struct {
	Change plan.Change
	Entry  record.Entry
	Swap   SwapResult
}

// EntryError is one entry that did not land.
type EntryError struct {
	Change plan.Change

	Removal *plan.Removal // set instead of Change for a planned removal
	Err     error
	Refusal bool // a pre-stage failure the user can act on; internal/cmd exits differently for it
}

func (e *EntryError) Error() string {
	who, target := e.Change.ID, e.Change.Target
	if e.Removal != nil {
		who, target = e.Removal.ID, e.Removal.Target
	}
	if who == "" { // a run-level failure, today only the final record write
		return e.Err.Error()
	}
	return fmt.Sprintf("%s (%s): %v", who, target, e.Err)
}

func (e *EntryError) Unwrap() error { return e.Err }

// Result is what one Apply did, entry by entry.
type Result struct {
	Installed []Installed
	Unchanged []plan.Change
	Removed   []plan.Removal

	Retained []plan.Removal // resolved by dropping a record row; disk untouched

	Failed []EntryError

	Leftovers    []string // `.amctl-old` paths sweepAsides could not remove
	RecordWrites int      // times state.json actually changed; zero on an idempotent run
}

func (r *Result) Refusals() []EntryError { return r.filter(true) }
func (r *Result) Failures() []EntryError { return r.filter(false) }

func (r *Result) filter(refusal bool) []EntryError {
	var out []EntryError
	for i := range r.Failed {
		if r.Failed[i].Refusal == refusal {
			out = append(out, r.Failed[i])
		}
	}
	return out
}

// Err joins every per-entry failure without discarding what did land.
func (r *Result) Err() error {
	if len(r.Failed) == 0 {
		return nil
	}
	errs := make([]error, 0, len(r.Failed))
	for i := range r.Failed {
		errs = append(errs, &r.Failed[i])
	}
	return errors.Join(errs...)
}

// Apply executes p and always returns a Result, even alongside an error,
// since it is the partial report of what already landed. A plan with
// conflicts is refused before a single byte is staged.
func (a *Applier) Apply(ctx context.Context, p plan.Plan) (*Result, error) {
	res := &Result{}
	if p.Refuses() {
		return res, p.ConflictError()
	}
	if err := a.checkProfiles(p); err != nil {
		return res, err
	}

	// plan.Plan is pure and never consults disk, so an "unchanged" entry
	// whose destination has actually vanished must be re-routed through
	// guard(), which re-installs a From with no destination, rather than
	// copied into the result as a success over an empty path.
	unchanged, gone := a.presentAndGone(p.Unchanged)
	res.Unchanged = unchanged
	writes := p.Writes()
	if len(gone) > 0 {
		writes = append(writes, gone...)
		slices.SortFunc(writes, plan.ChangeOrder)
	}
	for i := range writes {
		c := writes[i]
		if err := a.mayContinue(ctx); err != nil {
			res.Failed = append(res.Failed, EntryError{Change: c, Err: err})
			joined := res.Err()
			return res, joined
		}
		a.applyChange(ctx, c, res)
	}
	a.applyRemovals(ctx, p, res)
	a.saveRecord(res)
	a.pruneStaging(p)
	a.sweepAsides(p, res)
	joined := res.Err()
	return res, joined
}

// mayContinue is the two questions asked before every entry: has the caller
// cancelled, and does this run still own the tree. See Config.Continue.
func (a *Applier) mayContinue(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.cfg.Continue == nil {
		return nil
	}
	return a.cfg.Continue()
}

// checkProfiles refuses a plan naming a profile the caller did not describe,
// before the tree changes rather than at Save time.
func (a *Applier) checkProfiles(p plan.Plan) error {
	known := make(map[string]struct{}, len(a.cfg.Profiles))
	for _, ps := range a.cfg.Profiles {
		if ps.Slug == "" {
			return fmt.Errorf("%w: a profile state has no slug", ErrConfig)
		}
		if ps.Revision < 1 {
			return fmt.Errorf("%w: profile %s has revision %d; `head` must be resolved to a number before it is recorded (FR-013)",
				ErrConfig, ps.Slug, ps.Revision)
		}
		known[ps.Slug] = struct{}{}
	}
	writes := p.Writes()
	for i := range writes {
		if _, ok := known[writes[i].Profile]; !ok {
			return fmt.Errorf("%w: the plan writes %s for profile %s, which no ProfileState describes",
				ErrConfig, writes[i].ID, writes[i].Profile)
		}
	}
	return nil
}

// applyChange runs one entry all the way through, or records why it did not.
func (a *Applier) applyChange(ctx context.Context, c plan.Change, res *Result) {
	cont, err := a.cfg.Home.Contains(c.Dest)
	if err != nil {
		res.Failed = append(res.Failed, EntryError{Change: c, Err: err, Refusal: true})
		return
	}
	if gerr := a.guard(c, cont); gerr != nil {
		res.Failed = append(res.Failed, EntryError{Change: c, Err: gerr, Refusal: true})
		return
	}

	inst, err := a.install(ctx, c, cont)
	if err != nil {
		res.Failed = append(res.Failed, EntryError{Change: c, Err: err})
		return
	}
	if leftover := inst.Swap.LeftoverAside(); leftover != "" {
		// Reported, not recorded: sweepAsides retries and owns Result.Leftovers.
		a.cfg.Log.Debugf("%s: the swap could not remove %s (%v); it is retried at the end of this run",
			c.ID, leftover, inst.Swap.RemoveAsideErr)
	}
	res.Installed = append(res.Installed, *inst)
	a.recordEntry(c, inst.Entry, res)
}

// install is stage -> hash -> swap -> read modes; every failure before the
// swap leaves the destination untouched (Swap step 3 rolls back its own).
func (a *Applier) install(ctx context.Context, c plan.Change, cont Contained) (*Installed, error) {
	bundle, err := a.cfg.Bundles.Bundle(ctx, c)
	if err != nil {
		return nil, err
	}

	markerBytes, err := markerFor(c)
	if err != nil {
		return nil, err
	}

	staged, err := Stage(ctx, StageRequest{
		Dest:       c.Dest,
		Digest:     c.Digest,
		Bundle:     bundle,
		Marker:     markerBytes,
		MarkerName: layout.MarkerFileName,
	})
	if err != nil {
		return nil, err
	}

	fp, err := a.hash(staged)
	if err != nil {
		a.discard(c, staged)
		return nil, err
	}

	swapped, err := Swap(staged.Path, c.Dest)
	if err != nil {
		a.discard(c, staged)
		return nil, err
	}
	if swapped.SyncDirErr != nil {
		a.cfg.Log.Debugf("%s: could not fsync %s (%v); the entry is installed and the record write follows it",
			c.ID, filepath.Dir(c.Dest), swapped.SyncDirErr)
	}
	if swapped.Reclaimed {
		a.cfg.Log.Debugf("%s: reclaimed %s — a previous sync was interrupted mid-install", c.ID, swapped.Aside)
	}
	if swapped.DiscardedAside {
		a.cfg.Log.Debugf("%s: discarded a superseded %s left by an interrupted sync", c.ID, swapped.Aside)
	}
	a.cfg.Log.Debugf("%s: installed %s at %s (resolved %s)", c.ID, c.Version, c.Dest, cont.Resolved)

	fp = a.modes(c, fp)
	return &Installed{
		Change: c,
		Entry: record.Entry{
			ID:          c.ID,
			Version:     c.Version,
			Digest:      c.Digest,
			Kind:        c.Kind,
			Target:      c.Target,
			Dest:        c.Dest,
			Fingerprint: fp,
		},
		Swap: swapped,
	}, nil
}

// hash takes the content half of the fingerprint from the staged tree; a
// fingerprinter failure fails the entry, since an unfingerprinted install
// can never be checked for modification again.
func (a *Applier) hash(staged *Staged) (record.Fingerprint, error) {
	if a.cfg.Fingerprints == nil {
		return record.Fingerprint{}, nil
	}
	fp, err := a.cfg.Fingerprints.Hash(staged)
	if err != nil {
		return record.Fingerprint{}, fmt.Errorf("fingerprint the staged tree at %s: %w", staged.Path, err)
	}
	return fp, nil
}

// modes fills in the lstat half after the swap; a failure here does not
// fail the entry, but drops the fingerprint entirely rather than leave it
// half-written, which would misreport every unrecorded file as an addition.
func (a *Applier) modes(c plan.Change, fp record.Fingerprint) record.Fingerprint {
	if a.cfg.Fingerprints == nil {
		return record.Fingerprint{}
	}
	full, err := a.cfg.Fingerprints.Modes(c.Dest, fp)
	if err != nil {
		a.cfg.Log.Warnf("%s: installed, but its install fingerprint could not be completed (%v); "+
			"a later sync will refuse to overwrite it without --force", c.ID, err)
		return record.Fingerprint{}
	}
	return full
}

func (a *Applier) discard(c plan.Change, staged *Staged) {
	if err := staged.Discard(); err != nil {
		a.cfg.Log.Warnf("%s: could not remove the staged tree at %s (%v); it is named after the bundle digest, "+
			"so the next attempt re-stages over it", c.ID, staged.Path, err)
	}
}

// markerFor builds the provenance marker here, not on the plan, since the
// plan is pure and the marker is a file: layout owns its shape, this owns
// writing it into the staged tree so it rides the same rename as the entry.
func markerFor(c plan.Change) ([]byte, error) {
	m := layout.Marker{
		SchemaVersion: layout.MarkerSchemaVersion,
		ID:            c.ID,
		Version:       c.Version,
		Kind:          c.Kind,
		Target:        c.Target,
		Digest:        c.Digest,
	}
	b, err := m.Bytes()
	if err != nil {
		return nil, fmt.Errorf("build the provenance marker for %s: %w", c.ID, err)
	}
	return b, nil
}

// guard runs the record and modification checks once the destination is
// proven inside the home and before anything is staged into it. Swap itself
// is unconditional, replacing whatever is at the destination including a
// symlink, so this is the only thing standing between a sync and somebody's
// hand-written skill.
func (a *Applier) guard(c plan.Change, cont Contained) error {
	st, err := inspectDest(cont)
	if err != nil {
		return err
	}
	switch {
	case !st.exists:
		if c.From != nil {
			a.cfg.Log.Warnf("%s: the record claims %s at %s but nothing is there; re-installing",
				c.ID, c.From.Version, c.Dest)
		}
		return nil

	case st.symlink:
		// amctl never creates a symlink at a destination, so this is
		// somebody else's; refused rather than followed, since following it
		// is how amctl would write outside the home.
		return a.override(fmt.Errorf("%w: %s is a symlink to %s, which amctl did not create",
			ErrUnrecorded, c.Dest, orUnknown(st.linkTarget)),
			"%s: --force is replacing the symlink %s -> %s; whatever it points at is left alone",
			c.ID, c.Dest, orUnknown(st.linkTarget))

	case c.From == nil:
		// The one legitimate case for an unclaimed path is amctl's own
		// leftover from a run killed between the swap and the record write.
		if st.marker != nil && st.marker.ID == c.ID && st.marker.Target == c.Target {
			a.cfg.Log.Warnf("%s: %s holds amctl's marker for %s but no record row; a previous sync was "+
				"interrupted between the install and the record write, so it is being re-installed",
				c.ID, c.Dest, st.marker.Version)
			return nil
		}
		return a.override(fmt.Errorf("%w: %s already exists", ErrUnrecorded, c.Dest),
			"%s: --force is replacing %s, which amctl's record does not claim", c.ID, c.Dest)

	case st.marker != nil && st.marker.ID == c.ID && st.marker.Target == c.Target &&
		st.marker.Version == c.Version && st.marker.Digest == c.Digest &&
		(c.From.Version != c.Version || c.From.Digest != c.Digest):
		// Record and tree disagree, but the tree already holds exactly what
		// this change would install and carries amctl's own marker for it —
		// proof of a run killed between swap and record write, not a real
		// conflict. Matched on marker+digest, not version alone, because a
		// republish can change bytes at the same version. Never widen this
		// to "marker says ours" alone: that would bypass verifyUnmodified on
		// every real upgrade too.
		a.cfg.Log.Warnf("%s: %s already holds %s and amctl's marker for it, but the record still names %s; "+
			"a previous sync was interrupted between the install and the record write, so the record is being caught up",
			c.ID, c.Dest, c.Version, describeFrom(c))
		return nil

	default:
		return a.verifyUnmodified(c)
	}
}

// verifyUnmodified requires a positive unmodified verdict before an
// overwrite; an entry with no usable fingerprint is refused, not assumed fine.
func (a *Applier) verifyUnmodified(c plan.Change) error {
	prev := record.Entry{
		ID: c.ID, Version: c.From.Version, Digest: c.From.Digest,
		Kind: c.Kind, Target: c.Target, Dest: c.Dest,
	}
	switch {
	case !c.From.Fingerprinted:
		return a.override(fmt.Errorf("%w: %s was recorded without an install fingerprint, so whether it has "+
			"changed cannot be established", ErrUnverifiable, c.Dest),
			"%s: --force is overwriting %s, whose contents could not be verified", c.ID, c.Dest)
	case a.cfg.Verifier == nil:
		return a.override(fmt.Errorf("%w: %s carries a fingerprint and this build has no verifier for it",
			ErrUnverifiable, c.Dest),
			"%s: --force is overwriting %s without verifying it", c.ID, c.Dest)
	}

	changed, err := a.cfg.Verifier.Modifications(prev)
	if err != nil {
		return a.override(fmt.Errorf("%w: %s: %w", ErrUnverifiable, c.Dest, err),
			"%s: --force is overwriting %s, which could not be verified (%v)", c.ID, c.Dest, err)
	}
	if len(changed) == 0 {
		return nil
	}
	return a.override(fmt.Errorf("%w: %s: %s", ErrModified, c.Dest, strings.Join(changed, ", ")),
		"%s: --force is destroying %d modified path(s) under %s: %s",
		c.ID, len(changed), c.Dest, strings.Join(changed, ", "))
}

// override returns refusal unless --force, which always names what it destroys.
func (a *Applier) override(refusal error, format string, args ...any) error {
	if !a.cfg.Force {
		return fmt.Errorf("%w; re-run with --force to overwrite it", refusal)
	}
	a.cfg.Log.Warnf(format, args...)
	return nil
}

// describeFrom names the record's prior claim, naming the digest instead of
// just the version when a republish left the version unchanged.
func describeFrom(c plan.Change) string {
	if c.From == nil {
		return "nothing"
	}
	if c.From.Version == c.Version {
		return c.From.Version + " at digest " + c.From.Digest.Lockfile()
	}
	return c.From.Version
}

func orUnknown(s string) string {
	if s == "" {
		return "an unreadable target"
	}
	return s
}

// destState is what is at a destination right now.
type destState struct {
	exists     bool
	symlink    bool
	linkTarget string
	marker     *layout.Marker
}

// presentAndGone splits unchanged changes by whether the destination is
// there; a path that can't be inspected counts as present rather than gone.
func (a *Applier) presentAndGone(unchanged []plan.Change) (present, gone []plan.Change) {
	for i := range unchanged {
		c := unchanged[i]
		cont, err := a.cfg.Home.Contains(c.Dest)
		if err != nil {
			present = append(present, c)
			continue
		}
		st, err := inspectDest(cont)
		if err != nil || st.exists {
			present = append(present, c)
			continue
		}
		gone = append(gone, c)
	}
	return present, gone
}

// inspectDest reads the marker through an *os.Root on the destination, so a
// symlink planted at the marker's name cannot redirect the read elsewhere.
func inspectDest(cont Contained) (destState, error) {
	info, err := os.Lstat(cont.Dest)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return destState{}, nil
	case err != nil:
		return destState{}, fmt.Errorf("inspect %s: %w", cont.Dest, err)
	}

	st := destState{exists: true}
	if info.Mode()&fs.ModeSymlink != 0 {
		st.symlink = true
		if target, rerr := os.Readlink(cont.Dest); rerr == nil {
			st.linkTarget = target
		}
		return st, nil
	}
	if !info.IsDir() {
		return st, nil
	}

	root, err := os.OpenRoot(cont.Dest)
	if err != nil {
		return st, nil
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile(layout.MarkerFileName)
	if err != nil {
		return st, nil
	}
	m, err := layout.ParseMarker(b)
	if err != nil {
		// Unparseable is treated as no marker: it is provenance, not authority.
		return st, nil
	}
	st.marker = &m
	return st, nil
}

// applyRemovals routes removals the plan resolved by dropping a row from
// the ones that still need prune.go.
func (a *Applier) applyRemovals(ctx context.Context, p plan.Plan, res *Result) {
	for i := range p.Remove {
		r := p.Remove[i]
		if !r.RemovesFromDisk() {
			// Another profile still claims this destination: drop the row, keep the tree.
			res.Retained = append(res.Retained, r)
			continue
		}
		if a.cfg.Pruner == nil {
			res.Failed = append(res.Failed, EntryError{
				Removal: &r,
				Err: fmt.Errorf("%w: %s at %s should be removed (%s) and no pruner is wired, so it is still installed",
					ErrPruneUnavailable, r.ID, r.Dest, r.Reason),
			})
			continue
		}
		removed, err := a.cfg.Pruner.Remove(ctx, r)
		if err != nil {
			res.Failed = append(res.Failed, EntryError{Removal: &r, Err: err})
			continue
		}
		if removed {
			res.Removed = append(res.Removed, r)
		}
	}
}

// recordEntry updates the in-memory record for one installed entry and saves it.
func (a *Applier) recordEntry(c plan.Change, e record.Entry, res *Result) {
	prof := a.profileRow(c.Profile)
	prof.Entries = upsertEntry(prof.Entries, e)
	prof.InstalledAt = a.cfg.Now()
	a.cfg.Record.SetProfile(prof)

	wrote, err := record.Save(a.cfg.RecordPath, a.cfg.Record)
	if err != nil {
		// The entry IS installed; reported as failed only so the run's exit
		// code reflects it, not because the write didn't land.
		a.cfg.Log.Warnf("%s: installed at %s, but the installation record could not be written (%v); "+
			"the next sync will re-install it", c.ID, c.Dest, err)
		res.Failed = append(res.Failed, EntryError{Change: c, Err: err})
		return
	}
	if wrote {
		res.RecordWrites++
	}
}

// saveRecord writes the profile rows once more for the revision, target
// list and any removals; a no-op write on an idempotent run.
func (a *Applier) saveRecord(res *Result) {
	dropped := make(map[string]map[string]struct{}, len(a.cfg.Profiles))
	noteDropped := func(rs []plan.Removal) {
		for i := range rs {
			if dropped[rs[i].Profile] == nil {
				dropped[rs[i].Profile] = map[string]struct{}{}
			}
			dropped[rs[i].Profile][entryKey(rs[i].ID, rs[i].Target)] = struct{}{}
		}
	}
	noteDropped(res.Removed)
	noteDropped(res.Retained)

	for _, ps := range a.cfg.Profiles {
		_, existed := a.cfg.Record.ProfileBySlug(ps.Slug)
		prof := a.profileRow(ps.Slug)
		if !existed && len(prof.Entries) == 0 {
			// A profile whose every entry failed gets no record row.
			continue
		}
		before := len(prof.Entries)
		if drops := dropped[ps.Slug]; len(drops) > 0 {
			kept := prof.Entries[:0:len(prof.Entries)]
			for i := range prof.Entries {
				if _, gone := drops[entryKey(prof.Entries[i].ID, prof.Entries[i].Target)]; !gone {
					kept = append(kept, prof.Entries[i])
				}
			}
			prof.Entries = kept
		}
		if len(prof.Entries) != before || prof.Revision != ps.Revision || prof.InstalledAt.IsZero() {
			prof.InstalledAt = a.cfg.Now()
		}
		prof.Revision = ps.Revision
		prof.Targets = ps.Targets
		a.cfg.Record.SetProfile(prof)
	}

	if a.cfg.Record.IsEmpty() {
		// A run that installed nothing does not create state.json.
		return
	}
	wrote, err := record.Save(a.cfg.RecordPath, a.cfg.Record)
	if err != nil {
		a.cfg.Log.Warnf("the installation record at %s could not be written (%v); what is on disk is still "+
			"installed and the next sync will reconcile it", a.cfg.RecordPath, err)
		res.Failed = append(res.Failed, EntryError{Err: err})
		return
	}
	if wrote {
		res.RecordWrites++
	}
}

// profileRow is the record's row for slug, or a new one for it.
func (a *Applier) profileRow(slug string) record.Profile {
	if p, ok := a.cfg.Record.ProfileBySlug(slug); ok {
		if rev, found := a.revisionOf(slug); found && p.Revision < 1 {
			p.Revision = rev
		}
		return p
	}
	rev, _ := a.revisionOf(slug)
	targets := []record.Target(nil)
	for _, ps := range a.cfg.Profiles {
		if ps.Slug == slug {
			targets = ps.Targets
		}
	}
	return record.Profile{Slug: slug, Revision: rev, Targets: targets}
}

// revisionOf is the requested revision for a profile, stored even when the
// sync is partial: the record's entries, not the revision, are what
// internal/plan reconciles against, so a revision ahead of a partial entry
// set changes nothing about the next run.
func (a *Applier) revisionOf(slug string) (int, bool) {
	for _, ps := range a.cfg.Profiles {
		if ps.Slug == slug {
			return ps.Revision, true
		}
	}
	return 0, false
}

func entryKey(id string, t record.Target) string { return id + "\x00" + string(t) }

// upsertEntry replaces the row keyed by (id, target) or appends it: one
// package can be installed for two targets, into two different roots.
func upsertEntry(entries []record.Entry, e record.Entry) []record.Entry {
	for i := range entries {
		if entries[i].ID == e.ID && entries[i].Target == e.Target {
			entries[i] = e
			return entries
		}
	}
	return append(entries, e)
}

// sweepAsides removes the `.amctl-old` left beside every planned destination.
// It runs over the WHOLE plan, not just this run's writes, because Swap's
// step 5 cleanup is non-fatal and step 1 is the only other remover — once an
// entry goes Unchanged, Swap never runs for it again, so an aside Swap
// couldn't clean up would otherwise sit there forever (and later make step 1
// fatal). It skips an aside whose destination is absent: that shape means
// Swap crashed mid-rename and step 1 still needs to reclaim it as the entry.
func (a *Applier) sweepAsides(p plan.Plan, res *Result) {
	res.Leftovers = nil
	for _, dest := range plannedDests(p) {
		if err := a.sweepAside(dest); err != nil {
			res.Leftovers = append(res.Leftovers, dest+AsideSuffix)
			a.cfg.Log.Warnf("%s could not be removed (%v); it is a leftover copy of an earlier version of %s "+
				"and is safe to delete by hand — amctl will keep trying, and every change to that entry fails until it goes",
				dest+AsideSuffix, err, dest)
		}
	}
}

// sweepAside reports an error only when an aside was observed to exist and
// its removal failed; every other outcome (outside the home, no parent, no
// aside) returns nil since none of those is evidence of a leftover.
func (a *Applier) sweepAside(dest string) error {
	cont, err := a.cfg.Home.Contains(dest)
	if err != nil {
		return nil //nolint:nilerr // see the comment above: not evidence of a leftover
	}
	parent, name, err := splitDest(cont.Dest)
	if err != nil {
		return nil //nolint:nilerr // as above
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil //nolint:nilerr // as above
	}
	defer func() { _ = root.Close() }()

	asideName := name + AsideSuffix
	if _, lerr := root.Lstat(asideName); lerr != nil {
		return nil //nolint:nilerr // as above
	}
	if _, derr := root.Lstat(name); errors.Is(derr, fs.ErrNotExist) {
		// The interrupted-swap shape: the aside is the only copy. Swap's step 1
		// puts it back; this must not delete it.
		return nil
	}
	return root.RemoveAll(asideName)
}

// plannedDests is every destination a plan mentions, deduplicated; a
// converged (Unchanged) entry still qualifies since it can carry an aside.
func plannedDests(p plan.Plan) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, p.ChangeCount()+len(p.Unchanged))
	add := func(dest string) {
		if dest == "" {
			return
		}
		if _, dup := seen[dest]; dup {
			return
		}
		seen[dest] = struct{}{}
		out = append(out, dest)
	}
	for _, set := range [][]plan.Change{p.Add, p.Upgrade, p.Downgrade, p.Unchanged} {
		for i := range set {
			add(set[i].Dest)
		}
	}
	for i := range p.Remove {
		add(p.Remove[i].Dest)
	}
	return out
}

// pruneStaging removes the shared .amctl-staging directory beside each
// destination this run touched, once and only when empty; best effort.
func (a *Applier) pruneStaging(p plan.Plan) {
	seen := map[string]struct{}{}
	writes := p.Writes()
	for i := range writes {
		dest := writes[i].Dest
		parent := filepath.Dir(dest)
		if _, done := seen[parent]; done {
			continue
		}
		seen[parent] = struct{}{}
		if err := PruneStagingRoot(dest); err != nil {
			a.cfg.Log.Debugf("could not remove the staging directory beside %s: %v", dest, err)
		}
	}
}

// Home is the invoking user's home: Contains proves a destination resolves
// inside it before anything is opened, by EvalSymlinks plus a string prefix
// check, not by an os.Root on the home — os.Root refuses every absolute
// symlink target, which would break the common `ln -s ~/dotfiles/x ~/.claude`
// setup. Do not "simplify" this to a structural root check on the home; the
// os.Root confinement that matters happens per-entry, below this check, in
// archive.Extract, Stage and Swap.
type Home struct {
	requested string
	resolved  string
}

// Contained is a destination that has been proven to live inside the home.
type Contained struct {
	// Dest is the REQUESTED path. It is what gets written and what gets
	// recorded, deliberately: the record's destination has to be the path
	// internal/layout derives, or the next run's plan reads it as a relocation
	// and removes and re-adds the entry forever.
	Dest string

	// Resolved is Dest with every existing symlink resolved; nothing is
	// written to it, since that would bypass a symlink the user put there on purpose.
	Resolved string
}

// OpenHome resolves dir (must be absolute and exist) and returns the
// containment check for it.
func OpenHome(dir string) (*Home, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: no home directory given", ErrOutsideHome)
	}
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("%w: home %s is not absolute", ErrOutsideHome, dir)
	}
	clean := filepath.Clean(dir)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot resolve home %s: %w", ErrOutsideHome, clean, err)
	}
	return &Home{requested: clean, resolved: filepath.Clean(resolved)}, nil
}

func (h *Home) Path() string { return h.requested }

// Resolved is the home with every symlink resolved; kept separately from
// Path because a destination is checked lexically against one and by
// resolution against the other.
func (h *Home) Resolved() string { return h.resolved }

// Contains proves dest is inside the home, called before dest is opened.
func (h *Home) Contains(dest string) (Contained, error) {
	if _, _, err := splitDest(dest); err != nil {
		return Contained{}, err
	}
	// Lexical, not the security check (a symlink defeats it), but it keeps
	// the message on-topic for a destination from the wrong root entirely.
	if err := relUnder(h.requested, dest); err != nil {
		return Contained{}, fmt.Errorf("%w: %s is not under %s", ErrOutsideHome, dest, h.requested)
	}

	existing, tail, err := deepestExisting(h.requested, dest)
	if err != nil {
		return Contained{}, err
	}
	resolvedPrefix, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return Contained{}, fmt.Errorf("%w: cannot resolve %s: %w", ErrOutsideHome, existing, err)
	}
	if err := underOrEqual(h.resolved, resolvedPrefix); err != nil {
		return Contained{}, fmt.Errorf(
			"%w: %s resolves to %s, which is outside %s; amctl installs under the invoking user's home and "+
				"will not follow a link out of it", ErrOutsideHome, dest, resolvedWithTail(resolvedPrefix, tail), h.resolved)
	}
	return Contained{Dest: dest, Resolved: resolvedWithTail(resolvedPrefix, tail)}, nil
}

// deepestExisting walks up from dest until something exists, returning that
// path plus the components below it; it stops at home, which OpenHome
// already proved exists.
func deepestExisting(home, dest string) (existing string, tail []string, err error) {
	p := dest
	for {
		if _, serr := os.Lstat(p); serr == nil {
			return p, tail, nil
		} else if !errors.Is(serr, fs.ErrNotExist) {
			return "", nil, fmt.Errorf("inspect %s: %w", p, serr)
		}
		parent, leaf := filepath.Dir(p), filepath.Base(p)
		if parent == p {
			return "", nil, fmt.Errorf("%w: nothing on the path to %s exists, not even the filesystem root",
				ErrOutsideHome, dest)
		}
		tail = append([]string{leaf}, tail...)
		if p == home {
			return "", nil, fmt.Errorf("%w: the home %s does not exist", ErrOutsideHome, home)
		}
		p = parent
	}
}

func resolvedWithTail(resolvedPrefix string, tail []string) string {
	if len(tail) == 0 {
		return resolvedPrefix
	}
	return filepath.Join(append([]string{resolvedPrefix}, tail...)...)
}

// relUnder reports whether p is strictly underneath base (the home itself
// is not a legal destination); filepath.Rel, not strings.HasPrefix, since a
// prefix match is wrong at a component boundary (/home/user2 vs /home/user).
func relUnder(base, p string) error {
	rel, err := rel(base, p)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%s is %s itself", p, base)
	}
	return nil
}

// underOrEqual is relUnder with equality allowed, for the resolved prefix:
// on a never-synced machine that prefix IS the home directory itself, and a
// strict check there would refuse every fresh install as "outside home".
func underOrEqual(base, p string) error {
	_, err := rel(base, p)
	return err
}

func rel(base, p string) (string, error) {
	r, err := filepath.Rel(base, p)
	if err != nil {
		return "", err
	}
	if r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is not under %s", p, base)
	}
	return r, nil
}
