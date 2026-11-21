package apply

// Each entry runs contain -> guard -> fetch -> stage -> hash -> swap -> record,
// never batched, so a crash mid-run converges: a swap with no record yet is
// recognised by amctl's provenance marker and adopted.

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

// ErrComponentConflict marks a plugin component whose place is held by
// something amctl did not write there for this entry.
var ErrComponentConflict = errors.New("plugin component conflicts with what is already there")

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

// ComponentSkip is one plugin component a target does not receive, and why.
type ComponentSkip struct {
	Kind   record.ComponentKind
	Name   string
	Reason string
}

// Components places a plugin's parts outside its own directory.
type Components interface {
	// Prepare reads the plugin at stagedDir and checks every guard against
	// what is on disk now; it writes nothing. prev is what this destination's
	// entries already own, others is what every other entry owns.
	Prepare(ctx context.Context, c plan.Change, stagedDir string, prev, others []record.Component) (Delivery, error)

	// Remove deletes recorded components, returning those it had to keep.
	Remove(ctx context.Context, target record.Target, comps []record.Component) ([]record.Component, error)
}

// Delivery is one prepared plugin placement; Apply runs after the plugin's
// own directory is swapped in, and returns what it placed even on error.
type Delivery interface {
	Skipped() []ComponentSkip
	Apply(ctx context.Context) ([]record.Component, error)
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
	Components   Components // nil fails every plugin entry
	Log          Logger

	Force bool // overrides symlink/unrecorded/unverified refusals, always naming what it destroys

	Now func() time.Time // stamps Profile.InstalledAt on change; defaults to time.Now

	// Continue is asked before each entry whether this run still owns the
	// lock, so a holder declared stale stops before two Swaps race one entry.
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
	Change  plan.Change
	Entry   record.Entry
	Swap    SwapResult
	Skipped []ComponentSkip
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
	if who == "" { // a run-level failure, e.g. the final record write
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

	// The plan never consults disk, so an unchanged entry whose destination
	// vanished is re-installed rather than reported as a success.
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
	if inst == nil {
		res.Failed = append(res.Failed, EntryError{Change: c, Err: err, Refusal: isRefusal(err)})
		return
	}
	if leftover := inst.Swap.LeftoverAside(); leftover != "" {
		a.cfg.Log.Debugf("%s: the swap could not remove %s (%v); it is retried at the end of this run",
			c.ID, leftover, inst.Swap.RemoveAsideErr)
	}
	res.Installed = append(res.Installed, *inst)
	a.recordEntry(c, inst.Entry, res)
	if err != nil {
		res.Failed = append(res.Failed, EntryError{Change: c, Err: err})
	}
}

func isRefusal(err error) bool {
	return errors.Is(err, ErrModified) || errors.Is(err, ErrUnrecorded) || errors.Is(err, ErrComponentConflict)
}

// install stages, hashes, swaps and places plugin components; every failure
// before the swap leaves the destination untouched. A non-nil Installed with
// an error is a plugin whose components only partly landed.
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

	var delivery Delivery
	if c.Kind == record.KindPlugin {
		if a.cfg.Components == nil {
			a.discard(c, staged)
			return nil, fmt.Errorf("%w: plugin %s: this build has no component delivery wired", ErrConfig, c.ID)
		}
		prev, others := a.componentClaims(c)
		delivery, err = a.cfg.Components.Prepare(ctx, c, staged.Path, prev, others)
		if err != nil {
			a.discard(c, staged)
			return nil, err
		}
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
	inst := &Installed{
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
	}
	if delivery == nil {
		return inst, nil
	}
	inst.Skipped = delivery.Skipped()
	comps, derr := delivery.Apply(ctx)
	inst.Entry.Components = comps
	if derr != nil {
		inst.Entry.Partial = true
		return inst, fmt.Errorf("plugin %s was only partly placed: %w", c.ID, derr)
	}
	return inst, nil
}

// componentClaims splits the record's components into those owned at this
// destination (any profile: a shared install shares its parts) and the rest.
func (a *Applier) componentClaims(c plan.Change) (prev, others []record.Component) {
	seen := map[string]bool{}
	refs := a.cfg.Record.Refs()
	for i := range refs {
		ref := &refs[i]
		for _, comp := range ref.Entry.Components {
			if ref.Entry.Dest != c.Dest {
				others = append(others, comp)
				continue
			}
			if !seen[comp.Identity()] {
				seen[comp.Identity()] = true
				prev = append(prev, comp)
			}
		}
	}
	return prev, others
}

// hash fails the entry on error, since an unfingerprinted install can never
// be checked for modification again.
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

// modes drops the whole fingerprint on error rather than keep a half-written
// one, which would misreport files as modified.
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

// markerFor builds the provenance marker, written into the staged tree so it
// rides the same rename as the entry.
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

func describeClaimants(claimants []record.Ref) string {
	out := claimants[0].Profile + "@" + claimants[0].Entry.Version
	for i := 1; i < len(claimants); i++ {
		out += ", " + claimants[i].Profile + "@" + claimants[i].Entry.Version
	}
	return out
}

// guard runs after containment and before staging. Swap replaces whatever is
// at the destination, so this is the only thing between a sync and somebody's
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
		// amctl never creates a symlink here; following it could write outside the home.
		return a.override(fmt.Errorf("%w: %s is a symlink to %s, which amctl did not create",
			ErrUnrecorded, c.Dest, orUnknown(st.linkTarget)),
			"%s: --force is replacing the symlink %s -> %s; whatever it points at is left alone",
			c.ID, c.Dest, orUnknown(st.linkTarget))

	case c.From == nil:
		// Another profile's claim means a legitimately shared install; the
		// plan's version-split check already refused any disagreement.
		if claimants := a.cfg.Record.ClaimantsOf(c.Dest); len(claimants) > 0 {
			a.cfg.Log.Debugf("%s: %s is already installed for %s; %s is adopting it",
				c.ID, c.Dest, describeClaimants(claimants), c.Profile)
			return nil
		}
		// amctl's own leftover from a run killed between swap and record write.
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
		// The tree already holds exactly this change, marker and digest: a run
		// killed between swap and record write. Never widen this to "marker
		// says ours" alone, which would bypass verifyUnmodified on every upgrade.
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
	if recorded, ok := a.recordedEntry(c.Profile, c.Target, c.ID); ok {
		prev.Fingerprint = recorded.Fingerprint
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
		// Unparseable means no marker: it is provenance, not authority.
		return st, nil
	}
	st.marker = &m
	return st, nil
}

func (a *Applier) applyRemovals(ctx context.Context, p plan.Plan, res *Result) {
	for i := range p.Remove {
		r := p.Remove[i]
		if !r.RemovesFromDisk() {
			res.Retained = append(res.Retained, r)
			continue
		}
		if r.Kind == record.KindPlugin && a.cfg.Components != nil {
			a.removePlugin(ctx, r, res)
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

func (a *Applier) recordEntry(c plan.Change, e record.Entry, res *Result) {
	prof := a.profileRow(c.Profile)
	prof.Entries = upsertEntry(prof.Entries, e)
	prof.InstalledAt = a.cfg.Now()
	a.cfg.Record.SetProfile(prof)

	wrote, err := record.Save(a.cfg.RecordPath, a.cfg.Record)
	if err != nil {
		// The entry is installed; failing it only sets the exit code.
		a.cfg.Log.Warnf("%s: installed at %s, but the installation record could not be written (%v); "+
			"the next sync will re-install it", c.ID, c.Dest, err)
		res.Failed = append(res.Failed, EntryError{Change: c, Err: err})
		return
	}
	if wrote {
		res.RecordWrites++
	}
}

// saveRecord writes the revision, target list and removals; a no-op on an
// idempotent run.
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

// revisionOf is stored even on a partial sync: the plan reconciles against
// entries, not the revision.
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

// sweepAsides removes the `.amctl-old` beside every planned destination, not
// just this run's writes: once an entry is Unchanged, Swap never runs for it
// again to clean up. An aside with no destination is left for Swap to reclaim.
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

// sweepAside errors only when an aside exists and its removal failed; nothing
// else is evidence of a leftover.
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
		// Interrupted swap: the aside is the only copy and Swap step 1 restores it.
		return nil
	}
	return root.RemoveAll(asideName)
}

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

// Home is the invoking user's home. Contains uses EvalSymlinks plus a path
// check, not an os.Root on the home: os.Root refuses absolute symlink targets,
// which would break `ln -s ~/dotfiles/x ~/.claude`. The os.Root confinement
// that matters happens per entry in archive.Extract, Stage and Swap.
type Home struct {
	requested string
	resolved  string
}

// Contained is a destination that has been proven to live inside the home.
type Contained struct {
	// Dest is the requested path, written and recorded as is; recording a
	// resolved path would make every next plan see a relocation.
	Dest string

	// Resolved is Dest with existing symlinks resolved; never written to.
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

// Resolved is the home with every symlink resolved.
func (h *Home) Resolved() string { return h.resolved }

// Contains proves dest is inside the home, called before dest is opened.
func (h *Home) Contains(dest string) (Contained, error) {
	if _, _, err := splitDest(dest); err != nil {
		return Contained{}, err
	}
	// Lexical only, for a clear message; the resolved check below is the real one.
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

// deepestExisting walks up from dest to the first existing path, returning it
// and the components below it.
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

// relUnder requires p strictly under base; filepath.Rel, not a string prefix,
// so /home/user2 is not under /home/user.
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

// underOrEqual allows equality: on a fresh machine the resolved prefix is the
// home itself.
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
