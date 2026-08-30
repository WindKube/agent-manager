package apply

// This file is T042: execute a plan.Plan. It is the only thing in amctl that
// puts a package on disk, and the ORDER below is the whole of FR-024, FR-025
// and FR-028. Read it before changing anything here.
//
//	per entry:  contain -> guard -> fetch -> stage -> hash -> SWAP -> RECORD
//	per run:    refuse on conflicts BEFORE the first entry; prune staging last
//
// WHY THE RECORD IS LAST, AND WHY IT IS PER ENTRY. Last, because a record
// written before the swap describes a tree that does not exist yet, and a crash
// between the two leaves a lie on disk that prune would act on. Per entry, and
// not once at the end, because the interruption case has to CONVERGE: a run
// killed after entry three's swap must leave three recorded entries, not three
// unrecorded directories that the next run's FR-028 guard would then refuse as
// somebody else's files. record.Save writes nothing when the bytes are
// unchanged, so the per-entry write costs nothing on an idempotent run.
//
// The residual one-entry window — swap done, record write not yet — is closed by
// the FR-022 marker: a destination carrying amctl's own marker for the same id
// and target is amctl's leftover from an interrupted run and is adopted rather
// than refused. That is the only place a marker influences a decision, and it
// influences an OVERWRITE, never a removal. Prune consults state.json and
// nothing else (FR-028).
//
// WHAT THIS FILE DELIBERATELY DOES NOT DO:
//
//   - It does not download. Bundle bytes arrive through BundleSource, already
//     digest-verified (FR-014) by internal/hub, which is the only place that
//     check may live. Nothing here re-checks it and nothing here may accept an
//     io.Reader, because a reader is something a caller could hand over
//     unverified.
//   - It does not resolve a version, order two versions or read a range
//     (FR-009). Change.Version is carried verbatim from the hub's lockfile into
//     the marker and the record.
//   - It does not compute a destination. Change.Dest comes from internal/layout
//     through internal/plan, both pure. This file checks the destination and
//     writes to it.
//   - It does not remove anything from the agent tree. Removals are T048's
//     prune.go, reached through the Pruner seam; with no pruner wired, a
//     planned removal is REPORTED AS NOT DONE and makes the run's error
//     non-nil. A sync that reports success while having removed nothing is the
//     failure this package exists to prevent.
//   - It does not hash a tree. R4's fingerprint is internal/record's algorithm
//     (T049), reached through the Fingerprinter seam. With no fingerprinter,
//     entries are recorded unfingerprinted — which the record permits and which
//     later reads as "unverifiable", i.e. a refusal naming --force, never an
//     assumption of unmodified.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ErrOutsideHome is FR-020: a destination whose RESOLVED path is not inside the
// invoking user's home. See Home for what "resolved" means and why it is not
// the same question as "is this path lexically under $HOME".
var ErrOutsideHome = errors.New("destination resolves outside the invoking user's home")

// ErrUnrecorded is FR-028: something is at the destination and amctl's own
// record does not claim it. Overwriting it would destroy a file amctl did not
// write, which is the one thing the record exists to make impossible.
var ErrUnrecorded = errors.New("destination exists and is not in amctl's installation record")

// ErrModified is FR-029: the destination is amctl's, and it has changed since
// amctl wrote it. The entry is preserved and reported.
var ErrModified = errors.New("destination has been modified since it was installed")

// ErrUnverifiable is FR-029's fail-closed half: the destination is amctl's, and
// whether it has changed CANNOT be established — the record carries no
// fingerprint, or this build has no verifier for the one it carries. Assuming
// unmodified is the direction that deletes somebody's work, so it is not
// available; the refusal names --force.
var ErrUnverifiable = errors.New("destination cannot be verified as unmodified")

// ErrPruneUnavailable is what a planned removal becomes in a build with no
// Pruner wired. It is an error and not a warning on purpose: the alternative is
// a sync that exits 0 having removed nothing, which is indistinguishable from
// one that had nothing to remove.
var ErrPruneUnavailable = errors.New("this build cannot execute a removal")

// ErrConfig marks an Applier that cannot be constructed.
var ErrConfig = errors.New("invalid apply configuration")

// Logger is the diagnostic stream, narrowed to what this package emits.
// *output.Streams satisfies it; the interface is local so that internal/apply
// does not depend on the renderer and so a test can capture lines.
type Logger interface {
	Warnf(format string, args ...any)
	Debugf(format string, args ...any)
}

// BundleSource supplies the verified bytes for one planned change.
//
// It takes a plan.Change and not a URL, an id or a hub reference, because
// building the bundle path is internal/hub's — and the bundle path's
// `{publisher}` parameter is the NAMESPACE, a trap this package must not be in
// a position to fall into. The caller (internal/cmd/sync.go) holds the lockfile
// entries that hub.ParseBundleRef needs and is the right place to pair them
// with a downloader.
//
// The contract on the returned bytes: they hash to Change.Digest, and that was
// checked before they were handed over (FR-014). Nothing here verifies it
// again, so an implementation that skips the check breaks FR-014 silently.
type BundleSource interface {
	Bundle(ctx context.Context, c plan.Change) ([]byte, error)
}

// Fingerprinter is internal/record's R4 mechanism (T049), injected because the
// algorithm belongs to the record and the record must be able to change it
// without this file knowing.
//
// It is two calls because R4 requires two moments and they are not
// interchangeable: content is hashed from the STAGED tree, before the swap,
// where the extractor's caps have just bounded what can be read; permission
// bits and kinds are read with lstat from the entry AS ACTUALLY WRITTEN, after
// the swap, never from the archive header — measured, under umask 0027 a
// requested 0755 lands as 0750, so recording the header's mode reports a mode
// conflict on every executable file on the very next sync.
type Fingerprinter interface {
	Hash(staged *Staged) (record.Fingerprint, error)
	Modes(dest string, fp record.Fingerprint) (record.Fingerprint, error)
}

// Verifier answers FR-029 for an entry the record already claims.
//
// Modifications names every path under e.Dest that differs from what the record
// says was installed, entry-root-relative. An empty slice means unmodified, and
// only that verdict permits an overwrite; an error means unverifiable, which is
// a refusal.
type Verifier interface {
	Modifications(e record.Entry) ([]string, error)
}

// Pruner executes one planned removal (T048's prune.go, FR-027/FR-028). It
// reports whether anything was removed from disk.
type Pruner interface {
	Remove(ctx context.Context, r plan.Removal) (bool, error)
}

// ProfileState is what the record needs about a profile and the plan does not
// carry: the resolved revision and the targets actually written.
//
// Revision must be the RESOLVED number (FR-013). `head` is a request, not a
// state, and record.Profile refuses anything below 1.
type ProfileState struct {
	Slug     string
	Revision int
	Targets  []record.Target
}

// Config builds an Applier. Home, Record, RecordPath and Bundles are required;
// the four seams and the logger are optional and each has a documented
// consequence when absent.
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

	// Force overrides the three destination refusals — a symlink, an
	// unrecorded destination, an unverified modification — and every override
	// NAMES what it is about to destroy on the diagnostic stream. A --force
	// that destroys silently is worse than no --force.
	Force bool

	// Now defaults to time.Now. It stamps Profile.InstalledAt, and only when
	// the profile's entries or revision actually change: refreshing it on an
	// unchanged sync would rewrite state.json on every run and make FR-025
	// false of the record while being true of the tree.
	Now func() time.Time
}

// Applier executes plans against one home and one installation record.
type Applier struct {
	cfg Config
}

// New validates a Config and returns an Applier.
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

// Installed is one entry that landed.
type Installed struct {
	Change plan.Change
	Entry  record.Entry
	Swap   SwapResult
}

// EntryError is one entry that did not land, and whether the user can fix it.
type EntryError struct {
	Change plan.Change

	// Removal is set instead of Change when the failure is a planned removal.
	Removal *plan.Removal

	Err error

	// Refusal marks a failure that happened BEFORE anything was staged and that
	// the user can act on: a containment failure, an unrecorded destination, an
	// unverifiable or modified destination. internal/cmd maps it to FR-036's
	// "refusal the user can fix" exit code; everything else is an unexpected
	// failure.
	Refusal bool
}

func (e *EntryError) Error() string {
	who, target := e.Change.ID, e.Change.Target
	if e.Removal != nil {
		who, target = e.Removal.ID, e.Removal.Target
	}
	if who == "" {
		// A run-level failure, which today means the final record write.
		return e.Err.Error()
	}
	return fmt.Sprintf("%s (%s): %v", who, target, e.Err)
}

func (e *EntryError) Unwrap() error { return e.Err }

// Result is what one Apply did, entry by entry. It is the input to the partial
// report a failed sync owes (plan.md Risks): which entries landed, which are
// untouched, and why.
type Result struct {
	Installed []Installed
	Unchanged []plan.Change
	Removed   []plan.Removal

	// Retained are removals the plan resolved by dropping a record row while
	// another profile still claims the destination. Nothing on disk is touched.
	Retained []plan.Removal

	Failed []EntryError

	// Leftovers are `.amctl-old` paths a swap could not remove (an open handle,
	// routinely on Windows). Each is already inside the entry's removable set,
	// so the next swap of the same entry discards it; the caller reports them
	// and does nothing else.
	Leftovers []string

	// RecordWrites counts the times state.json actually changed on disk. Zero
	// on a fully idempotent run, which is what makes FR-025 assertable about
	// the record and not only about the tree.
	RecordWrites int
}

// Refusals are the failures a user can fix.
func (r *Result) Refusals() []EntryError { return r.filter(true) }

// Failures are the failures a user cannot fix by editing their own tree.
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

// Err joins every per-entry failure, so a sync of twelve entries that failed at
// the seventh still installed the other eleven AND still exits non-zero.
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

// Apply executes p. It returns a Result even when it returns an error: the
// Result is the partial report, and discarding it loses the account of what
// landed.
//
// A plan with conflicts is refused before a single byte is staged (FR-012,
// FR-023, R2's unwritable target). That check is first for a reason — a
// version-split conflict discovered halfway through has already installed one
// of the two versions.
func (a *Applier) Apply(ctx context.Context, p plan.Plan) (*Result, error) {
	res := &Result{}
	if p.Refuses() {
		return res, p.ConflictError()
	}
	if err := a.checkProfiles(p); err != nil {
		return res, err
	}

	res.Unchanged = p.Unchanged
	writes := p.Writes()
	for i := range writes {
		c := writes[i]
		if err := ctx.Err(); err != nil {
			res.Failed = append(res.Failed, EntryError{Change: c, Err: err})
			joined := res.Err()
			return res, joined
		}
		a.applyChange(ctx, c, res)
	}
	a.applyRemovals(ctx, p, res)
	a.saveRecord(res)
	a.pruneStaging(p)
	joined := res.Err()
	return res, joined
}

// checkProfiles refuses a plan naming a profile the caller did not describe.
// Without it the record would be written with a revision of zero, which
// record.Profile refuses — but at Save time, after the tree was already
// changed, which is the wrong moment to discover it.
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
		a.cfg.Log.Warnf("%s: could not remove %s (%v); it will be cleaned up on the next sync of this entry",
			c.ID, leftover, inst.Swap.RemoveAsideErr)
		res.Leftovers = append(res.Leftovers, leftover)
	}
	res.Installed = append(res.Installed, *inst)

	// The record write for THIS entry, immediately after its swap. See the file
	// comment on why it is per entry and not once at the end.
	a.recordEntry(c, inst.Entry, res)
}

// install is stage -> hash -> swap -> read modes. Every failure before the swap
// leaves the destination untouched; a failure at the swap has already rolled
// back (see Swap step 3).
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

// hash takes R4's content half from the staged tree. A fingerprinter that fails
// FAILS THE ENTRY: an entry installed with no fingerprint can never be checked
// for modification afterwards, so continuing would trade FR-029 for one install.
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

// modes fills in the lstat half, AFTER the swap. A failure here does NOT fail
// the entry — the entry is installed and readable, and failing it would report a
// broken install for a working one — but the fingerprint is then dropped rather
// than half-written, because a partial fingerprint would report every unrecorded
// file as an addition on the next run. An absent fingerprint reads as
// unverifiable, which is a refusal naming --force: the safe direction.
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

// markerFor builds FR-022's provenance marker.
//
// The marker is assembled here rather than carried on the plan because the plan
// is pure and the marker is a file: layout owns its shape (Marker, its schema
// version and MarkerFileName), this owns writing it. It is written INTO the
// staged tree so it arrives with the same single rename as the rest of the entry
// (FR-024) and is inside R4's fingerprint of the tree as installed.
//
// MarkerFileName assumes the entry root is a DIRECTORY, which is true of every
// shipped target — R2 ships claude-code skills only. A target whose unit is a
// single file needs a decision about where its provenance goes, and this is the
// line that has to change; it is not a silent assumption elsewhere.
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

// guard is FR-028 and FR-029 at the one moment they can be enforced: after the
// destination has been proven to be inside the home and before anything is
// staged into it.
//
// Swap is unconditional by design — it replaces whatever is at the destination,
// including a symlink — so this function is the only thing standing between a
// sync and somebody's hand-written skill.
func (a *Applier) guard(c plan.Change, cont Contained) error {
	st, err := inspectDest(cont)
	if err != nil {
		return err
	}
	switch {
	case !st.exists:
		if c.From != nil {
			// The record claims an entry that is not on disk. Re-installing is
			// the convergent answer; the record row is corrected by this run.
			a.cfg.Log.Warnf("%s: the record claims %s at %s but nothing is there; re-installing",
				c.ID, c.From.Version, c.Dest)
		}
		return nil

	case st.symlink:
		// amctl never creates a symlink at a destination — extraction refuses
		// symlink members (FR-019) — so this is somebody else's. It is refused
		// rather than followed, and replaced rather than written through when
		// --force is given: following it is exactly how amctl would write
		// outside the home without ever constructing a path outside it.
		return a.override(fmt.Errorf("%w: %s is a symlink to %s, which amctl did not create",
			ErrUnrecorded, c.Dest, orUnknown(st.linkTarget)),
			"%s: --force is replacing the symlink %s -> %s; whatever it points at is left alone",
			c.ID, c.Dest, orUnknown(st.linkTarget))

	case c.From == nil:
		// Nothing in the record claims this path. The one legitimate case is
		// amctl's own leftover from a run killed between the swap and the record
		// write, which the marker identifies.
		if st.marker != nil && st.marker.ID == c.ID && st.marker.Target == c.Target {
			a.cfg.Log.Warnf("%s: %s holds amctl's marker for %s but no record row; a previous sync was "+
				"interrupted between the install and the record write, so it is being re-installed",
				c.ID, c.Dest, st.marker.Version)
			return nil
		}
		return a.override(fmt.Errorf("%w: %s already exists", ErrUnrecorded, c.Dest),
			"%s: --force is replacing %s, which amctl's record does not claim", c.ID, c.Dest)

	case st.marker != nil && st.marker.ID == c.ID && st.marker.Target == c.Target &&
		st.marker.Version == c.Version && c.From.Version != c.Version:
		// The record and the tree disagree, and the TREE is already at the
		// version being installed. The only thing that produces that state is a
		// run killed between the swap and the record write, and the FR-022
		// marker — amctl's own file, written into the staged tree before the
		// swap — is the proof.
		//
		// The branch above does the same for an entry the record does not claim
		// at all; this is the same interruption on an UPGRADE, where the record
		// still names the old version. Without it, verifyUnmodified demands a
		// positive unmodified verdict for a version that is no longer on disk,
		// gets none, and refuses — so `sync` exits non-zero forever on a machine
		// whose tree is already correct, until a human passes --force. T046
		// measured exactly that.
		//
		// The guard is deliberately narrow. `c.From.Version != c.Version` is
		// what keeps it to the interrupted case: when the record and the tree
		// agree there is no change to apply, so a marker matching the target
		// version while the record names a different one is not a state any
		// completed run can leave. It never widens to "the marker says it is
		// ours, so overwrite" — that would silence verifyUnmodified for every
		// upgrade and hand back the user-edit protection it exists to give.
		a.cfg.Log.Warnf("%s: %s already holds %s and amctl's marker for it, but the record still names %s; "+
			"a previous sync was interrupted between the install and the record write, so the record is being caught up",
			c.ID, c.Dest, c.Version, c.From.Version)
		return nil

	default:
		return a.verifyUnmodified(c)
	}
}

// verifyUnmodified requires a POSITIVE unmodified verdict before an overwrite.
// Absence of evidence is not evidence of absence here: an entry with no
// fingerprint, or a fingerprint this build cannot verify, is refused.
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

// override returns refusal unless --force, and when --force is given it NAMES
// what is about to be destroyed on the diagnostic stream. Every --force path in
// this file goes through here so that none of them can be silent.
func (a *Applier) override(refusal error, format string, args ...any) error {
	if !a.cfg.Force {
		return fmt.Errorf("%w; re-run with --force to overwrite it", refusal)
	}
	a.cfg.Log.Warnf(format, args...)
	return nil
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

// inspectDest lstats the destination and, when it is a directory, reads the
// FR-022 marker out of it.
//
// The marker is read through an *os.Root opened on the destination, so a symlink
// planted where the marker should be cannot make amctl read a file elsewhere,
// and — the half that is easy to miss — so the read passes FILE_SHARE_DELETE on
// Windows and does not deny the swap's own rename of this very directory.
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
		// A marker amctl cannot parse is treated as no marker: it is provenance,
		// not authority, and guessing at a format this build does not know would
		// give a confident wrong answer about whose directory this is.
		return st, nil
	}
	st.marker = &m
	return st, nil
}

// applyRemovals routes the plan's removals: the ones the plan itself resolved by
// dropping a record row, and the ones that need prune.go.
func (a *Applier) applyRemovals(ctx context.Context, p plan.Plan, res *Result) {
	for i := range p.Remove {
		r := p.Remove[i]
		if !r.RemovesFromDisk() {
			// Another profile still claims this destination. The row goes, the
			// directory stays; removing it would delete a package the other
			// profile still wants.
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
		// The entry IS installed. A record that does not mention it means the
		// next run re-installs it (recoverable) — while failing the entry here
		// would claim an install did not happen when it did.
		a.cfg.Log.Warnf("%s: installed at %s, but the installation record could not be written (%v); "+
			"the next sync will re-install it", c.ID, c.Dest, err)
		res.Failed = append(res.Failed, EntryError{Change: c, Err: err})
		return
	}
	if wrote {
		res.RecordWrites++
	}
}

// saveRecord writes the profile rows once more at the end, for the revision, the
// target list and the rows dropped by removals. record.Save writes nothing when
// the bytes are unchanged, so on an idempotent run this is free and
// Result.RecordWrites stays zero.
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
			// A profile whose every entry failed gets NO record row. A row with
			// no entries claiming a revision describes nothing that is
			// installed, and creating one would also rewrite state.json on a run
			// that changed nothing on disk.
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
		// An absent state.json and one describing nothing are the same
		// statement, so a run that installed nothing does not create the file.
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

// profileRow is the record's row for slug, or a new one carrying the requested
// revision and targets.
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

// revisionOf is the requested revision for a profile.
//
// The requested revision is stored even when the sync is PARTIAL, and that is a
// decision rather than an oversight: the record's ENTRIES are the authority for
// what is installed, and internal/plan reconciles against them and never against
// the revision, so a revision ahead of a partial entry set costs nothing and
// changes nothing about what the next run does. Storing the old revision instead
// would need a second code path, and record.Profile refuses a revision below 1,
// so a brand-new partially installed profile could not be written at all.
func (a *Applier) revisionOf(slug string) (int, bool) {
	for _, ps := range a.cfg.Profiles {
		if ps.Slug == slug {
			return ps.Revision, true
		}
	}
	return 0, false
}

func entryKey(id string, t record.Target) string { return id + "\x00" + string(t) }

// upsertEntry replaces the row for (id, target) or appends it. The slot is
// (id, target) and not id, because one package may legitimately be installed
// for two targets, into two different roots.
func upsertEntry(entries []record.Entry, e record.Entry) []record.Entry {
	for i := range entries {
		if entries[i].ID == e.ID && entries[i].Target == e.Target {
			entries[i] = e
			return entries
		}
	}
	return append(entries, e)
}

// pruneStaging removes the shared .amctl-staging directory beside each
// destination this run touched, once, and only when it is empty. Best effort: an
// empty directory left behind is tidiness, not correctness.
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

// ---------------------------------------------------------------------------
// FR-020 containment
// ---------------------------------------------------------------------------

// Home is the invoking user's home directory, and the answer to FR-020: amctl
// installs under it and writes nothing outside it.
//
// THE CHECK IS ON THE RESOLVED PATH, NOT THE REQUESTED ONE. An agent directory
// is frequently a symlink into a dotfiles repo, so `$HOME/.claude/skills/x` says
// nothing about where the bytes land; `~/.claude -> /etc/whatever` is precisely
// how amctl would write outside the home without ever constructing a path
// outside it. Contains therefore resolves the deepest EXISTING prefix of a
// destination and requires THAT to be inside the resolved home.
//
// WHY THIS IS NOT os.Root DOING IT STRUCTURALLY, WHICH IS THE OBVIOUS DESIGN
// AND IS WRONG. Measured on go1.26, linux/arm64, with a root opened on the home:
//
//	~/.x -> dotfiles/claude          (relative, inside)  Root.Lstat  -> nil
//	~/.x -> ../outside               (relative, escapes) Root.Lstat  -> "path escapes from parent"
//	~/.x -> /home/u/dotfiles/claude  (ABSOLUTE, inside)  Root.Lstat  -> "path escapes from parent"
//
// os.Root refuses every ABSOLUTE symlink target, wherever it points, because it
// has no way to re-anchor an absolute path inside the root. `ln -s
// ~/dotfiles/claude ~/.claude` expands to an absolute target, so a structural
// root check on the home would refuse the commonest dotfiles setup there is —
// the exact case R3 says must keep working, and the case that turns a
// containment check into "no symlinks". So the entry-root check is
// filepath.EvalSymlinks plus a component-wise prefix comparison: a string
// comparison, named as one.
//
// THE STRUCTURAL HALF THAT SURVIVES, and it is the larger half by volume:
// everything BELOW a checked destination is confined by *os.Root and not by any
// string. archive.Extract creates the staged tree through a root and refuses
// symlink members (FR-019); Stage opens .amctl-staging through a root on the
// parent, having lstat-ed it for a planted symlink; Swap performs every rename,
// remove and stat through a root on the destination's parent. So the resolution
// check governs one path per entry — the entry root — and the root governs every
// path inside it.
//
// WHAT IS NOT CLOSED: the window between resolving a prefix and writing through
// it. A local attacker who can create symlinks inside the agent tree while a
// sync is running can move a checked destination afterwards. What bounds it is
// the per-home lock (FR-038), the fact that the tree is the user's own, and
// Swap's refusal to follow a symlink at the destination — it renames the link
// aside and installs beside it, so a link planted at the leaf redirects nothing.
// A TOCTOU-free version needs the destination's parent opened as a root by this
// type and handed to Stage and Swap, which is a change to their signatures and
// not to their behaviour.
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

	// Resolved is Dest with every existing symlink resolved. It is what FR-020
	// was checked on and what a diagnostic should name; nothing is written to
	// it, because writing to it would silently bypass a symlink the user put
	// there on purpose.
	Resolved string
}

// OpenHome resolves dir and returns the containment check for it.
//
// dir must be absolute and must exist. Neither is checked here as a courtesy:
// FR-039 requires the refusal for an unset or unwritable home to name the
// variable and to happen before any network request, and that check is
// internal/cmd.ResolveHome's. This one refuses a home it cannot resolve because
// an unresolvable home makes every containment answer meaningless.
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

// Path is the home as it was given.
func (h *Home) Path() string { return h.requested }

// Resolved is the home with every symlink resolved. Both are kept because the
// two comparisons need different sides: a destination is lexically under the
// REQUESTED home, and its resolution is under the RESOLVED home.
func (h *Home) Resolved() string { return h.resolved }

// Contains proves dest is inside the home, and is called before dest is opened.
//
// It refuses, in order: a destination that is not a usable install path at all
// (empty, relative, unclean, or ending in the swap's aside suffix); one that is
// not lexically under the home; one whose deepest existing prefix cannot be
// resolved; and one whose resolution is outside the resolved home.
func (h *Home) Contains(dest string) (Contained, error) {
	if _, _, err := splitDest(dest); err != nil {
		return Contained{}, err
	}
	// The lexical side. It is not the security check — a symlink defeats it —
	// but it is what keeps the message about the right thing when a destination
	// was derived from the wrong root entirely, and it runs before any stat.
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

// deepestExisting walks up from dest until something exists, and returns that
// path plus the components below it.
//
// It stops at the home, which OpenHome established exists, so the walk
// terminates. os.Lstat and not a root method: this is a stat, it follows no
// final symlink and it holds no handle open, so it cannot deny another process
// the delete access the Windows measurement is about.
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

// relUnder reports whether p is STRICTLY underneath base. The home itself is
// not a legal install destination, so equality is a refusal here.
//
// filepath.Rel is used rather than strings.HasPrefix because a prefix match is
// wrong at a component boundary: /home/user2 has /home/user as a string prefix
// and is a different person's home.
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

// underOrEqual is relUnder with equality allowed, which is the right predicate
// for the RESOLVED PREFIX rather than for the destination: on a machine that has
// never synced, the deepest existing path on the way to
// ~/.claude/skills/<pkg> is the home directory itself. Refusing that — which is
// what a single strict predicate for both sides does — refuses every install on
// a fresh machine, and it does so with an "outside your home" message about a
// path that is plainly inside it.
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
