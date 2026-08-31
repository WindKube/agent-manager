// Package resolve answers one question in one place: given a profile's entries,
// the versions each entry may consider and the organisation's scan gate, what
// does each entry resolve to, and what does the screen say about it.
//
// It exists because that answer has to be the same on the profile screen, in the
// lockfile a revision freezes and in what the CLI writes to a machine. 003 T078
// states the rule: the gate's effect is computed by CALLING this, never by
// restating the gate rules in a query or a template, because two implementations
// of the gate is how the screen and the CLI start disagreeing about what is
// installed.
//
// The rules themselves are 001 FR-035 and US5 scenarios 2, 3 and 4:
//
//	block               a flagged version does not resolve; a floating entry
//	                    falls back to its most recent clean version
//	approval            an unapproved flagged version EXCLUDES the entry and says
//	                    a named reviewer has to approve it — a skip, never a
//	                    quiet downgrade
//	warn-with-override  a flagged version resolves with a warning, and an active
//	                    override is recorded on it
//
// plus FR-029, which sits above all three: a rejected version never resolves,
// whatever the gate says.
//
// PURE BY CONSTRUCTION, and internal/archcheck keeps it that way: no store, no
// blob, no HTTP. That is why nothing here takes a models.* type — it declares its
// own small input shapes and leaves every load to the caller. The constraint is a
// feature: every rule below is unit-testable with no container.
//
// Gate, Mode and Verdict are therefore hand-written copies of enums that live in
// internal/store/models, which this package may not import.
// TestTheResolversPolicyEnumsHoldExactlyTheValuesTheColumnsDo, over in that
// package, is what stops the copies drifting.
//
// Two things it deliberately does NOT do:
//
//   - It does not decide who may read a profile, a package or a version. That is
//     the caller's predicate; a candidate the caller must not show is a candidate
//     it must not pass in.
//   - It does not format a finding. Candidate.FlagDetail arrives already written,
//     because turning evidence into a phrase is a rendering decision with its own
//     escaping rules (FR-055). It carries attacker-controlled bundle text — a
//     path out of a package — and so does every Note and Skip.Detail built from
//     it. Escape them at render.
package resolve

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/Masterminds/semver/v3"
)

// Gate is the organisation's scan gate: what a flagged verdict does to a
// resolution. Copy of models.ScanGate.
type Gate string

const (
	GateBlock            Gate = "block"
	GateApproval         Gate = "approval"
	GateWarnWithOverride Gate = "warn-with-override"
)

func (g Gate) Valid() bool {
	switch g {
	case GateBlock, GateApproval, GateWarnWithOverride:
		return true
	}
	return false
}

// Mode is how one entry tracks versions. Copy of models.EntryMode.
type Mode string

const (
	ModeLatest Mode = "latest"
	ModePinned Mode = "pinned"
	ModeRange  Mode = "range"
)

func (m Mode) Valid() bool {
	switch m {
	case ModeLatest, ModePinned, ModeRange:
		return true
	}
	return false
}

// Verdict is a version's scan state. Copy of models.Verdict.
type Verdict string

const (
	VerdictScanning Verdict = "scanning"
	VerdictClean    Verdict = "clean"
	VerdictFlagged  Verdict = "flagged"
	VerdictRejected Verdict = "rejected"
)

func (v Verdict) Valid() bool {
	switch v {
	case VerdictScanning, VerdictClean, VerdictFlagged, VerdictRejected:
		return true
	}
	return false
}

// Reason is why an entry was excluded. The six values are frozen by
// contracts/lockfile.schema.json: the CLI ships separately from the hub and
// reports an unrecognised reason verbatim rather than dropping it, so adding a
// seventh is a contract change, not a commit.
type Reason string

const (
	ReasonFlaggedBlockedByGate       Reason = "flagged-blocked-by-gate"
	ReasonFlaggedAwaitingApproval    Reason = "flagged-awaiting-approval"
	ReasonVersionRejected            Reason = "version-rejected"
	ReasonNoCleanVersionAvailable    Reason = "no-clean-version-available"
	ReasonPinTargetMissing           Reason = "pin-target-missing"
	ReasonUnsignedSignaturesRequired Reason = "unsigned-and-signatures-required"
)

// Reasons returns the frozen six in the schema's own order.
func Reasons() []Reason {
	return []Reason{
		ReasonFlaggedBlockedByGate,
		ReasonFlaggedAwaitingApproval,
		ReasonVersionRejected,
		ReasonNoCleanVersionAvailable,
		ReasonPinTargetMissing,
		ReasonUnsignedSignaturesRequired,
	}
}

// Outcome is what happened to one entry. It is finer than "resolved or not"
// because the profile screen has to state the gate's effect per row, and
// "resolved" alone cannot distinguish a clean version from a flagged one that
// only got through on a reviewer's signature.
type Outcome string

const (
	// OutcomeResolved is the unremarkable case: the entry took the version it
	// wanted and the gate had nothing to do. Note is empty.
	OutcomeResolved Outcome = "resolved"
	// OutcomeWarned is a flagged version included under warn-with-override with
	// nobody's name on it (FR-035 includes them; it does not require an override
	// to exist first).
	OutcomeWarned Outcome = "warned"
	// OutcomeOverridden is a flagged version included because a reviewer accepted
	// the finding and that acceptance has not lapsed.
	OutcomeOverridden Outcome = "overridden"
	// OutcomeDowngraded is US5 scenario 2: the version the entry wanted was
	// unusable, so an older one was taken. PassedOver names the one it wanted.
	OutcomeDowngraded Outcome = "downgraded"
	// OutcomeSkipped is an exclusion. Skip is non-nil exactly here (FR-036).
	OutcomeSkipped Outcome = "skipped"
)

// Override is a reviewer accepting a finding on a version (FR-028): a name, a
// note and an expiry.
//
// The expiry is carried rather than pre-evaluated into a boolean because "an
// override that has lapsed is not an override" is a gate rule, and a gate rule
// evaluated by the caller is the second implementation this package exists to
// prevent.
type Override struct {
	Reviewer string
	Note     string
	// ExpiresAt nil means the acceptance does not lapse.
	ExpiresAt *time.Time
}

// ActiveAt reports whether this acceptance still stands at t. Nil is not an
// override, which is what lets callers pass Candidate.Override straight in.
func (o *Override) ActiveAt(t time.Time) bool {
	return o != nil && (o.ExpiresAt == nil || o.ExpiresAt.After(t))
}

// Signature is registry-side signature provenance (FR-048). Verified stays nil
// or false until cryptographic verification ships and must never be rendered as
// a pass (FR-048a); nothing here reads it, only Ref decides eligibility.
type Signature struct {
	Ref      string
	Verified *bool
}

// Candidate is one version an entry may resolve to.
//
// Digest and ObjectKey are opaque here and are carried only so that a caller
// building a lockfile entry copies them out of the result instead of going back
// to the database for the version it was just told about.
type Candidate struct {
	// ID identifies this version to the caller and must be unique within an
	// entry's candidate set. The resolver never parses it; it matches
	// Entry.PinnedID against it and nothing else.
	ID     string
	Semver string
	// Verdict must be valid: an unrecognised one is an error rather than a
	// candidate quietly treated as unusable, because a resolution that silently
	// drops a version is the failure FR-036 exists to prevent.
	Verdict Verdict
	// Visible is whether the catalog still offers this version. A floating entry
	// never picks an invisible one; an explicit pin at one still resolves, because
	// withdrawing a version from the shelf is not the same as withdrawing it from
	// the machines that already chose it, and re-pointing a pin behind the owner's
	// back is exactly what this package refuses to do.
	Visible bool
	// FlagDetail is how this version's flag reads to a human, e.g.
	// "SH-INJ-011 in SKILL.md". It reaches Skip.Detail and the notes verbatim.
	// See the package comment: it is attacker-controlled and is escaped at render.
	FlagDetail string
	// Override is the acceptance recorded against this version, active or lapsed.
	Override  *Override
	Signature *Signature
	Digest    string
	ObjectKey string
}

// Entry is one package in a profile and how it tracks versions.
type Entry struct {
	// ID is the lockfile's `id`, publisher/name.
	ID string
	// Kind is plugin or skill, carried through to the lockfile untouched.
	Kind string
	Mode Mode
	// PinnedID is the Candidate.ID the pin names. Required when Mode is
	// ModePinned; ignored otherwise.
	PinnedID string
	// Range is the constraint expression. Required when Mode is ModeRange.
	Range string
	// Candidates is every version this entry may consider, in any order. The
	// caller has already applied readability: what is not here does not exist as
	// far as this resolution is concerned.
	Candidates []Candidate
}

// Input is one whole resolution.
type Input struct {
	Gate Gate
	// RequireSignatures is org_policy.require_signed_bundles (FR-047, FR-048): a
	// version with no signature reference is not resolvable while it is set.
	RequireSignatures bool
	// At is the instant the resolution happens, and it is what decides whether an
	// override has lapsed. It is passed rather than read off the clock so that the
	// resolver stays pure and so that re-resolving a published revision as of its
	// own publication instant gives back what it published.
	At      time.Time
	Entries []Entry
}

// Skip is one excluded entry, field for field in the shape
// contract.LockfileSkip fixes (FR-036), so a caller assembling a lockfile copies
// rather than derives.
type Skip struct {
	ID                  string
	Reason              Reason
	Detail              string
	WouldHaveResolvedTo string
}

// Resolution is what one entry resolved to and what the screen says about it.
type Resolution struct {
	ID   string
	Kind string
	// Mode is the mode the profile holds, which is also the lockfile's
	// `resolution`. It is deliberately not re-labelled by what happened: a pin the
	// gate refused is still a pin, and calling it something else would hide the
	// conflict the screen has to state.
	Mode    Mode
	Outcome Outcome
	// Version is what the entry resolved to, nil exactly when Outcome is
	// OutcomeSkipped.
	Version *Candidate
	// PassedOver is the version the entry would have taken had policy not stopped
	// it. It is set on a downgrade and on every skip that had something to skip,
	// and it is where Skip.WouldHaveResolvedTo comes from.
	PassedOver *Candidate
	// Override is the ACTIVE acceptance that let a flagged version through, and
	// nil otherwise. It is not the same as Version.Override, which may have
	// lapsed: only this one belongs in a lockfile.
	Override *Override
	// Note is the policy note the screen renders, empty when the gate did nothing
	// worth saying. It embeds FlagDetail, so escape it (FR-055).
	Note string
	// Skip is non-nil exactly when Outcome is OutcomeSkipped.
	Skip *Skip
}

// Result is a whole profile resolved.
type Result struct {
	// Gate is the gate that was applied, so a caller writing a lockfile records
	// what actually ran rather than re-reading the policy row.
	Gate Gate
	// Entries holds one resolution per input entry, in input order, INCLUDING the
	// skipped ones: the screen draws a row for every entry a profile holds, not
	// only for the ones that survived.
	Entries []Resolution
}

// Skipped is the exclusion list in lockfile order (FR-036).
func (r Result) Skipped() []Skip {
	out := make([]Skip, 0, len(r.Entries))
	for _, entry := range r.Entries {
		if entry.Skip != nil {
			out = append(out, *entry.Skip)
		}
	}
	return out
}

// Resolved is every entry that produced a version, in input order.
func (r Result) Resolved() []Resolution {
	out := make([]Resolution, 0, len(r.Entries))
	for _, entry := range r.Entries {
		if entry.Skip == nil {
			out = append(out, entry)
		}
	}
	return out
}

// Resolve applies the gate to every entry.
//
// It returns an error for malformed input — an unknown gate, an unknown mode, an
// unknown verdict, a version string that is not a semver — rather than resolving
// around it. A gate value nothing recognises must not fall through to a default,
// because the only defaults available are "let it through", which is a bypass,
// and "drop it", which is a silent one.
func Resolve(in Input) (Result, error) {
	if !in.Gate.Valid() {
		return Result{}, fmt.Errorf("scan gate %q is not block, approval or warn-with-override", in.Gate)
	}

	out := Result{Gate: in.Gate, Entries: make([]Resolution, 0, len(in.Entries))}
	for _, entry := range in.Entries {
		resolution, err := resolveEntry(in, entry)
		if err != nil {
			return Result{}, fmt.Errorf("resolve %s: %w", entry.ID, err)
		}
		out.Entries = append(out.Entries, resolution)
	}
	return out, nil
}

func resolveEntry(in Input, entry Entry) (Resolution, error) {
	if !entry.Mode.Valid() {
		return Resolution{}, fmt.Errorf("entry mode %q is not latest, pinned or range", entry.Mode)
	}
	for _, candidate := range entry.Candidates {
		if !candidate.Verdict.Valid() {
			return Resolution{}, fmt.Errorf("version %s carries verdict %q, which is not a verdict",
				candidate.Semver, candidate.Verdict)
		}
	}

	out := Resolution{ID: entry.ID, Kind: entry.Kind, Mode: entry.Mode}
	if entry.Mode == ModePinned {
		return resolvePinned(in, entry, out), nil
	}
	return resolveFloating(in, entry, out)
}

// resolvePinned honours the pin or excludes the entry. It never re-points one.
//
// That is the whole of US5's "a pin at a flagged version under block is a
// conflict the screen has to state": an owner who pinned 2.0.0 and finds 1.9.0
// on their machine has been lied to by their own lockfile, and the lockfile is
// the artefact that is supposed to make an install reproducible.
func resolvePinned(in Input, entry Entry, out Resolution) Resolution {
	pin := findCandidate(entry.Candidates, entry.PinnedID)
	if pin == nil {
		out.Note = notePinTargetMissing()
		return skip(out, ReasonPinTargetMissing, "")
	}

	out.PassedOver = pin
	verdict := dispositionOf(in, *pin)
	if !verdict.eligible {
		out.Note = noteSkipped(*pin, verdict.reason, ModePinned)
		return skip(out, verdict.reason, pin.FlagDetail)
	}

	out.Version = pin
	out.Override = verdict.override
	out.PassedOver = nil
	out.Outcome = outcomeOf(*pin, verdict)
	out.Note = noteFlagged(in.Gate, *pin, verdict)
	return out
}

// resolveFloating walks the candidates newest first and takes the first the
// policy allows.
//
// Walking rather than filtering is what makes the two fallback rules different,
// and they have to be different. Under `block` the organisation has said a
// flagged version is simply not distributable, so the most recent clean one is
// the right answer and the note says the newer one was blocked. Under `approval`
// it has said a human must look at this version — installing an older one instead
// answers a question nobody asked and buries the pending review, so a flagged,
// unapproved candidate stops the walk and the entry is excluded (US5 scenario 3).
func resolveFloating(in Input, entry Entry, out Resolution) (Resolution, error) {
	pool, err := poolFor(entry)
	if err != nil {
		return Resolution{}, err
	}
	if len(pool) == 0 {
		out.Note = noteNothingToResolve()
		return skip(out, ReasonNoCleanVersionAvailable, ""), nil
	}

	newest := pool[0]
	out.PassedOver = &newest
	newestVerdict := dispositionOf(in, newest)

	for i := range pool {
		candidate := pool[i]
		verdict := dispositionOf(in, candidate)
		switch {
		case verdict.eligible:
			out.Version = &candidate
			out.Override = verdict.override
			if i == 0 {
				out.PassedOver = nil
				out.Outcome = outcomeOf(candidate, verdict)
				out.Note = noteFlagged(in.Gate, candidate, verdict)
				return out, nil
			}
			out.Outcome = OutcomeDowngraded
			out.Note = join(
				notePassedOver(newest, newestVerdict.reason, candidate.Semver),
				noteFlagged(in.Gate, candidate, verdict),
			)
			return out, nil
		case verdict.reason == ReasonFlaggedAwaitingApproval:
			out.Note = noteSkipped(candidate, verdict.reason, entry.Mode)
			out.PassedOver = &candidate
			return skip(out, verdict.reason, candidate.FlagDetail), nil
		}
	}

	// Nothing in the pool was usable. The newest candidate's obstacle is the one
	// that explains the entry: it is the version the owner expected to get.
	out.Note = noteSkipped(newest, newestVerdict.reason, entry.Mode)
	return skip(out, newestVerdict.reason, newest.FlagDetail), nil
}

// disposition is what policy does to ONE candidate, decided with no reference to
// the others.
type disposition struct {
	eligible bool
	// override is the acceptance that let a flagged candidate through, and is nil
	// for every other case — including a candidate carrying a lapsed one, which is
	// the point of evaluating it here.
	override *Override
	reason   Reason
}

func dispositionOf(in Input, candidate Candidate) disposition {
	switch candidate.Verdict {
	case VerdictRejected:
		// FR-029, above every gate: a rejected version is not resolvable by any
		// profile regardless of gate.
		return disposition{reason: ReasonVersionRejected}
	case VerdictScanning:
		return disposition{reason: ReasonNoCleanVersionAvailable}
	case VerdictClean, VerdictFlagged:
	}

	if in.RequireSignatures && (candidate.Signature == nil || candidate.Signature.Ref == "") {
		return disposition{reason: ReasonUnsignedSignaturesRequired}
	}
	if candidate.Verdict == VerdictClean {
		return disposition{eligible: true}
	}

	active := candidate.Override.ActiveAt(in.At)
	switch in.Gate {
	case GateBlock:
		// An override does not lift a block, and deliberately so: `block` is the
		// organisation saying a flagged version is not distributed, and if an
		// acceptance were enough to get past it then `block` and
		// `warn-with-override` would be the same gate wherever a reviewer had
		// signed. The reviewer's lever under `block` is to clear the finding.
		return disposition{reason: ReasonFlaggedBlockedByGate}
	case GateApproval:
		if !active {
			return disposition{reason: ReasonFlaggedAwaitingApproval}
		}
		return disposition{eligible: true, override: candidate.Override}
	case GateWarnWithOverride:
		// FR-035: warn-with-override INCLUDES flagged versions and records the
		// override. It does not require one to exist first — the organisation has
		// already decided a warning is enough, and an override turns the warning
		// into a decision with a name on it.
		out := disposition{eligible: true}
		if active {
			out.override = candidate.Override
		}
		return out
	}
	// Unreachable: Resolve rejects an invalid gate before any entry is walked.
	return disposition{reason: ReasonFlaggedBlockedByGate}
}

func outcomeOf(candidate Candidate, verdict disposition) Outcome {
	switch {
	case candidate.Verdict != VerdictFlagged:
		return OutcomeResolved
	case verdict.override != nil:
		return OutcomeOverridden
	default:
		return OutcomeWarned
	}
}

func skip(out Resolution, reason Reason, detail string) Resolution {
	out.Outcome = OutcomeSkipped
	out.Version = nil
	out.Override = nil
	would := ""
	if out.PassedOver != nil {
		would = out.PassedOver.Semver
	}
	out.Skip = &Skip{ID: out.ID, Reason: reason, Detail: detail, WouldHaveResolvedTo: would}
	return out
}

func findCandidate(candidates []Candidate, id string) *Candidate {
	if id == "" {
		return nil
	}
	for i := range candidates {
		if candidates[i].ID == id {
			return &candidates[i]
		}
	}
	return nil
}

// poolFor is the set a floating entry may choose from, newest first: visible
// candidates, narrowed to the range expression when the entry has one.
func poolFor(entry Entry) ([]Candidate, error) {
	var match func(*semver.Version) bool
	if entry.Mode == ModeRange {
		if entry.Range == "" {
			return nil, fmt.Errorf("entry mode is range but no range expression is set")
		}
		constraint, err := semver.NewConstraint(entry.Range)
		if err != nil {
			return nil, fmt.Errorf("range %q is not a constraint: %w", entry.Range, err)
		}
		match = constraint.Check
	}

	parsed := make(map[string]*semver.Version, len(entry.Candidates))
	pool := make([]Candidate, 0, len(entry.Candidates))
	for _, candidate := range entry.Candidates {
		version, err := semver.NewVersion(candidate.Semver)
		if err != nil {
			return nil, fmt.Errorf("version %q is not a semver: %w", candidate.Semver, err)
		}
		if _, duplicate := parsed[candidate.ID]; duplicate {
			return nil, fmt.Errorf("two candidates share the id %q, so newest-first is undefined", candidate.ID)
		}
		parsed[candidate.ID] = version
		if !candidate.Visible || (match != nil && !match(version)) {
			continue
		}
		pool = append(pool, candidate)
	}

	sort.SliceStable(pool, func(i, j int) bool {
		return parsed[pool[i].ID].GreaterThan(parsed[pool[j].ID])
	})
	return slices.Clip(pool), nil
}
