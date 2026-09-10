// Package resolve turns a profile's entries, their candidate versions and
// the org's scan gate into what each entry resolves to, so the profile
// screen, lockfile and CLI can't disagree.
//
// Gate rules:
//
//	block               a flagged version does not resolve; a floating
//	                    entry falls back to its newest clean version
//	approval            an unapproved flagged version excludes the entry
//	warn-with-override  a flagged version resolves with a warning, plus
//	                    an active override if one exists
//
// A rejected version never resolves, under any gate.
//
// Pure by construction: no store, no blob, no HTTP. It does not decide who
// may read a profile, package or version (the caller's job), and it does
// not format findings — Candidate.FlagDetail, Note and Skip.Detail carry
// attacker-controlled text and must be escaped at render.
package resolve

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/Masterminds/semver/v3"
)

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

// Reason is why an entry was excluded; the six values are frozen by the
// lockfile schema.
type Reason string

const (
	ReasonFlaggedBlockedByGate       Reason = "flagged-blocked-by-gate"
	ReasonFlaggedAwaitingApproval    Reason = "flagged-awaiting-approval"
	ReasonVersionRejected            Reason = "version-rejected"
	ReasonNoCleanVersionAvailable    Reason = "no-clean-version-available"
	ReasonPinTargetMissing           Reason = "pin-target-missing"
	ReasonUnsignedSignaturesRequired Reason = "unsigned-and-signatures-required"
)

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

// Outcome is finer than "resolved or not": it distinguishes a clean
// version from one that got through flagged, downgraded, or excluded.
type Outcome string

const (
	OutcomeResolved   Outcome = "resolved"
	OutcomeWarned     Outcome = "warned"
	OutcomeOverridden Outcome = "overridden"
	OutcomeDowngraded Outcome = "downgraded"
	OutcomeSkipped    Outcome = "skipped"
)

// Override is a reviewer accepting a finding on a version. The expiry is
// carried rather than pre-evaluated, so "a lapsed override is not an
// override" stays a gate rule instead of something callers judge.
type Override struct {
	Reviewer string
	Note     string
	// ExpiresAt nil means the acceptance does not lapse.
	ExpiresAt *time.Time
}

// ActiveAt: nil is not an override, so callers can pass Candidate.Override
// straight in.
func (o *Override) ActiveAt(t time.Time) bool {
	return o != nil && (o.ExpiresAt == nil || o.ExpiresAt.After(t))
}

// Signature is registry-side signature provenance. Verified stays nil or
// false until cryptographic verification ships and must never be rendered
// as a pass; nothing here reads it, only Ref decides eligibility.
type Signature struct {
	Ref      string
	Verified *bool
}

// Candidate is one version an entry may resolve to. Digest and ObjectKey
// are opaque here, carried only so a caller building a lockfile entry
// copies them out instead of going back to the database.
type Candidate struct {
	ID      string
	Semver  string
	Verdict Verdict
	// Visible: a floating entry never picks an invisible one, but an
	// explicit pin at one still resolves — withdrawing a version from the
	// shelf isn't the same as withdrawing it from machines that chose it.
	Visible bool
	// FlagDetail is how this version's flag reads to a human. It reaches
	// Skip.Detail and the notes verbatim: attacker-controlled, escape at
	// render.
	FlagDetail string
	Override   *Override
	Signature  *Signature
	Digest     string
	ObjectKey  string
}

type Entry struct {
	ID   string // the lockfile's `id`, publisher/name
	Kind string
	Mode Mode
	// PinnedID is the Candidate.ID the pin names; required when Mode is
	// ModePinned.
	PinnedID string
	// Range is the constraint expression; required when Mode is ModeRange.
	Range      string
	Candidates []Candidate
}

type Input struct {
	Gate Gate
	// RequireSignatures: a version with no signature reference is not
	// resolvable while it is set.
	RequireSignatures bool
	// At is passed rather than read off the clock so the resolver stays
	// pure and re-resolving a published revision as of its own publication
	// instant gives back what it published.
	At      time.Time
	Entries []Entry
}

// Skip is one excluded entry, shaped to match contract.LockfileSkip.
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
	// Mode is deliberately not re-labelled by what happened: a pin the
	// gate refused is still a pin.
	Mode    Mode
	Outcome Outcome
	Version *Candidate
	// PassedOver is the version the entry would have taken had policy not
	// stopped it: set on a downgrade and on every skip that had something
	// to skip.
	PassedOver *Candidate
	// Override is the ACTIVE acceptance that let a flagged version
	// through, nil otherwise; not the same as Version.Override, which may
	// have lapsed.
	Override *Override
	// Note embeds FlagDetail, so escape it at render.
	Note string
	Skip *Skip
}

type Result struct {
	Gate Gate
	// Entries includes the skipped ones: the screen draws a row for every
	// entry a profile holds, not only for the ones that survived.
	Entries []Resolution
}

func (r Result) Skipped() []Skip {
	out := make([]Skip, 0, len(r.Entries))
	for _, entry := range r.Entries {
		if entry.Skip != nil {
			out = append(out, *entry.Skip)
		}
	}
	return out
}

func (r Result) Resolved() []Resolution {
	out := make([]Resolution, 0, len(r.Entries))
	for _, entry := range r.Entries {
		if entry.Skip == nil {
			out = append(out, entry)
		}
	}
	return out
}

// Resolve applies the gate to every entry, erroring on malformed input
// (unknown gate, mode, verdict, or a non-semver version) rather than
// falling through to a default — the only defaults available are "let it
// through" or "drop it", and neither is safe to pick silently.
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

// resolvePinned honours the pin or excludes the entry; it never re-points
// one, since re-pointing behind the owner's back is exactly what a pin
// promises not to do.
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

// resolveFloating walks candidates newest first: under `block` it falls
// back to the most recent clean one, but under `approval` a flagged
// unapproved candidate stops the walk instead, since installing an older
// version would bury the pending review.
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

	// Nothing usable: the newest candidate's obstacle explains the entry.
	out.Note = noteSkipped(newest, newestVerdict.reason, entry.Mode)
	return skip(out, newestVerdict.reason, newest.FlagDetail), nil
}

// disposition is what policy does to one candidate, decided in isolation.
type disposition struct {
	eligible bool
	// override is nil for every case but an active acceptance — including
	// a candidate carrying a lapsed one, the point of evaluating it here.
	override *Override
	reason   Reason
}

func dispositionOf(in Input, candidate Candidate) disposition {
	switch candidate.Verdict {
	case VerdictRejected:
		// Above every gate: a rejected version is never resolvable.
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
		// An override does not lift a block: otherwise `block` and
		// `warn-with-override` would be the same gate wherever a reviewer
		// signed. The lever under `block` is to clear the finding.
		return disposition{reason: ReasonFlaggedBlockedByGate}
	case GateApproval:
		if !active {
			return disposition{reason: ReasonFlaggedAwaitingApproval}
		}
		return disposition{eligible: true, override: candidate.Override}
	case GateWarnWithOverride:
		// Includes flagged versions with no override required to exist first.
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

// ValidRange lets the store reject a bad range using the same parser that
// will later evaluate it, instead of surfacing a 500 at resolution time.
func ValidRange(expr string) error {
	if expr == "" {
		return fmt.Errorf("a range entry needs a constraint expression")
	}
	if _, err := semver.NewConstraint(expr); err != nil {
		return fmt.Errorf("range %q is not a constraint: %w", expr, err)
	}
	return nil
}

// poolFor is visible candidates, newest first, narrowed to the range
// expression when the entry has one.
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
