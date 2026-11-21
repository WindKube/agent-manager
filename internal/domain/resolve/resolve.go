// Package resolve applies the org's scan gate to a profile's entries so the
// profile screen, lockfile and CLI agree on what each entry resolves to.
//
// A rejected version never resolves, under any gate. The package is pure (no
// store, blob or HTTP) and does no authorization.
// Candidate.FlagDetail, Note and Skip.Detail carry attacker-controlled text
// and must be escaped at render.
package resolve

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/Masterminds/semver/v3"

	"agent-manager/internal/domain/signer"
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
// evaluated here so callers cannot treat a lapsed override as active.
type Override struct {
	Reviewer string
	Note     string
	// ExpiresAt nil means the acceptance does not lapse.
	ExpiresAt *time.Time
}

// ActiveAt reports whether o is non-nil and unexpired at t.
func (o *Override) ActiveAt(t time.Time) bool {
	return o != nil && (o.ExpiresAt == nil || o.ExpiresAt.After(t))
}

// Signature is a version's Sigstore signature evaluated against its
// package's expected signer at read time, never cached. Verified is true
// only for signer.StatusMatching.
type Signature struct {
	Ref      string
	Status   signer.Status
	Issuer   string
	Identity string
	Verified *bool
}

// NewSignature derives Verified from Status, so the two cannot disagree.
func NewSignature(ref string, status signer.Status, issuer, identity string) *Signature {
	matching := status == signer.StatusMatching
	return &Signature{Ref: ref, Status: status, Issuer: issuer, Identity: identity, Verified: &matching}
}

func (s *Signature) status() signer.Status {
	if s == nil || s.Status == "" {
		return signer.StatusUnsigned
	}
	return s.Status
}

// Candidate is one version an entry may resolve to. Digest and ObjectKey
// are opaque, carried so lockfile builders need not re-query the database.
type Candidate struct {
	ID      string
	Semver  string
	Verdict Verdict
	// Visible: a floating entry never picks an invisible version, but an
	// explicit pin at one still resolves.
	Visible bool
	// FlagDetail is attacker-controlled and reaches Skip.Detail and notes
	// verbatim; escape at render.
	FlagDetail string
	Override   *Override
	Signature  *Signature
	Digest     string
	ObjectKey  string
}

type Entry struct {
	ID         string // the lockfile's `id`, publisher/name
	Kind       string
	Mode       Mode
	PinnedID   string
	Range      string
	Candidates []Candidate
}

type Input struct {
	Gate Gate
	// RequireSignatures admits only versions whose signature matches the
	// package's expected signer.
	RequireSignatures bool
	// At is passed in so re-resolving a revision as of its publication
	// instant reproduces what it published.
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
	ID      string
	Kind    string
	Mode    Mode
	Outcome Outcome
	Version *Candidate
	// PassedOver is the version the entry would have taken had policy not
	// stopped it.
	PassedOver *Candidate
	// Override is the active acceptance that let a flagged version through;
	// Version.Override may have lapsed.
	Override *Override
	// Note embeds FlagDetail, so escape it at render.
	Note string
	Skip *Skip
}

type Result struct {
	Gate    Gate
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

// Resolve applies the gate to every entry. Malformed input is an error
// because neither "let it through" nor "drop it" is a safe default.
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

// resolvePinned honours the pin or excludes the entry; it never re-points it.
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
		return skip(out, verdict.reason, verdict.detailFor(*pin))
	}

	out.Version = pin
	out.Override = verdict.override
	out.PassedOver = nil
	out.Outcome = outcomeOf(*pin, verdict)
	out.Note = noteFlagged(in.Gate, *pin, verdict)
	return out
}

// resolveFloating walks candidates newest first. Under `approval` a flagged
// unapproved candidate stops the walk, since falling back to an older
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

	out.Note = noteSkipped(newest, newestVerdict.reason, entry.Mode)
	return skip(out, newestVerdict.reason, newestVerdict.detailFor(newest)), nil
}

type disposition struct {
	eligible bool
	// override is set only for an active acceptance, never a lapsed one.
	override *Override
	// detail replaces the candidate's FlagDetail as Skip.Detail when set.
	detail string
	reason Reason
}

func dispositionOf(in Input, candidate Candidate) disposition {
	switch candidate.Verdict {
	case VerdictRejected:
		return disposition{reason: ReasonVersionRejected}
	case VerdictScanning:
		return disposition{reason: ReasonNoCleanVersionAvailable}
	case VerdictClean, VerdictFlagged:
	}

	if in.RequireSignatures && candidate.Signature.status() != signer.StatusMatching {
		return disposition{reason: ReasonUnsignedSignaturesRequired, detail: signatureProblem(candidate)}
	}
	if candidate.Verdict == VerdictClean {
		return disposition{eligible: true}
	}

	active := candidate.Override.ActiveAt(in.At)
	switch in.Gate {
	case GateBlock:
		// An override does not lift a block, or `block` would equal
		// `warn-with-override` wherever a reviewer signed.
		return disposition{reason: ReasonFlaggedBlockedByGate}
	case GateApproval:
		if !active {
			return disposition{reason: ReasonFlaggedAwaitingApproval}
		}
		return disposition{eligible: true, override: candidate.Override}
	case GateWarnWithOverride:
		out := disposition{eligible: true}
		if active {
			out.override = candidate.Override
		}
		return out
	}
	// Unreachable: Resolve rejects an invalid gate before any entry is walked.
	return disposition{reason: ReasonFlaggedBlockedByGate}
}

func (d disposition) detailFor(candidate Candidate) string {
	if d.detail != "" {
		return d.detail
	}
	return candidate.FlagDetail
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

// ValidRange validates expr with the same parser resolution uses.
func ValidRange(expr string) error {
	if expr == "" {
		return fmt.Errorf("a range entry needs a constraint expression")
	}
	if _, err := semver.NewConstraint(expr); err != nil {
		return fmt.Errorf("range %q is not a constraint: %w", expr, err)
	}
	return nil
}

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
