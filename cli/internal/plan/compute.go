package plan

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// This file is the DECIDING side of FR-009. It asks two questions about
// versions and digests and no others:
//
//	installed.Version == locked.Version    // string equality
//	installed.Digest  == locked.Digest     // 32 bytes, not a formatted string
//
// Equality, never ordering. It imports nothing that has an opinion about which
// of two versions is newer, and it must not acquire one: direction.go labels
// the change, and the label is not consulted here. If you find yourself
// wanting to know which version is greater in order to decide WHETHER to
// write, the answer is that you do not — the hub already decided, and the
// lockfile is that decision.

// ErrInputs marks a malformed call. It is separate from a Conflict: a conflict
// is a coherent question with the answer "refuse", while this is a caller bug.
var ErrInputs = errors.New("invalid plan inputs")

// Inputs are the three things a plan is a function of, plus the reporting-side
// comparer.
type Inputs struct {
	// Lockfiles is one resolved revision per profile being synced. The set of
	// profiles here is the set under reconciliation: a profile the record knows
	// about and this slice does not is left completely alone, because syncing
	// one profile must never prune another.
	Lockfiles []*hub.Lockfile

	// Record is amctl's installation record for this hub. Nil means a machine
	// that has never synced — install everything, remove nothing — which is the
	// correct reading of absence and the WRONG reading of a corrupt file. Load
	// distinguishes those; this package is handed the result.
	Record *record.Record

	// Targets is what THIS build can write, including the ones it cannot: a
	// Target with a non-nil Err is reported as unwritable rather than omitted,
	// which is the difference between "we refuse to guess where codex reads"
	// and "your profile turned codex off".
	Targets []Target

	// Compare is optional and reporting-only. Nil uses CompareVersions. It
	// cannot change what the plan writes; only the word it prints.
	Compare Comparer
}

type entryKey struct {
	profile string
	target  record.Target
	id      string
}

type desiredEntry struct {
	key        entryKey
	kind       record.Kind
	dest       string
	version    string
	digest     record.Digest
	resolution string
	verdict    string
	signature  *Signature
}

// Compute is the whole of this package's behaviour: three inputs in, one Plan
// out, nothing touched.
func Compute(in Inputs) (Plan, error) {
	targets, err := indexTargets(in.Targets)
	if err != nil {
		return Plan{}, err
	}
	lockfiles, err := orderLockfiles(in.Lockfiles)
	if err != nil {
		return Plan{}, err
	}

	var p Plan
	b := builder{compare: in.Compare}

	// Pass 1: which targets does each profile enable, and which of those can
	// this build actually write? Target-level refusals are collected across all
	// profiles first, so one unwritable target produces one conflict naming
	// every profile that asked for it rather than one per profile.
	enabled := make(map[string]map[record.Target]bool, len(lockfiles))
	writable := make(map[string]map[record.Target]Target, len(lockfiles))
	for _, lf := range lockfiles {
		slug := lf.Profile.Slug
		enabled[slug] = map[record.Target]bool{}
		writable[slug] = map[record.Target]Target{}
		alreadyRefused := false
		for _, name := range dedupeTargets(lf.Targets) {
			t := record.Target(name)
			enabled[slug][t] = true
			resolved, ok := targets[t]
			switch {
			case !ok:
				b.targetRefusal(ConflictTargetUnknown, t, nil, slug)
				alreadyRefused = true
			case resolved.Withdrawn != nil:
				// Reported by the caller, not refused here. See Target.Withdrawn
				// for why this one class of unwritable target does not abort the
				// sync; the empty-set check below is what stops it becoming
				// "installed nothing and exited 0".
			case resolved.Err != nil:
				b.targetRefusal(ConflictTargetUnwritable, t, resolved.Err, slug)
				alreadyRefused = true
			default:
				writable[slug][t] = resolved
			}
		}
		// Only when nothing else already refuses this profile. A profile whose
		// one target is gated is refused by ConflictTargetUnwritable, which says
		// more and says it once across every profile; adding a second sentence
		// per profile would bury it. What is left is the case this check is for:
		// every target the profile named was WITHDRAWN, which on its own is not
		// a refusal, so without this the sync would install nothing and exit 0.
		if len(enabled[slug]) > 0 && len(writable[slug]) == 0 && !alreadyRefused {
			claims := make([]Claim, 0, len(enabled[slug]))
			for _, name := range dedupeTargets(lf.Targets) {
				claims = append(claims, Claim{Profile: slug, Target: record.Target(name)})
			}
			b.other = append(b.other, Conflict{Kind: ConflictNoWritableTarget, Claims: claims})
		}
	}

	// Pass 2: the hub's own exclusions, verbatim (FR-011).
	for _, lf := range lockfiles {
		for _, s := range lf.Skipped {
			p.Skipped = append(p.Skipped, Skip{
				Profile:             lf.Profile.Slug,
				ID:                  s.Id,
				Reason:              string(s.Reason),
				Recognised:          IsKnownSkipReason(string(s.Reason)),
				Detail:              deref(s.Detail),
				WouldHaveResolvedTo: deref(s.WouldHaveResolvedTo),
			})
		}
	}

	// Pass 3: the desired state — every (profile, target, entry) triple that
	// this build could route to a path.
	desired := map[entryKey]desiredEntry{}
	order := make([]entryKey, 0, len(lockfiles)*8)
	listed := map[string]map[string]bool{}
	for _, lf := range lockfiles {
		slug := lf.Profile.Slug
		listed[slug] = make(map[string]bool, len(lf.Entries))
		for i := range lf.Entries {
			listed[slug][lf.Entries[i].Id] = true
		}
		for i := range lf.Entries {
			e := lf.Entries[i]
			for _, t := range sortedTargetNames(writable[slug]) {
				d, err := b.route(slug, t, writable[slug][t], e)
				if err != nil {
					continue // already recorded as an unroutable conflict
				}
				if _, dup := desired[d.key]; dup {
					return Plan{}, fmt.Errorf("%w: profile %s lists %s twice", ErrInputs, slug, e.Id)
				}
				desired[d.key] = d
				order = append(order, d.key)
			}
		}
	}

	b.versionSplits(in.Record, desired, order)
	b.destCollisions(desired, order)

	// Pass 4: the record side. Every recorded entry of a profile under
	// reconciliation is either matched by a desired entry or removed.
	matched := map[entryKey]struct{}{}
	var removals []Removal
	for _, lf := range lockfiles {
		slug := lf.Profile.Slug
		prof, ok := profileOf(in.Record, slug)
		if !ok {
			continue
		}
		for i := range prof.Entries {
			e := prof.Entries[i]
			key := entryKey{profile: slug, target: e.Target, id: e.ID}

			d, wanted := desired[key]
			switch {
			case wanted && d.dest == e.Dest:
				matched[key] = struct{}{}
				p.appendChange(b.change(d, &e))
			case wanted:
				// The destination moved for the same package under the same
				// target — a layout change, e.g. disambiguation kicking in when
				// a second publisher took the same name. Emitted as a removal
				// of the old path plus an add at the new one, rather than as one
				// "upgrade", because two paths are involved and folding them
				// into a single operation would orphan the old directory while
				// reporting success.
				removals = append(removals, removalOf(slug, e, RemoveRelocated))
			case !enabled[slug][e.Target]:
				removals = append(removals, removalOf(slug, e, RemoveTargetDisabled))
			case writable[slug][e.Target].Dest == nil:
				// The target is still enabled but this build cannot route it, so
				// a conflict is already recorded and the plan refuses. Emitting
				// a removal here would report a deletion the CLI has no basis
				// to perform and would read as "the target was turned off".
				continue
			case listed[slug][e.ID]:
				// Still in the profile, but this run could not route it — a
				// kind that changed to plugin, a name the target now refuses.
				// The unroutable conflict already refuses the plan; calling it
				// "no longer in the profile" would send the user to look at the
				// profile, which is not where the problem is.
				continue
			default:
				removals = append(removals, removalOf(slug, e, RemoveLeftProfile))
			}
		}
	}

	// Pass 5: everything desired that the record does not claim.
	// A relocated entry is deliberately NOT in `matched`, so it reaches here and
	// becomes an add at the new path alongside the removal of the old one.
	for _, key := range order {
		if _, have := matched[key]; have {
			continue
		}
		p.appendChange(b.change(desired[key], nil))
	}

	p.Remove = retain(in.Record, removals, desired)
	p.Conflicts = b.conflicts()

	sortPlan(&p)
	return p, nil
}

type builder struct {
	compare Comparer

	targetRefusals map[record.Target]*Conflict
	other          []Conflict
}

func (b *builder) targetRefusal(kind ConflictKind, t record.Target, err error, profile string) {
	if b.targetRefusals == nil {
		b.targetRefusals = map[record.Target]*Conflict{}
	}
	c, ok := b.targetRefusals[t]
	if !ok {
		c = &Conflict{Kind: kind, Target: t, Err: err}
		b.targetRefusals[t] = c
	}
	c.Claims = append(c.Claims, Claim{Profile: profile, Target: t})
}

// route turns one lockfile entry into a destination, or records the refusal.
// Everything it validates it refuses rather than repairs: a value amctl
// silently rewrote would not match the record it later prunes against.
func (b *builder) route(profile string, t record.Target, target Target, e hub.LockfileEntry) (desiredEntry, error) {
	fail := func(detail string, err error) (desiredEntry, error) {
		if err == nil {
			err = errors.New(detail)
		}
		b.other = append(b.other, Conflict{
			Kind: ConflictUnroutable, ID: e.Id, Target: t,
			Claims: []Claim{{Profile: profile, Target: t, ID: e.Id, Version: e.Version}},
			Err:    err, Detail: detail,
		})
		return desiredEntry{}, err
	}

	if err := validateID(e.Id); err != nil {
		return fail(err.Error(), err)
	}
	kind := record.Kind(e.Kind)
	if !kind.IsValid() {
		return fail(fmt.Sprintf("entry kind %q is not skill or plugin", e.Kind), nil)
	}
	digest, err := record.ParseDigest(e.Digest)
	if err != nil {
		return fail(fmt.Sprintf("digest %q is not sha256:<64 hex>", e.Digest), err)
	}
	if strings.TrimSpace(e.Version) == "" {
		return fail("no version", nil)
	}
	dest, err := target.Dest(e.Id, kind)
	if err != nil {
		return fail(err.Error(), err)
	}

	d := desiredEntry{
		key:        entryKey{profile: profile, target: t, id: e.Id},
		kind:       kind,
		dest:       dest,
		version:    e.Version,
		digest:     digest,
		resolution: string(e.Resolution),
		verdict:    string(e.Verdict),
	}
	if e.Signature != nil {
		d.signature = &Signature{
			Ref:      deref(e.Signature.Ref),
			Verified: e.Signature.Verified != nil && *e.Signature.Verified,
		}
	}
	return d, nil
}

// versionSplits is FR-012. Grouping is by package id across ALL profiles and
// targets, not per target: the requirement is about a set of profiles
// disagreeing, and a disagreement that only bites under one target is the same
// disagreement. The digest arm catches the subtler shape — one version, two
// byte-sets — which is one directory with two possible contents just as much
// as two versions are.
func (b *builder) versionSplits(rec *record.Record, desired map[entryKey]desiredEntry, order []entryKey) {
	byID := map[string][]desiredEntry{}
	var ids []string
	for _, key := range order {
		d := desired[key]
		if _, seen := byID[d.key.id]; !seen {
			ids = append(ids, d.key.id)
		}
		byID[d.key.id] = append(byID[d.key.id], d)
	}
	for _, id := range ids {
		group := byID[id]
		versions := map[string]struct{}{}
		digests := map[record.Digest]struct{}{}
		for i := range group {
			versions[group[i].version] = struct{}{}
			digests[group[i].digest] = struct{}{}
		}
		if len(versions) < 2 && len(digests) < 2 {
			continue
		}
		detail := ""
		if len(versions) < 2 {
			detail = "the versions agree but the digests do not, so one directory has two possible contents"
		}
		b.other = append(b.other, Conflict{
			Kind: ConflictVersionSplit, ID: id, Claims: claimsOf(group), Detail: detail,
			Installed: installedClaims(rec, id),
		})
	}
}

// destCollisions is the negative control for FR-023. Two different packages
// routed to one directory is a layout defect rather than a user error, but it
// is refused here because the record attributes a destination to an entry and
// two entries cannot own one path: whichever pruned second would delete the
// other's live install.
func (b *builder) destCollisions(desired map[entryKey]desiredEntry, order []entryKey) {
	type destKey struct {
		target record.Target
		dest   string
	}
	byDest := map[destKey][]desiredEntry{}
	dests := map[destKey]string{}
	var keys []destKey
	for _, key := range order {
		d := desired[key]
		// layout.DestCollisionKey, not the raw path: `Acme/x` and `acme/x` are
		// two directories on ext4 and ONE on APFS, which is half the release
		// matrix. Comparing the paths as strings finds no collision, both
		// entries install, and the second one's swap overwrites the first — with
		// the record then holding two rows for one directory, so pruning either
		// would delete the other's live install. The refusal is unconditional
		// rather than filesystem-dependent, for the reason internal/layout gives
		// for the id charset: one lockfile must behave the same on both
		// platforms.
		dk := destKey{target: d.key.target, dest: layout.DestCollisionKey(d.dest)}
		if _, seen := byDest[dk]; !seen {
			keys = append(keys, dk)
			dests[dk] = d.dest
		}
		byDest[dk] = append(byDest[dk], d)
	}
	for _, dk := range keys {
		group := byDest[dk]
		if len(distinctIDs(claimsOf(group))) < 2 {
			continue
		}
		b.other = append(b.other, Conflict{
			Kind: ConflictDestCollision, Target: dk.target, Dest: dests[dk], Claims: claimsOf(group),
		})
	}
}

func (b *builder) conflicts() []Conflict {
	out := make([]Conflict, 0, len(b.other)+len(b.targetRefusals))
	out = append(out, b.other...)
	for _, c := range b.targetRefusals {
		out = append(out, *c)
	}
	return out
}

// change is where the deciding side ends and the reporting side begins. The
// operation is chosen by EQUALITY alone; DirectionOf then supplies the word.
func (b *builder) change(d desiredEntry, prev *record.Entry) Change {
	c := Change{
		Op:         OpAdd,
		Profile:    d.key.profile,
		Target:     d.key.target,
		ID:         d.key.id,
		Kind:       d.kind,
		Dest:       d.dest,
		Version:    d.version,
		Digest:     d.digest,
		Resolution: d.resolution,
		Verdict:    d.verdict,
		Signature:  d.signature,
	}
	if prev == nil {
		return c
	}

	c.From = &Installed{
		Version:       prev.Version,
		Digest:        prev.Digest,
		Fingerprinted: !prev.Fingerprint.IsZero(),
	}
	if prev.Version == d.version && prev.Digest == d.digest {
		c.Op = OpUnchanged
		c.Direction = DirectionSame
		return c
	}

	// Everything below is a write. The digest differing at an unchanged version
	// is enough on its own: the hub republished, and the bytes on disk are not
	// the bytes this revision names.
	c.Direction = DirectionOf(b.compare, prev.Version, d.version)
	switch c.Direction {
	case DirectionUp:
		c.Op = OpUpgrade
	case DirectionDown:
		c.Op = OpDowngrade
	default:
		c.Op = OpReplace
	}
	return c
}

func (p *Plan) appendChange(c Change) {
	switch c.Op {
	case OpAdd:
		p.Add = append(p.Add, c)
	case OpUpgrade, OpReplace:
		p.Upgrade = append(p.Upgrade, c)
	case OpDowngrade:
		p.Downgrade = append(p.Downgrade, c)
	case OpUnchanged:
		p.Unchanged = append(p.Unchanged, c)
	}
}

func removalOf(profile string, e record.Entry, reason RemoveReason) Removal {
	return Removal{
		Profile:       profile,
		Target:        e.Target,
		ID:            e.ID,
		Kind:          e.Kind,
		Version:       e.Version,
		Dest:          e.Dest,
		Reason:        reason,
		Paths:         e.RemovablePaths(),
		Fingerprinted: !e.Fingerprint.IsZero(),
	}
}

// retain works out which removals may touch the filesystem.
//
// More than one profile claiming one destination is LEGITIMATE: two profiles
// may include the same package at the same version, in which case one directory
// exists and both own it. Removing it because one of them dropped the package
// would delete an install the other still wants, and the next sync would put
// the bytes back but not anything the user changed inside. So a removal whose
// destination is still claimed drops the record row and stops there.
//
// Two sources of a surviving claim, and both are needed:
//   - a recorded entry at the same destination that is not itself being removed
//     in this plan (record.ClaimantsOf), and
//   - a desired entry at the same destination, i.e. another profile in this very
//     run installs it.
func retain(rec *record.Record, removals []Removal, desired map[entryKey]desiredEntry) []Removal {
	if len(removals) == 0 {
		return nil
	}
	removing := make(map[entryKey]struct{}, len(removals))
	for i := range removals {
		r := &removals[i]
		removing[entryKey{profile: r.Profile, target: r.Target, id: r.ID}] = struct{}{}
	}
	// Keyed by layout.DestCollisionKey for the same reason destCollisions is:
	// on a case-insensitive filesystem a removal of `<root>/Acme--x` unlinks the
	// directory a desired `<root>/acme--x` was just installed into. destCollisions
	// cannot see that pair — it is one desired entry and one recorded one, not
	// two desired ones — so the retention check is the only thing between the
	// prune and somebody's live install. Retaining across case on a
	// case-SENSITIVE filesystem leaves a directory behind instead of removing
	// it, which is the harmless direction of the same mistake.
	byDest := map[string][]Claim{}
	for key := range desired {
		d := desired[key]
		k := layout.DestCollisionKey(d.dest)
		byDest[k] = append(byDest[k], Claim{
			Profile: d.key.profile, Target: d.key.target, ID: d.key.id, Version: d.version,
		})
	}

	out := make([]Removal, 0, len(removals))
	for i := range removals {
		r := removals[i]
		self := entryKey{profile: r.Profile, target: r.Target, id: r.ID}
		var kept []Claim

		// Source 1: another profile in THIS run installs the same directory.
		for _, c := range byDest[layout.DestCollisionKey(r.Dest)] {
			if (entryKey{profile: c.Profile, target: c.Target, id: c.ID}) == self {
				continue
			}
			kept = append(kept, c)
		}

		// Source 2: a recorded entry at the same destination that this plan is
		// not itself removing. Skipped when a desired entry already speaks for
		// it, so the claim carries the version that will be on disk afterwards
		// rather than the one that is there now.
		if rec != nil {
			claimants := rec.ClaimantsOf(r.Dest)
			for j := range claimants {
				ref := &claimants[j]
				key := entryKey{profile: ref.Profile, target: ref.Entry.Target, id: ref.Entry.ID}
				if key == self {
					continue
				}
				if _, gone := removing[key]; gone {
					continue
				}
				if _, superseded := desired[key]; superseded {
					continue
				}
				kept = append(kept, Claim{
					Profile: ref.Profile, Target: ref.Entry.Target,
					ID: ref.Entry.ID, Version: ref.Entry.Version,
				})
			}
		}

		r.RetainedBy = dedupeClaims(kept)
		out = append(out, r)
	}
	return out
}

// installedClaims names what the record says is installed for a package, per
// profile. record.ByID exists for exactly this: at the moment FR-012 fires
// neither of the two versions has been installed yet, so the record cannot
// decide the conflict — it can only say what the machine currently has, which
// is the first thing a user asks when told two profiles disagree.
func installedClaims(rec *record.Record, id string) []Claim {
	if rec == nil {
		return nil
	}
	refs := rec.ByID(id)
	if len(refs) == 0 {
		return nil
	}
	out := make([]Claim, 0, len(refs))
	for i := range refs {
		out = append(out, Claim{
			Profile: refs[i].Profile, Target: refs[i].Entry.Target,
			ID: refs[i].Entry.ID, Version: refs[i].Entry.Version,
		})
	}
	return dedupeClaims(out)
}

func claimsOf(group []desiredEntry) []Claim {
	out := make([]Claim, 0, len(group))
	for i := range group {
		out = append(out, Claim{
			Profile: group[i].key.profile, Target: group[i].key.target,
			ID: group[i].key.id, Version: group[i].version,
		})
	}
	return out
}

func dedupeClaims(in []Claim) []Claim {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[Claim]struct{}, len(in))
	out := make([]Claim, 0, len(in))
	for _, c := range in {
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	slices.SortFunc(out, claimOrder)
	return out
}

func claimOrder(a, b Claim) int {
	return cmp.Or(
		strings.Compare(a.Profile, b.Profile),
		strings.Compare(a.Version, b.Version),
		strings.Compare(string(a.Target), string(b.Target)),
		strings.Compare(a.ID, b.ID),
	)
}

func indexTargets(in []Target) (map[record.Target]Target, error) {
	out := make(map[record.Target]Target, len(in))
	for _, t := range in {
		if t.Name == "" {
			return nil, fmt.Errorf("%w: a target has no name", ErrInputs)
		}
		if _, dup := out[t.Name]; dup {
			return nil, fmt.Errorf("%w: target %s given twice", ErrInputs, t.Name)
		}
		if t.Err != nil && t.Withdrawn != nil {
			return nil, fmt.Errorf("%w: target %s is both unwritable and withdrawn; "+
				"one refuses the plan and the other does not, so the caller has to choose", ErrInputs, t.Name)
		}
		if t.Err == nil && t.Withdrawn == nil && t.Dest == nil {
			return nil, fmt.Errorf("%w: target %s has neither a destination resolver nor an error, "+
				"so nothing can be said about it", ErrInputs, t.Name)
		}
		out[t.Name] = t
	}
	return out, nil
}

// orderLockfiles sorts by profile slug so that conflict discovery — which
// aggregates claims as it goes — does not depend on the caller's argument
// order. The output is sorted again at the end; this is about the intermediate
// claim lists.
func orderLockfiles(in []*hub.Lockfile) ([]*hub.Lockfile, error) {
	out := make([]*hub.Lockfile, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, lf := range in {
		if lf == nil {
			return nil, fmt.Errorf("%w: a nil lockfile", ErrInputs)
		}
		if lf.Profile.Slug == "" {
			return nil, fmt.Errorf("%w: a lockfile with no profile slug", ErrInputs)
		}
		if _, dup := seen[lf.Profile.Slug]; dup {
			return nil, fmt.Errorf("%w: profile %s given twice", ErrInputs, lf.Profile.Slug)
		}
		seen[lf.Profile.Slug] = struct{}{}
		out = append(out, lf)
	}
	slices.SortFunc(out, func(a, b *hub.Lockfile) int {
		return strings.Compare(a.Profile.Slug, b.Profile.Slug)
	})
	return out, nil
}

func dedupeTargets(in []hub.LockfileTargets) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		s := string(t)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func sortedTargetNames(m map[record.Target]Target) []record.Target {
	out := make([]record.Target, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func profileOf(r *record.Record, slug string) (record.Profile, bool) {
	if r == nil {
		return record.Profile{}, false
	}
	return r.ProfileBySlug(slug)
}

// validateID is the two-segment rule. The lockfile schema describes this field
// as "publisher/name" and that description is wrong in a way that has shipped
// three times: the first segment is the NAMESPACE, and two publishers may share
// one. Nothing here depends on which it is — only that there are exactly two
// non-empty segments, because everything downstream (the bundle URL, the
// directory name, FR-023's distinctness) splits on that single slash.
func validateID(id string) error {
	ns, name, ok := strings.Cut(id, "/")
	if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("entry id %q is not exactly two non-empty segments", id)
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ChangeOrder is the order every bucket in a Plan is sorted in, exported so a
// caller that has to extend a write set keeps that order rather than inventing a
// second one. internal/apply needs it: a destination the record claims and the
// disk does not have is promoted from Unchanged to a write, and two orderings
// for one list is how `--dry-run` output and a real run start disagreeing.
func ChangeOrder(a, b Change) int { return changeOrder(a, b) }

func changeOrder(a, b Change) int {
	return cmp.Or(
		strings.Compare(string(a.Target), string(b.Target)),
		strings.Compare(a.ID, b.ID),
		strings.Compare(a.Profile, b.Profile),
	)
}

func sortPlan(p *Plan) {
	for _, set := range [][]Change{p.Add, p.Upgrade, p.Downgrade, p.Unchanged} {
		slices.SortFunc(set, changeOrder)
	}
	slices.SortFunc(p.Remove, func(a, b Removal) int {
		return cmp.Or(
			strings.Compare(string(a.Target), string(b.Target)),
			strings.Compare(a.ID, b.ID),
			strings.Compare(a.Profile, b.Profile),
		)
	})
	slices.SortFunc(p.Conflicts, func(a, b Conflict) int {
		return cmp.Or(
			strings.Compare(string(a.Kind), string(b.Kind)),
			strings.Compare(a.ID, b.ID),
			strings.Compare(string(a.Target), string(b.Target)),
			strings.Compare(a.Dest, b.Dest),
		)
	})
	for i := range p.Conflicts {
		p.Conflicts[i].Claims = dedupeClaims(p.Conflicts[i].Claims)
	}
	slices.SortFunc(p.Skipped, func(a, b Skip) int {
		return cmp.Or(
			strings.Compare(a.Profile, b.Profile),
			strings.Compare(a.ID, b.ID),
			strings.Compare(a.Reason, b.Reason),
		)
	})
}
