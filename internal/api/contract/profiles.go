package contract

import (
	"time"

	"agent-manager/internal/domain/resolve"
)

// The profile screen's surface (001 US5, 003 US5 scenario 2, T078-T083).
//
// Every shape here is emitted rather than frozen: the machine-facing contract
// inventories these paths and specifies none of them. What IS frozen is the
// lockfile a revision publishes, which is why LockfileFrom lives in this file —
// the mapping from a resolution into the frozen document sits beside the frozen
// types, so adding a field to LockfileEntry puts the compiler in front of
// whoever has to fill it.
//
// Nothing here re-derives a gate outcome. The screen's per-entry policy note,
// the resolved version and the exclusions all come out of
// internal/domain/resolve, because two implementations of the gate is how the
// screen and the CLI start disagreeing about what is installed (T078).
//
// Note, Skip.Detail and a member's DisplayName all quote content this hub did
// not write — a path out of a package bundle, a name out of the identity
// provider. Every consumer renders them escaped (FR-055).

// ProfileDetail is one profile as the detail screen draws it: what it holds, what
// each entry resolves to under the org gate, who it is shared with, which agent
// directories a client writes, and its published history.
type ProfileDetail struct {
	Slug        string `json:"slug" example:"example/platform-engineer"`
	Name        string `json:"name" example:"Platform Engineer"`
	Description string `json:"description,omitempty"`
	Visibility  string `json:"visibility" enum:"organisation,shared,private" example:"organisation"`
	OwnerTeam   string `json:"ownerTeam,omitempty" doc:"The team named on the header line. Free text, not a membership." example:"example/platform"`

	DefaultPolicy string `json:"defaultPolicy" enum:"floating-latest,pinned,range" doc:"The profile's own default, which a per-entry mode overrides (FR-032)." example:"floating-latest"`
	// Gate is the org gate in force NOW, which is what the entries below were
	// resolved under. It is not the gate the head revision recorded: a lockfile
	// freezes the gate it was published with, and the two disagreeing is exactly
	// what UnpublishedChanges reports.
	Gate         string `json:"gate" enum:"block,approval,warn-with-override" example:"warn-with-override"`
	HeadRevision int    `json:"headRevision" doc:"The most recent published revision, 0 when nothing has been published yet." example:"14"`
	// ForkedFrom is LINEAGE and nothing else. A fork does not subscribe to the
	// upstream's future revisions (FR-038) and no read anywhere follows this the
	// other way; it is here so a screen can say where a profile came from.
	ForkedFrom string `json:"forkedFrom,omitempty" doc:"Slug of the profile this was forked from. Lineage only: a fork never inherits the upstream's future revisions (FR-038)." example:"example/sre-oncall"`

	// Role is the caller's membership role, and it is legitimately empty: a
	// profile with organisation visibility is readable by everyone (FR-044) and
	// most of those readers hold no membership at all.
	Role        string             `json:"role,omitempty" enum:"owner,maintainer,reviewer,consumer" doc:"This identity's role on this profile. Absent when they read it through organisation visibility rather than a membership."`
	Permissions ProfilePermissions `json:"permissions" doc:"What this identity may do here. FR-126: a screen disables what it may not do rather than offering it and being refused."`

	// UnpublishedChanges is 001 US5 scenario 1's "not durable until a revision is
	// published", at the profile level: resolving the draft now would produce a
	// different lockfile from the one the head revision froze.
	UnpublishedChanges bool `json:"unpublishedChanges" doc:"Publishing now would write a lockfile different from the head revision's. True for a profile with no revisions at all."`

	Entries   []ProfileEntry    `json:"entries" doc:"Every package this profile holds, in the profile's own order — INCLUDING the ones the gate excludes, which are reported and never silently omitted (FR-036)."`
	Members   []ProfileMember   `json:"members" doc:"Individual members and identity-provider groups, with the role each holds (FR-037)."`
	Targets   []ProfileTarget   `json:"targets" doc:"Every sync target this hub knows, each with whether the profile enables it. The whole vocabulary, so a screen draws the same checkboxes without holding a copy of the enum."`
	Revisions []ProfileRevision `json:"revisions" doc:"Published history, most recent first. Previous revisions stay readable for ever (FR-034)."`
}

// ProfilePermissions is what the caller may do, decided by their membership role
// and reported so the screen can disable a control instead of offering one that
// will be refused (FR-126). The refusals themselves are enforced by the
// operations; this is the screen's copy of the answer, never the mechanism.
type ProfilePermissions struct {
	Curate  bool `json:"curate" doc:"May change entries and sync targets. Owner or maintainer."`
	Share   bool `json:"share" doc:"May change who the profile is shared with. Owner only: who can see a profile is not a curation decision."`
	Publish bool `json:"publish" doc:"May publish a revision. Owner or maintainer — a consumer may not (FR-037)."`
}

// ProfileEntry is one package in a profile, its scan state and what the gate did
// to it.
//
// Two version pairs, and they answer different questions. LatestVersion /
// LatestVerdict are the CATALOG's newest offering and its scan state — the badge
// the design's Scan column draws, which stays `flagged` whether the gate then
// includes that version, falls back to an older one or excludes the entry.
// Version / Verdict are what this entry actually RESOLVES to, and are empty
// exactly when the entry is excluded.
type ProfileEntry struct {
	ID   string `json:"id" doc:"namespace/name, as the catalog renders it." example:"community/postgres-migration-guard"`
	Name string `json:"name" doc:"The package's own name, for the row's title." example:"Postgres Migration Guard"`
	Kind string `json:"kind" enum:"plugin,skill" example:"skill"`

	// Mode is the profile's setting and is deliberately not re-labelled by what
	// happened: a pin the gate refused is still a pin, and calling it something
	// else would hide the conflict the screen has to state.
	Mode          string `json:"mode" enum:"latest,pinned,range" example:"latest"`
	Range         string `json:"range,omitempty" doc:"The constraint expression, present only when mode is range." example:">=1.4.0 <2.0.0"`
	PinnedVersion string `json:"pinnedVersion,omitempty" doc:"The version the pin names, present only when mode is pinned. Absent when the pin names a version this hub no longer holds — which is the pin-target-missing exclusion." example:"3.0.2"`

	LatestVersion string `json:"latestVersion,omitempty" doc:"The catalog's newest visible version of this package. Absent when it has none." example:"0.8.3"`
	LatestVerdict string `json:"latestVerdict,omitempty" enum:"scanning,clean,flagged,rejected" doc:"That version's scan state — the row's Scan badge. Unaffected by what the gate then does." example:"flagged"`

	Version string `json:"version,omitempty" doc:"What this entry resolves to. Absent exactly when the entry is excluded." example:"0.8.3"`
	Verdict string `json:"verdict,omitempty" enum:"scanning,clean,flagged" doc:"The RESOLVED version's verdict. The vocabulary is narrower than the catalog's on purpose: a rejected version never resolves, under any gate (FR-029)."`
	Digest  string `json:"digest,omitempty" pattern:"^sha256:[0-9a-f]{64}$" doc:"The resolved version's bundle digest, so the screen shows the same identity the lockfile would freeze."`

	// Outcome is finer than resolved-or-not because the screen states the gate's
	// effect per row, and "resolved" alone cannot tell a clean version from a
	// flagged one that only got through on a reviewer's signature.
	Outcome string `json:"outcome" enum:"resolved,warned,overridden,downgraded,skipped" example:"warned"`
	// Note is the policy note the row renders, empty when the gate did nothing
	// worth saying. It embeds a path out of a package bundle: render it escaped
	// (FR-055).
	Note     string            `json:"note,omitempty" example:"Flagged (SH-SQL-004 in SKILL.md); warn-with-override includes it with a warning."`
	Skip     *LockfileSkip     `json:"skip,omitempty" doc:"Present exactly when outcome is skipped. The same shape the lockfile publishes, so the screen and the CLI report an exclusion identically (FR-036)."`
	Override *LockfileOverride `json:"override,omitempty" doc:"The ACTIVE acceptance that let a flagged version through. A lapsed one is not an override and is absent here."`

	// Unpublished is 001 US5 scenario 1 per row. It covers both halves of "not
	// durable": somebody toggled a pin, or the catalog moved under a floating
	// entry. Either way the machines are still on the head revision.
	Unpublished bool `json:"unpublished" doc:"This row would resolve differently from the head revision's lockfile. Nothing reaches a machine until a revision is published."`
}

// ProfileMember is one subject a profile is shared with (FR-037).
type ProfileMember struct {
	Kind string `json:"kind" enum:"user,group" doc:"group is an identity-provider group, matched against the claim on every request rather than expanded into people." example:"group"`
	Ref  string `json:"ref" doc:"The person's email or subject, or the group's name as the provider spells it." example:"eng-platform"`
	Role string `json:"role" enum:"owner,maintainer,reviewer,consumer" example:"maintainer"`
	// DisplayName is the identity row's name when this hub has seen the person
	// sign in, and empty otherwise — a membership may name someone who never has.
	// It is identity-provider content: render it escaped (FR-055).
	DisplayName string `json:"displayName,omitempty" example:"Krzysztof Wiatrzyk"`
}

// ProfileTarget is one agent directory convention and whether this profile
// enables it. FR-039: a target affects only what a CLIENT writes locally, and
// nothing server-side reads this to decide anything.
type ProfileTarget struct {
	Target  string `json:"target" enum:"claude-code,codex" example:"claude-code"`
	Enabled bool   `json:"enabled"`
}

// ProfileRevision is one published revision, as the history panel lists it.
type ProfileRevision struct {
	Revision    int       `json:"revision" minimum:"1" example:"14"`
	Note        string    `json:"note,omitempty" example:"pinned ADR Writer to 3.0.2"`
	PublishedAt time.Time `json:"publishedAt"`
	PublishedBy string    `json:"publishedBy" doc:"The email or subject of whoever published it." example:"pkaczmarek@example.com"`
}

// ProfileCreate is the body of POST /v1/profiles.
type ProfileCreate struct {
	Slug string `json:"slug" minLength:"1" maxLength:"120" pattern:"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$" doc:"URL-safe identifier, unique across the organisation. May carry several segments — the design's profiles live at example/platform-engineer — and each one is validated, because the slug becomes an object-store prefix." example:"example/platform-engineer"`
	Name string `json:"name" minLength:"1" maxLength:"200" example:"Platform Engineer"`

	Description string `json:"description,omitempty" maxLength:"2000"`
	Visibility  string `json:"visibility,omitempty" enum:"organisation,shared,private" doc:"Defaults to private. A new profile is not readable by the whole organisation until somebody says so (FR-037, FR-044)." example:"organisation"`
	OwnerTeam   string `json:"ownerTeam,omitempty" maxLength:"200" example:"example/platform"`
	// DefaultPolicy defaults to floating-latest, which is the organisation
	// default FR-032 names.
	DefaultPolicy string `json:"defaultPolicy,omitempty" enum:"floating-latest,pinned,range" example:"floating-latest"`

	// ForkOf makes this a fork: the upstream's CURRENT entries are copied and the
	// lineage is recorded. What is deliberately NOT created is any subscription —
	// FR-038 forbids a fork inheriting the upstream's future revisions, and the
	// way to forbid it is to build no mechanism that could.
	ForkOf string `json:"forkOf,omitempty" doc:"Slug of a profile to fork. Its entries are COPIED at this instant; the fork never sees an upstream revision published afterwards (FR-038). The upstream must be readable by this identity." example:"example/sre-oncall"`
}

// ProfileEntries is the body of PUT /v1/profiles/{slug}/entries: the WHOLE
// ordered set of packages the profile holds.
//
// It is the whole set rather than a patch because position is what "ordered set"
// (FR-032) means, and a patch cannot express a reorder without a second grammar.
// An entry the profile holds and the body omits is REFUSED and named, because
// `am_api` deliberately holds no DELETE on `profile_entry` (data-model.md's
// withheld-grant list: removal is unspecified and no screen carries the control),
// so quietly keeping it would leave the stored set disagreeing with the request
// that was answered 200.
type ProfileEntries struct {
	Entries []ProfileEntrySetting `json:"entries" doc:"Every package the profile holds, in the order it holds them. Naming one it does not hold adds it."`
}

// ProfileEntrySetting is one package's version policy (FR-032).
type ProfileEntrySetting struct {
	ID   string `json:"id" minLength:"1" doc:"namespace/name of a registered package." example:"example/adr-writer"`
	Mode string `json:"mode" enum:"latest,pinned,range" example:"pinned"`
	// Version carries the pin or the range, depending on Mode, and is ignored for
	// `latest`. One field rather than two because exactly one of them is ever
	// meaningful, and two would admit a request that sets both.
	Version string `json:"version,omitempty" doc:"The exact version when mode is pinned, the constraint expression when mode is range, and unused for latest." example:"3.0.2"`
}

// ProfileSharing is the body of PUT /v1/profiles/{slug}/sharing.
//
// It is an UPSERT of roles and not a replacement of the membership set: FR-037 is
// about per-member and per-group ROLES, a demotion is an update of `role`, and
// `am_api` holds no DELETE on `membership` (data-model.md). A subject the body
// does not name keeps the role it has.
type ProfileSharing struct {
	Members []ProfileShare `json:"members" minItems:"1" doc:"The subjects whose role is being set. Others keep theirs."`
}

// ProfileShare is one subject and the role they are to hold.
type ProfileShare struct {
	Kind string `json:"kind" enum:"user,group" example:"group"`
	Ref  string `json:"ref" minLength:"1" maxLength:"320" doc:"The person's email or subject, or the group's name exactly as the identity provider spells it — it is compared against the groups claim, so a near miss silently grants nothing." example:"eng-platform"`
	Role string `json:"role" enum:"owner,maintainer,reviewer,consumer" example:"maintainer"`
}

// ProfileTargetSelection is the body of PUT /v1/profiles/{slug}/targets: the
// enabled set, in full.
//
// Unlike sharing this IS a replacement, and it can be one without a DELETE grant
// because `sync_target.enabled` is a column: a target the body omits is updated
// to false rather than removed. FR-039 — none of it changes what the server
// stores about a resolution; it changes what a client writes to a machine.
type ProfileTargetSelection struct {
	Targets []string `json:"targets" enum:"claude-code,codex" doc:"The agent directories a client should write. An omitted target is disabled. An empty list is legal and means the profile writes nothing until somebody chooses."`
}

// RevisionPublish is the body of POST /v1/profiles/{slug}/revisions.
//
// It carries no revision number. The sequence is allocated by the server inside
// the publish transaction, so a client cannot name a number to overwrite — which
// is how "republishing a number is refused, not overwritten" (principle IV,
// FR-033, FR-034) becomes a property of the operation rather than a check
// somebody has to remember to write.
type RevisionPublish struct {
	Note string `json:"note,omitempty" maxLength:"500" doc:"The publisher's note on this revision, shown in the history and carried in the lockfile." example:"pinned ADR Writer to 3.0.2"`
}

// LockfileFrom assembles the frozen document from one resolution.
//
// It exists exactly once and both callers use it: the publish command and
// internal/seed, which builds the representative dataset's history. Two field-by-
// field copies of this mapping is how a seeded lockfile and a published one come
// to disagree about a field somebody added to only one of them — and the seeded
// lockfiles are the design canon the screens are checked against.
//
// Nothing here is re-derived. Every value comes out of the resolution or out of
// the profile row; the resolver already carried Digest and ObjectKey through for
// exactly this reason.
func LockfileFrom(
	profile LockfileProfile,
	revision int,
	note string,
	at time.Time,
	defaultPolicy string,
	targets []string,
	result resolve.Result,
) Lockfile {
	lockfile := Lockfile{
		SchemaVersion: "1.0.0",
		Profile:       profile,
		Revision:      revision,
		Note:          note,
		ResolvedAt:    at,
		Gate:          string(result.Gate),
		DefaultPolicy: defaultPolicy,
		Entries:       make([]LockfileEntry, 0, len(result.Entries)),
		Skipped:       make([]LockfileSkip, 0, len(result.Entries)),
		Targets:       targets,
	}
	if lockfile.Targets == nil {
		lockfile.Targets = []string{}
	}

	for _, resolution := range result.Entries {
		if resolution.Skip != nil {
			lockfile.Skipped = append(lockfile.Skipped, SkipFrom(*resolution.Skip))
			continue
		}
		row := LockfileEntry{
			ID:         resolution.ID,
			Kind:       resolution.Kind,
			Version:    resolution.Version.Semver,
			Digest:     resolution.Version.Digest,
			ObjectKey:  resolution.Version.ObjectKey,
			Resolution: string(resolution.Mode),
			Verdict:    string(resolution.Version.Verdict),
		}
		row.Override = OverrideFrom(resolution.Override)
		if ref := resolution.Version.Signature; ref != nil && (ref.Ref != "" || ref.Verified != nil) {
			row.Signature = &LockfileSignature{Ref: ref.Ref, Verified: ref.Verified}
		}
		lockfile.Entries = append(lockfile.Entries, row)
	}
	return lockfile
}

// SkipFrom copies one exclusion into the shape the schema fixes (FR-036).
func SkipFrom(skip resolve.Skip) LockfileSkip {
	return LockfileSkip{
		ID:                  skip.ID,
		Reason:              string(skip.Reason),
		Detail:              skip.Detail,
		WouldHaveResolvedTo: skip.WouldHaveResolvedTo,
	}
}

// OverrideFrom copies the ACTIVE acceptance, and nil stays nil: a lapsed
// acceptance is not an override and must not appear in a lockfile or on a screen.
func OverrideFrom(override *resolve.Override) *LockfileOverride {
	if override == nil {
		return nil
	}
	out := &LockfileOverride{Reviewer: override.Reviewer, Note: override.Note}
	if override.ExpiresAt != nil {
		out.ExpiresAt = *override.ExpiresAt
	}
	return out
}
