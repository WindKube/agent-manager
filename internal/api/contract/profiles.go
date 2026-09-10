package contract

import (
	"time"

	"agent-manager/internal/domain/resolve"
)

// Note, Skip.Detail and a member's DisplayName all quote content this hub
// did not write. Every consumer must render them escaped.

type ProfileDetail struct {
	Slug        string `json:"slug" example:"example/platform-engineer"`
	Name        string `json:"name" example:"Platform Engineer"`
	Description string `json:"description,omitempty"`
	Visibility  string `json:"visibility" enum:"organisation,shared,private" example:"organisation"`
	OwnerTeam   string `json:"ownerTeam,omitempty" doc:"The team named on the header line. Free text, not a membership." example:"example/platform"`

	DefaultPolicy string `json:"defaultPolicy" enum:"floating-latest,pinned,range" doc:"The profile's own default, which a per-entry mode overrides (FR-032)." example:"floating-latest"`
	// Gate is the org gate in force NOW, not the one the head revision froze.
	Gate         string `json:"gate" enum:"block,approval,warn-with-override" example:"warn-with-override"`
	HeadRevision int    `json:"headRevision" doc:"The most recent published revision, 0 when nothing has been published yet." example:"14"`
	// ForkedFrom is lineage only, no subscription to future revisions.
	ForkedFrom string `json:"forkedFrom,omitempty" doc:"Slug of the profile this was forked from. Lineage only: a fork never inherits the upstream's future revisions (FR-038)." example:"example/sre-oncall"`

	Role        string             `json:"role,omitempty" enum:"owner,maintainer,reviewer,consumer" doc:"This identity's role on this profile. Absent when they read it through organisation visibility rather than a membership."`
	Permissions ProfilePermissions `json:"permissions" doc:"What this identity may do here. FR-126: a screen disables what it may not do rather than offering it and being refused."`

	UnpublishedChanges bool `json:"unpublishedChanges" doc:"Publishing now would write a lockfile different from the head revision's. True for a profile with no revisions at all."`

	Entries   []ProfileEntry    `json:"entries" doc:"Every package this profile holds, in the profile's own order — INCLUDING the ones the gate excludes, which are reported and never silently omitted (FR-036)."`
	Members   []ProfileMember   `json:"members" doc:"Individual members and identity-provider groups, with the role each holds (FR-037)."`
	Targets   []ProfileTarget   `json:"targets" doc:"Every sync target this hub knows, each with whether the profile enables it. The whole vocabulary, so a screen draws the same checkboxes without holding a copy of the enum."`
	Revisions []ProfileRevision `json:"revisions" doc:"Published history, most recent first. Previous revisions stay readable for ever (FR-034)."`
}

type ProfilePermissions struct {
	Curate  bool `json:"curate" doc:"May change entries and sync targets. Owner or maintainer."`
	Share   bool `json:"share" doc:"May change who the profile is shared with. Owner only: who can see a profile is not a curation decision."`
	Publish bool `json:"publish" doc:"May publish a revision. Owner or maintainer — a consumer may not (FR-037)."`
}

// ProfileEntry: Version/Verdict are what this entry resolves to, distinct
// from LatestVersion/LatestVerdict, the catalog's newest offering.
type ProfileEntry struct {
	ID   string `json:"id" doc:"namespace/name, as the catalog renders it." example:"community/postgres-migration-guard"`
	Name string `json:"name" doc:"The package's own name, for the row's title." example:"Postgres Migration Guard"`
	Kind string `json:"kind" enum:"plugin,skill" example:"skill"`

	// Mode is the profile's setting, deliberately not re-labelled by what
	// happened: a pin the gate refused is still a pin.
	Mode          string `json:"mode" enum:"latest,pinned,range" example:"latest"`
	Range         string `json:"range,omitempty" doc:"The constraint expression, present only when mode is range." example:">=1.4.0 <2.0.0"`
	PinnedVersion string `json:"pinnedVersion,omitempty" doc:"The version the pin names, present only when mode is pinned. Absent when the pin names a version this hub no longer holds — which is the pin-target-missing exclusion." example:"3.0.2"`

	LatestVersion string `json:"latestVersion,omitempty" doc:"The catalog's newest visible version of this package. Absent when it has none." example:"0.8.3"`
	LatestVerdict string `json:"latestVerdict,omitempty" enum:"scanning,clean,flagged,rejected" doc:"That version's scan state — the row's Scan badge. Unaffected by what the gate then does." example:"flagged"`

	Version string `json:"version,omitempty" doc:"What this entry resolves to. Absent exactly when the entry is excluded." example:"0.8.3"`
	Verdict string `json:"verdict,omitempty" enum:"scanning,clean,flagged" doc:"The RESOLVED version's verdict. The vocabulary is narrower than the catalog's on purpose: a rejected version never resolves, under any gate (FR-029)."`
	Digest  string `json:"digest,omitempty" pattern:"^sha256:[0-9a-f]{64}$" doc:"The resolved version's bundle digest, so the screen shows the same identity the lockfile would freeze."`

	// Outcome is finer than resolved-or-not: "resolved" alone can't tell a
	// clean version from a flagged one that got through on a signature.
	Outcome string `json:"outcome" enum:"resolved,warned,overridden,downgraded,skipped" example:"warned"`
	// Note embeds a path out of a package bundle: render it escaped.
	Note     string            `json:"note,omitempty" example:"Flagged (SH-SQL-004 in SKILL.md); warn-with-override includes it with a warning."`
	Skip     *LockfileSkip     `json:"skip,omitempty" doc:"Present exactly when outcome is skipped. The same shape the lockfile publishes, so the screen and the CLI report an exclusion identically (FR-036)."`
	Override *LockfileOverride `json:"override,omitempty" doc:"The ACTIVE acceptance that let a flagged version through. A lapsed one is not an override and is absent here."`

	Unpublished bool `json:"unpublished" doc:"This row would resolve differently from the head revision's lockfile. Nothing reaches a machine until a revision is published."`
}

type ProfileMember struct {
	Kind string `json:"kind" enum:"user,group" doc:"group is an identity-provider group, matched against the claim on every request rather than expanded into people." example:"group"`
	Ref  string `json:"ref" doc:"The person's email or subject, or the group's name as the provider spells it." example:"eng-platform"`
	Role string `json:"role" enum:"owner,maintainer,reviewer,consumer" example:"maintainer"`
	// DisplayName is identity-provider content: render it escaped.
	DisplayName string `json:"displayName,omitempty" example:"Krzysztof Wiatrzyk"`
}

type ProfileTarget struct {
	Target  string `json:"target" enum:"claude-code,codex" example:"claude-code"`
	Enabled bool   `json:"enabled"`
}

type ProfileRevision struct {
	Revision    int       `json:"revision" minimum:"1" example:"14"`
	Note        string    `json:"note,omitempty" example:"pinned ADR Writer to 3.0.2"`
	PublishedAt time.Time `json:"publishedAt"`
	PublishedBy string    `json:"publishedBy" doc:"The email or subject of whoever published it." example:"pkaczmarek@example.com"`
}

type ProfileCreate struct {
	Slug string `json:"slug" minLength:"1" maxLength:"120" pattern:"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$" doc:"URL-safe identifier, unique across the organisation. May carry several segments — the design's profiles live at example/platform-engineer — and each one is validated, because the slug becomes an object-store prefix." example:"example/platform-engineer"`
	Name string `json:"name" minLength:"1" maxLength:"200" example:"Platform Engineer"`

	Description   string `json:"description,omitempty" maxLength:"2000"`
	Visibility    string `json:"visibility,omitempty" enum:"organisation,shared,private" doc:"Defaults to private. A new profile is not readable by the whole organisation until somebody says so (FR-037, FR-044)." example:"organisation"`
	OwnerTeam     string `json:"ownerTeam,omitempty" maxLength:"200" example:"example/platform"`
	DefaultPolicy string `json:"defaultPolicy,omitempty" enum:"floating-latest,pinned,range" example:"floating-latest"`

	// ForkOf copies the upstream's current entries; no subscription is
	// created to its future revisions.
	ForkOf string `json:"forkOf,omitempty" doc:"Slug of a profile to fork. Its entries are COPIED at this instant; the fork never sees an upstream revision published afterwards (FR-038). The upstream must be readable by this identity." example:"example/sre-oncall"`
}

// ProfileEntries is the WHOLE ordered set, not a patch: an omitted entry
// is REFUSED, not silently dropped.
type ProfileEntries struct {
	Entries []ProfileEntrySetting `json:"entries" doc:"Every package the profile holds, in the order it holds them. Naming one it does not hold adds it."`
}

type ProfileEntrySetting struct {
	ID      string `json:"id" minLength:"1" doc:"namespace/name of a registered package." example:"example/adr-writer"`
	Mode    string `json:"mode" enum:"latest,pinned,range" example:"pinned"`
	Version string `json:"version,omitempty" doc:"The exact version when mode is pinned, the constraint expression when mode is range, and unused for latest." example:"3.0.2"`
}

// ProfileSharing is an UPSERT of roles, not a replacement of the membership
// set: a subject the body does not name keeps the role it has.
type ProfileSharing struct {
	Members []ProfileShare `json:"members" minItems:"1" doc:"The subjects whose role is being set. Others keep theirs."`
}

type ProfileShare struct {
	Kind string `json:"kind" enum:"user,group" example:"group"`
	Ref  string `json:"ref" minLength:"1" maxLength:"320" doc:"The person's email or subject, or the group's name exactly as the identity provider spells it — it is compared against the groups claim, so a near miss silently grants nothing." example:"eng-platform"`
	Role string `json:"role" enum:"owner,maintainer,reviewer,consumer" example:"maintainer"`
}

// ProfileTargetSelection, unlike sharing, IS a replacement: an omitted
// target is updated to false rather than removed.
type ProfileTargetSelection struct {
	Targets []string `json:"targets" enum:"claude-code,codex" doc:"The agent directories a client should write. An omitted target is disabled. An empty list is legal and means the profile writes nothing until somebody chooses."`
}

// RevisionPublish carries no revision number: the sequence is allocated
// server-side, so a client cannot name a number to overwrite.
type RevisionPublish struct {
	Note string `json:"note,omitempty" maxLength:"500" doc:"The publisher's note on this revision, shown in the history and carried in the lockfile." example:"pinned ADR Writer to 3.0.2"`
}

// LockfileFrom exists once; the publish command and internal/seed both use
// it so they can't drift.
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

// SkipFrom copies one exclusion into the shape the schema fixes.
func SkipFrom(skip resolve.Skip) LockfileSkip {
	return LockfileSkip{
		ID:                  skip.ID,
		Reason:              string(skip.Reason),
		Detail:              skip.Detail,
		WouldHaveResolvedTo: skip.WouldHaveResolvedTo,
	}
}

// OverrideFrom copies the ACTIVE acceptance; nil stays nil, since a lapsed
// acceptance must not appear in a lockfile.
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
