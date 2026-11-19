package fixture

import (
	"context"
	"time"

	"agent-manager/internal/web/view"
)

// The Profiles screens' stand-in.
//
// It implements web.ProfileSource and deliberately does NOT implement
// web.ProfileCurator: a fixture that could accept a curation write would be
// claiming it had recorded a stored entry, a membership or a revision, none of
// which exist here, and every screen test would then be exercising that claim.
// The screens render their write controls against a nil curator the same way
// the registration modal renders against a nil registrar.
//
// The two profiles are handles, not people: a display name in this product is a
// defect, and a plausible one in fixture data is that defect wearing a
// fixture's clothes.

const (
	fixtureProfileSlug       = "platform-engineer"
	fixtureProfileForkedSlug = "sre-oncall"
)

// Profiles implements the list half of web.ProfileSource.
func (c *Catalog) Profiles(context.Context) ([]view.ProfileRow, error) {
	return []view.ProfileRow{
		{Slug: fixtureProfileSlug, Name: "Platform Engineer", Visibility: "organisation",
			PackageCount: 2, HeadRevision: 14, CanCurate: true},
		{Slug: fixtureProfileForkedSlug, Name: "SRE On-call", Visibility: "shared",
			PackageCount: 0, HeadRevision: 0, CanCurate: false},
	}, nil
}

// Profile implements the detail half of web.ProfileSource.
func (c *Catalog) Profile(_ context.Context, slug string) (view.Profile, error) {
	now := time.Now().UTC()

	switch slug {
	case fixtureProfileSlug:
		return view.Profile{
			Slug: fixtureProfileSlug, Name: "Platform Engineer",
			Description: "The tools platform engineers sync onto a new machine.",
			Visibility:  "organisation", OwnerTeam: "example/platform",
			DefaultPolicy: "floating-latest", Gate: "warn-with-override",
			HeadRevision: 14, Role: "owner",
			Permissions: view.ProfilePermissions{Curate: true, Share: true, Publish: true},
			Entries: []view.ProfileEntryRow{
				{
					ID: "example/adr-writer", Name: "ADR Writer", Kind: "skill",
					Mode: "pinned", PinnedVersion: "3.0.2",
					LatestVersion: "3.0.2", LatestVerdict: "clean",
					Version: "3.0.2", Verdict: "clean", Digest: "sha256:" + fixtureDigest,
					Outcome: "resolved",
				},
				{
					ID: "community/postgres-migration-guard", Name: "Postgres Migration Guard", Kind: "skill",
					Mode:          "latest",
					LatestVersion: "0.8.3", LatestVerdict: "flagged",
					Version: "0.8.3", Verdict: "flagged", Digest: "sha256:" + fixtureDigest,
					Outcome: "warned",
					Note:    "Flagged (SH-INJ-011 in SKILL.md); warn-with-override includes it with a warning.",
					Override: &view.ProfileOverride{
						Reviewer: "fixture-reviewer",
						Note:     "Accepted for the platform team's own use; the instruction text is inert here.",
						Expires:  view.Timestamp(now.Add(9 * 24 * time.Hour)),
					},
				},
			},
			Members: []view.ProfileMemberRow{
				{Kind: "user", Ref: "fixture-owner@fixture.invalid", Role: "owner", DisplayName: "Fixture Owner"},
				{Kind: "group", Ref: "eng-platform", Role: "maintainer"},
			},
			Targets: []view.ProfileTargetRow{
				{Target: "claude-code", Enabled: true},
				{Target: "codex", Enabled: false},
			},
			Revisions: []view.ProfileRevisionRow{
				{Revision: 14, Note: "pinned ADR Writer to 3.0.2", PublishedAt: view.Timestamp(now.Add(-7 * 24 * time.Hour)), PublishedBy: "fixture-owner@fixture.invalid"},
				{Revision: 13, PublishedAt: view.Timestamp(now.Add(-30 * 24 * time.Hour)), PublishedBy: "fixture-owner@fixture.invalid"},
			},
		}, nil
	case fixtureProfileForkedSlug:
		return view.Profile{
			Slug: fixtureProfileForkedSlug, Name: "SRE On-call",
			Visibility: "shared", DefaultPolicy: "floating-latest", Gate: "warn-with-override",
			ForkedFrom: fixtureProfileSlug, Role: "consumer",
			Permissions:        view.ProfilePermissions{},
			UnpublishedChanges: true,
			Targets: []view.ProfileTargetRow{
				{Target: "claude-code", Enabled: false},
				{Target: "codex", Enabled: false},
			},
		}, nil
	default:
		return view.Profile{}, view.ErrNotFound
	}
}

const fixtureDigest = "9f2c6a1e4b7d3f5081a2c9e6b7d4f1a3c8e5b2d9f6a1c4e7b0d3f6a9c2e5b8d1"

// Revision implements the "Show diff" panel's read: one published revision's
// resolved lockfile. Revision 14's note above ("pinned ADR Writer to 3.0.2")
// is what the diff between these two revisions shows: a version bump and a
// pin-mode change on that one entry, nothing else.
func (c *Catalog) Revision(_ context.Context, slug string, revision int) (view.LockfileSnapshot, error) {
	if slug != fixtureProfileSlug {
		return view.LockfileSnapshot{}, view.ErrNotFound
	}
	switch revision {
	case 14:
		return view.LockfileSnapshot{
			Revision: 14, Gate: "warn-with-override", DefaultPolicy: "floating-latest",
			Targets: []string{"claude-code"},
			Entries: []view.LockfileEntrySnapshot{
				{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"},
				{ID: "community/postgres-migration-guard", Version: "0.8.3", Resolution: "latest"},
			},
		}, nil
	case 13:
		return view.LockfileSnapshot{
			Revision: 13, Gate: "warn-with-override", DefaultPolicy: "floating-latest",
			Targets: []string{"claude-code"},
			Entries: []view.LockfileEntrySnapshot{
				{ID: "example/adr-writer", Version: "3.0.1", Resolution: "latest"},
				{ID: "community/postgres-migration-guard", Version: "0.8.3", Resolution: "latest"},
			},
		}, nil
	default:
		return view.LockfileSnapshot{}, view.ErrNotFound
	}
}
