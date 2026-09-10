package fixture

import (
	"context"
	"time"

	"agent-manager/internal/web/hub"
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
func (c *Catalog) Profiles(context.Context) ([]hub.ProfileSummary, error) {
	return []hub.ProfileSummary{
		{Slug: fixtureProfileSlug, Name: "Platform Engineer", Visibility: "organisation", PackageCount: 2, HeadRevision: 14},
		{Slug: fixtureProfileForkedSlug, Name: "SRE On-call", Visibility: "shared", PackageCount: 0, HeadRevision: 0},
	}, nil
}

// Profile implements the detail half of web.ProfileSource.
func (c *Catalog) Profile(_ context.Context, slug string) (hub.ProfileDetail, error) {
	now := time.Now().UTC()

	switch slug {
	case fixtureProfileSlug:
		expires := now.Add(9 * 24 * time.Hour)
		return hub.ProfileDetail{
			Slug: fixtureProfileSlug, Name: "Platform Engineer",
			Description: "The tools platform engineers sync onto a new machine.",
			Visibility:  "organisation", OwnerTeam: "example/platform",
			DefaultPolicy: "floating-latest", Gate: "warn-with-override",
			HeadRevision: 14, Role: "owner",
			Permissions: hub.ProfilePermissions{Curate: true, Share: true, Publish: true},
			Entries: []hub.ProfileEntry{
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
					Override: &hub.EntryOverride{
						Reviewer:  "fixture-reviewer",
						Note:      "Accepted for the platform team's own use; the instruction text is inert here.",
						ExpiresAt: &expires,
					},
				},
			},
			Members: []hub.ProfileMember{
				{Kind: "user", Ref: "fixture-owner@fixture.invalid", Role: "owner", DisplayName: "Fixture Owner"},
				{Kind: "group", Ref: "eng-platform", Role: "maintainer"},
			},
			Targets: []hub.ProfileTarget{
				{Target: "claude-code", Enabled: true},
				{Target: "codex", Enabled: false},
			},
			Revisions: []hub.ProfileRevision{
				{Revision: 14, Note: "pinned ADR Writer to 3.0.2", PublishedAt: now.Add(-7 * 24 * time.Hour), PublishedBy: "fixture-owner@fixture.invalid"},
				{Revision: 13, PublishedAt: now.Add(-30 * 24 * time.Hour), PublishedBy: "fixture-owner@fixture.invalid"},
			},
		}, nil
	case fixtureProfileForkedSlug:
		return hub.ProfileDetail{
			Slug: fixtureProfileForkedSlug, Name: "SRE On-call",
			Visibility: "shared", DefaultPolicy: "floating-latest", Gate: "warn-with-override",
			ForkedFrom: fixtureProfileSlug, Role: "consumer",
			Permissions:        hub.ProfilePermissions{},
			UnpublishedChanges: true,
			Targets: []hub.ProfileTarget{
				{Target: "claude-code", Enabled: false},
				{Target: "codex", Enabled: false},
			},
		}, nil
	default:
		return hub.ProfileDetail{}, view.ErrNotFound
	}
}

const fixtureDigest = "9f2c6a1e4b7d3f5081a2c9e6b7d4f1a3c8e5b2d9f6a1c4e7b0d3f6a9c2e5b8d1"
