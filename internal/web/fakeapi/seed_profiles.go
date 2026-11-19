package fakeapi

import (
	"time"

	"agent-manager/internal/apiclient"
)

const profileDigest = "9f2c6a1e4b7d3f5081a2c9e6b7d4f1a3c8e5b2d9f6a1c4e7b0d3f6a9c2e5b8d1"

func seedProfiles(d *Data, now time.Time) {
	d.Profiles = []apiclient.Profile{
		{Slug: "platform-engineer", Name: "Platform Engineer", Visibility: ptr(apiclient.ProfileVisibilityOrganisation),
			PackageCount: 2, HeadRevision: 14, CanCurate: true},
		{Slug: "sre-oncall", Name: "SRE On-call", Visibility: ptr(apiclient.ProfileVisibilityShared)},
	}

	owner := "fixture-owner@fixture.invalid"
	d.ProfileDetails = map[string]apiclient.ProfileDetail{
		"platform-engineer": {
			Slug: "platform-engineer", Name: "Platform Engineer",
			Description:   ptr("The tools platform engineers sync onto a new machine."),
			Visibility:    apiclient.ProfileDetailVisibilityOrganisation,
			OwnerTeam:     ptr("example/platform"),
			DefaultPolicy: apiclient.ProfileDetailDefaultPolicyFloatingLatest,
			Gate:          apiclient.ProfileDetailGateWarnWithOverride,
			HeadRevision:  14,
			Role:          ptr(apiclient.ProfileDetailRoleOwner),
			Permissions:   apiclient.ProfilePermissions{Curate: true, Share: true, Publish: true},
			Entries: []apiclient.ProfileEntry{
				{
					Id: "example/adr-writer", Name: "ADR Writer", Kind: apiclient.ProfileEntryKindSkill,
					Mode: apiclient.ProfileEntryModePinned, PinnedVersion: ptr("3.0.2"),
					LatestVersion: ptr("3.0.2"), LatestVerdict: ptr(apiclient.ProfileEntryLatestVerdictClean),
					Version: ptr("3.0.2"), Verdict: ptr(apiclient.ProfileEntryVerdictClean),
					Digest: ptr("sha256:" + profileDigest), Outcome: apiclient.Resolved,
				},
				{
					Id: "community/postgres-migration-guard", Name: "Postgres Migration Guard", Kind: apiclient.ProfileEntryKindSkill,
					Mode:          apiclient.ProfileEntryModeLatest,
					LatestVersion: ptr("0.8.3"), LatestVerdict: ptr(apiclient.ProfileEntryLatestVerdictFlagged),
					Version: ptr("0.8.3"), Verdict: ptr(apiclient.ProfileEntryVerdictFlagged),
					Digest: ptr("sha256:" + profileDigest), Outcome: apiclient.Warned,
					Note: ptr("Flagged (SH-INJ-011 in SKILL.md); warn-with-override includes it with a warning."),
					Override: &apiclient.LockfileOverride{
						Reviewer:  "fixture-reviewer",
						Note:      "Accepted for the platform team's own use; the instruction text is inert here.",
						ExpiresAt: now.Add(9 * day),
					},
				},
			},
			Members: []apiclient.ProfileMember{
				{Kind: apiclient.ProfileMemberKindUser, Ref: owner, Role: apiclient.ProfileMemberRoleOwner, DisplayName: ptr("Fixture Owner")},
				{Kind: apiclient.ProfileMemberKindGroup, Ref: "eng-platform", Role: apiclient.ProfileMemberRoleMaintainer},
			},
			Targets: []apiclient.ProfileTarget{
				{Target: apiclient.ProfileTargetTargetClaudeCode, Enabled: true},
				{Target: apiclient.ProfileTargetTargetCodex, Enabled: false},
			},
			Revisions: []apiclient.ProfileRevision{
				{Revision: 14, Note: ptr("pinned ADR Writer to 3.0.2"), PublishedAt: now.Add(-7 * day), PublishedBy: owner},
				{Revision: 13, PublishedAt: now.Add(-30 * day), PublishedBy: owner},
			},
		},
		"sre-oncall": {
			Slug: "sre-oncall", Name: "SRE On-call",
			Visibility:         apiclient.ProfileDetailVisibilityShared,
			DefaultPolicy:      apiclient.ProfileDetailDefaultPolicyFloatingLatest,
			Gate:               apiclient.ProfileDetailGateWarnWithOverride,
			ForkedFrom:         ptr("platform-engineer"),
			Role:               ptr(apiclient.ProfileDetailRoleConsumer),
			UnpublishedChanges: true,
			Entries:            []apiclient.ProfileEntry{},
			Members:            []apiclient.ProfileMember{},
			Revisions:          []apiclient.ProfileRevision{},
			Targets: []apiclient.ProfileTarget{
				{Target: apiclient.ProfileTargetTargetClaudeCode, Enabled: false},
				{Target: apiclient.ProfileTargetTargetCodex, Enabled: false},
			},
		},
	}

	// r14 against r13 is the "pinned ADR Writer to 3.0.2" diff: one version bump and a mode change.
	d.Revisions = map[string]map[int64]apiclient.Lockfile{
		"platform-engineer": {
			14: lockfile(14, now.Add(-7*day), ptr("pinned ADR Writer to 3.0.2"),
				lockEntry("example/adr-writer", "3.0.2", apiclient.LockfileEntryResolutionPinned, apiclient.LockfileEntryVerdictClean),
				lockEntry("community/postgres-migration-guard", "0.8.3", apiclient.LockfileEntryResolutionLatest, apiclient.LockfileEntryVerdictFlagged)),
			13: lockfile(13, now.Add(-30*day), nil,
				lockEntry("example/adr-writer", "3.0.1", apiclient.LockfileEntryResolutionLatest, apiclient.LockfileEntryVerdictClean),
				lockEntry("community/postgres-migration-guard", "0.8.3", apiclient.LockfileEntryResolutionLatest, apiclient.LockfileEntryVerdictFlagged)),
		},
	}
}

func lockfile(revision int64, resolvedAt time.Time, note *string, entries ...apiclient.LockfileEntry) apiclient.Lockfile {
	return apiclient.Lockfile{
		SchemaVersion: apiclient.N100,
		Profile: apiclient.LockfileProfile{
			Slug: "platform-engineer", Name: "Platform Engineer",
			Visibility: ptr(apiclient.LockfileProfileVisibilityOrganisation),
		},
		Revision:      revision,
		Note:          note,
		ResolvedAt:    resolvedAt,
		Gate:          apiclient.LockfileGateWarnWithOverride,
		DefaultPolicy: ptr(apiclient.LockfileDefaultPolicyFloatingLatest),
		Targets:       []apiclient.LockfileTargets{apiclient.LockfileTargetsClaudeCode},
		Entries:       entries,
		Skipped:       []apiclient.LockfileSkip{},
	}
}

func lockEntry(id, version string, resolution apiclient.LockfileEntryResolution, verdict apiclient.LockfileEntryVerdict) apiclient.LockfileEntry {
	return apiclient.LockfileEntry{
		Id: id, Kind: apiclient.LockfileEntryKindSkill, Version: version,
		Resolution: resolution, Verdict: verdict, Digest: profileDigest,
		ObjectKey: "skills/" + id + "/" + version + "/bundle.tar.zst",
	}
}
