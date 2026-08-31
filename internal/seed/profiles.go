package seed

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/blob"
	"agent-manager/internal/domain/resolve"
	"agent-manager/internal/store/models"
)

// Profiles, their revisions and the lockfiles those revisions hold.
//
// A revision is immutable and its lockfile is the resolution as it stood when it
// was published — including the gate that was in force, which is why one seeded
// profile's head disagrees with the current org_policy row.
//
// The gate is applied by internal/domain/resolve and nowhere else (003 T078). The
// seed used to state each exclusion as data instead, which meant the dataset
// asserted an outcome nothing computed: a dataset can claim a package is awaiting
// approval while the versions and findings beside it say otherwise, and nothing
// would notice. Feeding the seeded versions, findings and overrides through the
// same resolver the screen and the CLI use makes the seeded history a consequence
// of the seeded catalog rather than a second opinion about it.

// buildRevisions is pure, and it runs before anything is written because both
// halves of the seed need its output: the row carries the lockfile, and the
// object store carries the same lockfile at the key the row names.
func buildRevisions(idx index, now time.Time) ([]models.Revision, error) {
	out := make([]models.Revision, 0, 32)
	for i := range designProfiles {
		rows, err := revisions(&designProfiles[i], idx, now)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

func writeProfiles(
	insert func(string, any) error,
	idx index,
	revisionRows []models.Revision,
	now time.Time,
) error {
	var (
		profileRows []models.Profile
		entryRows   []models.ProfileEntry
		memberRows  []models.Membership
		targetRows  []models.SyncTarget
	)

	for i := range designProfiles {
		spec := &designProfiles[i]
		profileID := seedID("profile", spec.slug)
		profileRows = append(profileRows, models.Profile{
			ID: profileID, Slug: spec.slug, Name: spec.name, Description: spec.description,
			Visibility: spec.visibility, OwnerTeam: spec.ownerTeam,
			DefaultPolicy: spec.defaultPolicy, CreatedAt: now, UpdatedAt: now,
		})

		for position, entry := range spec.entries {
			row := models.ProfileEntry{
				ProfileID: profileID, PackageID: seedID("package", entry.pkg),
				Mode: entry.mode, Position: int32(position), CreatedAt: now, UpdatedAt: now,
			}
			switch entry.mode {
			case models.EntryModePinned:
				pinned, ok := idx.byRef[entry.pkg+"@"+entry.version]
				if !ok {
					return fmt.Errorf("%s pins %s@%s, which the dataset does not seed",
						spec.slug, entry.pkg, entry.version)
				}
				id := seedID("version", pinned.ref.String())
				row.PinnedVersionID = &id
			case models.EntryModeRange:
				row.RangeExpr = entry.version
			}
			entryRows = append(entryRows, row)
		}

		for _, member := range spec.members {
			memberRows = append(memberRows, models.Membership{
				ProfileID: profileID, SubjectKind: member.kind, SubjectRef: member.ref,
				Role: member.role, CreatedAt: now, UpdatedAt: now,
			})
		}
		for _, target := range spec.targets {
			targetRows = append(targetRows, models.SyncTarget{
				ProfileID: profileID, Target: target, Enabled: true,
				CreatedAt: now, UpdatedAt: now,
			})
		}
	}

	if err := insert("profiles", &profileRows); err != nil {
		return err
	}
	if err := insert("profile entries", &entryRows); err != nil {
		return err
	}
	if err := insert("profile revisions", &revisionRows); err != nil {
		return err
	}
	if err := insert("profile memberships", &memberRows); err != nil {
		return err
	}
	if err := insert("profile sync targets", &targetRows); err != nil {
		return err
	}
	events := syncEvents(now)
	return insert("sync events", &events)
}

// revisions builds a profile's whole published history.
//
// The lockfile contract documents the sequence as gapless, so the history starts
// at r1 rather than at the head — and it is a history rather than N copies of the
// present: revision k resolves the first k entries, which is a profile that grew.
// Only the head carries the design's note.
func revisions(spec *profileSpec, idx index, now time.Time) ([]models.Revision, error) {
	owner := ownerOf(spec)
	rows := make([]models.Revision, 0, spec.revisions)

	// Built once for the whole history: the candidate set is a property of the
	// catalog, not of the revision, and `now` here is seed time — the instant the
	// findings and their acceptances are dated from — which is not the instant a
	// revision was published.
	all, err := resolverEntries(spec, idx, now)
	if err != nil {
		return nil, err
	}

	for seq := 1; seq <= spec.revisions; seq++ {
		entries := all
		if seq < len(entries) {
			entries = entries[:seq]
		}
		note := ""
		if seq == spec.revisions {
			note = spec.headNote
		}
		// The head lands where the design's audit row publishes it and each earlier
		// revision three days before the next, so the profile screen's "published"
		// column reads as a cadence rather than as a single instant.
		publishedAt := now.Add(-4 * time.Hour).Add(-time.Duration(spec.revisions-seq) * 72 * time.Hour)

		lockfile, err := lockfileFor(spec, seq, note, entries, publishedAt)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(lockfile)
		if err != nil {
			return nil, err
		}
		key, err := blob.ProfileRevisionKey(spec.slug, seq)
		if err != nil {
			return nil, err
		}

		rows = append(rows, models.Revision{
			ID:        seedID("revision", fmt.Sprintf("%s#%d", spec.slug, seq)),
			ProfileID: seedID("profile", spec.slug),
			Seq:       int32(seq),
			Note:      note,
			Lockfile:  encoded,
			ObjectKey: key,
			CreatedAt: publishedAt,
			CreatedBy: owner,
		})
	}
	return rows, nil
}

func lockfileFor(
	spec *profileSpec,
	seq int,
	note string,
	entries []resolve.Entry,
	at time.Time,
) (contract.Lockfile, error) {
	lockfile := contract.Lockfile{
		SchemaVersion: "1.0.0",
		Profile: contract.LockfileProfile{
			Slug: spec.slug, Name: spec.name, Visibility: string(spec.visibility),
		},
		Revision:      seq,
		Note:          note,
		ResolvedAt:    at,
		Gate:          string(spec.gate),
		DefaultPolicy: string(spec.defaultPolicy),
		Entries:       []contract.LockfileEntry{},
		Skipped:       []contract.LockfileSkip{},
		Targets:       []string{},
	}
	for _, target := range spec.targets {
		lockfile.Targets = append(lockfile.Targets, string(target))
	}

	// `at` rather than seed time: a revision records the resolution as it stood
	// when it was published, and whether an acceptance had lapsed by then is part
	// of that.
	result, err := resolve.Resolve(resolve.Input{
		Gate:    resolve.Gate(spec.gate),
		At:      at,
		Entries: entries,
	})
	if err != nil {
		return contract.Lockfile{}, fmt.Errorf("%s r%d: %w", spec.slug, seq, err)
	}

	for _, resolution := range result.Entries {
		if resolution.Skip != nil {
			lockfile.Skipped = append(lockfile.Skipped, contract.LockfileSkip{
				ID:                  resolution.Skip.ID,
				Reason:              string(resolution.Skip.Reason),
				Detail:              resolution.Skip.Detail,
				WouldHaveResolvedTo: resolution.Skip.WouldHaveResolvedTo,
			})
			continue
		}
		row := contract.LockfileEntry{
			ID:         resolution.ID,
			Kind:       resolution.Kind,
			Version:    resolution.Version.Semver,
			Digest:     resolution.Version.Digest,
			ObjectKey:  resolution.Version.ObjectKey,
			Resolution: string(resolution.Mode),
			Verdict:    string(resolution.Version.Verdict),
		}
		if resolution.Override != nil {
			row.Override = &contract.LockfileOverride{
				Reviewer: resolution.Override.Reviewer,
				Note:     resolution.Override.Note,
			}
			if resolution.Override.ExpiresAt != nil {
				row.Override.ExpiresAt = *resolution.Override.ExpiresAt
			}
		}
		lockfile.Entries = append(lockfile.Entries, row)
	}
	return lockfile, nil
}

// resolverEntries is the dataset in the shape the resolver takes: one entry per
// package the profile holds, each carrying every seeded version of it with the
// verdict, the finding and the acceptance that decide what the gate does.
//
// A pin that names an unseeded version fails the seed here rather than becoming a
// `pin-target-missing` skip in the lockfile. The skip reason is for a hub whose
// catalog has moved under a profile; a dataset that pins a version it does not
// seed is a typo, and a typo that publishes itself as a documented exclusion is a
// typo nobody finds.
func resolverEntries(spec *profileSpec, idx index, now time.Time) ([]resolve.Entry, error) {
	out := make([]resolve.Entry, 0, len(spec.entries))
	for _, entry := range spec.entries {
		built := resolve.Entry{ID: entry.pkg, Mode: resolve.Mode(entry.mode)}

		for _, version := range idx.byRef {
			if version.id() != entry.pkg {
				continue
			}
			candidate, err := candidateFor(version, now)
			if err != nil {
				return nil, err
			}
			built.Kind = string(version.pkg.kind)
			built.Candidates = append(built.Candidates, candidate)
		}
		if len(built.Candidates) == 0 {
			return nil, fmt.Errorf("%s holds %s, which the dataset does not seed", spec.slug, entry.pkg)
		}

		switch entry.mode {
		case models.EntryModePinned:
			built.PinnedID = entry.pkg + "@" + entry.version
			if _, ok := idx.byRef[built.PinnedID]; !ok {
				return nil, fmt.Errorf("%s pins %s@%s, which the dataset does not seed",
					spec.slug, entry.pkg, entry.version)
			}
		case models.EntryModeRange:
			built.Range = entry.version
		}
		out = append(out, built)
	}
	return out, nil
}

// candidateFor reads the finding and the acceptance the scan writers will record
// against this version out of the same dataset rows they read, so a seeded
// lockfile cannot disagree with the seeded scan history it is a consequence of.
func candidateFor(version *builtVersion, now time.Time) (resolve.Candidate, error) {
	digest := version.digest
	candidate := resolve.Candidate{
		ID:      version.ref.String(),
		Semver:  version.ref.Semver,
		Verdict: resolve.Verdict(version.spec.verdict),
		// An archived version stays out of a floating resolution and stays valid as
		// an explicit pin, which is resolve.Candidate.Visible exactly.
		Visible:   version.spec.distTag != models.DistTagArchived,
		Digest:    "sha256:" + hex.EncodeToString(digest[:]),
		ObjectKey: version.ref.BundleKey(),
	}

	finding := findingFor(version.ref.String())
	if finding == nil {
		return candidate, nil
	}
	// The path comes off the packed bytes, the same way the finding row's evidence
	// does, so the policy note cannot name a file the bundle does not hold.
	path, _, _, err := version.locate(finding.rule)
	if err != nil {
		return resolve.Candidate{}, err
	}
	candidate.FlagDetail = finding.rule + " in " + path

	if finding.override != nil {
		expires := findingDecidedAt(finding, version, now).Add(finding.override.expiresIn)
		candidate.Override = &resolve.Override{
			Reviewer:  finding.override.reviewer,
			Note:      finding.override.note,
			ExpiresAt: &expires,
		}
	}
	return candidate, nil
}

func ownerOf(spec *profileSpec) string {
	for _, member := range spec.members {
		if member.kind == models.SubjectKindUser && member.role == models.MembershipRoleOwner {
			return member.ref
		}
	}
	return "seed"
}

// syncEvents is the design's one recorded sync (its audit row names the host and
// the revision). It is what the catalog's use counts and the storage screen's
// CLI-read figure are computed from, so an unseeded table would read as a hub
// nobody has ever synced.
func syncEvents(now time.Time) []models.SyncEvent {
	profile := &designProfiles[0]
	identity, ok := identityBy("jkowalski@example.com")
	if !ok {
		return nil
	}
	return []models.SyncEvent{{
		ID:         seedID("sync-event", profile.slug+"#mbp-jk"),
		IdentityID: identity,
		ProfileID:  seedID("profile", profile.slug),
		RevisionID: seedID("revision", fmt.Sprintf("%s#%d", profile.slug, profile.revisions)),
		Host:       "mbp-jk",
		OccurredAt: now.Add(-40 * time.Minute),
	}}
}
