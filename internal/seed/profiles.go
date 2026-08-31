package seed

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/blob"
	"agent-manager/internal/store/models"
)

// Profiles, their revisions and the lockfiles those revisions hold.
//
// A revision is immutable and its lockfile is the resolution as it stood when it
// was published — including the gate that was in force, which is why one seeded
// profile's head disagrees with the current org_policy row. Nothing here
// re-resolves anything: the resolution logic lives on the read side and a second
// implementation of the gate is how the screen and the CLI start disagreeing (003
// T078).

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

	for seq := 1; seq <= spec.revisions; seq++ {
		entries := spec.entries
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

		lockfile, err := lockfileFor(spec, seq, note, entries, idx, publishedAt)
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
	entries []entrySpec,
	idx index,
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

	for _, entry := range entries {
		resolved, err := resolveEntry(entry, idx)
		if err != nil {
			return contract.Lockfile{}, fmt.Errorf("%s r%d: %w", spec.slug, seq, err)
		}
		if entry.skipReason != "" {
			lockfile.Skipped = append(lockfile.Skipped, contract.LockfileSkip{
				ID:                  entry.pkg,
				Reason:              entry.skipReason,
				Detail:              entry.skipDetail,
				WouldHaveResolvedTo: resolved.ref.Semver,
			})
			continue
		}
		digest := resolved.digest
		lockfile.Entries = append(lockfile.Entries, contract.LockfileEntry{
			ID:         entry.pkg,
			Kind:       string(resolved.pkg.kind),
			Version:    resolved.ref.Semver,
			Digest:     "sha256:" + hex.EncodeToString(digest[:]),
			ObjectKey:  resolved.ref.BundleKey(),
			Resolution: string(entry.mode),
			Verdict:    string(resolved.spec.verdict),
		})
	}
	return lockfile, nil
}

func resolveEntry(entry entrySpec, idx index) (*builtVersion, error) {
	if entry.mode == models.EntryModePinned {
		pinned, ok := idx.byRef[entry.pkg+"@"+entry.version]
		if !ok {
			return nil, fmt.Errorf("%s@%s is pinned but not seeded", entry.pkg, entry.version)
		}
		return pinned, nil
	}
	return idx.resolvable(entry.pkg)
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
