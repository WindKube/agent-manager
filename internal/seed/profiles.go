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

// Seeded lockfiles are computed by internal/domain/resolve, the same resolver
// the product uses, so they cannot disagree with the seeded catalog.

// buildRevisions is pure; both the rows and the object store need its lockfiles.
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

// revisions builds a profile's gapless history from r1: revision k resolves the
// first k entries.
func revisions(spec *profileSpec, idx index, now time.Time) ([]models.Revision, error) {
	owner := ownerOf(spec)
	rows := make([]models.Revision, 0, spec.revisions)

	// Built once: candidates depend on the catalog, not the revision. `now` is seed time.
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
		// Earlier revisions are spaced three days apart.
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
	// Resolve at publish time, since whether an acceptance had lapsed depends on it.
	result, err := resolve.Resolve(resolve.Input{
		Gate:    resolve.Gate(spec.gate),
		At:      at,
		Entries: entries,
	})
	if err != nil {
		return contract.Lockfile{}, fmt.Errorf("%s r%d: %w", spec.slug, seq, err)
	}

	targets := make([]string, 0, len(spec.targets))
	for _, target := range spec.targets {
		targets = append(targets, string(target))
	}

	// Same assembly as the publish command, so seeded and real lockfiles cannot drift.
	return contract.LockfileFrom(
		contract.LockfileProfile{
			Slug: spec.slug, Name: spec.name, Visibility: string(spec.visibility),
		},
		seq, note, at, string(spec.defaultPolicy), targets, result,
	), nil
}

// resolverEntries is the profile's packages in resolver form. A pin naming an
// unseeded version fails the seed rather than becoming a `pin-target-missing` skip,
// since in a dataset it is a typo.
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

// candidateFor reads the finding and acceptance from the same dataset rows the
// scan writers use, so lockfiles match the scan history.
func candidateFor(version *builtVersion, now time.Time) (resolve.Candidate, error) {
	digest := version.digest
	candidate := resolve.Candidate{
		ID:        version.ref.String(),
		Semver:    version.ref.Semver,
		Verdict:   resolve.Verdict(version.spec.verdict),
		Visible:   version.spec.distTag != models.DistTagArchived,
		Digest:    "sha256:" + hex.EncodeToString(digest[:]),
		ObjectKey: version.ref.BundleKey(),
	}

	finding := findingFor(version.ref.String())
	if finding == nil {
		return candidate, nil
	}
	// Taken from the packed bytes so the note cannot name a file the bundle lacks.
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

// syncEvents is the design's one recorded sync, which use counts are computed from.
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
