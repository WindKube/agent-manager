package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/store/models"
)

// reporter is who a machine's report is attributed to.
type reporter struct {
	identityID   uuid.UUID
	serviceToken *uuid.UUID
}

// recordMachine upserts the reporting machine and replaces its installs and
// skips for the reported profile. Runs inside ReportSync's transaction; the
// upsert's row lock serialises concurrent reports from one machine.
func recordMachine(ctx context.Context, tx bun.Tx, machineID uuid.UUID, by reporter,
	ref queries.RevisionRef, in contract.SyncReport,
) error {
	installs, err := resolveInstalls(ctx, tx, in.Installed)
	if err != nil {
		return err
	}
	skips, err := reportedSkips(in)
	if err != nil {
		return err
	}

	machine := &models.Machine{
		ID: machineID, Hostname: in.Host, OS: in.OS, Arch: in.Arch, AmctlVersion: in.AmctlVersion,
		LastIdentityID: by.identityID, LastServiceTokenID: by.serviceToken,
		LastProfileID: ref.ProfileID, LastRevisionID: ref.RevisionID,
	}
	if _, err := tx.NewInsert().Model(machine).
		ExcludeColumn("first_seen_at", "last_seen_at").
		On("conflict (id) do update").
		Set("hostname = excluded.hostname, os = excluded.os, arch = excluded.arch").
		Set("amctl_version = excluded.amctl_version, last_identity_id = excluded.last_identity_id").
		Set("last_service_token_id = excluded.last_service_token_id").
		Set("last_profile_id = excluded.last_profile_id, last_revision_id = excluded.last_revision_id").
		Set("last_seen_at = now()").
		Exec(ctx); err != nil {
		return fmt.Errorf("record machine %s: %w", machineID, err)
	}

	// Component skips of an entry this sync did not write still describe
	// what is on disk, so they survive the replace.
	untouched := map[string]bool{}
	for _, inst := range in.Installed {
		if !inst.Changed {
			untouched[inst.ID+"\x00"+inst.Target] = true
		}
	}
	var kept []models.MachineSkip
	if len(untouched) > 0 {
		var previous []models.MachineSkip
		if err := tx.NewSelect().Model(&previous).
			Where("machine_id = ? and profile_id = ? and component is not null", machineID, ref.ProfileID).
			Scan(ctx); err != nil {
			return fmt.Errorf("read the component skips of machine %s: %w", machineID, err)
		}
		for i := range previous {
			if untouched[previous[i].Entry+"\x00"+string(previous[i].Target)] {
				kept = append(kept, previous[i])
			}
		}
	}

	for _, model := range []any{(*models.MachineInstall)(nil), (*models.MachineSkip)(nil)} {
		if _, err := tx.NewDelete().Model(model).
			Where("machine_id = ? and profile_id = ?", machineID, ref.ProfileID).
			Exec(ctx); err != nil {
			return fmt.Errorf("clear the inventory of machine %s: %w", machineID, err)
		}
	}

	rows := make([]models.MachineInstall, 0, len(installs))
	for _, inst := range installs {
		rows = append(rows, models.MachineInstall{
			MachineID: machineID, ProfileID: ref.ProfileID, Target: models.SyncTargetKind(inst.target),
			PackageID: inst.packageID, VersionID: inst.versionID,
		})
	}
	if len(rows) > 0 {
		if _, err := tx.NewInsert().Model(&rows).Exec(ctx); err != nil {
			return fmt.Errorf("record the installs of machine %s: %w", machineID, err)
		}
	}

	skips = append(skips, kept...)
	for i := range skips {
		skips[i].ID, skips[i].MachineID, skips[i].ProfileID = models.NewID(), machineID, ref.ProfileID
	}
	if len(skips) > 0 {
		if _, err := tx.NewInsert().Model(&skips).Exec(ctx); err != nil {
			return fmt.Errorf("record the skips of machine %s: %w", machineID, err)
		}
	}
	return nil
}

type resolvedInstall struct {
	packageID, versionID uuid.UUID
	target               string
}

// resolveInstalls maps reported id@version pairs onto catalog rows in one
// query, refusing the report when any of them names nothing the hub holds.
func resolveInstalls(ctx context.Context, tx bun.Tx, in []contract.SyncInstall) ([]resolvedInstall, error) {
	if len(in) == 0 {
		return nil, nil
	}
	namespaces, names, versions := make([]string, 0, len(in)), make([]string, 0, len(in)), make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, inst := range in {
		key := inst.ID + "\x00" + inst.Target
		if seen[key] {
			return nil, fmt.Errorf("%w: %s is reported twice for target %s", ErrValidation, inst.ID, inst.Target)
		}
		seen[key] = true
		ns, name, ok := strings.Cut(inst.ID, "/")
		if !ok || ns == "" || name == "" {
			return nil, fmt.Errorf("%w: installed id %q is not namespace/name", ErrValidation, inst.ID)
		}
		namespaces, names, versions = append(namespaces, ns), append(names, name), append(versions, inst.Version)
	}

	var found []struct {
		PackageID uuid.UUID `bun:"package_id"`
		VersionID uuid.UUID `bun:"version_id"`
		Ref       string    `bun:"ref"`
	}
	if err := tx.NewRaw(`
select p.id as package_id, v.id as version_id, p.namespace || '/' || p.name || '@' || v.semver as ref
from unnest(?::text[], ?::text[], ?::text[]) as want(namespace, name, semver)
join package as p on p.namespace = want.namespace and p.name = want.name
join version as v on v.package_id = p.id and v.semver = want.semver`,
		pgdialect.Array(namespaces), pgdialect.Array(names), pgdialect.Array(versions)).
		Scan(ctx, &found); err != nil {
		return nil, fmt.Errorf("resolve installed versions: %w", err)
	}
	byRef := make(map[string]int, len(found))
	for i := range found {
		byRef[found[i].Ref] = i
	}

	out := make([]resolvedInstall, 0, len(in))
	var unknown []string
	for _, inst := range in {
		i, ok := byRef[inst.ID+"@"+inst.Version]
		if !ok {
			unknown = append(unknown, inst.ID+"@"+inst.Version)
			continue
		}
		out = append(out, resolvedInstall{packageID: found[i].PackageID, versionID: found[i].VersionID, target: inst.Target})
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("%w: the hub holds no version %s", ErrValidation, strings.Join(unknown, ", "))
	}
	return out, nil
}

// reportedSkips is the report's own skips: whole entries from `skipped`,
// components from `skippedComponents`.
func reportedSkips(in contract.SyncReport) ([]models.MachineSkip, error) {
	out := make([]models.MachineSkip, 0, len(in.Skipped)+len(in.SkippedComponents))
	for _, entry := range in.Skipped {
		if entry == "" || len(entry) > 256 {
			return nil, fmt.Errorf("%w: skipped entry %q is empty or longer than 256 bytes", ErrValidation, entry)
		}
		out = append(out, models.MachineSkip{Entry: entry})
	}
	for _, sk := range in.SkippedComponents {
		out = append(out, models.MachineSkip{
			Entry: sk.Entry, Target: models.SyncTargetKind(sk.Target), Component: sk.Component, Reason: sk.Reason,
		})
	}
	return out, nil
}
