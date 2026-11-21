package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// StaleAfterDays is how long a machine may go without a report before it
// is listed as stale.
const StaleAfterDays = 14

// MaxMachinePageSize caps one page of the machine list.
const MaxMachinePageSize = 200

// MachineFilter narrows the machine list. Version needs Package; Stale is
// "", "true" or "false".
type MachineFilter struct {
	Package, Version, Profile, Stale string
	Page, PageSize                   int
}

// MachineVisible renders which machines p may see, over the given alias of
// table `machine`: every one for a catalog-admin, otherwise the ones whose
// last report was p's own or one of p's service tokens'. A token sees none.
func MachineVisible(alias string, p auth.Principal) (predicate string, args []any) {
	switch {
	case p.IsServiceToken() || p.IdentityID == uuid.Nil:
		return "false", nil
	case p.Role == models.OrgRoleCatalogAdmin:
		return "true", nil
	default:
		return alias + ".last_identity_id = ?", []any{p.IdentityID}
	}
}

type machineRow struct {
	ID           uuid.UUID `bun:"id"`
	Hostname     string    `bun:"hostname"`
	OS           string    `bun:"os"`
	Arch         string    `bun:"arch"`
	AmctlVersion string    `bun:"amctl_version"`
	FirstSeenAt  time.Time `bun:"first_seen_at"`
	LastSeenAt   time.Time `bun:"last_seen_at"`
	Stale        bool      `bun:"stale"`
	LastProfile  string    `bun:"last_profile"`
	LastRevision int       `bun:"last_revision"`
	ReportedBy   string    `bun:"reported_by"`
	ServiceToken string    `bun:"service_token"`
}

func (r *machineRow) wire() contract.Machine {
	return contract.Machine{
		ID: r.ID.String(), Hostname: r.Hostname, OS: r.OS, Arch: r.Arch, AmctlVersion: r.AmctlVersion,
		FirstSeenAt: r.FirstSeenAt, LastSeenAt: r.LastSeenAt, Stale: r.Stale,
		LastProfile: r.LastProfile, LastRevision: r.LastRevision, ReportedBy: r.ReportedBy,
		ServiceToken: r.ServiceToken,
	}
}

const machineColumns = `
select m.id, m.hostname, coalesce(m.os, '') as os, coalesce(m.arch, '') as arch,
	coalesce(m.amctl_version, '') as amctl_version, m.first_seen_at, m.last_seen_at,
	m.last_seen_at < now() - make_interval(days => ?) as stale,
	lp.slug as last_profile, lr.seq as last_revision,
	coalesce(li.email, li.subject) as reported_by, coalesce(lt.name, '') as service_token
from machine as m
join profile as lp on lp.id = m.last_profile_id
join revision as lr on lr.id = m.last_revision_id
join identity as li on li.id = m.last_identity_id
left join service_token as lt on lt.id = m.last_service_token_id`

// Machines lists the machines p may see that match f. A package or profile
// filter p cannot read is ErrNotFound, never an empty list.
func Machines(ctx context.Context, db bun.IDB, p auth.Principal, f MachineFilter) (contract.MachineList, error) {
	out := contract.MachineList{Machines: []contract.Machine{}, StaleAfterDays: StaleAfterDays}

	visible, visibleArgs := MachineVisible("m", p)
	where, args := []string{visible}, visibleArgs
	add := func(clause string, a ...any) {
		where = append(where, clause)
		args = append(args, a...)
	}

	var packageID, versionID uuid.UUID
	if f.Package != "" {
		id, err := readablePackageID(ctx, db, p, f.Package)
		if err != nil {
			return out, err
		}
		packageID = id
	}
	if f.Version != "" {
		if packageID == uuid.Nil {
			return out, fmt.Errorf("%w: a version filter needs a package", ErrInvalidFilter)
		}
		err := db.NewSelect().Model((*models.Version)(nil)).Column("id").
			Where("package_id = ? and semver = ?", packageID, f.Version).Scan(ctx, &versionID)
		if errors.Is(err, sql.ErrNoRows) {
			return out, ErrNotFound
		} else if err != nil {
			return out, fmt.Errorf("resolve version filter: %w", err)
		}
	}
	if f.Profile != "" {
		readable, readableArgs := Readable("p", p)
		var profileID uuid.UUID
		err := db.QueryRowContext(ctx, "select p.id from profile as p where p.slug = ? and "+readable,
			append([]any{f.Profile}, readableArgs...)...).Scan(&profileID)
		if errors.Is(err, sql.ErrNoRows) {
			return out, ErrNotFound
		} else if err != nil {
			return out, fmt.Errorf("resolve profile filter: %w", err)
		}
		add("(m.last_profile_id = ? or exists (select 1 from machine_install as fp where fp.machine_id = m.id and fp.profile_id = ?))",
			profileID, profileID)
	}
	switch f.Stale {
	case "true":
		add("m.last_seen_at < now() - make_interval(days => ?)", StaleAfterDays)
	case "false":
		add("m.last_seen_at >= now() - make_interval(days => ?)", StaleAfterDays)
	}
	// The version counts take every filter but the package's own.
	base, baseArgs := strings.Join(where, " and "), append([]any{}, args...)
	switch {
	case versionID != uuid.Nil:
		add("exists (select 1 from machine_install as fi where fi.machine_id = m.id and fi.package_id = ? and fi.version_id = ?)",
			packageID, versionID)
	case packageID != uuid.Nil:
		add("exists (select 1 from machine_install as fi where fi.machine_id = m.id and fi.package_id = ?)", packageID)
	}
	cond := strings.Join(where, " and ")

	if err := db.QueryRowContext(ctx, "select count(*) from machine as m where "+cond, args...).
		Scan(&out.Total); err != nil {
		return out, fmt.Errorf("count machines: %w", err)
	}
	out.PageSize, out.Page = min(max(f.PageSize, 1), MaxMachinePageSize), max(f.Page, 1)
	if pages := (out.Total + out.PageSize - 1) / out.PageSize; out.Total > 0 && out.Page > pages {
		out.Page = pages
	}

	var rows []machineRow
	if err := db.NewRaw(machineColumns+" where "+cond+" order by m.last_seen_at desc, m.id limit ? offset ?",
		append(append([]any{StaleAfterDays}, args...), out.PageSize, (out.Page-1)*out.PageSize)...).
		Scan(ctx, &rows); err != nil {
		return out, fmt.Errorf("list machines: %w", err)
	}
	for i := range rows {
		out.Machines = append(out.Machines, rows[i].wire())
	}

	if packageID != uuid.Nil {
		if err := db.NewRaw(`
select v.semver as version, count(distinct i.machine_id) as machines
from machine_install as i
join version as v on v.id = i.version_id
join machine as m on m.id = i.machine_id
where i.package_id = ? and `+base+`
group by v.semver, v.semver_sort
order by v.semver_sort desc`, append([]any{packageID}, baseArgs...)...).Scan(ctx, &out.Versions); err != nil {
			return out, fmt.Errorf("count machines per version: %w", err)
		}
	}
	return out, nil
}

// ErrInvalidFilter is a filter combination that means nothing.
var ErrInvalidFilter = errors.New("invalid filter")

func readablePackageID(ctx context.Context, db bun.IDB, p auth.Principal, ref string) (uuid.UUID, error) {
	namespace, name, ok := strings.Cut(ref, "/")
	if !ok || namespace == "" || name == "" {
		return uuid.Nil, ErrNotFound
	}
	readable, readableArgs := PackageReadable("pkg", p)
	var id uuid.UUID
	err := db.QueryRowContext(ctx, "select pkg.id from package as pkg where pkg.namespace = ? and pkg.name = ? and "+readable,
		append([]any{namespace, name}, readableArgs...)...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	} else if err != nil {
		return uuid.Nil, fmt.Errorf("resolve package filter: %w", err)
	}
	return id, nil
}

// Machine is one machine p may see, with its installs and latest skips
// limited to the profiles and packages p may read.
func Machine(ctx context.Context, db bun.IDB, p auth.Principal, id uuid.UUID) (contract.MachineDetail, error) {
	out := contract.MachineDetail{
		StaleAfterDays: StaleAfterDays, Installs: []contract.MachineInstall{}, Skipped: []contract.MachineSkip{},
	}
	visible, visibleArgs := MachineVisible("m", p)
	var rows []machineRow
	if err := db.NewRaw(machineColumns+" where m.id = ? and "+visible,
		append([]any{StaleAfterDays, id}, visibleArgs...)...).Scan(ctx, &rows); err != nil {
		return out, fmt.Errorf("read machine %s: %w", id, err)
	}
	if len(rows) == 0 {
		return out, ErrNotFound
	}
	out.Machine = rows[0].wire()

	// Installs and skips share one scoping: readable profiles, and readable
	// packages where the row names one the hub holds.
	profileReadable, profileArgs := Readable("pr", p)
	packageReadable, packageArgs := PackageReadable("pkg", p)
	if err := db.NewRaw(`
select pkg.namespace || '/' || pkg.name as package, v.semver as version, i.target::text as target, pr.slug as profile
from machine_install as i
join package as pkg on pkg.id = i.package_id
join version as v on v.id = i.version_id
join profile as pr on pr.id = i.profile_id
where i.machine_id = ? and `+profileReadable+` and `+packageReadable+`
order by i.target, pkg.namespace, pkg.name, pr.slug`, append(append([]any{id}, profileArgs...), packageArgs...)...).
		Scan(ctx, &out.Installs); err != nil {
		return out, fmt.Errorf("read the installs of machine %s: %w", id, err)
	}

	if err := db.NewRaw(`
select pr.slug as profile, s.entry, coalesce(s.target::text, '') as target,
	coalesce(s.component, '') as component, coalesce(s.reason, '') as reason
from machine_skip as s
join profile as pr on pr.id = s.profile_id
left join package as pkg on pkg.namespace = split_part(s.entry, '/', 1)
	and pkg.name = substr(s.entry, strpos(s.entry, '/') + 1)
where s.machine_id = ? and `+profileReadable+` and (pkg.id is null or `+packageReadable+`)
order by pr.slug, s.entry, s.target nulls first, s.component`, append(append([]any{id}, profileArgs...), packageArgs...)...).
		Scan(ctx, &out.Skipped); err != nil {
		return out, fmt.Errorf("read the skips of machine %s: %w", id, err)
	}
	return out, nil
}
