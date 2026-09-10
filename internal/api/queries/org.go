package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// The Organization screen's reads.
//
// The provider panel is NOT here: issuer, client id and scopes are this role's
// own configuration, and the device endpoint comes from a live discovery fetch.
// Neither is a database read, so both are assembled by the handler.

// Policy reads org_policy's mutable half. ErrNoPolicy mirrors
// profile_detail.go's: the singleton row missing is a broken deployment, not a
// default to fall back on.
func Policy(ctx context.Context, db bun.IDB) (contract.OrganizationPolicy, error) {
	var out contract.OrganizationPolicy
	err := db.QueryRowContext(ctx,
		`select scan_gate::text, require_signed_bundles, community_needs_review,
		        rescan_on_new_version, allow_personal_profiles
		   from org_policy where id = ?`, models.OrgPolicySingletonID).
		Scan(&out.ScanGate, &out.RequireSignedBundles, &out.CommunityNeedsReview,
			&out.RescanOnNewVersion, &out.AllowPersonalProfiles)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contract.OrganizationPolicy{}, ErrNoPolicy
	case err != nil:
		return contract.OrganizationPolicy{}, fmt.Errorf("read the organisation policy: %w", err)
	}
	return out, nil
}

// GroupRoleMappings reads every group-to-role mapping, alphabetically: the
// screen's table has no other order to preserve.
func GroupRoleMappings(ctx context.Context, db bun.IDB) ([]contract.GroupRoleMapping, error) {
	rows, err := db.QueryContext(ctx,
		`select group_name, role::text from group_role_map order by group_name`)
	if err != nil {
		return nil, fmt.Errorf("read the group-to-role mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []contract.GroupRoleMapping{}
	for rows.Next() {
		var row contract.GroupRoleMapping
		if err := rows.Scan(&row.GroupName, &row.Role); err != nil {
			return nil, fmt.Errorf("scan a group-to-role mapping: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the group-to-role mappings: %w", err)
	}
	return out, nil
}

// Categories reads the curated vocabulary with per-category package counts.
// The count joins package on category_id and is exactly the figure the
// screen's table shows beside each name.
func Categories(ctx context.Context, db bun.IDB) ([]contract.OrganizationCategory, error) {
	rows, err := db.QueryContext(ctx,
		`select cat.id::text, cat.name, cat.slug,
		        (select count(*) from package as pkg where pkg.category_id = cat.id)
		   from category as cat
		  order by cat.name`)
	if err != nil {
		return nil, fmt.Errorf("read the category vocabulary: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []contract.OrganizationCategory{}
	for rows.Next() {
		var row contract.OrganizationCategory
		if err := rows.Scan(&row.ID, &row.Name, &row.Slug, &row.Count); err != nil {
			return nil, fmt.Errorf("scan a category: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the category vocabulary: %w", err)
	}
	return out, nil
}
