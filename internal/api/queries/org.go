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

// Policy reads org_policy's mutable half. A missing singleton row is a broken
// deployment, hence ErrNoPolicy rather than a default.
func Policy(ctx context.Context, db bun.IDB) (contract.OrganizationPolicy, error) {
	var out contract.OrganizationPolicy
	err := db.QueryRowContext(ctx,
		`select scan_gate::text, require_signed_bundles, community_needs_review,
		        rescan_on_new_version, allow_personal_profiles,
		        (select count(*) from package
		          where latest_version_id is not null and expected_signer_issuer is null)
		   from org_policy where id = ?`, models.OrgPolicySingletonID).
		Scan(&out.ScanGate, &out.RequireSignedBundles, &out.CommunityNeedsReview,
			&out.RescanOnNewVersion, &out.AllowPersonalProfiles, &out.PackagesWithoutExpectedSigner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contract.OrganizationPolicy{}, ErrNoPolicy
	case err != nil:
		return contract.OrganizationPolicy{}, fmt.Errorf("read the organisation policy: %w", err)
	}
	return out, nil
}

// GroupRoleMappings reads every group-to-role mapping, alphabetically.
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
