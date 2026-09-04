package commands

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// The Organization screen's mutations.
//
// Every command here writes exactly one audit row inside its own transaction,
// except the two that write nothing at all: TestIdentityConnection performs no
// mutation, and RotateClientSecret and the two deletes below are refusals — an
// audited action is one that happened, and nothing here did.

const (
	categoryNameConstraint = "category_name_key"
	categorySlugConstraint = "category_slug_key"
)

// ---- identity -------------------------------------------------------------------

// IdentityConfig is what this role is configured with for its own provider —
// never the client secret, which this package never reads.
type IdentityConfig struct {
	Issuer       string
	DiscoveryURL string
	ClientID     string
	Scopes       []string
}

// discoveryDocument is the subset of an OIDC discovery document this screen
// needs. jwks_uri is fetched too, to make the connection test a real proof of
// reachability and not merely a well-formed URL.
type discoveryDocument struct {
	Issuer                      string `json:"issuer"`
	JWKSURI                     string `json:"jwks_uri"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

const (
	identityFetchTimeout = 5 * time.Second
	maxIdentityBytes     = 1 << 20
)

// fetchDiscovery mirrors internal/auth/oidc.go's own discovery fetch: same
// bounded read, same rule that the document's issuer must equal the configured
// one rather than being trusted verbatim. It is duplicated rather than shared
// because that package reads the session table and internal/api/commands must
// not import a package with a datastore-shaped API for what is, here, an
// unauthenticated network probe.
func fetchDiscovery(ctx context.Context, cfg IdentityConfig) (discoveryDocument, error) {
	if cfg.Issuer == "" {
		return discoveryDocument{}, errors.New("no identity provider is configured")
	}
	base := cfg.DiscoveryURL
	if base == "" {
		base = cfg.Issuer
	}
	url := strings.TrimSuffix(base, "/") + "/.well-known/openid-configuration"

	doc, err := getJSON[discoveryDocument](ctx, url)
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("discovery against %s: %w", url, err)
	}
	if doc.Issuer != cfg.Issuer {
		return discoveryDocument{}, fmt.Errorf(
			"discovery against %s: document names issuer %q, not the configured %q",
			url, doc.Issuer, cfg.Issuer)
	}
	return doc, nil
}

func getJSON[T any](ctx context.Context, url string) (T, error) {
	var out T
	ctx, cancel := context.WithTimeout(ctx, identityFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return out, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIdentityBytes)).Decode(&out); err != nil {
		return out, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// DeviceAuthorizationEndpoint serves getOrganization's provider panel. Absent
// rather than an error when discovery cannot be completed: the panel still owes
// the reader the issuer, client id and scopes this role actually holds.
func DeviceAuthorizationEndpoint(ctx context.Context, cfg IdentityConfig) string {
	doc, err := fetchDiscovery(ctx, cfg)
	if err != nil {
		return ""
	}
	return doc.DeviceAuthorizationEndpoint
}

// TestIdentityConnection performs a real OIDC discovery and JWKS fetch against
// the configured issuer. It reads no stored secret and echoes none: a failure
// reason names discovery or the key endpoint, never a credential.
func TestIdentityConnection(ctx context.Context, cfg IdentityConfig) contract.IdentityConnectionTest {
	doc, err := fetchDiscovery(ctx, cfg)
	if err != nil {
		return contract.IdentityConnectionTest{Detail: err.Error()}
	}
	if doc.JWKSURI == "" {
		return contract.IdentityConnectionTest{Detail: "the discovery document names no signing-key endpoint"}
	}
	if _, err := getJSON[struct {
		Keys []json.RawMessage `json:"keys"`
	}](ctx, doc.JWKSURI); err != nil {
		return contract.IdentityConnectionTest{Detail: fmt.Sprintf("signing keys unreachable: %s", err)}
	}
	return contract.IdentityConnectionTest{OK: true}
}

// ErrSecretRotationUnsupported is RotateClientSecret's whole implementation.
//
// The client secret is environment configuration (config.API.ClientSecret,
// research R-none: this hub does not own the identity provider's client
// registration), so there is no registration for this hub to rotate a secret
// against. A rotation that only overwrote a local copy would tell the operator
// it had changed something at the provider, and it would not have. That is worse
// than refusing plainly, so this is a refusal and not a fake write: no row
// changes and no audit event is recorded, because nothing happened.
var ErrSecretRotationUnsupported = errors.New(
	"the identity provider's client secret is managed by the deployment environment " +
		"(the OIDC_CLIENT_SECRET this role was started with), not by this hub; there is no " +
		"provider-side registration here for a rotation to act on")

// RotateClientSecret always refuses. See ErrSecretRotationUnsupported.
func RotateClientSecret(context.Context) error { return ErrSecretRotationUnsupported }

// ---- policy -----------------------------------------------------------------

// ErrInvalidGate is returned when a scan gate is not one of the three the schema
// allows.
var ErrInvalidGate = errors.New("scan gate must be block, approval or warn-with-override")

// UpdatePolicy writes every org_policy toggle and one `policy` audit row.
//
// Downstream effect is not this command's job to prove: the gate and
// require_signed_bundles are read live by internal/domain/resolve on every
// profile resolution (queries.ResolveProfileFacts), community_needs_review and
// rescan_on_new_version are read live by the scanner (see
// internal/worker/scanner). This command's only job is to write the row those
// reads see next.
func UpdatePolicy(ctx context.Context, db bun.IDB, p auth.Principal,
	in contract.UpdatePolicyRequest,
) (contract.OrganizationPolicy, error) {
	gate := models.ScanGate(in.ScanGate)
	if !gate.Valid() {
		return contract.OrganizationPolicy{}, ErrInvalidGate
	}

	out := contract.OrganizationPolicy{
		ScanGate:              string(gate),
		RequireSignedBundles:  in.RequireSignedBundles,
		CommunityNeedsReview:  in.CommunityNeedsReview,
		RescanOnNewVersion:    in.RescanOnNewVersion,
		AllowPersonalProfiles: in.AllowPersonalProfiles,
	}

	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, txErr := tx.NewUpdate().Model((*models.OrgPolicy)(nil)).
			Set("scan_gate = ?", gate).
			Set("require_signed_bundles = ?", in.RequireSignedBundles).
			Set("community_needs_review = ?", in.CommunityNeedsReview).
			Set("rescan_on_new_version = ?", in.RescanOnNewVersion).
			Set("allow_personal_profiles = ?", in.AllowPersonalProfiles).
			Set("updated_at = now()").
			Where("id = ?", models.OrgPolicySingletonID).
			Exec(ctx)
		if txErr != nil {
			return fmt.Errorf("update the organisation policy: %w", txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return fmt.Errorf("update the organisation policy: %w", sql.ErrNoRows)
		}
		return writeOrgAudit(ctx, tx, p, models.AuditKindPolicy, "updated the organisation policy")
	})
	if err != nil {
		return contract.OrganizationPolicy{}, err
	}
	return out, nil
}

// ---- group-to-role mappings ---------------------------------------------------

// ErrInvalidRole is returned when a role is not one of the four the schema
// allows.
var ErrInvalidRole = errors.New(
	"role must be catalog-admin, scanner-reviewer, profile-consumer or read-only")

// ErrValidation wraps a request the caller can fix by changing the body — a
// missing name, a name with nothing left after slugifying.
var ErrValidation = errors.New("invalid request")

// ErrMappingNotFound is returned when no mapping holds the given group name.
var ErrMappingNotFound = errors.New("no such mapping")

// CreateMapping upserts a group's role and writes one `role` audit row. It is an
// upsert rather than a strict create because a mapping is keyed on the group
// name alone and re-pointing an existing group at a new role is the same screen
// action as adding one.
func CreateMapping(ctx context.Context, db bun.IDB, p auth.Principal,
	in contract.CreateMappingRequest,
) (contract.GroupRoleMapping, error) {
	groupName := strings.TrimSpace(in.GroupName)
	role := models.OrgRole(in.Role)
	switch {
	case groupName == "":
		return contract.GroupRoleMapping{}, fmt.Errorf("%w: a mapping needs a group name", ErrValidation)
	case !role.Valid():
		return contract.GroupRoleMapping{}, ErrInvalidRole
	}

	out := contract.GroupRoleMapping{GroupName: groupName, Role: string(role)}
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if _, txErr := tx.NewInsert().Model(&models.GroupRoleMap{GroupName: groupName, Role: role}).
			On("conflict (group_name) do update").
			Set("role = excluded.role").
			Set("updated_at = now()").
			Exec(ctx); txErr != nil {
			return fmt.Errorf("map group %q to %s: %w", groupName, role, txErr)
		}
		return writeOrgAudit(ctx, tx, p, models.AuditKindRole,
			fmt.Sprintf("mapped group %q to role %s", groupName, role))
	})
	if err != nil {
		return contract.GroupRoleMapping{}, err
	}
	return out, nil
}

// DeleteMapping removes a group's mapping and writes one `role` audit row.
func DeleteMapping(ctx context.Context, db bun.IDB, p auth.Principal, groupName string) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, txErr := tx.NewDelete().Model((*models.GroupRoleMap)(nil)).
			Where("group_name = ?", groupName).
			Exec(ctx)
		if txErr != nil {
			return fmt.Errorf("remove mapping %q: %w", groupName, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrMappingNotFound
		}
		return writeOrgAudit(ctx, tx, p, models.AuditKindRole, fmt.Sprintf("removed mapping for group %q", groupName))
	})
}

// ---- categories -----------------------------------------------------------------

// ErrCategoryNotFound is returned when no category holds the given id.
var ErrCategoryNotFound = errors.New("no such category")

// ErrCategoryExists is returned when a category's name or slug collides with an
// existing one.
var ErrCategoryExists = errors.New("a category with that name already exists")

// ErrCategoryInUse is returned when a category is still assigned to at least
// one package.
var ErrCategoryInUse = errors.New("category is still assigned to at least one package")

// CreateCategory adds a category to the curated vocabulary and writes one
// `category` audit row.
func CreateCategory(ctx context.Context, db bun.IDB, p auth.Principal,
	in contract.CreateCategoryRequest,
) (contract.OrganizationCategory, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return contract.OrganizationCategory{}, fmt.Errorf("%w: a category needs a name", ErrValidation)
	}
	slug := slugify(name)
	if slug == "" {
		return contract.OrganizationCategory{}, fmt.Errorf("%w: that name has no usable characters for a slug", ErrValidation)
	}

	row := &models.Category{ID: models.NewID(), Name: name, Slug: slug}
	out := contract.OrganizationCategory{ID: row.ID.String(), Name: name, Slug: slug}

	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if _, txErr := tx.NewInsert().Model(row).Exec(ctx); txErr != nil {
			if isUniqueViolation(txErr, categoryNameConstraint) || isUniqueViolation(txErr, categorySlugConstraint) {
				return ErrCategoryExists
			}
			return fmt.Errorf("create category %q: %w", name, txErr)
		}
		return writeOrgAudit(ctx, tx, p, models.AuditKindCategory, fmt.Sprintf("added category %q", name))
	})
	if err != nil {
		return contract.OrganizationCategory{}, err
	}
	return out, nil
}

// UpdateCategory renames a category and writes one `category` audit row. Its
// count is not returned here — the caller already has the read path for that —
// because a rename does not change how many packages carry the category.
func UpdateCategory(ctx context.Context, db bun.IDB, p auth.Principal,
	id string, in contract.UpdateCategoryRequest,
) (contract.OrganizationCategory, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return contract.OrganizationCategory{}, fmt.Errorf("%w: a category needs a name", ErrValidation)
	}
	slug := slugify(name)
	if slug == "" {
		return contract.OrganizationCategory{}, fmt.Errorf("%w: that name has no usable characters for a slug", ErrValidation)
	}

	out := contract.OrganizationCategory{ID: id, Name: name, Slug: slug}
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, txErr := tx.NewUpdate().Model((*models.Category)(nil)).
			Set("name = ?", name).
			Set("slug = ?", slug).
			Set("updated_at = now()").
			Where("id = ?", id).
			Exec(ctx)
		if txErr != nil {
			if isUniqueViolation(txErr, categoryNameConstraint) || isUniqueViolation(txErr, categorySlugConstraint) {
				return ErrCategoryExists
			}
			return fmt.Errorf("rename category %s: %w", id, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrCategoryNotFound
		}
		return writeOrgAudit(ctx, tx, p, models.AuditKindCategory, fmt.Sprintf("renamed category to %q", name))
	})
	if err != nil {
		return contract.OrganizationCategory{}, err
	}
	return out, nil
}

// DeleteCategory removes a category and writes one `category` audit row.
// Refuses with ErrCategoryInUse when a package still carries it — the
// package.category_id foreign key has no ON DELETE clause, so that refusal is
// the database's own, not a check duplicated here.
func DeleteCategory(ctx context.Context, db bun.IDB, p auth.Principal, id string) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, txErr := tx.NewDelete().Model((*models.Category)(nil)).
			Where("id = ?", id).
			Exec(ctx)
		if txErr != nil {
			if isForeignKeyViolation(txErr) {
				return ErrCategoryInUse
			}
			return fmt.Errorf("delete category %s: %w", id, txErr)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return ErrCategoryNotFound
		}
		return writeOrgAudit(ctx, tx, p, models.AuditKindCategory, fmt.Sprintf("deleted category %s", id))
	})
}

// isForeignKeyViolation reports whether err is Postgres 23503, the sqlstate a
// delete gets when another table still references the row.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23503"
}

// slugify is the same shape resolveCategory's lookup already expects: lowercase,
// non-alphanumeric runs collapsed to one hyphen, trimmed.
func slugify(name string) string {
	var b strings.Builder
	prevHyphen := true // leading hyphens are trimmed by never starting one
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevHyphen = false
		case !prevHyphen:
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

// writeOrgAudit is the one audit write every mutation in this file that
// actually mutates something goes through, so the actor derivation cannot drift
// between them.
func writeOrgAudit(ctx context.Context, tx bun.IDB, p auth.Principal, kind models.AuditKind, text string) error {
	actor := p.Email
	if actor == "" {
		actor = p.Subject
	}
	return writeAudit(ctx, tx, kind, actor, string(models.ActorKindIdentity), text, p.Source)
}
