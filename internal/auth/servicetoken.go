package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/logging"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

const (
	// ServiceTokenPrefix marks a service token secret, for secret scanners and
	// for routing a bearer token to the right resolver.
	ServiceTokenPrefix = "amst_"
	// MaxServiceTokenLifetime is the longest expiry a token may be created with;
	// there is no "never expires".
	MaxServiceTokenLifetime = 365 * 24 * time.Hour
	// DefaultServiceTokenLifetime is what a client offers when nobody chose.
	DefaultServiceTokenLifetime = 90 * 24 * time.Hour
	// MaxServiceTokenScopes bounds one token's scope list.
	MaxServiceTokenScopes = 50
	// MaxServiceTokenNameLength matches service_token_name_is_bounded.
	MaxServiceTokenNameLength = 100

	// SourceServiceToken is the audit source of a request a token made.
	SourceServiceToken = "service-token"
)

// Scope is one thing a service token may do. There are no write scopes.
type Scope string

const (
	// ScopeReadCatalog permits read-only catalog, package and scan reads.
	ScopeReadCatalog Scope = "read:catalog"

	syncProfileScopePrefix = "sync:profile/"
	maxProfileSlugLength   = 120
)

// profileSlugPattern is contract.CreateProfileRequest's slug pattern.
var profileSlugPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)

// ErrInvalidScope is a scope string that is not one this hub knows.
var ErrInvalidScope = errors.New("invalid service token scope")

// SyncProfileScope permits resolving one profile's lockfile, downloading its
// bundles and reporting syncs of it.
func SyncProfileScope(slug string) Scope { return Scope(syncProfileScopePrefix + slug) }

// Profile returns the slug a sync:profile scope names.
func (s Scope) Profile() (string, bool) {
	slug, ok := strings.CutPrefix(string(s), syncProfileScopePrefix)
	return slug, ok && slug != ""
}

// ParseScope accepts exactly read:catalog and sync:profile/<slug>.
func ParseScope(raw string) (Scope, error) {
	scope := Scope(raw)
	if scope == ScopeReadCatalog {
		return scope, nil
	}
	if slug, ok := scope.Profile(); ok && len(slug) <= maxProfileSlugLength && profileSlugPattern.MatchString(slug) {
		return scope, nil
	}
	return "", fmt.Errorf("%w: %q (want %s or %s<slug>)", ErrInvalidScope, raw, ScopeReadCatalog, syncProfileScopePrefix)
}

// ParseScopes parses, de-duplicates and sorts a scope list, refusing an empty
// or oversized one.
func ParseScopes(raw []string) ([]Scope, error) {
	scopes := make([]Scope, 0, len(raw))
	for _, r := range raw {
		scope, err := ParseScope(r)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	switch {
	case len(scopes) == 0:
		return nil, fmt.Errorf("%w: a token needs at least one scope", ErrInvalidScope)
	case len(scopes) > MaxServiceTokenScopes:
		return nil, fmt.Errorf("%w: at most %d scopes", ErrInvalidScope, MaxServiceTokenScopes)
	}
	slices.Sort(scopes)
	return scopes, nil
}

// ServiceTokenGrant is what a service-token principal may do. Creator bounds
// it: a token never reads what its creator could not, but it never holds the
// creator's role, so no role check can pass for it.
type ServiceTokenGrant struct {
	ID      uuid.UUID
	Name    string
	Scopes  []Scope
	Creator Principal
}

// Allows reports whether the grant carries scope.
func (g *ServiceTokenGrant) Allows(scope Scope) bool {
	return g != nil && slices.Contains(g.Scopes, scope)
}

// Profiles is every slug a sync:profile scope names.
func (g *ServiceTokenGrant) Profiles() []string {
	if g == nil {
		return nil
	}
	var slugs []string
	for _, scope := range g.Scopes {
		if slug, ok := scope.Profile(); ok {
			slugs = append(slugs, slug)
		}
	}
	return slugs
}

// NewServiceTokenSecret mints an `amst_`-prefixed secret with NewToken's 256
// bits; store only HashToken of it.
func NewServiceTokenSecret() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate service token: %w", err)
	}
	return ServiceTokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// IsServiceTokenSecret reports whether a bearer token is shaped like a
// service token rather than a session.
func IsServiceTokenSecret(token string) bool {
	return strings.HasPrefix(token, ServiceTokenPrefix)
}

// ServiceTokens resolves service-token secrets. Every resolve reads the row,
// so a revocation takes effect on the next request.
type ServiceTokens struct {
	db bun.IDB
}

func NewServiceTokens(db bun.IDB) ServiceTokens { return ServiceTokens{db: db} }

// The `due` columns are computed by the database clock so replicas agree on
// the throttles.
//
//nolint:gosec // G101: a query, not a credential.
const serviceTokenResolveSQL = `
select
  t.id,
  t.name,
  array_to_json(t.scopes)::text,
  t.revoked_at is not null,
  t.expires_at <= now(),
  t.last_used_at is null or t.last_used_at < now() - interval '1 minute',
  t.last_use_audited_at is null or t.last_use_audited_at < now() - interval '1 day',
  t.last_use_audited_at is null,
  i.id,
  i.subject,
  coalesce(i.email, ''),
  coalesce(i.display_name, ''),
  array_to_json(i.groups)::text
from service_token as t
join identity as i on i.id = t.created_by_identity_id
where t.token_hash = ?`

// Resolve exchanges a service-token secret for a principal with no identity,
// no groups and no role of its own. Expired and revoked tokens are refused as
// unknown ones are, and the refusal is logged rather than audited.
func (s ServiceTokens) Resolve(ctx context.Context, token string) (Principal, error) {
	if !IsServiceTokenSecret(token) {
		return Principal{}, ErrUnauthenticated
	}

	var (
		grant                        ServiceTokenGrant
		scopesJSON, groupsJSON       string
		revoked, expired             bool
		touchDue, auditDue, firstUse bool
	)
	creator := &grant.Creator
	err := s.db.QueryRowContext(ctx, serviceTokenResolveSQL, HashToken(token)).Scan(
		&grant.ID, &grant.Name, &scopesJSON, &revoked, &expired, &touchDue, &auditDue, &firstUse,
		&creator.IdentityID, &creator.Subject, &creator.Email, &creator.DisplayName, &groupsJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Principal{}, ErrUnauthenticated
	case err != nil:
		return Principal{}, fmt.Errorf("resolve service token: %w", err)
	}

	if revoked || expired {
		reason := "expired"
		if revoked {
			reason = "revoked"
		}
		log := logging.From(ctx)
		log.Warn().Str("serviceTokenId", grant.ID.String()).Str("reason", reason).
			Msg("refused a service token")
		return Principal{}, ErrUnauthenticated
	}

	var rawScopes []string
	if err := json.Unmarshal([]byte(scopesJSON), &rawScopes); err != nil {
		return Principal{}, fmt.Errorf("decode service token scopes: %w", err)
	}
	// A stored scope that no longer parses grants nothing rather than failing
	// the token outright.
	for _, raw := range rawScopes {
		if scope, err := ParseScope(raw); err == nil {
			grant.Scopes = append(grant.Scopes, scope)
		}
	}
	if err := json.Unmarshal([]byte(groupsJSON), &creator.Groups); err != nil {
		return Principal{}, fmt.Errorf("decode service token creator groups: %w", err)
	}
	creator.Source = SourceServiceToken

	if touchDue || auditDue {
		if err := s.recordUse(ctx, grant, auditDue, firstUse); err != nil {
			return Principal{}, err
		}
	}

	return Principal{ServiceToken: &grant, Source: SourceServiceToken}, nil
}

// recordUse moves last_used_at and, at most once a day, writes the audit row
// for the use. The conditional update decides which replica writes that row.
func (s ServiceTokens) recordUse(ctx context.Context, grant ServiceTokenGrant, auditDue, firstUse bool) error {
	return s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewUpdate().Model((*models.ServiceToken)(nil)).
			Set("last_used_at = now()").
			Where("id = ?", grant.ID).
			Where("last_used_at is null or last_used_at < now() - interval '1 minute'").
			Exec(ctx); err != nil {
			return fmt.Errorf("touch service token: %w", err)
		}
		if !auditDue {
			return nil
		}

		res, err := tx.NewUpdate().Model((*models.ServiceToken)(nil)).
			Set("last_use_audited_at = now()").
			Where("id = ?", grant.ID).
			Where("last_use_audited_at is null or last_use_audited_at < now() - interval '1 day'").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("mark service token use audited: %w", err)
		}
		if n, rowsErr := res.RowsAffected(); rowsErr != nil || n == 0 {
			return rowsErr
		}

		action, text := "used", "service token "+grant.Name+" was used"
		if firstUse {
			action, text = "first-used", "service token "+grant.Name+" was used for the first time"
		}
		event, err := audit.New(audit.Entry{
			Kind: models.AuditKindToken, Action: action, Actor: grant.Name,
			ActorKind: models.ActorKindServiceToken, Text: text, Source: SourceServiceToken,
			Subject: audit.ServiceToken(grant.ID, grant.Name),
		})
		if err != nil {
			return err
		}
		if _, err := tx.NewInsert().Model(event).Exec(ctx); err != nil {
			return fmt.Errorf("write service token use audit row: %w", err)
		}
		return nil
	})
}

// Chain routes a bearer token to the service-token resolver by its prefix
// and to sessions otherwise.
type Chain struct {
	Sessions      Resolver
	ServiceTokens Resolver
}

func (c Chain) Resolve(ctx context.Context, token string) (Principal, error) {
	if IsServiceTokenSecret(token) {
		if c.ServiceTokens == nil {
			return Principal{}, ErrUnauthenticated
		}
		return c.ServiceTokens.Resolve(ctx, token)
	}
	if c.Sessions == nil {
		return Principal{}, ErrUnauthenticated
	}
	return c.Sessions.Resolve(ctx, token)
}
