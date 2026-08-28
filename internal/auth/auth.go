// Package auth is the api role's identity plumbing: OIDC discovery and
// ID-token verification, the `groups` claim to organisation-role mapping, and
// opaque server-side sessions whose tokens are hashed at rest.
//
// Nothing here is provider-specific. The local stack's identity provider is a
// deployment choice; this package knows only what OIDC discovery tells it and
// what the `groups` claim contains.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"agent-manager/internal/store/models"
)

// ErrUnauthenticated is returned when a credential is missing, unknown or
// expired. Callers must not distinguish the three on the wire: which one it was
// tells an attacker whether a token ever existed.
var ErrUnauthenticated = errors.New("unauthenticated")

// Principal is who a request is acting as. Groups come from the identity row,
// which is refreshed on every token issue, so losing a group takes effect at the
// next refresh (FR-045). Role is derived per request from group_role_map, so an
// admin's mapping change takes effect immediately (FR-040).
type Principal struct {
	IdentityID  uuid.UUID
	Subject     string
	Email       string
	DisplayName string
	Groups      []string
	Role        models.OrgRole
	// Source is the audit row's source column: `web`, or `cli / <host>`
	// (constitution principle IV, FR-050).
	Source string
}

// Refs are the values a membership row's subject_ref may name for this
// principal. The sharing panel in the design lists a member by email, while a
// fixture or an IdP-driven import may know only the subject, so both are
// accepted and nothing else is.
func (p Principal) Refs() []string {
	refs := make([]string, 0, 2)
	if p.Email != "" {
		refs = append(refs, p.Email)
	}
	if p.Subject != "" {
		refs = append(refs, p.Subject)
	}
	return refs
}

// Resolver turns a bearer token into a principal. Sessions implements it today;
// the device-flow layer adds a second implementation for machine tokens, which is
// why the api holds this interface and not a concrete store.
type Resolver interface {
	Resolve(ctx context.Context, token string) (Principal, error)
}

// rolePrecedence is highest privilege first. A person in several mapped groups
// holds the union of their permissions, which for a single-role column means the
// most privileged of them (FR-040, data-model.md's membership note).
var rolePrecedence = []models.OrgRole{
	models.OrgRoleCatalogAdmin,
	models.OrgRoleScannerReviewer,
	models.OrgRoleProfileConsumer,
	models.OrgRoleReadOnly,
}

// HighestRole picks the most privileged of the roles a principal's groups map
// to. An unmapped group contributes nothing: it never reaches this function,
// because group_role_map is the only source of a role. No mapped group at all
// means no role, not a default one — a default is how an unknown group silently
// acquires privilege.
func HighestRole(mapped []string) models.OrgRole {
	best := models.OrgRole("")
	bestRank := len(rolePrecedence)
	for _, raw := range mapped {
		role := models.OrgRole(raw)
		rank := slices.Index(rolePrecedence, role)
		if rank < 0 {
			// A value the database enum allows but this list does not rank. Failing
			// closed is the only safe reading: an unranked role grants nothing.
			continue
		}
		if rank < bestRank {
			best, bestRank = role, rank
		}
	}
	return best
}

// tokenBytes is 256 bits, which is what makes HashToken's choice of a plain hash
// the right one.
const tokenBytes = 32

// NewToken mints an opaque bearer token. It is returned exactly once and never
// stored: what is stored is HashToken's output.
func NewToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken hashes an opaque bearer token for storage.
//
// sha256 rather than a password KDF, deliberately: NewToken draws 256 bits from
// crypto/rand, so there is no low-entropy secret for an attacker to grind
// against, and a KDF would add its cost to every authenticated request. The
// property that matters is the one the schema names — `token_hash bytea unique`
// — a database read must not yield a usable bearer credential. Lookup is by hash
// and therefore not constant-time, which leaks nothing: the value compared is
// already a hash of 256 random bits.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
