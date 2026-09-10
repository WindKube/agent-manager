// Package auth is the api role's identity plumbing: OIDC discovery and
// ID-token verification, the `groups` claim to organisation-role mapping,
// and opaque server-side sessions whose tokens are hashed at rest. Nothing
// here is provider-specific.
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

// ErrUnauthenticated covers missing, unknown and expired credentials alike:
// distinguishing them on the wire tells an attacker whether a token existed.
var ErrUnauthenticated = errors.New("unauthenticated")

// Principal's Role is derived fresh per request, so a mapping change takes
// effect immediately.
type Principal struct {
	IdentityID  uuid.UUID
	Subject     string
	Email       string
	DisplayName string
	Groups      []string
	Role        models.OrgRole
	// Source is the audit row's source column: `web`, or `cli / <host>`.
	Source string
}

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

// Resolver turns a bearer token into a principal; Sessions and the
// device-flow layer each implement it.
type Resolver interface {
	Resolve(ctx context.Context, token string) (Principal, error)
}

// rolePrecedence is highest privilege first.
var rolePrecedence = []models.OrgRole{
	models.OrgRoleCatalogAdmin,
	models.OrgRoleScannerReviewer,
	models.OrgRoleProfileConsumer,
	models.OrgRoleReadOnly,
}

// HighestRole: no mapped group means no role, not a default one — a
// default is how an unknown group would silently acquire privilege.
func HighestRole(mapped []string) models.OrgRole {
	best := models.OrgRole("")
	bestRank := len(rolePrecedence)
	for _, raw := range mapped {
		role := models.OrgRole(raw)
		rank := slices.Index(rolePrecedence, role)
		if rank < 0 {
			// Unranked: fail closed, grant nothing.
			continue
		}
		if rank < bestRank {
			best, bestRank = role, rank
		}
	}
	return best
}

// tokenBytes is 256 bits, which is what makes HashToken's plain hash safe.
const tokenBytes = 32

// NewToken mints an opaque bearer token; only HashToken's output is stored.
func NewToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken uses sha256, not a password KDF: NewToken already draws 256
// random bits, so there's no low-entropy secret to grind against.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
