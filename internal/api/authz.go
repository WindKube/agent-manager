package api

import (
	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/store/models"
)

// Role checks for operations whose permission is the caller's organisation role
// rather than a row's readability.
//
// The row-level half of this system's authorisation is queries.Readable, which is
// a WHERE clause and therefore cannot be forgotten by a statement that composes
// it. This half has no such property: it is a branch, and a branch is only where
// somebody put it. So there is one function, and every operation that needs a
// role calls it — three hand-written copies of an authorisation check is how one
// of them silently drifts, which is the argument queries.Readable's own comment
// makes.
//
// It lives in the api and not in the database's grants because `am_api` holds
// every grant on behalf of every caller: the cluster cannot tell two sessions
// apart, so the role a person holds is only enforceable here. That is the same
// reasoning the read-only refusal on registerPackage already carries.
//
// FR-126 requires an impermissible action to be ABSENT OR DISABLED WITH ITS
// REASON, not offered and then refused. This is not that requirement — it is the
// backstop under it. A screen that hides a button satisfies FR-126; it does not
// stop a request, and a request is what reaches this code.

// requireRole refuses the request unless the caller holds one of the roles given.
//
// `Principal.Role` is legitimately the empty string: auth.HighestRole returns no
// role rather than a default one when no group the identity holds is mapped, and
// FR-117 makes that a screen state of its own. It matches nothing here, which is
// the only safe reading — a default would be how an unmapped group acquires
// privilege.
//
// The 403's message names what the action needed. That is deliberate and is not
// an enumeration risk: the role vocabulary is published in the document, the
// caller is authenticated, and a refusal that says only "forbidden" leaves a
// person unable to tell an unmapped group from a wrong one — which is exactly the
// confusion FR-117 exists to remove.
func requireRole(role models.OrgRole, action string, allowed ...models.OrgRole) error {
	for _, candidate := range allowed {
		if role != "" && role == candidate {
			return nil
		}
	}
	return huma.Error403Forbidden("this identity may not " + action + "; it requires " +
		joinRoles(allowed))
}

// scannerDecisionRoles is who may adjudicate a finding.
//
// `catalog-admin` is included beside `scanner-reviewer` because auth's role
// precedence — catalog-admin, scanner-reviewer, profile-consumer, read-only,
// highest privilege first — states that a person in several mapped groups holds
// the UNION of their permissions, "which for a single-role column means the most
// privileged of them". A privilege ordering in which the top role cannot do what
// the second can is not an ordering, and a catalog admin who also sat in the
// security group would otherwise be demoted by holding both.
var scannerDecisionRoles = []models.OrgRole{
	models.OrgRoleScannerReviewer,
	models.OrgRoleCatalogAdmin,
}

func joinRoles(roles []models.OrgRole) string {
	out := ""
	for i, role := range roles {
		switch {
		case i == 0:
			out = string(role)
		case i == len(roles)-1:
			out += " or " + string(role)
		default:
			out += ", " + string(role)
		}
	}
	return out
}
