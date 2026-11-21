package api

import (
	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/store/models"
)

// Role checks for operations whose permission is the caller's organisation role.
// They live here, not in database grants, because `am_api` holds every grant for
// every caller. Hiding a button in the UI is not enforcement; this is the backstop.

// requireRole refuses the request unless the caller holds one of the roles given.
// An empty role (no mapped group) matches nothing, so an unmapped group never gains
// privilege. The 403 names the required roles so a person can tell an unmapped group from a wrong one.
func requireRole(role models.OrgRole, action string, allowed ...models.OrgRole) error {
	for _, candidate := range allowed {
		if role != "" && role == candidate {
			return nil
		}
	}
	return huma.Error403Forbidden("this identity may not " + action + "; it requires " +
		joinRoles(allowed))
}

// scannerDecisionRoles is who may adjudicate a finding. catalog-admin is included
// because role precedence gives the most privileged role the union of permissions.
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
