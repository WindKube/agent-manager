package view

import "slices"

// RiverEmbedPrefix must match the dashboard's own PATH_PREFIX, so the proxy rewrites no bytes. It is a
// constant so no request value can reach the frame's src.
const RiverEmbedPrefix = "/river/embed"

// River is the embedded River dashboard, served through this role's session rather than its own port.
type River struct {
	// EmbedPath is empty when there is nothing to embed.
	EmbedPath string
	// Gate is why the frame is absent: no dashboard deployed, or the role may not read it.
	Gate string
}

// RiverAccessFor requires the same role as GET /v1/runtime, since the dashboard also exposes job arguments.
func RiverAccessFor(viewer *Viewer) OrgAccess {
	switch {
	case viewer == nil || !viewer.SignedIn:
		return OrgAccess{Reason: "Sign in to read the queue dashboard."}
	case !viewer.HasRole:
		return OrgAccess{Reason: "Your identity is not mapped to a role yet, so it may not read " +
			"the queue's internals."}
	case !slices.Contains(OrgAdminRoles, viewer.Role):
		return OrgAccess{Reason: "Your role, " + viewer.RoleLabel() + ", may not read the queue's " +
			"internals. Queue depth, job arguments and runner errors are operational detail; this " +
			"needs the catalog admin role."}
	}
	return OrgAccess{Allowed: true}
}

const RiverUnconfiguredReason = "This hub runs no River dashboard. An operator sets " +
	"AGENT_MANAGER_RIVER_UI_URL on the web role to point at one; until then the Runtime screen " +
	"is where the queue's state is reported."

func RiverFor(viewer *Viewer, configured bool) River {
	if access := RiverAccessFor(viewer); !access.Allowed {
		return River{Gate: access.Reason}
	}
	if !configured {
		return River{Gate: RiverUnconfiguredReason}
	}
	return River{EmbedPath: RiverEmbedPrefix + "/"}
}
