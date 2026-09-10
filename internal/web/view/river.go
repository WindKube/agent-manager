package view

import "slices"

// RiverEmbedPrefix is where this hub serves the dashboard from, and it is also
// the prefix the dashboard itself must be started with (its PATH_PREFIX): it
// rewrites its own asset and api URLs from that, so the proxy in front of it
// rewrites no bytes and an upgrade cannot break a rewrite that does not exist.
//
// A constant, and the frame's src is built from it here rather than passed in,
// so no value off a request can ever reach that attribute.
const RiverEmbedPrefix = "/river/embed"

// River is the River Dashboard screen: the queue dashboard embedded in this
// hub rather than opened on a port of its own, so a person reading it is
// reading it as themselves, through this role's session.
type River struct {
	// EmbedPath is the same-origin path the frame loads. Empty when there is
	// nothing to embed, so the frame is never rendered pointing at nothing.
	EmbedPath string
	// Gate is why the frame is absent, and empty when it is there. The two
	// reasons a reader gets are different facts — no dashboard is deployed, or
	// their role may not read it — and neither is "the page is broken".
	Gate string
}

// RiverAccessFor is the role gate on the dashboard, which is the same role the
// api demands for GET /v1/runtime: the dashboard shows the runtime report's
// queue state and then some, job arguments included.
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

// RiverUnconfiguredReason is what a hub that deploys no dashboard says. Stated
// as a deployment fact, because that is what it is: nothing is broken and
// nothing the reader can do here will change it.
const RiverUnconfiguredReason = "This hub runs no River dashboard. An operator sets " +
	"AGENT_MANAGER_RIVER_UI_URL on the web role to point at one; until then the Runtime screen " +
	"is where the queue's state is reported."

// RiverFor decides which of the three states this screen is in.
func RiverFor(viewer *Viewer, configured bool) River {
	if access := RiverAccessFor(viewer); !access.Allowed {
		return River{Gate: access.Reason}
	}
	if !configured {
		return River{Gate: RiverUnconfiguredReason}
	}
	return River{EmbedPath: RiverEmbedPrefix + "/"}
}
