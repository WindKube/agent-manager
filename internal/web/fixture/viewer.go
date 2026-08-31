package fixture

import (
	"context"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The viewer variants a screen test renders with (T050).
//
// They live HERE, in the one package this role admits is a stand-in, and the
// placement is the point rather than a convenience: SC-106 makes a display name in
// the product a defect and the same display name in a test's input a fixture, so
// the identity sweep in internal/web excludes this package by name. Put one of
// these values in a component instead and that sweep fails, which is the whole
// mechanism.
//
// The names and the addresses are deliberately nobody's. `.invalid` cannot resolve
// (RFC 2606), and neither value names either of the two people in
// deploy/local/glauth who can actually sign in — a fixture naming one of them
// would be the seeded-identity defect internal/seed/groups.go describes, moved one
// layer up the stack: a constant holding a viewer who cannot be that viewer.

// SignedInViewer holds a role, for a test that wants the shell with its chip.
//
// SignedIn is set explicitly, and it is not decoration: Initials() reads it
// rather than inferring presence from the name, so a fixture that left it false
// would render a chip with a blank avatar and every test would be asserting the
// signed-out derivation of a signed-in viewer.
func SignedInViewer() *view.Viewer {
	return &view.Viewer{
		SignedIn:    true,
		DisplayName: "Ada Fixture",
		Email:       "ada@fixture.invalid",
		// Hyphenated as the org_role enum spells it. A pre-humanised string here
		// would exercise a path the product does not take.
		Role:    "catalog-admin",
		HasRole: true,
		Groups:  []string{"eng-platform", "eng-all"},
	}
}

// UnmappedViewer is signed in and holds no role — FR-117's state, which is neither
// signed out nor an empty hub. It is a variant of its own rather than
// SignedInViewer with Role blanked, because HasRole is what the templates branch
// on and a test that blanked only the string would not be in this state.
func UnmappedViewer() *view.Viewer {
	return &view.Viewer{
		// Signed in. Holding no role is not a degree of being signed out — the
		// identity resolved, and HasRole is the only thing that separates this from
		// the variant above.
		SignedIn:    true,
		DisplayName: "Bo Fixture",
		Email:       "bo@fixture.invalid",
		Groups:      []string{"contractors-eu"},
	}
}

// SignedOutViewer is nil, which is what Shell.Viewer holds when a request
// resolved nobody.
//
// A function rather than a bare nil at the call site, so a test reads as the state
// it exercises and there is one place to look when asking what signed out means to
// a component: the absence of a viewer, never a viewer with empty fields.
func SignedOutViewer() *view.Viewer { return nil }

// Viewers is a ViewerSource for a screen test: one viewer resolved on every
// request, or one error on every request.
//
// It exists because web.Deps.Viewers fails CLOSED when nil — the guard sends every
// protected route to the sign-in screen — so a test that wants to render a screen
// at all has to say who is looking at it. That is deliberate (SC-106: there is no
// default viewer and there must not be one), and it means the signed-in state is
// something a test states rather than something it inherits.
type Viewers struct {
	V   hub.Viewer
	Err error
}

// Viewer resolves on every request, which is what FR-118 asks of the real one: the
// role is read per request, so a mapping change needs no cache invalidated.
func (v Viewers) Viewer(context.Context) (hub.Viewer, error) {
	if v.Err != nil {
		return hub.Viewer{}, v.Err
	}
	return v.V, nil
}

// SignedInViewers resolves SignedInViewer, for the ordinary case of a screen test
// that wants the shell with its chip.
func SignedInViewers() Viewers { return Viewers{V: wireViewer(SignedInViewer())} }

// UnmappedViewers resolves UnmappedViewer — signed in, holding no role. The guard
// renders FR-117's screen for this one, not the screen that was asked for.
func UnmappedViewers() Viewers { return Viewers{V: wireViewer(UnmappedViewer())} }

// SignedOutViewers resolves nobody, reporting the sentinel the guard branches on.
// This is the state a request arrives in with no session cookie, or with one the
// api no longer recognises.
func SignedOutViewers() Viewers { return Viewers{Err: view.ErrSignedOut} }

// wireViewer maps a render fixture onto the wire shape the api answers with, so
// the two cannot drift: a test's viewer travels the same path a real one does.
func wireViewer(v *view.Viewer) hub.Viewer {
	if v == nil {
		return hub.Viewer{}
	}
	return hub.Viewer{
		Subject:     v.Subject,
		DisplayName: v.DisplayName,
		Email:       v.Email,
		Role:        v.Role,
		HasRole:     v.HasRole,
		Groups:      v.Groups,
	}
}
