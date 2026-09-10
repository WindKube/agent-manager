package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

// The profile curation surface (003 T078-T083, 001 US5).
//
// Authorisation here has two layers and they answer different questions. FR-044
// readability decides whether the profile EXISTS as far as this caller is
// concerned, and it is a WHERE clause inside every query and command — a profile
// this identity may not read is a 404 on every one of these paths, because a 403
// would confirm the slug and that is the enumeration FR-044 forbids. The caller's
// MEMBERSHIP role then decides what they may do to a profile they can see, and
// that refusal IS a 403 naming what the action needed: the caller already knows
// the profile is there, so the only useful thing left to tell them is which role
// would have worked.
//
// The one path with no membership to consult is creating a profile, which is
// gated on the organisation role instead. Everything else deliberately ignores
// the organisation role: a catalog admin cannot read a private profile they hold
// no membership on, so letting one publish an organisation-visible profile they
// are not a member of would be an authorisation model with two answers.

type profileSlugInput struct {
	Slug string `path:"slug" doc:"The profile's URL-safe identifier. It may carry several segments, as the design's example/platform-engineer does." example:"example/platform-engineer"`
}

// ---- GET /v1/profiles/{slug} -------------------------------------------------

type profileDetailOutput struct {
	Body contract.ProfileDetail
}

func (s *Server) getProfile(ctx context.Context, in *profileSlugInput) (*profileDetailOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	detail, err := queries.ProfileDetail(ctx, s.deps.DB, principal, in.Slug)
	if err != nil {
		return nil, profileFailure(ctx, err)
	}
	return &profileDetailOutput{Body: detail}, nil
}

// ---- POST /v1/profiles -------------------------------------------------------

// profileCreateRoles is who may create a profile.
//
// Everything except read-only and the empty role, which is the same shape
// registerPackage's refusal has: a contractor mapped to `read-only` may consume
// what the organisation publishes and may not create organisation state. The
// empty role matches nothing here for the reason requireRole states — a default
// is how an unmapped group acquires privilege.
var profileCreateRoles = []models.OrgRole{
	models.OrgRoleCatalogAdmin,
	models.OrgRoleScannerReviewer,
	models.OrgRoleProfileConsumer,
}

type createProfileInput struct {
	Body contract.ProfileCreate
}

type createProfileOutput struct {
	Body contract.Profile
}

func (s *Server) createProfile(ctx context.Context, in *createProfileInput) (*createProfileOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "create a profile", profileCreateRoles...); err != nil {
		return nil, err
	}

	profile, err := commands.CreateProfile(ctx, s.deps.DB, principal, commands.ProfileCreation{
		Slug:          in.Body.Slug,
		Name:          in.Body.Name,
		Description:   in.Body.Description,
		OwnerTeam:     in.Body.OwnerTeam,
		Visibility:    models.ProfileVisibility(in.Body.Visibility),
		DefaultPolicy: models.VersionPolicy(in.Body.DefaultPolicy),
		ForkOf:        in.Body.ForkOf,
	})
	if err != nil {
		return nil, profileFailure(ctx, err)
	}
	return &createProfileOutput{Body: profile}, nil
}

// ---- PUT /v1/profiles/{slug}/entries -----------------------------------------

type setEntriesInput struct {
	Slug string `path:"slug"`
	Body contract.ProfileEntries
}

func (s *Server) setProfileEntries(ctx context.Context, in *setEntriesInput) (*profileDetailOutput, error) {
	return s.mutateProfile(ctx, in.Slug, func(principal auth.Principal) error {
		return commands.SetProfileEntries(ctx, s.deps.DB, principal, in.Slug, in.Body)
	})
}

// ---- PUT /v1/profiles/{slug}/sharing -----------------------------------------

type setSharingInput struct {
	Slug string `path:"slug"`
	Body contract.ProfileSharing
}

func (s *Server) setProfileSharing(ctx context.Context, in *setSharingInput) (*profileDetailOutput, error) {
	return s.mutateProfile(ctx, in.Slug, func(principal auth.Principal) error {
		return commands.SetProfileSharing(ctx, s.deps.DB, principal, in.Slug, in.Body)
	})
}

// ---- PUT /v1/profiles/{slug}/targets -----------------------------------------

type setTargetsInput struct {
	Slug string `path:"slug"`
	Body contract.ProfileTargetSelection
}

func (s *Server) setProfileTargets(ctx context.Context, in *setTargetsInput) (*profileDetailOutput, error) {
	return s.mutateProfile(ctx, in.Slug, func(principal auth.Principal) error {
		return commands.SetProfileTargets(ctx, s.deps.DB, principal, in.Slug, in.Body)
	})
}

// mutateProfile runs one curation command and answers with the profile as it now
// stands.
//
// Re-reading rather than echoing the request is the point. A pin the caller set
// changes what the profile RESOLVES to, and the resolution is the gate's answer
// rather than the request's — a body that echoed "pinned to 2.0.0" while the gate
// had blocked that version would be a screen that disagrees with the lockfile it
// is about to publish. The read is a second statement after the command's
// transaction has committed, so it reports committed state and nothing else.
func (s *Server) mutateProfile(ctx context.Context, slug string,
	mutate func(auth.Principal) error,
) (*profileDetailOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := mutate(principal); err != nil {
		return nil, profileFailure(ctx, err)
	}

	detail, err := queries.ProfileDetail(ctx, s.deps.DB, principal, slug)
	if err != nil {
		return nil, profileFailure(ctx, err)
	}
	return &profileDetailOutput{Body: detail}, nil
}

// ---- POST /v1/profiles/{slug}/revisions --------------------------------------

type publishRevisionInput struct {
	Slug string `path:"slug"`
	Body contract.RevisionPublish
}

type publishRevisionOutput struct {
	// Location names the revision that was created, which is the number the
	// caller could not choose. A client that wants the document again reads it
	// from here rather than guessing head+1 — the sequence is allocated inside the
	// transaction and a concurrent publish may hold the number the caller expected.
	Location string `header:"Location" doc:"The published revision's own path."`
	Body     contract.Lockfile
}

func (s *Server) publishRevision(ctx context.Context, in *publishRevisionInput) (*publishRevisionOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	lockfile, err := commands.PublishRevision(ctx, s.deps.DB, principal, in.Slug, in.Body.Note)
	if err != nil {
		return nil, profileFailure(ctx, err)
	}
	return &publishRevisionOutput{
		Location: fmt.Sprintf("/v1/profiles/%s/revisions/%d", in.Slug, lockfile.Revision),
		Body:     lockfile,
	}, nil
}

// profileFailure maps the profile commands' refusals onto the wire.
//
// queries.ErrNotFound reaches fail() and becomes the 404 that makes an unreadable
// profile indistinguishable from a missing one. A membership refusal is a 403
// carrying the sentence, because the caller can already see the profile and the
// only useful thing left to say is which role would have worked (FR-126).
func profileFailure(ctx context.Context, err error) error {
	var notPermitted *commands.NotPermittedError
	switch {
	case errors.As(err, &notPermitted):
		return huma.Error403Forbidden(notPermitted.Error())
	case errors.Is(err, commands.ErrProfileExists):
		// A 409 and not a 422: the request is well formed and the caller is
		// permitted; the slug is taken and will stay taken. Same reading
		// registerPackage's immutability conflict uses.
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, commands.ErrProfileRefused):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.Is(err, queries.ErrNoPolicy):
		// Not the caller's mistake and not something to explain to them: a hub with
		// no policy row has no gate, and every resolution is refused until an
		// operator fixes it.
		return fail(logging.From(ctx), err)
	default:
		return fail(logging.From(ctx), err)
	}
}
