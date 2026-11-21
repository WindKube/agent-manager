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

// The profile curation surface. Readability decides whether a profile exists for
// the caller: an unreadable one is a 404, never a 403 that would confirm the slug.
// The membership role then decides what they may do, and that refusal is a 403.
// Only creation uses the organisation role; everything else ignores it.

type profileSlugInput struct {
	Slug string `path:"slug" doc:"The profile's URL-safe identifier. It may carry several segments, as the design's example/platform-engineer does." example:"example/platform-engineer"`
}

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

// profileCreateRoles is everyone except read-only and the empty role.
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

type setEntriesInput struct {
	Slug string `path:"slug"`
	Body contract.ProfileEntries
}

func (s *Server) setProfileEntries(ctx context.Context, in *setEntriesInput) (*profileDetailOutput, error) {
	return s.mutateProfile(ctx, in.Slug, func(principal auth.Principal) error {
		return commands.SetProfileEntries(ctx, s.deps.DB, principal, in.Slug, in.Body)
	})
}

type removeEntryInput struct {
	Slug string `path:"slug"`
	Body contract.ProfileEntryRemoval
}

func (s *Server) removeProfileEntry(ctx context.Context, in *removeEntryInput) (*profileDetailOutput, error) {
	return s.mutateProfile(ctx, in.Slug, func(principal auth.Principal) error {
		return commands.RemoveProfileEntry(ctx, s.deps.DB, principal, in.Slug, in.Body.ID)
	})
}

type setSharingInput struct {
	Slug string `path:"slug"`
	Body contract.ProfileSharing
}

func (s *Server) setProfileSharing(ctx context.Context, in *setSharingInput) (*profileDetailOutput, error) {
	return s.mutateProfile(ctx, in.Slug, func(principal auth.Principal) error {
		return commands.SetProfileSharing(ctx, s.deps.DB, principal, in.Slug, in.Body)
	})
}

type setTargetsInput struct {
	Slug string `path:"slug"`
	Body contract.ProfileTargetSelection
}

func (s *Server) setProfileTargets(ctx context.Context, in *setTargetsInput) (*profileDetailOutput, error) {
	return s.mutateProfile(ctx, in.Slug, func(principal auth.Principal) error {
		return commands.SetProfileTargets(ctx, s.deps.DB, principal, in.Slug, in.Body)
	})
}

// mutateProfile runs one curation command and answers with the profile re-read
// after commit, since the gate, not the request, decides what it resolves to.
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

type publishRevisionInput struct {
	Slug string `path:"slug"`
	Body contract.RevisionPublish
}

type publishRevisionOutput struct {
	// Location names the revision created; the sequence is allocated in the
	// transaction, so clients must not guess head+1.
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

func (s *Server) deleteProfile(ctx context.Context, in *profileSlugInput) (*struct{}, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := commands.DeleteProfile(ctx, s.deps.DB, principal, in.Slug); err != nil {
		return nil, profileFailure(ctx, err)
	}
	return &struct{}{}, nil
}

// profileFailure maps the profile commands' refusals onto the wire. Unreadable
// profiles are a 404, indistinguishable from missing; membership refusals are a 403.
func profileFailure(ctx context.Context, err error) error {
	var notPermitted *commands.NotPermittedError
	switch {
	case errors.As(err, &notPermitted):
		return huma.Error403Forbidden(notPermitted.Error())
	case errors.Is(err, commands.ErrProfileExists), errors.Is(err, commands.ErrProfileHasRevisions):
		// A 409: the request is well formed; the resource's own state refuses it.
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, commands.ErrProfileRefused):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.Is(err, queries.ErrNoPolicy):
		// No policy row means no gate: an operator problem, not the caller's.
		return fail(logging.From(ctx), err)
	default:
		return fail(logging.From(ctx), err)
	}
}
