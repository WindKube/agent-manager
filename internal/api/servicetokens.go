package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/logging"
)

// tokenScope is the class of scope an operation accepts a service token with.
type tokenScope string

const (
	tokenReadCatalog tokenScope = "read:catalog"
	tokenSyncProfile tokenScope = "sync:profile"

	serviceTokenMetadataKey = "serviceTokenScopes"
)

// allowServiceTokens marks an operation a service token may call when it holds
// any one of scopes. An unmarked operation refuses every token, so a new
// operation is closed to tokens until somebody decides otherwise here.
func allowServiceTokens(scopes ...tokenScope) map[string]any {
	return map[string]any{serviceTokenMetadataKey: scopes}
}

// ServiceTokenScopes is the scope classes an operation accepts a token with;
// empty means it refuses every token.
func ServiceTokenScopes(op *huma.Operation) []string {
	if op == nil {
		return nil
	}
	scopes, _ := op.Metadata[serviceTokenMetadataKey].([]tokenScope)
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, string(scope))
	}
	return out
}

// serviceTokenMayCall is the deny-by-default gate every bearer operation
// passes for a token, before its handler runs.
func serviceTokenMayCall(op *huma.Operation, grant *auth.ServiceTokenGrant) bool {
	return slices.ContainsFunc(ServiceTokenScopes(op), func(scope string) bool {
		switch tokenScope(scope) {
		case tokenReadCatalog:
			return grant.Allows(auth.ScopeReadCatalog)
		case tokenSyncProfile:
			return len(grant.Profiles()) > 0
		default:
			return false
		}
	})
}

// requireProfileScope refuses a service token whose scopes do not name slug.
// It answers from the token alone, so it says nothing about whether the
// profile exists.
func requireProfileScope(p auth.Principal, slug string) error {
	if !p.IsServiceToken() || p.ServiceToken.Allows(auth.SyncProfileScope(slug)) {
		return nil
	}
	return huma.Error403Forbidden("this service token is not scoped to profile " + slug +
		"; it needs " + string(auth.SyncProfileScope(slug)))
}

func (s *Server) registerServiceTokens() {
	unauthorized := s.errorResponse("Missing, expired or invalid token.")
	forbidden := s.errorResponse("A service token cannot manage service tokens.")

	huma.Register(s.api, huma.Operation{
		OperationID:   "createServiceToken",
		Method:        http.MethodPost,
		Path:          "/v1/service-tokens",
		Tags:          []string{"service-tokens"},
		Summary:       "Create a scoped service token",
		DefaultStatus: http.StatusCreated,
		Description: "Mints a non-human bearer credential for CI and headless machines and writes one " +
			"`token` audit row. The secret is returned in this response and never again. Every " +
			"sync:profile scope must name a profile the caller can read now.",
		Responses: map[string]*huma.Response{
			"201": {
				Description: "Created.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.ServiceTokenCreated{}, "ServiceTokenCreated")},
				},
			},
			"401": unauthorized,
			"403": forbidden,
			"422": s.errorResponse("A scope is unknown or names a profile the caller cannot read, or the expiry is missing, past or more than a year away."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.createServiceToken)

	huma.Register(s.api, huma.Operation{
		OperationID: "listServiceTokens",
		Method:      http.MethodGet,
		Path:        "/v1/service-tokens",
		Tags:        []string{"service-tokens"},
		Summary:     "The service tokens the caller may manage",
		Description: "The caller's own tokens, or every token for a catalog-admin. Never carries a secret or its hash.",
		Responses: map[string]*huma.Response{
			"401": unauthorized,
			"403": forbidden,
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.listServiceTokens)

	huma.Register(s.api, huma.Operation{
		OperationID:   "revokeServiceToken",
		Method:        http.MethodDelete,
		Path:          "/v1/service-tokens/{id}",
		Tags:          []string{"service-tokens"},
		Summary:       "Revoke a service token",
		DefaultStatus: http.StatusNoContent,
		Description: "Effective on the token's next request, and writes one `token` audit row. The " +
			"creator or a catalog-admin may revoke; revoking a revoked token is a no-op.",
		Responses: map[string]*huma.Response{
			"204": {Description: "Revoked."},
			"401": unauthorized,
			"403": forbidden,
			"404": s.errorResponse("No such token, or not one the caller may manage."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.revokeServiceToken)
}

type createServiceTokenInput struct {
	Body contract.CreateServiceTokenRequest
}

type createServiceTokenOutput struct {
	Body contract.ServiceTokenCreated
}

func (s *Server) createServiceToken(ctx context.Context, in *createServiceTokenInput) (*createServiceTokenOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	created, err := commands.CreateServiceToken(ctx, s.deps.DB, principal, commands.CreateServiceTokenInput{
		Name: in.Body.Name, Scopes: in.Body.Scopes, ExpiresAt: in.Body.ExpiresAt,
	})
	if err != nil {
		return nil, serviceTokenFailure(ctx, err)
	}
	createdBy := principal.Email
	if createdBy == "" {
		createdBy = principal.Subject
	}
	return &createServiceTokenOutput{Body: contract.ServiceTokenCreated{
		Token:  queries.ServiceTokenWire(&created.Token, createdBy, time.Now()),
		Secret: created.Secret,
	}}, nil
}

type listServiceTokensOutput struct {
	Body contract.ServiceTokenList
}

func (s *Server) listServiceTokens(ctx context.Context, _ *struct{}) (*listServiceTokensOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	tokens, err := queries.ServiceTokens(ctx, s.deps.DB, principal)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listServiceTokensOutput{Body: contract.ServiceTokenList{Tokens: tokens}}, nil
}

type revokeServiceTokenInput struct {
	ID string `path:"id" format:"uuid" doc:"The token's id, as listed."`
}

func (s *Server) revokeServiceToken(ctx context.Context, in *revokeServiceTokenInput) (*struct{}, error) {
	principal, _ := PrincipalFrom(ctx)
	id, err := uuid.Parse(in.ID)
	if err != nil {
		return nil, huma.Error404NotFound(commands.ErrServiceTokenNotFound.Error())
	}
	if _, err := commands.RevokeServiceToken(ctx, s.deps.DB, principal, id); err != nil {
		return nil, serviceTokenFailure(ctx, err)
	}
	return &struct{}{}, nil
}

func serviceTokenFailure(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, commands.ErrValidation):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.Is(err, commands.ErrServiceTokenNeedsAPerson):
		return huma.Error403Forbidden(err.Error())
	case errors.Is(err, commands.ErrServiceTokenNotFound):
		return huma.Error404NotFound(err.Error())
	default:
		return fail(logging.From(ctx), err)
	}
}
