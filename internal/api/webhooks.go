package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

func (s *Server) registerWebhooks() {
	unauthorized := s.errorResponse("Missing, expired or invalid token.")
	forbidden := s.errorResponse("Webhooks are managed by a catalog-admin.")
	notFound := s.errorResponse("No such webhook.")
	internal := s.errorResponse("The request could not be completed.")

	huma.Register(s.api, huma.Operation{
		OperationID:   "createWebhook",
		Method:        http.MethodPost,
		Path:          "/v1/webhooks",
		Tags:          []string{"webhooks"},
		Summary:       "Subscribe a URL to events",
		DefaultStatus: http.StatusCreated,
		Description: "Stores a subscription and writes one `webhook` audit row. The signing secret is " +
			"returned in this response and never again.",
		Responses: map[string]*huma.Response{
			"201": {
				Description: "Created.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.WebhookCreated{}, "WebhookCreated")},
				},
			},
			"401": unauthorized,
			"403": forbidden,
			"422": s.errorResponse("The URL is not https, carries credentials or names a private address, or an event type is unknown."),
			"500": internal,
		},
	}, s.createWebhook)

	huma.Register(s.api, huma.Operation{
		OperationID: "listWebhooks",
		Method:      http.MethodGet,
		Path:        "/v1/webhooks",
		Tags:        []string{"webhooks"},
		Summary:     "Every webhook subscription",
		Description: "Never carries a secret.",
		Responses: map[string]*huma.Response{
			"401": unauthorized,
			"403": forbidden,
			"500": internal,
		},
	}, s.listWebhooks)

	huma.Register(s.api, huma.Operation{
		OperationID: "updateWebhook",
		Method:      http.MethodPatch,
		Path:        "/v1/webhooks/{id}",
		Tags:        []string{"webhooks"},
		Summary:     "Change a webhook's name, URL, filters or whether it is enabled",
		Description: "Changes only the fields given and writes one `webhook` audit row.",
		Responses: map[string]*huma.Response{
			"401": unauthorized,
			"403": forbidden,
			"404": notFound,
			"422": s.errorResponse("The resulting webhook would be invalid."),
			"500": internal,
		},
	}, s.updateWebhook)

	huma.Register(s.api, huma.Operation{
		OperationID: "rotateWebhookSecret",
		Method:      http.MethodPost,
		Path:        "/v1/webhooks/{id}/secret",
		Tags:        []string{"webhooks"},
		Summary:     "Replace a webhook's signing secret",
		Description: "The new secret is returned once and signs every delivery from now on, retries included.",
		Responses: map[string]*huma.Response{
			"401": unauthorized,
			"403": forbidden,
			"404": notFound,
			"500": internal,
		},
	}, s.rotateWebhookSecret)

	huma.Register(s.api, huma.Operation{
		OperationID:   "deleteWebhook",
		Method:        http.MethodDelete,
		Path:          "/v1/webhooks/{id}",
		Tags:          []string{"webhooks"},
		Summary:       "Delete a webhook and its delivery log",
		DefaultStatus: http.StatusNoContent,
		Responses: map[string]*huma.Response{
			"204": {Description: "Deleted."},
			"401": unauthorized,
			"403": forbidden,
			"404": notFound,
			"500": internal,
		},
	}, s.deleteWebhook)

	huma.Register(s.api, huma.Operation{
		OperationID: "listWebhookDeliveries",
		Method:      http.MethodGet,
		Path:        "/v1/webhooks/{id}/deliveries",
		Tags:        []string{"webhooks"},
		Summary:     "A webhook's recent delivery attempts",
		Description: "The newest 100 attempts of the last 30 days, with the first KiB of each response.",
		Responses: map[string]*huma.Response{
			"401": unauthorized,
			"403": forbidden,
			"404": notFound,
			"500": internal,
		},
	}, s.listWebhookDeliveries)
}

type webhookIDInput struct {
	ID string `path:"id" format:"uuid" doc:"The webhook's id, as listed."`
}

func (s *Server) webhookID(ctx context.Context, raw, action string) (uuid.UUID, error) {
	if err := s.requireOrgAdmin(ctx, action); err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, huma.Error404NotFound(commands.ErrWebhookNotFound.Error())
	}
	return id, nil
}

type createWebhookInput struct {
	Body contract.CreateWebhookRequest
}

type createWebhookOutput struct {
	Body contract.WebhookCreated
}

func (s *Server) createWebhook(ctx context.Context, in *createWebhookInput) (*createWebhookOutput, error) {
	if err := s.requireOrgAdmin(ctx, "manage webhooks"); err != nil {
		return nil, err
	}
	principal, _ := PrincipalFrom(ctx)
	created, err := commands.CreateWebhook(ctx, s.deps.DB, principal, commands.WebhookInput{
		Name: in.Body.Name, URL: in.Body.URL, EventTypes: in.Body.EventTypes, Namespaces: in.Body.Namespaces,
	})
	if err != nil {
		return nil, webhookFailure(ctx, err)
	}
	hook, err := queries.Webhook(ctx, s.deps.DB, created.ID)
	if err != nil {
		return nil, webhookFailure(ctx, err)
	}
	return &createWebhookOutput{Body: contract.WebhookCreated{Webhook: hook, Secret: created.Secret}}, nil
}

type listWebhooksOutput struct {
	Body contract.WebhookList
}

func (s *Server) listWebhooks(ctx context.Context, _ *struct{}) (*listWebhooksOutput, error) {
	if err := s.requireOrgAdmin(ctx, "read the webhooks"); err != nil {
		return nil, err
	}
	list, err := queries.Webhooks(ctx, s.deps.DB)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listWebhooksOutput{Body: list}, nil
}

type updateWebhookInput struct {
	ID   string `path:"id" format:"uuid" doc:"The webhook's id, as listed."`
	Body contract.UpdateWebhookRequest
}

type webhookOutput struct {
	Body contract.Webhook
}

func (s *Server) updateWebhook(ctx context.Context, in *updateWebhookInput) (*webhookOutput, error) {
	id, err := s.webhookID(ctx, in.ID, "manage webhooks")
	if err != nil {
		return nil, err
	}
	principal, _ := PrincipalFrom(ctx)
	if err = commands.UpdateWebhook(ctx, s.deps.DB, principal, id, commands.WebhookPatch{
		Name: in.Body.Name, URL: in.Body.URL, EventTypes: in.Body.EventTypes,
		Namespaces: in.Body.Namespaces, Enabled: in.Body.Enabled,
	}); err != nil {
		return nil, webhookFailure(ctx, err)
	}
	hook, err := queries.Webhook(ctx, s.deps.DB, id)
	if err != nil {
		return nil, webhookFailure(ctx, err)
	}
	return &webhookOutput{Body: hook}, nil
}

type webhookSecretOutput struct {
	Body contract.WebhookSecret
}

func (s *Server) rotateWebhookSecret(ctx context.Context, in *webhookIDInput) (*webhookSecretOutput, error) {
	id, err := s.webhookID(ctx, in.ID, "manage webhooks")
	if err != nil {
		return nil, err
	}
	principal, _ := PrincipalFrom(ctx)
	secret, err := commands.RotateWebhookSecret(ctx, s.deps.DB, principal, id)
	if err != nil {
		return nil, webhookFailure(ctx, err)
	}
	return &webhookSecretOutput{Body: contract.WebhookSecret{Secret: secret}}, nil
}

func (s *Server) deleteWebhook(ctx context.Context, in *webhookIDInput) (*struct{}, error) {
	id, err := s.webhookID(ctx, in.ID, "manage webhooks")
	if err != nil {
		return nil, err
	}
	principal, _ := PrincipalFrom(ctx)
	if err := commands.DeleteWebhook(ctx, s.deps.DB, principal, id); err != nil {
		return nil, webhookFailure(ctx, err)
	}
	return &struct{}{}, nil
}

type webhookDeliveriesOutput struct {
	Body contract.WebhookDeliveryList
}

func (s *Server) listWebhookDeliveries(ctx context.Context, in *webhookIDInput) (*webhookDeliveriesOutput, error) {
	id, err := s.webhookID(ctx, in.ID, "read the webhooks")
	if err != nil {
		return nil, err
	}
	list, err := queries.WebhookDeliveries(ctx, s.deps.DB, id)
	if err != nil {
		return nil, webhookFailure(ctx, err)
	}
	return &webhookDeliveriesOutput{Body: list}, nil
}

func webhookFailure(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, commands.ErrValidation):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.Is(err, commands.ErrServiceTokenNeedsAPerson):
		return huma.Error403Forbidden(err.Error())
	case errors.Is(err, commands.ErrWebhookNotFound):
		return huma.Error404NotFound(err.Error())
	default:
		return fail(logging.From(ctx), err)
	}
}
