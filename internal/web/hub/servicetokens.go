package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The Service tokens screen's door to the api.

// ErrServiceTokenNotFound is a token that does not exist or that this viewer
// may not manage; the api answers both alike.
var ErrServiceTokenNotFound = errors.New("no such service token")

// ServiceTokenRefusedError is a 422 or 403 whose problem detail the screen
// shows as-is.
type ServiceTokenRefusedError struct{ Detail string }

func (e *ServiceTokenRefusedError) Error() string { return e.Detail }

// ServiceTokens reads GET /v1/service-tokens.
func (c *Client) ServiceTokens(ctx context.Context) ([]view.ServiceToken, error) {
	resp, err := c.api.ListServiceTokensWithResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("list service tokens: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, fmt.Errorf("list service tokens: %w", serviceTokenError(resp.HTTPResponse, resp.Body))
	}
	out := make([]view.ServiceToken, 0, len(resp.JSON200.Tokens))
	for i := range resp.JSON200.Tokens {
		out = append(out, serviceTokenView(&resp.JSON200.Tokens[i]))
	}
	return out, nil
}

// CreateServiceToken posts POST /v1/service-tokens and returns the secret,
// which nothing on this side stores.
func (c *Client) CreateServiceToken(ctx context.Context, name string, scopes []string, expiresAt time.Time) (view.CreatedServiceToken, error) {
	resp, err := c.api.CreateServiceTokenWithResponse(ctx, apiclient.CreateServiceTokenRequest{
		Name: name, Scopes: scopes, ExpiresAt: expiresAt,
	})
	if err != nil {
		return view.CreatedServiceToken{}, fmt.Errorf("create service token: %w", err)
	}
	if resp.JSON201 == nil {
		return view.CreatedServiceToken{}, serviceTokenError(resp.HTTPResponse, resp.Body)
	}
	return view.CreatedServiceToken{Name: resp.JSON201.Token.Name, Secret: resp.JSON201.Secret}, nil
}

// RevokeServiceToken deletes DELETE /v1/service-tokens/{id}.
func (c *Client) RevokeServiceToken(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return ErrServiceTokenNotFound
	}
	resp, err := c.api.RevokeServiceTokenWithResponse(ctx, parsed)
	if err != nil {
		return fmt.Errorf("revoke service token: %w", err)
	}
	if resp.StatusCode() == http.StatusNoContent {
		return nil
	}
	return serviceTokenError(resp.HTTPResponse, resp.Body)
}

func serviceTokenView(t *apiclient.ServiceToken) view.ServiceToken {
	return view.ServiceToken{
		ID: t.Id.String(), Name: t.Name, Scopes: append([]string{}, t.Scopes...), CreatedBy: t.CreatedBy,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, Status: string(t.Status),
	}
}

func serviceTokenError(resp *http.Response, body []byte) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return ErrServiceTokenNotFound
		case http.StatusUnprocessableEntity, http.StatusForbidden:
			detail := http.StatusText(resp.StatusCode)
			var problem apiclient.Error
			if err := json.Unmarshal(body, &problem); err == nil && problem.Detail != nil && *problem.Detail != "" {
				detail = *problem.Detail
			}
			return &ServiceTokenRefusedError{Detail: detail}
		}
	}
	return statusError(resp, body)
}
