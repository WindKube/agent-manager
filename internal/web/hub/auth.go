package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"agent-manager/internal/apiclient"
)

// SessionMintHeader carries the shared secret POST /v1/sessions requires. It is
// spelled out because archcheck forbids importing internal/api; a test checks it
// against the emitted document.
const SessionMintHeader = "X-Session-Mint-Secret"

// Session is a minted browser session.
type Session struct {
	Token     string
	ExpiresAt time.Time
	// ExpiresIn comes from the api, not ExpiresAt minus a possibly skewed local clock.
	ExpiresIn time.Duration
}

// Viewer is who a request acts as, per the api. HasRole is separate because
// "signed in, holding no role" is its own screen state.
type Viewer struct {
	Subject     string
	DisplayName string
	Email       string
	Role        string
	HasRole     bool
	Groups      []string
}

// ErrMintRefused covers every reason the api declines to open a session. One
// sentinel on purpose, so nothing can tell a browser which reason it was.
var ErrMintRefused = errors.New("the hub refused to mint a session")

// MintSession exchanges a raw ID token for a session; verification happens in the
// api, and the shared secret is defence in depth. The secret is set per request
// so no other call carries it.
func (c *Client) MintSession(ctx context.Context, idToken string) (Session, error) {
	if c.mintSecret == "" {
		return Session{}, fmt.Errorf("%w: this role holds no session mint secret", ErrMintRefused)
	}

	resp, err := c.api.CreateSessionWithResponse(ctx,
		apiclient.CreateSessionJSONRequestBody{IdToken: idToken},
		func(_ context.Context, req *http.Request) error {
			req.Header.Set(SessionMintHeader, c.mintSecret)
			return nil
		})
	if err != nil {
		return Session{}, fmt.Errorf("mint a session: %w", err)
	}
	if resp.JSON200 == nil {
		// Status only, never shown to the browser: 401 secrets disagree, 503 one
		// missing, 422 token did not verify.
		return Session{}, fmt.Errorf("%w: %s", ErrMintRefused, refusal(resp.HTTPResponse))
	}

	body := resp.JSON200
	return Session{
		Token:     body.Token,
		ExpiresAt: body.ExpiresAt,
		ExpiresIn: time.Duration(body.ExpiresIn) * time.Second,
	}, nil
}

// Viewer reads the caller's own identity. A 401 is view.ErrSignedOut, not a
// failure to log.
func (c *Client) Viewer(ctx context.Context) (Viewer, error) {
	resp, err := c.api.GetViewerWithResponse(ctx)
	if err != nil {
		return Viewer{}, fmt.Errorf("read the viewer: %w", err)
	}
	if resp.JSON200 == nil {
		return Viewer{}, fmt.Errorf("read the viewer: %w", statusError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	out := Viewer{
		Subject:     body.Subject,
		DisplayName: body.DisplayName,
		Email:       body.Email,
		HasRole:     body.HasRole,
		Groups:      body.Groups,
	}
	if body.Role != nil {
		out.Role = string(*body.Role)
	}
	if out.Groups == nil {
		out.Groups = []string{}
	}
	return out, nil
}

// SignOut expires the session server-side. Only view.ErrSignedOut may be
// swallowed; any other error means the row may still be live, so the caller must
// still clear the cookie and log the failure.
func (c *Client) SignOut(ctx context.Context) error {
	resp, err := c.api.DeleteSessionWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("sign out: %w", err)
	}
	if resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusNoContent {
		return nil
	}
	return fmt.Errorf("sign out: %w", statusError(resp.HTTPResponse, resp.Body))
}

// refusal names a refused mint by status only: echoing upstream text that
// discusses a secret into a log is how a secret ends up there.
func refusal(resp *http.Response) string {
	if resp == nil {
		return "the hub did not answer"
	}
	return fmt.Sprintf("the api answered %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
}
