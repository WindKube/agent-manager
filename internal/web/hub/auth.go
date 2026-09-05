package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"agent-manager/internal/apiclient"
)

// The web role's half of sign-in, through the generated client and nothing
// else. This role owns the browser's origin and holds no datastore
// credential, so the session row is opened by the api and reached only from here.

// SessionMintHeader carries the shared secret POST /v1/sessions requires.
// Spelled out rather than imported: internal/archcheck forbids internal/web
// from importing internal/api, so a test here reads the committed emitted
// document and fails if the two spellings ever drift.
const SessionMintHeader = "X-Session-Mint-Secret"

// Session is a minted browser session.
type Session struct {
	Token     string
	ExpiresAt time.Time
	// ExpiresIn comes from the api rather than ExpiresAt minus a local clock:
	// a Max-Age computed across a skewed clock could outlive the row or die early.
	ExpiresIn time.Duration
}

// Viewer is who a request is acting as, as the api resolved it. HasRole is
// separate from Role because "signed in, holding no role" is its own screen
// state, not an empty string to fall through on.
type Viewer struct {
	Subject     string
	DisplayName string
	Email       string
	Role        string
	HasRole     bool
	Groups      []string
}

// ErrMintRefused is the api declining to open a session — a wrong or missing
// shared secret, an ID token that did not verify, a rate limit, or a hub that
// cannot mint at all. One sentinel for all of them: a caller that could tell
// them apart would be a caller that could tell a browser which one it was.
var ErrMintRefused = errors.New("the hub refused to mint a session")

// MintSession exchanges a verified-at-the-provider ID token for a session,
// over POST /v1/sessions. The RAW token travels, not claims this role
// parsed: verification happens in the role that owns identity, and the
// shared secret is defence in depth, not the only control. The secret goes
// on this ONE request as a per-request editor so no other call carries it by accident.
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
		// Status only, never reaches the browser: 401 is the two secrets
		// disagreeing, 503 is one missing, 422 is a token that did not verify.
		return Session{}, fmt.Errorf("%w: %s", ErrMintRefused, refusal(resp.HTTPResponse))
	}

	body := resp.JSON200
	return Session{
		Token:     body.Token,
		ExpiresAt: body.ExpiresAt,
		ExpiresIn: time.Duration(body.ExpiresIn) * time.Second,
	}, nil
}

// Viewer reads GET /v1/viewer for the caller's own session. A 401 is
// view.ErrSignedOut, the same signed-out state the catalog reports, and not
// a failure to log: an expired session mid-visit redirects to sign-in.
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

// SignOut expires the caller's session server-side, over
// DELETE /v1/sessions/current. Clearing the cookie is the caller's next act,
// not the mechanism. A 401 is view.ErrSignedOut, the ONE error a sign-out
// handler should swallow; every other error means the row may still be
// live, so the cookie must still be cleared AND the failure logged.
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

// refusal names a refused mint by status alone, deliberately not the problem
// detail's text: echoing an upstream string that discusses a secret into a
// log line is how a secret ends up in one.
func refusal(resp *http.Response) string {
	if resp == nil {
		return "the hub did not answer"
	}
	return fmt.Sprintf("the api answered %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
}
