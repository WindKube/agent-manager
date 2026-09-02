package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"agent-manager/internal/apiclient"
)

// The web role's half of sign-in (US2), through the generated client and nothing
// else. contracts/auth.md is authoritative for the flow this serves.
//
// Constitution principle II is the whole reason these three methods exist: this
// role owns the browser's origin and therefore the cookie, and it holds no
// datastore credential, so the session row is opened by the api and reached only
// from here.

// SessionMintHeader carries the shared secret POST /v1/sessions requires.
//
// Spelled out rather than imported: internal/archcheck forbids internal/web from
// importing internal/api, which is the boundary that keeps this role free of a
// datastore credential, so the two spellings of this header cannot be one
// constant. The joint is the emitted document instead — the api declares the
// header on its security scheme, the document carries it, and a test in this
// package reads the committed document and fails if the two ever drift.
const SessionMintHeader = "X-Session-Mint-Secret"

// Session is a minted browser session: the token that goes in the cookie, and
// when the cookie must stop being sent.
type Session struct {
	Token     string
	ExpiresAt time.Time
	// ExpiresIn comes from the api rather than from ExpiresAt minus a local clock.
	// The two roles are two containers, and a cookie whose Max-Age was computed
	// across a skewed clock either outlives its row — which reads to a person as
	// being signed out at random — or dies early for no visible reason.
	ExpiresIn time.Duration
}

// Viewer is who a request is acting as, as the api resolved it on that request.
//
// It is the only source a screen may render an identity from (FR-116). HasRole is
// separate from Role because "signed in, holding no role" is a screen state of its
// own (FR-117) and not an empty string to fall through on.
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
// cannot mint at all.
//
// One sentinel for all of them on purpose: contracts/auth.md gives every one of
// those the same rendering ("the hub could not complete sign-in", logged at error
// with the correlation id), and a caller that could tell them apart would be a
// caller that could tell a browser which one it was.
var ErrMintRefused = errors.New("the hub refused to mint a session")

// MintSession exchanges a verified-at-the-provider ID token for a session, over
// POST /v1/sessions.
//
// The RAW token travels, not claims this role parsed: verification happens in the
// role that owns identity, so the api trusts nothing decoded here and the shared
// secret is defence in depth rather than the only control (plan.md's Complexity
// Tracking row).
//
// The secret goes on this ONE request, as a per-request editor rather than on the
// client, so no other call this role makes can carry it by accident.
func (c *Client) MintSession(ctx context.Context, idToken string) (Session, error) {
	if c.mintSecret == "" {
		// Said here rather than discovered as a 503 from the api, because this half
		// of the misconfiguration is visible from this side and the operator's fix is
		// the same variable either way.
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
		// The api's problem detail, not its body: it is an upstream string on its way
		// into this role's log, and it never reaches the browser. The status is what
		// an operator needs — 401 is the two secrets disagreeing, 503 is one of them
		// missing, 422 is a token that did not verify.
		return Session{}, fmt.Errorf("%w: %s", ErrMintRefused, refusal(resp.HTTPResponse))
	}

	body := resp.JSON200
	return Session{
		Token:     body.Token,
		ExpiresAt: body.ExpiresAt,
		ExpiresIn: time.Duration(body.ExpiresIn) * time.Second,
	}, nil
}

// Viewer reads GET /v1/viewer for the caller's own session.
//
// A 401 is view.ErrSignedOut, the same signed-out state the catalog reports, and
// not a failure to log: an expired session mid-visit is a redirect to sign-in
// preserving the current path, which contracts/auth.md is explicit is not an
// error.
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
// DELETE /v1/sessions/current. Clearing the cookie is the caller's next act and
// not the mechanism (FR-114).
//
// A 401 is view.ErrSignedOut, and it is the ONE error a sign-out handler should
// swallow: the session was already gone, which is the state the person asked for.
// Every other error means the row may still be live, so the cookie must be cleared
// AND the failure logged — a cleared cookie over a live session is a credential
// still valid to whoever else holds it.
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

// refusal names a refused mint by status alone.
//
// Deliberately not the problem detail's text: the api's 401 for this operation is
// about the shared secret, and echoing an upstream string that discusses a secret
// into a log line is how a secret ends up in one. The status is unambiguous and
// carries no value.
func refusal(resp *http.Response) string {
	if resp == nil {
		return "the hub did not answer"
	}
	return fmt.Sprintf("the api answered %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
}
