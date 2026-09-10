// Package hub is the web role's door to the api, and the only one it has.
// `serve web` holds no datastore credential, so everything it renders
// arrives over HTTP through internal/apiclient, GENERATED from the document
// internal/api emits.
//
// Nothing here decides what the catalog means: this package translates the
// screen's vocabulary into the operation's and back.
package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// Client is an api base URL plus the generated client over it.
type Client struct {
	api *apiclient.ClientWithResponses
	now func() time.Time
	// mintSecret buys exactly one operation: sent on that one request, never
	// installed on the client, so nothing else this role calls can carry it.
	mintSecret string
}

// Option tunes the client.
type Option func(*Client)

// WithClock fixes the clock the Updated column is rendered against.
func WithClock(now func() time.Time) Option {
	return func(c *Client) { c.now = now }
}

// WithSessionMintSecret gives the client the shared secret the session mint
// requires. Without it MintSession refuses before it reaches the api: there
// is no default, and an empty value is the api's cue to refuse every mint.
func WithSessionMintSecret(secret string) Option {
	return func(c *Client) { c.mintSecret = secret }
}

// New builds the client. It performs no I/O and does not reach the api, so
// a hub whose api is not up yet still starts.
func New(baseURL string, opts ...Option) (*Client, error) {
	api, err := apiclient.NewClientWithResponses(baseURL, apiclient.WithHTTPClient(&http.Client{
		// A hop with no timeout is how a slow api turns into a web role with
		// no free workers.
		Timeout: 15 * time.Second,
	}), apiclient.WithRequestEditorFn(bearer))
	if err != nil {
		return nil, fmt.Errorf("build the api client for %s: %w", baseURL, err)
	}

	client := &Client{api: api, now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(client)
	}
	return client, nil
}

// Catalog implements web.CatalogSource against GET /v1/packages.
func (c *Client) Catalog(ctx context.Context, q view.CatalogQuery) (view.CatalogPage, error) {
	q = q.Normalise()

	params := &apiclient.ListPackagesParams{
		Page:     ptr(int64(q.Page)),
		PageSize: ptr(int64(view.DefaultPageSize)),
		Sort:     ptr(apiclient.ListPackagesParamsSort(q.Sort)),
		Dir:      ptr(apiclient.ListPackagesParamsDir(q.Dir)),
		Kind:     ptr(apiclient.ListPackagesParamsKind(kindParam(q.Kind))),
		Status:   ptr(apiclient.ListPackagesParamsStatus(statusParam(q.Status))),
	}
	if q.Text != "" {
		params.Q = &q.Text
	}
	if len(q.Categories) > 0 {
		params.Category = &q.Categories
	}
	if len(q.Tags) > 0 {
		params.Tag = &q.Tags
	}

	resp, err := c.api.ListPackagesWithResponse(ctx, params)
	if err != nil {
		return view.CatalogPage{}, fmt.Errorf("list packages: %w", err)
	}
	if resp.JSON200 == nil {
		return view.CatalogPage{}, fmt.Errorf("list packages: %w", statusError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	page := view.CatalogPage{
		Query:      q,
		Rows:       make([]view.Row, 0, len(body.Packages)),
		Total:      int(body.Total),
		Page:       int(body.Page),
		PageSize:   int(body.PageSize),
		Categories: options(body.Categories, q.Categories),
		Tags:       options(body.Tags, q.Tags),
	}
	now := c.now()
	for i := range body.Packages {
		page.Rows = append(page.Rows, row(&body.Packages[i], now))
	}
	return page, nil
}

func row(entry *apiclient.CatalogPackage, now time.Time) view.Row {
	out := view.Row{
		Key:       entry.Id,
		ID:        entry.Id,
		Name:      view.Title(entry.Name),
		Publisher: entry.Publisher,
		Version:   entry.Version,
		Updated:   view.Relative(entry.UpdatedAt, now),
		Kind:      view.Kind(entry.Kind),
		Scan:      scanOf(string(entry.Verdict)),
		Uses:      int(entry.Uses),
		Tags:      entry.Tags,
	}
	if entry.Category != nil {
		out.Category = *entry.Category
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	return out
}

// scanOf collapses four verdicts onto three pills. `rejected` shows as
// Flagged rather than a fourth state: "do not adopt without reading the
// finding" applies to a rejected version most strongly of all.
func scanOf(verdict string) view.Scan {
	switch verdict {
	case "clean":
		return view.ScanClean
	case "flagged", "rejected":
		return view.ScanFlagged
	default:
		return view.ScanPending
	}
}

func options(counts []apiclient.CatalogFacetOption, selected []string) []view.FacetOption {
	chosen := make(map[string]struct{}, len(selected))
	for _, value := range selected {
		chosen[value] = struct{}{}
	}

	out := make([]view.FacetOption, 0, len(counts))
	for _, count := range counts {
		_, on := chosen[count.Value]
		out = append(out, view.FacetOption{Label: count.Value, Count: int(count.Count), Selected: on})
	}
	return out
}

// kindParam and statusParam translate chip labels into the operation's
// vocabulary: the screen says "Plugins", the API says "plugin".
func kindParam(kind string) string {
	switch kind {
	case view.KindFilterPlugins:
		return "plugin"
	case view.KindFilterSkills:
		return "skill"
	default:
		return "all"
	}
}

func statusParam(status string) string {
	switch status {
	case view.StatusVerified:
		return "verified"
	case view.StatusCommunity:
		return "community"
	case view.StatusFlagged:
		return "flagged"
	default:
		return "all"
	}
}

func ptr[T any](v T) *T { return &v }

// bearer forwards the caller's own session token, and only ever theirs. A
// request outside a signed-in browser session carries no Authorization
// header, and the web role must not appear to have a fallback.
func bearer(ctx context.Context, req *http.Request) error {
	if token := view.TokenFrom(ctx); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

// statusError turns a response the client could not decode into something a
// log line can carry. The body is deliberately NOT included. A 401 is the
// exception: it is the signed-out state, and the caller renders it as a screen.
func statusError(resp *http.Response, body []byte) error {
	if resp == nil {
		return errors.New("no response")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return view.ErrSignedOut
	}
	return fmt.Errorf("api answered %d with %d bytes", resp.StatusCode, len(body))
}
