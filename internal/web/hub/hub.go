// Package hub is the web role's only door to the api. `serve web` holds no
// datastore credential, so everything it renders arrives through the generated
// internal/apiclient; this package only translates screen vocabulary to the api's.
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
	// mintSecret is sent on the one mint request only, never installed on the client.
	mintSecret string
	transport  http.RoundTripper
}

// Option tunes the client.
type Option func(*Client)

// WithClock fixes the clock the Updated column is rendered against.
func WithClock(now func() time.Time) Option {
	return func(c *Client) { c.now = now }
}

// WithSessionMintSecret sets the shared secret the session mint requires; without
// it MintSession refuses before reaching the api.
func WithSessionMintSecret(secret string) Option {
	return func(c *Client) { c.mintSecret = secret }
}

// WithTransport sets the round tripper calls to the api go through; nil keeps
// http.DefaultTransport.
func WithTransport(rt http.RoundTripper) Option {
	return func(c *Client) { c.transport = rt }
}

// New builds the client without I/O, so a hub whose api is not up yet still starts.
func New(baseURL string, opts ...Option) (*Client, error) {
	client := &Client{now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(client)
	}

	api, err := apiclient.NewClientWithResponses(baseURL, apiclient.WithHTTPClient(&http.Client{
		Transport: client.transport,
		// Without a timeout a slow api exhausts the web role's workers.
		Timeout: 15 * time.Second,
	}), apiclient.WithRequestEditorFn(bearer))
	if err != nil {
		return nil, fmt.Errorf("build the api client for %s: %w", baseURL, err)
	}
	client.api = api
	return client, nil
}

// Catalog calls GET /v1/packages.
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
		Key:        entry.Id,
		ID:         entry.Id,
		Name:       view.Title(entry.Name),
		Publisher:  entry.Publisher,
		Version:    entry.Version,
		Updated:    view.Relative(entry.UpdatedAt, now),
		Kind:       view.Kind(entry.Kind),
		Scan:       scanOf(string(entry.Verdict)),
		Visibility: string(entry.Visibility),
		Uses:       int(entry.Uses),
		Tags:       entry.Tags,
	}
	if entry.Category != nil {
		out.Category = *entry.Category
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	return out
}

// scanOf collapses four verdicts onto three pills; `rejected` shows as Flagged
// because "read the finding first" applies to it most of all.
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

// kindParam and statusParam translate chip labels into the api's vocabulary.
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

func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// bearer forwards the caller's own session token and nothing else: the web role
// must have no fallback credential.
func bearer(ctx context.Context, req *http.Request) error {
	if token := view.TokenFrom(ctx); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

// statusError omits the body deliberately. A 401 maps to view.ErrSignedOut, which
// the caller renders as a screen.
func statusError(resp *http.Response, body []byte) error {
	if resp == nil {
		return errors.New("no response")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return view.ErrSignedOut
	}
	return fmt.Errorf("api answered %d with %d bytes", resp.StatusCode, len(body))
}
