package hub

// This file is the CLI's whole view of the hub. Everything above it talks to
// Hub, never the generated *Client: the bearer token is injected in ONE
// http.RoundTripper scoped to the hub's origin (never leaks to a redirect),
// and every hub answer becomes a Class in ONE place. It also bypasses
// ClientWithResponses: ParseListProfilesResponse et al. io.ReadAll the body
// uncapped and can't tell a bad JSON body from a transport failure.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Operation ids, from the frozen contract.
const (
	opHealth          = "health"
	opListProfiles    = "listProfiles"
	opGetRevision     = "getRevision"
	opReportSync      = "reportSync"
	opDeviceAuthorize = "deviceAuthorize"
	opDeviceToken     = "deviceToken"
	// OpGetBundle: bundles.go issues that call itself, bypassing
	// GetBundleWithResponse, which buffers the whole bundle before any digest
	// check.
	OpGetBundle = "getBundle"
)

// PlaintextFlagName lives beside the refusal that names it, so the flag and
// the message cannot disagree; the command layer registers it.
const PlaintextFlagName = "allow-plaintext-hub"

// maxRedirects reimposes net/http's own default, which setting
// Client.CheckRedirect otherwise removes.
const maxRedirects = 10

// maxBodyBytes caps every JSON body read here (never a bundle; see Raw), four
// orders of magnitude over the largest real lockfile, so a hostile endpoint
// can't make the CLI allocate until it dies.
const maxBodyBytes = 32 << 20

// revisionPattern is the contract's own `^(head|[0-9]+)$`, checked locally
// only to name a bad argument instead of round-tripping for a 422.
//
//nolint:gocritic // copied character for character from the frozen contract, so it stays greppable against it.
var revisionPattern = regexp.MustCompile(`^(head|[0-9]+)$`)

// Config constructs a Hub.
type Config struct {
	// URL is the hub base URL. https is required unless AllowPlaintext.
	URL            string
	Token          string       // bearer credential, or "" for device endpoints; copied into a closure by New
	AllowPlaintext bool         // accepts http://, with no "but it's localhost" exception
	HTTPClient     *http.Client // Transport wrapped, struct copied; New never mutates the caller's client
	UserAgent      string       // empty means "amctl", never Go's default
}

// Hub is a hub endpoint plus the credential to use against it. It holds no
// other state; two hub URLs need two Hubs, for per-hub credential scoping.
type Hub struct {
	base     *url.URL
	gen      ClientInterface
	httpc    *http.Client
	insecure bool
}

// New validates the URL, wires the bearer transport and returns a Hub. It
// makes no network call: the home and TLS checks must both land before
// anything dials.
func New(cfg Config) (*Hub, error) {
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return nil, fmt.Errorf("%w: no hub URL given", ErrHubURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrHubURL, raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !cfg.AllowPlaintext {
			return nil, fmt.Errorf("%w: %s would send the bearer token in cleartext; pass --%s to accept that",
				ErrInsecureHub, safeURL(u), PlaintextFlagName)
		}
	case "":
		return nil, fmt.Errorf("%w: %q has no scheme; write it as https://host[:port][/path]", ErrHubURL, raw)
	default:
		return nil, fmt.Errorf("%w: %q has scheme %q; amctl speaks https, and http only with --%s",
			ErrHubURL, raw, u.Scheme, PlaintextFlagName)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: %q has no host", ErrHubURL, raw)
	}
	// Not echoed: net/http copies URL credentials onto every redirect target,
	// so echoing the password into this refusal is the same leak in a hat.
	if u.User != nil {
		return nil, fmt.Errorf("%w: hub URL carries credentials in the URL; authenticate with `amctl login`", ErrHubURL)
	}
	u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""

	httpc := &http.Client{}
	if cfg.HTTPClient != nil {
		clone := *cfg.HTTPClient
		httpc = &clone
	}
	base := httpc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	agent := cfg.UserAgent
	if agent == "" {
		agent = "amctl"
	}
	token := cfg.Token
	httpc.Transport = &bearerTransport{
		base:   base,
		origin: originOf(u),
		// A closure, not a string field: fmt prints an unexported func field
		// as an address, which is what keeps a careless %+v from leaking it.
		token:     func() string { return token },
		userAgent: agent,
	}
	httpc.CheckRedirect = stripAuthorizationOnRedirect(httpc.CheckRedirect)

	gen, err := NewClient(u.String(), WithHTTPClient(httpc))
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrHubURL, raw, err)
	}
	return &Hub{base: u, gen: gen, httpc: httpc, insecure: scheme == "http"}, nil
}

func (h *Hub) URL() string { return h.base.String() }

// Insecure lets a verb warn on the diagnostic stream every run, not just where the flag was parsed.
func (h *Hub) Insecure() bool { return h.insecure }

// Raw is for getBundle only: it must stream the body to compute a digest
// before a byte reaches the tree. Anything else should use a Hub method, or
// classification stops being in one place.
func (h *Hub) Raw() ClientInterface { return h.gen }

// HTTPClient is what a caller following getBundle's 307 by hand must use: a
// fresh http.Client reinstates the stdlib's Authorization-preserving redirect.
func (h *Hub) HTTPClient() *http.Client { return h.httpc }

// Health calls /v1/health, unauthenticated, as the discriminator: if it
// answers and an authenticated call 401s, that's unauthorised, not unreachable.
func (h *Hub) Health(ctx context.Context) (*Health, error) {
	target := h.opURL("/v1/health")
	a, body, err := h.call(ctx, opHealth, target, http.StatusOK, func() (*http.Response, error) {
		return h.gen.Health(ctx)
	})
	if err != nil {
		if a.Status == http.StatusServiceUnavailable {
			if degraded, derr := decodeJSON[Health](opHealth, a, body); derr == nil {
				return degraded, err
			}
		}
		return nil, err
	}
	return decodeJSON[Health](opHealth, a, body)
}

// Reachable counts a 503 as reachable: the hub is there, a dependency isn't,
// which must not collapse into "unreachable".
func (h *Hub) Reachable(ctx context.Context) bool {
	_, err := h.Health(ctx)
	switch ClassOf(err) {
	case 0, ClassUnavailable:
		return true
	default:
		return false
	}
}

func (h *Hub) ListProfiles(ctx context.Context) (*ProfileList, error) {
	target := h.opURL("/v1/profiles")
	a, body, err := h.call(ctx, opListProfiles, target, http.StatusOK, func() (*http.Response, error) {
		return h.gen.ListProfiles(ctx)
	})
	if err != nil {
		return nil, err
	}
	return decodeJSON[ProfileList](opListProfiles, a, body)
}

// GetRevision's revision is "head" or an integer, as a string, exactly as the contract has it.
func (h *Hub) GetRevision(ctx context.Context, slug, revision string) (*Lockfile, error) {
	if slug == "" {
		return nil, errors.New("getRevision: no profile slug given")
	}
	if !revisionPattern.MatchString(revision) {
		return nil, fmt.Errorf("getRevision: revision %q is neither \"head\" nor a whole number", revision)
	}
	target := h.opURL("/v1/profiles/" + slug + "/revisions/" + revision)
	a, body, err := h.call(ctx, opGetRevision, target, http.StatusOK, func() (*http.Response, error) {
		return h.gen.GetRevision(ctx, slug, revision)
	})
	if err != nil {
		return nil, err
	}
	return decodeJSON[Lockfile](opGetRevision, a, body)
}

// ReportSync's failure is a warning, not a failed sync: the error is
// returned plainly, never wrapped as fatal.
func (h *Hub) ReportSync(ctx context.Context, report SyncReport) error {
	target := h.opURL("/v1/sync")
	_, _, err := h.call(ctx, opReportSync, target, http.StatusNoContent, func() (*http.Response, error) {
		return h.gen.ReportSync(ctx, report)
	})
	return err
}

// DeviceAuthorize is unauthenticated: it's how a machine with no credential gets one.
func (h *Hub) DeviceAuthorize(ctx context.Context, req DeviceAuthorizeRequest) (*DeviceAuthorization, error) {
	target := h.opURL("/v1/device/authorize")
	a, body, err := h.call(ctx, opDeviceAuthorize, target, http.StatusOK, func() (*http.Response, error) {
		return h.gen.DeviceAuthorize(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	return decodeJSON[DeviceAuthorization](opDeviceAuthorize, a, body)
}

// DeviceFlowError is RFC 8628's 400 body, not a failure: authorization_pending
// and slow_down are normal, and must not be ClassRequest, or a poll loop
// would abort on its first tick. This type reports the code and judges nothing.
type DeviceFlowError struct {
	Code DeviceTokenErrorError
}

// Error names the code and nothing else; the device/user codes are credentials.
func (e *DeviceFlowError) Error() string {
	if e.Code == "" {
		return "deviceToken: hub refused the poll without naming a reason"
	}
	return "deviceToken: " + string(e.Code)
}

// DeviceToken's 400 comes back as *DeviceFlowError; everything else is
// classified. The 200 body's token is never logged or put into an error.
func (h *Hub) DeviceToken(ctx context.Context, req DeviceTokenRequest) (*DeviceToken, error) {
	target := h.opURL("/v1/device/token")
	a, body, err := h.call(ctx, opDeviceToken, target, http.StatusOK, func() (*http.Response, error) {
		return h.gen.DeviceTokenWithFormdataBody(ctx, req)
	})
	if a.Status == http.StatusBadRequest {
		flow := &DeviceFlowError{}
		var wire DeviceTokenError
		if json.Unmarshal(body, &wire) == nil && wire.Error != nil {
			flow.Code = *wire.Error
		}
		return nil, flow
	}
	if err != nil {
		return nil, err
	}
	return decodeJSON[DeviceToken](opDeviceToken, a, body)
}

// answer avoids handing back an *http.Response whose Body is already closed.
type answer struct {
	Status      int
	ContentType string
	URL         string // the actual, post-redirect target, sanitised by safeURL
}

// call returns answer and body even on error: Health wants the 503 body, DeviceToken wants the 400 body.
func (h *Hub) call(ctx context.Context, op, target string, want int, fn func() (*http.Response, error)) (answer, []byte, error) {
	if err := ctx.Err(); err != nil {
		return answer{URL: target}, nil, classifyTransport(op, target, err)
	}
	resp, err := fn()
	if err != nil {
		return answer{URL: target}, nil, classifyTransport(op, target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	a := answer{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), URL: target}
	if resp.Request != nil {
		a.URL = safeURL(resp.Request.URL)
	}

	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if rerr != nil {
		// Status line arrived, body didn't: unreachable, not ClassProtocol.
		return a, nil, classifyTransport(op, target, rerr)
	}
	if len(body) > maxBodyBytes {
		return a, nil, &OpError{
			Class:  ClassProtocol,
			Op:     op,
			URL:    a.URL,
			Status: a.Status,
			Detail: fmt.Sprintf("response body exceeds the %d byte cap", maxBodyBytes),
		}
	}
	if e := classifyStatus(op, resp, body, want); e != nil {
		return a, body, e
	}
	return a, body, nil
}

// decodeJSON: a body that won't parse is ClassProtocol, never a nil value with a nil error.
func decodeJSON[T any](op string, a answer, body []byte) (*T, error) {
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		detail := "response body is not the documented one"
		if a.ContentType != "" {
			detail += " (content-type " + a.ContentType + ")"
		}
		return nil, &OpError{
			Class:  ClassProtocol,
			Op:     op,
			URL:    a.URL,
			Status: a.Status,
			Detail: detail,
			Err:    err,
		}
	}
	return &v, nil
}

// opURL is the best available target for a transport error, which has no response to read a URL off.
func (h *Hub) opURL(path string) string {
	u := *h.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	return safeURL(&u)
}

// bearerTransport is why the bearer token never leaks to a redirect target.
// Do not delete as redundant with the stdlib: net/http DELIBERATELY
// preserves Authorization across same-host/subdomain/port-only redirects
// (verified in net/http/client.go; pinned by
// TestStandardLibraryLeaksOnSameHostAndSubdomainRedirects). The token goes
// on the FIRST hop only (req.Response == nil) to the hub's own origin.
type bearerTransport struct {
	base   http.RoundTripper
	origin string
	// token is a closure, not a string field; see New for the measurement.
	token     func() string
	userAgent string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context()) // a RoundTripper must not modify the request handed to it
	if t.userAgent != "" && out.Header.Get("User-Agent") == "" {
		out.Header.Set("User-Agent", t.userAgent)
	}
	if req.Response == nil && originOf(req.URL) == t.origin {
		if tok := t.token(); tok != "" {
			out.Header.Set("Authorization", "Bearer "+tok)
		}
		return t.base.RoundTrip(out)
	}
	// Deleted, not skipped: net/http's redirect loop or a caller-built request
	// may already have set it.
	out.Header.Del("Authorization")
	return t.base.RoundTrip(out)
}

// stripAuthorizationOnRedirect is not redundant with bearerTransport:
// net/http copies the header onto the new request BEFORE calling
// CheckRedirect, so this removes it from the request object itself. Also
// reimposes net/http's own redirect limit, which setting CheckRedirect
// otherwise removes.
func stripAuthorizationOnRedirect(next func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		req.Header.Del("Authorization")
		if next != nil {
			return next(req, via)
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return nil
	}
}

// originOf is scheme://host:port with the default port made explicit and the
// host lower-cased, so https://Hub.Example.com:443 and https://hub.example.com
// compare equal. Deliberately does NOT fold a trailing dot on the host: fails
// closed (token withheld) rather than risk a wrong DNS-canonicalisation guess.
func originOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}
