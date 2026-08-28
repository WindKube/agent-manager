package hub

// This file is the CLI's whole view of the hub. Everything above it — the
// verbs, the device flow, the bundle downloader — talks to Hub and never to
// the generated *Client directly, for two reasons that are both security
// properties rather than tidiness:
//
//  1. The bearer token is injected in ONE place, an http.RoundTripper scoped
//     to the hub's own origin, so FR-016 (never send the token to a redirect
//     target) is a property of the transport instead of a rule that every call
//     site has to remember.
//  2. Every answer the hub can give is turned into a Class in ONE place, so
//     FR-040's four distinguishable failures cannot drift apart between verbs.
//
// WHY THIS USES THE RAW ClientInterface AND NOT ClientWithResponses.
// Measured against the generated file, not assumed: ParseListProfilesResponse
// and its siblings io.ReadAll the body uncapped, populate their typed field
// only when the Content-Type happens to contain "json", and return a bare
// error when json.Unmarshal fails — indistinguishable, at the call site, from
// the transport error the same call returns when nothing answered. Routing
// through them would classify a load balancer's HTML error page as
// "unreachable" and send the user hunting a network fault that is not there.
// Reading and decoding here keeps status, body and cause separable, which is
// the whole of FR-040.

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
	// OpGetBundle is exported because bundles.go (T038) issues that call
	// itself — the generated GetBundleWithResponse reads the whole bundle into
	// memory before anything can check its digest, which is the opposite of
	// FR-014 — and its errors must carry the same op name as everything else.
	OpGetBundle = "getBundle"
)

// PlaintextFlagName is the flag that makes an http:// hub acceptable
// (FR-041). It lives here, beside the refusal that names it, so the flag and
// the message cannot disagree; the command layer registers it.
const PlaintextFlagName = "allow-plaintext-hub"

// maxRedirects mirrors net/http's own default. Setting Client.CheckRedirect
// replaces the standard library's limit, so it has to be reimposed here — a
// CheckRedirect that only strips a header and always returns nil turns a
// redirect loop into an infinite one.
const maxRedirects = 10

// maxBodyBytes caps every JSON body this package reads. The largest real one
// is a lockfile — tens of kilobytes at the profile sizes R4 measured — so this
// is four orders of magnitude of headroom, and it exists so that a hostile or
// broken endpoint cannot make the CLI allocate until it dies. It does NOT
// apply to a bundle: those never come through here (see Raw).
const maxBodyBytes = 32 << 20

// revisionPattern is the contract's own `^(head|[0-9]+)$`. Checked locally
// only to name the bad argument instead of round-tripping for a 422; it makes
// no decision about WHICH revision to fetch, which would be the second
// resolver FR-009 forbids.
//
//nolint:gocritic // copied character for character from the frozen contract, so it stays greppable against it.
var revisionPattern = regexp.MustCompile(`^(head|[0-9]+)$`)

// Config constructs a Hub.
type Config struct {
	// URL is the hub base URL. https is required unless AllowPlaintext.
	URL string
	// Token is the bearer credential, or "" for the device endpoints, which
	// take none. It is copied into a closure and never stored in a struct
	// field; see New for the measurement behind that.
	Token string
	// AllowPlaintext accepts an http:// URL (FR-041). There is no
	// "but it is localhost" exception: a shortcut that fires by itself under
	// some conditions is a default, and FR-041 exists to stop plaintext being
	// one.
	AllowPlaintext bool
	// HTTPClient supplies the transport, timeouts and TLS configuration when
	// non-nil. Its Transport is WRAPPED rather than replaced and the struct is
	// copied, so New never mutates a client the caller still holds.
	HTTPClient *http.Client
	// UserAgent identifies this CLI to the hub. Empty means "amctl"; it is set
	// explicitly because net/http would otherwise send Go-http-client/1.1 and
	// a hub operator reading access logs deserves better.
	UserAgent string
}

// Hub is a hub endpoint plus the credential to use against it.
//
// It holds no state beyond that: no cached lockfile, nothing to close. Two
// Hubs for two hub URLs is the supported way to talk to two hubs, which is
// what FR-006's per-hub credential scoping needs.
type Hub struct {
	base     *url.URL
	gen      ClientInterface
	httpc    *http.Client
	insecure bool
}

// New validates the URL, wires the bearer transport and returns a Hub.
//
// It makes no network call. FR-039's home check and FR-041's TLS check both
// have to happen before anything is dialled, and a constructor that probed
// would make that ordering impossible to guarantee.
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
	// Refused rather than ignored, and the offending value is NOT echoed:
	// net/http copies URL credentials onto every redirect target, which is
	// FR-016's leak wearing a different hat, and a password echoed into a
	// refusal lands in whatever captured stderr.
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
		// A closure, not a string field. Measured, not assumed: fmt prints the
		// values of UNEXPORTED struct fields under %v, %+v and %#v, and it
		// cannot call String() on them (reflect.Value.CanInterface is false for
		// a field reached through reflection), so the usual "wrap it in a
		// redacting Stringer" defence does not work here. A func field prints
		// as an address. This is what keeps FR-007 true for a careless
		// fmt.Sprintf("%+v", someStructHoldingAHub).
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

// URL is the hub's base URL as a string, without userinfo, query or fragment.
func (h *Hub) URL() string { return h.base.String() }

// Insecure reports whether this Hub talks plaintext, so a verb can warn on the
// diagnostic stream every run rather than only where the flag was parsed.
func (h *Hub) Insecure() bool { return h.insecure }

// Raw is the generated client, with the bearer transport already wired.
//
// It exists for one caller: getBundle, which must stream the response body to
// compute its digest before a byte reaches the tree (FR-014, FR-019), and so
// cannot use a wrapper that reads the whole bundle first. Anything else should
// use a method on Hub, or the classification stops being in one place.
func (h *Hub) Raw() ClientInterface { return h.gen }

// HTTPClient is the redirect- and token-safe client. Same audience as Raw: a
// caller that follows getBundle's 307 by hand must use THIS client, because a
// fresh http.Client reinstates the standard library's subdomain-preserving
// Authorization copy that stripAuthorizationOnRedirect exists to prevent.
func (h *Hub) HTTPClient() *http.Client { return h.httpc }

// Health calls /v1/health, which takes no credential.
//
// That is what makes it the discriminator FR-040 needs: if Health answers and
// an authenticated call returns 401, the diagnosis is unauthorised rather than
// unreachable, and the CLI can say which.
//
// A 503 returns the parsed body AND a ClassUnavailable error, because the body
// names the dependency that is down and dropping it would leave the caller
// with a diagnosis it cannot act on.
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

// Reachable reports whether the hub answered /v1/health at all. A 503 counts:
// the hub is there and a dependency it needs is not, which is a different
// sentence from "unreachable" and must not be collapsed into it.
func (h *Hub) Reachable(ctx context.Context) bool {
	_, err := h.Health(ctx)
	switch ClassOf(err) {
	case 0, ClassUnavailable:
		return true
	default:
		return false
	}
}

// ListProfiles returns the profiles this credential may read.
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

// GetRevision fetches a resolved revision lockfile. revision is "head" or an
// integer, as a string, exactly as the contract has it.
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

// ReportSync posts the one sync event for a completed sync (204 on success).
//
// FR-033 makes a failure here a warning rather than a failed sync, so the
// error is returned plainly for the caller to report on the diagnostic stream
// and is deliberately not wrapped in anything that looks fatal.
func (h *Hub) ReportSync(ctx context.Context, report SyncReport) error {
	target := h.opURL("/v1/sync")
	_, _, err := h.call(ctx, opReportSync, target, http.StatusNoContent, func() (*http.Response, error) {
		return h.gen.ReportSync(ctx, report)
	})
	return err
}

// DeviceAuthorize opens an RFC 8628 device authorisation. Unauthenticated: it
// is how a machine with no credential gets one.
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

// DeviceFlowError is RFC 8628's 400 body: the polling protocol, not a failure
// of it. authorization_pending and slow_down are the normal course of a login
// and MUST NOT be classified as ClassRequest, or a poll loop would abort on
// its first tick. Which codes are terminal is the device state machine's
// decision (T025), so this type reports the code and judges nothing.
type DeviceFlowError struct {
	Code DeviceTokenErrorError
}

// Error implements error. It names the code and nothing else — the device code
// and the user code are credentials under FR-007 and never appear here.
func (e *DeviceFlowError) Error() string {
	if e.Code == "" {
		return "deviceToken: hub refused the poll without naming a reason"
	}
	return "deviceToken: " + string(e.Code)
}

// DeviceToken polls for the issued token. Unauthenticated.
//
// A 400 comes back as *DeviceFlowError; everything else is classified. The
// token in the 200 body is returned to the caller and never logged or put into
// an error by this package.
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

// answer is what survives a call once the body has been read and the response
// closed: the three facts a diagnosis needs, and nothing that has to be
// released. call deliberately does NOT return the *http.Response — handing back
// a response whose Body it has already closed is a trap for the next caller,
// and it is what made the bodyclose linter right to complain.
type answer struct {
	Status      int
	ContentType string
	// URL is the target the response actually came from, after any redirect,
	// sanitised by safeURL.
	URL string
}

// call issues one request, reads its body under maxBodyBytes and classifies
// anything that is not `want`.
//
// The answer and body are returned even when the error is non-nil, because two
// callers need them: Health wants the 503 body and DeviceToken wants the 400
// body. Status is 0 only when nothing answered.
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
		// The status line arrived and the body did not. That is the connection
		// failing, not a hub misbehaving, so it is unreachable rather than
		// ClassProtocol.
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

// decodeJSON is the only place a hub body becomes a Go value. A body that will
// not parse is ClassProtocol — "that endpoint is not a hub" — and never a nil
// value with a nil error, which would fail somewhere far from the cause.
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

// opURL is the best available target string for a transport error, which by
// definition has no response to read a URL off.
func (h *Hub) opURL(path string) string {
	u := *h.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	return safeURL(&u)
}

// bearerTransport injects the bearer token, and is the reason FR-016 holds.
//
// WHY THIS IS NOT A RequestEditorFn: the generated client's request editors
// run once, on the request the client builds. http.Client then follows
// getBundle's 307 on its own, and by that point Authorization is already set.
// A request editor cannot see the second hop at all, so the stripping has to
// live in the transport — or in CheckRedirect; this code does both.
//
// WHY THE STANDARD LIBRARY IS NOT ENOUGH. Do not delete this as redundant.
// Verified in $GOROOT/src/net/http/client.go: the redirect loop only considers
// dropping sensitive headers when `reqs[0].URL.Host != req.URL.Host`, and even
// then it asks shouldCopyHeaderOnRedirect, which returns
// isDomainOrSubdomain(dest, initial). So net/http DELIBERATELY preserves
// Authorization on:
//
//   - a same-host redirect — hub.example.com/v1/bundles/… -> hub.example.com/objects/…
//   - a subdomain redirect — hub.example.com -> s3.hub.example.com
//   - a PORT-ONLY change  — hub.example.com:8443 -> hub.example.com:9000
//
// That third one was measured rather than read: idnaASCIIFromURL is u.Hostname(),
// so the port is not part of shouldCopyHeaderOnRedirect's comparison at all,
// and a hub fronting a MinIO on another port of the same host — the commonest
// self-hosted layout there is — leaks the token with the default client.
//
// All three are exactly how a self-hosted hub fronts its object store, and
// FR-016 has no subdomain, path or port exception. The default leaks the token,
// and no line of calling code looks wrong.
// TestStandardLibraryLeaksOnSameHostAndSubdomainRedirects asserts the default
// behaviour directly, so if a future Go release changes it this comment fails
// rather than merely ages.
//
// The rule enforced here: the token goes on the FIRST hop of a request to the
// hub's own origin, and on nothing else. First-hop-ness is req.Response == nil
// — net/http documents Request.Response as "the redirect response which caused
// this request to be created… only populated during client redirects" and sets
// it on every redirect-generated request. The origin comparison includes the
// scheme, so an https -> http downgrade on the same host is refused too.
type bearerTransport struct {
	base   http.RoundTripper
	origin string
	// token is a closure so that no struct here holds the credential as a
	// string. See New for the measurement.
	token     func() string
	userAgent string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// A RoundTripper must not modify the request it is handed.
	out := req.Clone(req.Context())
	if t.userAgent != "" && out.Header.Get("User-Agent") == "" {
		out.Header.Set("User-Agent", t.userAgent)
	}
	if req.Response == nil && originOf(req.URL) == t.origin {
		if tok := t.token(); tok != "" {
			out.Header.Set("Authorization", "Bearer "+tok)
		}
		return t.base.RoundTrip(out)
	}
	// Not ours: delete rather than merely skip injecting. The header may
	// already be present — copied by net/http's redirect loop, or set by a
	// caller that built its own request — and skipping would leave that copy
	// in place.
	out.Header.Del("Authorization")
	return t.base.RoundTrip(out)
}

// stripAuthorizationOnRedirect is the second of the two defences, and it is
// not redundant with bearerTransport: net/http copies the header onto the new
// request BEFORE calling CheckRedirect (client.go calls copyHeaders, then
// c.checkRedirect), so deleting it here means the credential is gone from the
// request object itself rather than merely omitted on the wire. If someone
// later swaps the transport out, this still holds.
//
// It also has to reimpose net/http's redirect limit, which setting
// CheckRedirect otherwise removes.
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
// host lower-cased, which is what makes the comparison in RoundTrip immune to
// https://Hub.Example.com:443 versus https://hub.example.com.
//
// What it deliberately does NOT normalise: a trailing dot on the host, so
// "hub.example.com." is a distinct origin here. Treating them as equal would
// be a second opinion on DNS canonicalisation, and being wrong in this
// direction fails closed — the token is withheld — rather than leaking it.
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
