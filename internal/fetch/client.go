// Package fetch is the only way anything in this project reaches a
// user-supplied URL.
//
// R10 required that the SSRF control be proven by this project's own six-case
// suite (safe_test.go) before a client was chosen. github.com/doyensec/safeurl
// failed case 2: its check is a net.Dialer.Control hook that runs per connect
// attempt, so a name answering with both a public and a private address has the
// private attempt refused and then connects over the public one. R10's stated
// fallback is what ships here.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrBlocked marks a refusal by the outbound policy rather than a transport
// failure. FR-002 and US1 scenario 5 need the two to be told apart: a refusal is
// a fetch error the operator must see, never a scan finding.
var ErrBlocked = errors.New("refused by outbound policy")

// BlockedError names the address or URL that was refused and why. The target is
// the offending address, not the URL the user typed, because for a name with
// several answers only one of them is the problem.
type BlockedError struct {
	Target string
	Reason string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("outbound request to %s refused: %s", e.Target, e.Reason)
}

func (e *BlockedError) Unwrap() error { return ErrBlocked }

// Client is the interface this project owns. Callers depend on this, never on
// whatever library sits behind it.
type Client interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
	Get(ctx context.Context, url string) (*http.Response, error)
}

const (
	// DefaultTimeout matches config.Fetcher.FetchTimeout's default.
	DefaultTimeout = 60 * time.Second
	maxRedirects   = 5
	dialTimeout    = 10 * time.Second
)

// Options configures a Client. The intended call site is the fetcher bootstrap:
//
//	fetch.New(fetch.Options{Timeout: cfg.FetchTimeout, Allowlist: cfg.OutboundAllowlist})
type Options struct {
	// Timeout bounds the whole request including redirects. Zero means
	// DefaultTimeout.
	Timeout time.Duration

	// Allowlist widens the refusal for deployments whose package sources really
	// do live on a private address (an on-prem git mirror, a MinIO in the same
	// VPC). Entries are "ip", "ip:port" or a CIDR, and a match exempts the
	// address from both the reserved-range rule and the default port list.
	//
	// Hostnames are rejected: a name is not an address, and allowlisting one
	// would reintroduce exactly the rebinding hole this package exists to close.
	Allowlist []string

	// Resolver is the seam that makes R10 cases 2 and 4 expressible at all.
	// Nil means net.DefaultResolver.
	Resolver Resolver
}

type guardedClient struct {
	http     *http.Client
	policy   policy
	resolver Resolver
}

func New(opts Options) (Client, error) {
	allow, err := parseAllowlist(opts.Allowlist)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	c := &guardedClient{policy: policy{allow: allow}, resolver: resolver}
	c.http = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Proxy stays nil on purpose. A proxy would move every connection to
			// the proxy's address, so the dial-time address checks below would be
			// validating the proxy instead of the destination.
			Proxy:       nil,
			DialContext: c.dialContext,
			// A reused connection skips DialContext and therefore skips the
			// connect-time address check. The fetcher makes a handful of requests
			// per job, so closing that reuse window costs nothing worth keeping.
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			// Each hop is a fresh attacker-controlled URL. This is the check that
			// turns a 302 into a private address into a refusal at the hop, before
			// the transport gets a chance to dial it.
			return c.checkURL(req.Context(), req.URL)
		},
	}
	return c, nil
}

func (c *guardedClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("fetch: request has no url")
	}
	req = req.Clone(ctx)

	if err := c.checkURL(ctx, req.URL); err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, redactedError{fmt.Errorf("fetch %s: %w", req.URL.Redacted(), err)}
	}
	return resp, nil
}

func (c *guardedClient) Get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, redactedError{fmt.Errorf("build request for %q: %w", rawURL, err)}
	}
	return c.Do(ctx, req)
}

// credentialsInURL matches the "user:password@" of any URL embedded in a string.
// The authority cannot contain "/?#@" or whitespace, which is what keeps a path
// segment or a neighbouring word from being mistaken for one.
var credentialsInURL = regexp.MustCompile(`//([^/?#@\s"']*):[^/?#@\s"']*@`)

// redactedError renders its message with every embedded password removed, and
// unwraps to the original chain so errors.Is(err, ErrBlocked) still answers.
//
// This scrubs the rendered message rather than a URL field because the secret
// arrives by several routes and a fetch error is persisted and shown to an
// operator. On a refused redirect net/http puts the raw, origin-supplied Location
// header into url.Error.URL without stripping it (net/http/client.go,
// "ue.(*url.Error).URL = loc"), and into the message verbatim when that header
// does not parse; net/url likewise repeats an unparseable input in full. So a
// password an attacker puts in a Location header, or a caller mistypes into a URL
// that never parses, would otherwise land in the audit trail.
type redactedError struct{ err error }

func (e redactedError) Error() string {
	return credentialsInURL.ReplaceAllString(e.err.Error(), "//$1:xxxxx@")
}

func (e redactedError) Unwrap() error { return e.err }

// checkURL is the pre-flight half of the control: it validates the URL shape and
// every address the name currently answers with. It runs on the initial request
// and again on every redirect hop.
func (c *guardedClient) checkURL(ctx context.Context, u *url.URL) error {
	if err := c.policy.checkURL(u); err != nil {
		return err
	}

	port, err := portOf(u)
	if err != nil {
		return err
	}

	ips, err := c.resolve(ctx, u.Hostname())
	if err != nil {
		return err
	}
	// Refusing the whole set, rather than skipping the bad entries, is the
	// difference between this and safeurl: a name answering with one public and
	// one private address is unreachable, not reachable over the public half.
	for _, ip := range ips {
		if err := c.policy.checkAddr(ip, port); err != nil {
			return err
		}
	}
	return nil
}

func portOf(u *url.URL) (int, error) {
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return 0, &BlockedError{Target: u.Redacted(), Reason: fmt.Sprintf("port %q is not a valid port", p)}
		}
		return port, nil
	}
	// Lowercased for the same reason policy.checkURL lowercases: two checks that
	// disagree about how to read one field are a bypass waiting for a refactor.
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	default:
		return 0, &BlockedError{Target: u.Redacted(), Reason: "scheme " + u.Scheme + " has no default port"}
	}
}
