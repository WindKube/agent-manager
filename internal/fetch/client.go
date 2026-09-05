// Package fetch is the only way anything in this project reaches a
// user-supplied URL. Its SSRF control checks every resolved address, not just
// the first, so a name answering with both a public and a private address
// cannot connect over the public one after the private attempt is refused.
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
// failure.
var ErrBlocked = errors.New("refused by outbound policy")

// BlockedError names the address or URL that was refused and why.
type BlockedError struct {
	Target string
	Reason string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("outbound request to %s refused: %s", e.Target, e.Reason)
}

func (e *BlockedError) Unwrap() error { return ErrBlocked }

// Client is the interface this project owns.
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

// Options configures a Client.
type Options struct {
	// Timeout bounds the whole request including redirects. Zero means
	// DefaultTimeout.
	Timeout time.Duration

	// Allowlist widens the refusal for deployments whose sources live on a
	// private address. Entries are "ip", "ip:port" or a CIDR; hostnames are
	// rejected since a name can be made to resolve to a private address.
	Allowlist []string

	// Resolver is the seam that makes the multi-address SSRF cases testable.
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
			// Proxy stays nil: it would move every connection to the proxy's
			// address, defeating the dial-time checks below.
			Proxy:       nil,
			DialContext: c.dialContext,
			// A reused connection skips DialContext and its address check.
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			// Each redirect hop is checked before the transport dials it.
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

// credentialsInURL matches the "user:password@" of any URL embedded in a
// string.
var credentialsInURL = regexp.MustCompile(`//([^/?#@\s"']*):[^/?#@\s"']*@`)

// redactedError scrubs embedded credentials from its message before a fetch
// error reaches an audit row or log line, and still unwraps to ErrBlocked.
type redactedError struct{ err error }

func (e redactedError) Error() string {
	return credentialsInURL.ReplaceAllString(e.err.Error(), "//$1:xxxxx@")
}

func (e redactedError) Unwrap() error { return e.err }

// checkURL is the pre-flight half of the control: it validates the URL shape
// and every address the name currently answers with.
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
	// The whole set is refused if any address is bad, not just skipped.
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
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	default:
		return 0, &BlockedError{Target: u.Redacted(), Reason: "scheme " + u.Scheme + " has no default port"}
	}
}
