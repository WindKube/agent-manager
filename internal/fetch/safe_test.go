package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The R10 gate. Six cases: five things that must be refused and one that must
// get through, because a control that refuses everything looks identical to one
// that works.
//
// None of it touches the network. Cases 1, 3 and 6 use httptest servers; cases 2
// and 4 use stubResolver, which is why Options.Resolver exists.

// publicIP is a routable address used only as a DNS answer. Nothing in this file
// connects to it — if a regression ever tried, the short client timeout below
// turns the hang into a failure instead of a wedged test run.
const publicIP = "93.184.216.34"

const testTimeout = 2 * time.Second

// stubResolver answers a scripted sequence per host. The last answer repeats, so
// a single-element script is a stable name and a two-element script is a name
// that rebinds between the pre-flight check and the connect.
type stubResolver struct {
	mu      sync.Mutex
	answers map[string][][]string
	calls   map[string]int
}

func newStubResolver(answers map[string][][]string) *stubResolver {
	return &stubResolver{answers: answers, calls: map[string]int{}}
}

func (r *stubResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	script, ok := r.answers[host]
	if !ok || len(script) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	i := min(r.calls[host], len(script)-1)
	r.calls[host]++

	out := make([]net.IPAddr, 0, len(script[i]))
	for _, s := range script[i] {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("stub resolver: %q is not an ip", s)
		}
		out = append(out, net.IPAddr{IP: ip})
	}
	return out, nil
}

func (r *stubResolver) lookups(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

func newTestClient(t *testing.T, opts Options) Client {
	t.Helper()
	if opts.Timeout == 0 {
		opts.Timeout = testTimeout
	}
	c, err := New(opts)
	require.NoError(t, err)
	return c
}

// addrOf returns an httptest server's "ip:port", suitable as an allowlist entry.
func addrOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "http://")
}

func portOfServer(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addrOf(t, srv))
	require.NoError(t, err)
	n, err := strconv.Atoi(p)
	require.NoError(t, err)
	return n
}

// requireBlocked asserts the refusal came from the policy and not from a failed
// connection. FR-002 and US1 scenario 5 rest on this distinction.
func requireBlocked(t *testing.T, err error, mustName string) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIsf(t, err, ErrBlocked, "want a policy refusal, got %v", err)

	var blocked *BlockedError
	require.ErrorAs(t, err, &blocked)
	require.Containsf(t, err.Error(), mustName,
		"refusal should name the offending target %q, got %q", mustName, err.Error())
}

// --- R10 case 1 ---------------------------------------------------------------

func TestRedirectToLoopbackIsRefusedAtTheHop(t *testing.T) {
	// Counters are atomic because the handlers run on the server's goroutines
	// and the assertions read them from the test's.
	var victimHits atomic.Int32
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		victimHits.Add(1)
		fmt.Fprint(w, "ssrf reached the victim")
	}))
	defer victim.Close()

	var originHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		http.Redirect(w, r, victim.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer origin.Close()

	// Only the origin's exact ip:port is permitted, so the victim on a different
	// port of the same loopback address falls back under the reserved-range rule.
	// That is what makes the refusal a real one and not a spelling of "port 0".
	require.NotEqual(t, portOfServer(t, origin), portOfServer(t, victim))
	c := newTestClient(t, Options{Allowlist: []string{addrOf(t, origin)}})

	resp, err := c.Get(context.Background(), origin.URL)
	if resp != nil {
		resp.Body.Close()
	}

	requireBlocked(t, err, victim.Listener.Addr().String())
	require.EqualValues(t, 1, originHits.Load(), "the first hop must have been made, or the test proves nothing")
	require.EqualValues(t, 0, victimHits.Load(), "the redirect target was reached")
}

// The end-to-end cases above are also caught by the connect-time check, so they
// pass even with the per-hop check removed. This pins the hop check on its own:
// it must refuse a hop before the transport is ever asked to dial it, which is
// what "refused before any connection completes" (US1 scenario 5) requires.
func TestEachRedirectHopIsCheckedBeforeItIsDialled(t *testing.T) {
	gc, ok := newTestClient(t, Options{Allowlist: []string{"203.0.113.7:8443"}}).(*guardedClient)
	require.True(t, ok)
	require.NotNil(t, gc.http.CheckRedirect)

	hop := func(rawURL string) *http.Request {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
		require.NoError(t, err)
		return req
	}

	refused := []string{
		"http://127.0.0.1:9/",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/",
		"http://[::1]:8080/",
		"http://8.8.8.8:6379/",
		"http://admin:hunter2@203.0.113.7:8443/",
	}
	for _, rawURL := range refused {
		t.Run("refuses "+rawURL, func(t *testing.T) {
			require.ErrorIs(t, gc.http.CheckRedirect(hop(rawURL), nil), ErrBlocked)
		})
	}

	// Non-vacuity: a hop the policy permits must be followed.
	t.Run("permits an allowlisted hop", func(t *testing.T) {
		require.NoError(t, gc.http.CheckRedirect(hop("http://203.0.113.7:8443/bundle.tar.gz"), nil))
	})

	t.Run("caps the chain", func(t *testing.T) {
		via := make([]*http.Request, maxRedirects)
		require.ErrorContains(t,
			gc.http.CheckRedirect(hop("http://203.0.113.7:8443/x"), via),
			"stopped after 5 redirects")
	})
}

// --- R10 case 2 ---------------------------------------------------------------

func TestHostResolvingToPublicAndPrivateIsRefused(t *testing.T) {
	// Both orderings, because the failure mode being guarded against is a control
	// that refuses the private attempt and then connects over the public one.
	// safeurl fails this case in exactly that way.
	tests := []struct {
		name    string
		answer  []string
		offends string
	}{
		{"private address listed first", []string{"10.0.0.5", publicIP}, "10.0.0.5"},
		{"private address listed second", []string{publicIP, "10.0.0.5"}, "10.0.0.5"},
		{"loopback alongside a public address", []string{publicIP, "127.0.0.1"}, "127.0.0.1"},
		{"ipv6 unique-local alongside a public address", []string{publicIP, "fd00::1"}, "fd00::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := newStubResolver(map[string][][]string{"split.invalid": {tt.answer}})
			c := newTestClient(t, Options{Resolver: res})

			resp, err := c.Get(context.Background(), "http://split.invalid/plugin.json")
			if resp != nil {
				resp.Body.Close()
			}
			requireBlocked(t, err, tt.offends)
		})
	}
}

// --- R10 case 3 ---------------------------------------------------------------

func TestRedirectToLinkLocalMetadataIsRefused(t *testing.T) {
	tests := []struct {
		name string
		to   string
		host string
	}{
		{"ec2 imds", "http://169.254.169.254/latest/meta-data/", "169.254.169.254"},
		{"gce metadata by address", "http://169.254.169.254/computeMetadata/v1/", "169.254.169.254"},
		{"azure imds", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "169.254.169.254"},
		{"alibaba imds over ipv6 link-local", "http://[fe80::a9fe:a9fe]/latest/meta-data/", "fe80::a9fe:a9fe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tt.to, http.StatusFound)
			}))
			defer origin.Close()

			c := newTestClient(t, Options{Allowlist: []string{addrOf(t, origin)}})
			resp, err := c.Get(context.Background(), origin.URL)
			if resp != nil {
				resp.Body.Close()
			}
			requireBlocked(t, err, tt.host)
		})
	}
}

// --- R10 case 4 ---------------------------------------------------------------

func TestDNSRebindingBetweenCheckAndConnectIsRefused(t *testing.T) {
	tests := []struct {
		name    string
		script  [][]string
		offends string
	}{
		{"public then loopback", [][]string{{publicIP}, {"127.0.0.1"}}, "127.0.0.1"},
		{"public then link-local metadata", [][]string{{publicIP}, {"169.254.169.254"}}, "169.254.169.254"},
		{"public then rfc1918", [][]string{{publicIP}, {"172.16.9.9"}}, "172.16.9.9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := newStubResolver(map[string][][]string{"rebind.invalid": tt.script})
			c := newTestClient(t, Options{Resolver: res})

			resp, err := c.Get(context.Background(), "http://rebind.invalid/plugin.json")
			if resp != nil {
				resp.Body.Close()
			}

			requireBlocked(t, err, tt.offends)
			// The point of the case: the first answer passed the pre-flight check,
			// and the refusal came from the second lookup, the one whose addresses
			// would actually have been connected to.
			require.Equal(t, 2, res.lookups("rebind.invalid"),
				"want a pre-flight lookup and a connect-time lookup")
		})
	}
}

// --- R10 case 5 ---------------------------------------------------------------

func TestNonHTTPSchemesAreRefused(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"file", "file:///etc/passwd"},
		{"file with a host", "file://localhost/etc/shadow"},
		{"gopher", "gopher://127.0.0.1:70/_%0d%0aSET%20k%20v"},
		{"ftp", "ftp://example.invalid/x.tar.gz"},
		{"data", "data:text/plain;base64,aGk="},
		{"jar", "jar:file:///etc/passwd!/"},
		{"dict", "dict://127.0.0.1:11211/stat"},
	}

	c := newTestClient(t, Options{Allowlist: []string{"127.0.0.1"}})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := c.Get(context.Background(), tt.url)
			if resp != nil {
				resp.Body.Close()
			}
			require.Error(t, err)
			require.ErrorIsf(t, err, ErrBlocked, "want a policy refusal, got %v", err)
			require.Contains(t, err.Error(), "is not http or https")
		})
	}
}

func TestCredentialsInURLAreRefused(t *testing.T) {
	c := newTestClient(t, Options{Allowlist: []string{"127.0.0.1"}})

	resp, err := c.Get(context.Background(), "http://admin:hunter2@127.0.0.1:80/plugin.json")
	if resp != nil {
		resp.Body.Close()
	}
	require.ErrorIs(t, err, ErrBlocked)
	require.Contains(t, err.Error(), "carries credentials")
	require.NotContains(t, err.Error(), "hunter2", "the password must not reach an error string")
}

// --- R10 case 6 ---------------------------------------------------------------

func TestLegitimateDestinationIsAllowed(t *testing.T) {
	// Non-vacuity, without internet: the httptest server's address is explicitly
	// permitted by configuration, so a control that refuses everything fails here.
	var served atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		served.Store(&path)
		fmt.Fprint(w, `{"name":"platform-toolkit"}`)
	}))
	defer srv.Close()

	c := newTestClient(t, Options{Allowlist: []string{addrOf(t, srv)}})

	resp, err := c.Get(context.Background(), srv.URL+"/plugins/platform-toolkit/plugin.json")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"platform-toolkit"}`, string(body))
	require.NotNil(t, served.Load())
	require.Equal(t, "/plugins/platform-toolkit/plugin.json", *served.Load())
}

func TestLegitimateRedirectChainIsAllowed(t *testing.T) {
	// The same non-vacuity proof for the redirect path: refusing every hop would
	// pass case 1 and 3 while being useless.
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "final")
	}))
	defer final.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/bundle.tar.gz", http.StatusFound)
	}))
	defer origin.Close()

	c := newTestClient(t, Options{Allowlist: []string{addrOf(t, origin), addrOf(t, final)}})

	resp, err := c.Get(context.Background(), origin.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, final.URL+"/bundle.tar.gz", resp.Request.URL.String())
}

// --- the ErrBlocked / transport-error distinction ------------------------------

func TestTransportFailureIsNotAPolicyRefusal(t *testing.T) {
	// US1 scenario 5 requires an SSRF refusal to be recorded as a fetch error and
	// never as a finding, which only works if callers can tell the two apart.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := addrOf(t, srv)
	srv.Close() // nothing is listening now

	c := newTestClient(t, Options{Allowlist: []string{addr}})

	resp, err := c.Get(context.Background(), "http://"+addr+"/plugin.json")
	if resp != nil {
		resp.Body.Close()
	}
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrBlocked, "a refused connection is not a policy refusal")
}

func TestRedirectCountIsCapped(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+r.URL.Path+"x", http.StatusFound)
	}))
	defer srv.Close()

	c := newTestClient(t, Options{Allowlist: []string{addrOf(t, srv)}})
	resp, err := c.Get(context.Background(), srv.URL+"/a")
	if resp != nil {
		resp.Body.Close()
	}
	require.ErrorContains(t, err, "stopped after 5 redirects")
}

// --- the classifier on its own -------------------------------------------------

func TestReservedReason(t *testing.T) {
	tests := []struct {
		ip       string
		reserved bool
	}{
		{"93.184.216.34", false},
		{"8.8.8.8", false},
		{"2606:4700::1111", false},
		{"0.0.0.0", true},
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"198.18.0.1", true},
		{"192.0.2.1", true},
		{"198.51.100.1", true},
		{"203.0.113.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"::1", true},
		{"::", true},
		{"fe80::1", true},
		{"fd00::1", true},
		{"ff02::1", true},
		{"2001:db8::1", true},
		{"2002:7f00:0001::", true},
		{"64:ff9b::7f00:1", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:8.8.8.8", false},
		// Embeddings that are not IPv4-mapped, so To4 does not normalise them and
		// every net.IP.Is* predicate answers false. Only the CIDR table catches
		// these.
		{"::7f00:1", true},
		{"::127.0.0.1", true},
		{"::a9fe:a9fe", true},
		{"::ffff:0:7f00:1", true},
		{"::ffff:0:a9fe:a9fe", true},
		{"2620:4f:8000::1", true},
		{"2001:20::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "test fixture %q is not an ip", tt.ip)
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			reason := reservedReason(ip)
			if tt.reserved {
				require.NotEmpty(t, reason, "%s should be refused", tt.ip)
			} else {
				require.Empty(t, reason, "%s should be reachable", tt.ip)
			}
		})
	}
}

func TestPortPolicy(t *testing.T) {
	tests := []struct {
		name      string
		allowlist []string
		ip        string
		port      int
		allowed   bool
	}{
		{"public host on 443", nil, "8.8.8.8", 443, true},
		{"public host on 80", nil, "8.8.8.8", 80, true},
		{"public host on redis", nil, "8.8.8.8", 6379, false},
		{"public host on 8443 without an allowlist", nil, "8.8.8.8", 8443, false},
		{"public host on 8443 with the address allowlisted", []string{"8.8.8.8"}, "8.8.8.8", 8443, true},
		{"allowlisted ip:port matches", []string{"10.0.0.5:8443"}, "10.0.0.5", 8443, true},
		{"allowlisted ip:port does not cover another port", []string{"10.0.0.5:8443"}, "10.0.0.5", 8444, false},
		{"allowlisted cidr covers the address", []string{"10.0.0.0/8"}, "10.9.9.9", 9000, true},
		{"allowlisted cidr does not cover a neighbour range", []string{"10.0.0.0/8"}, "172.16.0.1", 443, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, err := parseAllowlist(tt.allowlist)
			require.NoError(t, err)
			p := policy{allow: allow}

			err = p.checkAddr(net.ParseIP(tt.ip), tt.port)
			if tt.allowed {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrBlocked)
			}
		})
	}
}

func TestAllowlistRejectsHostnames(t *testing.T) {
	tests := []string{"mirror.internal", "mirror.internal:8443", "*.example.com", "not an address", "10.0.0.5:0", "10.0.0.5:99999"}

	for _, entry := range tests {
		t.Run(entry, func(t *testing.T) {
			_, err := New(Options{Allowlist: []string{entry}})
			require.ErrorContains(t, err, "outbound allowlist entry")
		})
	}
}

func TestDialAddrGuardRejectsNonLiteralAddresses(t *testing.T) {
	p := policy{}
	for _, addr := range []string{"metadata.google.internal:80", "127.0.0.1", "127.0.0.1:notaport"} {
		require.ErrorIs(t, p.checkDialAddr(addr), ErrBlocked, addr)
	}
	require.ErrorIs(t, p.checkDialAddr("127.0.0.1:80"), ErrBlocked)
	require.NoError(t, p.checkDialAddr("8.8.8.8:443"))
}

func TestDoRejectsARequestWithNoURL(t *testing.T) {
	c := newTestClient(t, Options{})
	resp, err := c.Do(context.Background(), nil)
	if resp != nil {
		resp.Body.Close()
	}
	require.ErrorContains(t, err, "request has no url")
}

var _ Resolver = (*net.Resolver)(nil)

// Obfuscated loopback literals (127.1, 2130706433, 0x7f.0.0.1) are not addresses
// net.ParseIP accepts, so they reach the resolver. Whatever the resolver makes of
// them is then classified like any other answer — which is why the bypass class
// closes without a table of spellings.
func TestObfuscatedLoopbackLiteralsAreRefused(t *testing.T) {
	hosts := []string{"127.1", "2130706433", "0x7f.0.0.1", "017700000001"}

	answers := map[string][][]string{}
	for _, h := range hosts {
		answers[h] = [][]string{{"127.0.0.1"}}
	}
	res := newStubResolver(answers)
	c := newTestClient(t, Options{Resolver: res})

	for _, h := range hosts {
		t.Run(h, func(t *testing.T) {
			resp, err := c.Get(context.Background(), "http://"+h+"/plugin.json")
			if resp != nil {
				resp.Body.Close()
			}
			requireBlocked(t, err, "127.0.0.1")
		})
	}
}

func TestErrorsAreUnwrappable(t *testing.T) {
	err := fmt.Errorf("fetch: %w", &BlockedError{Target: "169.254.169.254:80", Reason: "link-local address"})
	require.ErrorIs(t, err, ErrBlocked)

	var blocked *BlockedError
	require.ErrorAs(t, err, &blocked)
	require.Equal(t, "169.254.169.254:80", blocked.Target)
	require.Equal(t,
		"outbound request to 169.254.169.254:80 refused: link-local address",
		blocked.Error())
}

// The classifier answers "" for a public address, so anything it cannot reason
// about must be refused explicitly rather than fall out of the bottom of the
// switch. Options.Resolver is a public seam, and a resolver handing back a
// net.IP of any other length used to be reported as reachable.
func TestClassifierFailsClosedOnAMalformedAddress(t *testing.T) {
	for _, ip := range []net.IP{nil, {}, {10, 0, 0}, make(net.IP, 5), make(net.IP, 15), make(net.IP, 17)} {
		t.Run(fmt.Sprintf("%d bytes", len(ip)), func(t *testing.T) {
			require.NotEmpty(t, reservedReason(ip))
			require.ErrorIs(t, policy{}.checkAddr(ip, 443), ErrBlocked)
		})
	}
}

// R10 case 6 without the allowlist. Both httptest-backed "allowed" cases permit
// their target through Options.Allowlist, and checkAddr consults the allowlist
// before it consults anything else — so a policy that refused every address on
// earth would still pass them. This drives the whole pre-flight chain (scheme,
// credentials, host, port, resolve, classify) on the default configuration, which
// is the configuration that actually ships.
func TestDefaultConfigurationPermitsALegitimateDestination(t *testing.T) {
	tests := []string{
		"http://mirror.test/plugin.json",
		"https://mirror.test/plugin.json",
		"https://mirror.test:443/bundle.tar.gz",
		"http://" + publicIP + "/plugin.json",
		"https://[2606:4700::1111]/plugin.json",
	}

	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			res := newStubResolver(map[string][][]string{"mirror.test": {{publicIP, "2606:4700::1111"}}})
			gc, ok := newTestClient(t, Options{Resolver: res}).(*guardedClient)
			require.True(t, ok)
			require.Empty(t, gc.policy.allow, "the allowlist must be empty or this proves nothing")

			// checkURL rather than Get: with no allowlist the only addresses this
			// package permits are public ones, and connecting to one would make the
			// suite need the internet.
			require.NoError(t, gc.checkURL(context.Background(), mustParse(t, rawURL)))
		})
	}
}

func mustParse(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u
}

// net/http records the raw, origin-supplied Location header in url.Error.URL when
// CheckRedirect refuses a hop, without stripping its password. A fetch error is
// persisted and shown to an operator, so the refusal must not carry the secret an
// attacker put in the header.
func TestCredentialsInARefusedRedirectAreNotLeaked(t *testing.T) {
	tests := []struct {
		name    string
		loc     string
		blocked bool
	}{
		{"credentials on a private target", "http://admin:hunter2@10.0.0.5/secrets", true},
		{"credentials on a public target", "http://admin:hunter2@" + publicIP + "/x", true},
		{"credentials on a loopback target", "http://admin:hunter2@127.0.0.1:22/x", true},
		{"credentials on a scheme-relative target", "//admin:hunter2@10.0.0.5/x", true},
		// net/http embeds an unparseable Location in the error message rather than
		// in url.Error.URL, so redacting one field is not enough. It is a client
		// error rather than a policy refusal, hence blocked:false.
		{"credentials on an unparseable target", "http://admin:hunter2@exa mple.com/x", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", tt.loc)
				w.WriteHeader(http.StatusFound)
			}))
			defer origin.Close()

			c := newTestClient(t, Options{Allowlist: []string{addrOf(t, origin)}})
			resp, err := c.Get(context.Background(), origin.URL)
			if resp != nil {
				resp.Body.Close()
			}
			require.Error(t, err)
			if tt.blocked {
				require.ErrorIs(t, err, ErrBlocked)
			}
			require.NotContains(t, err.Error(), "hunter2", "the password must not reach an error string")
			require.Contains(t, err.Error(), "admin:xxxxx", "the error should still name the hop")
		})
	}
}

// The same guarantee on the path where the URL never parses: url.Redacted is not
// available, and both the caller's string and net/url's own error repeat the
// password verbatim.
func TestCredentialsInAnUnparseableURLAreNotLeaked(t *testing.T) {
	tests := []string{
		"http://admin:hunter2@exa mple.com/x",
		"http://admin:hunter2@[::1/x",
		"http://admin:hunter2@example.com:notaport/",
		"http://admin:hunter2@example.com/\x7f",
	}

	c := newTestClient(t, Options{})
	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			resp, err := c.Get(context.Background(), rawURL)
			if resp != nil {
				resp.Body.Close()
			}
			require.Error(t, err)
			require.NotContains(t, err.Error(), "hunter2", "the password must not reach an error string")
			require.Contains(t, err.Error(), "admin:xxxxx")
		})
	}
}

func TestRedactedErrorScrubsEveryEmbeddedPassword(t *testing.T) {
	tests := []struct{ in, want string }{
		{`Get "http://admin:hunter2@10.0.0.5/x"`, `Get "http://admin:xxxxx@10.0.0.5/x"`},
		{`failed to parse Location header "http://u:p@exa mple.com/"`, `failed to parse Location header "http://u:xxxxx@exa mple.com/"`},
		{"//admin:hunter2@10.0.0.5/x", "//admin:xxxxx@10.0.0.5/x"},
		{"http://admin:xxxxx@10.0.0.5/x", "http://admin:xxxxx@10.0.0.5/x"},
		// No password, so nothing to remove — url.Redacted keeps the username too.
		{"http://admin@10.0.0.5/x", "http://admin@10.0.0.5/x"},
		// Must not fire on an ordinary refusal: a port colon is not a userinfo
		// colon, and a path @ is not an authority @.
		{`fetch http://127.0.0.1:33849: Get "http://127.0.0.1:22/x": refused`, `fetch http://127.0.0.1:33849: Get "http://127.0.0.1:22/x": refused`},
		{"http://example.com:8080/a@b", "http://example.com:8080/a@b"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			require.Equal(t, tt.want, redactedError{errors.New(tt.in)}.Error())
		})
	}
}

func TestRedactedErrorStaysUnwrappable(t *testing.T) {
	inner := &BlockedError{Target: "10.0.0.5:80", Reason: "private address"}
	err := redactedError{fmt.Errorf("fetch http://u:p@x/: %w", inner)}

	require.ErrorIs(t, err, ErrBlocked)
	var blocked *BlockedError
	require.ErrorAs(t, err, &blocked)
	require.Equal(t, inner, blocked)
	require.NotContains(t, err.Error(), ":p@")
}
