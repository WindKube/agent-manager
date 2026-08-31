//go:build integration

// The local identity provider, asserted against the real thing: the pinned Dex
// and glauth images, the configuration files deploy/local actually ships, and
// tokens Dex actually signed.
//
// The order below is the order contracts/local-identity.md sets out, and it is
// the order of increasing consequence. Discovery answering proves the containers
// booted. The device endpoint proves FR-102. A `groups` claim per user proves the
// LDAP connector's attribute names are right. And the two claims DIFFERING is the
// one that matters: a presence-only check passes against Dex's own mockCallback
// connector, which hands one hard-coded group to everybody, so presence alone
// would have signed off on the exact bug this file exists to catch.
//
// The fixture files are also checked against internal/seed's constants — cheaply,
// without Docker, in localidp_fixture_test.go, which runs in the ordinary build.
package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"agent-manager/internal/seed"
)

// dexImage, glauthImage and issuer live in localidp_fixture_test.go, where the
// ordinary build can check them against the compose files that declare them.
const (
	// FR-103 / SC-103, and the quantity matters as much as the number: this is the
	// UNPACKED on-disk size of the two images, what `docker image ls` prints, and
	// what research.md's 268 MB and the 730 MB it compares against both are. It is
	// NOT what `docker image inspect` reports — under the containerd snapshotter
	// that field is the compressed content size, 62 MB for this pair, so measuring
	// it left the budget 4.3x of false slack AND made the assertion silently
	// host-dependent, because the classic graph driver returns the unpacked size
	// from the same field. Measured 268.0 MB on 2026-08-31.
	//
	// Decimal MB, because that is the unit docker prints and the unit FR-103 and
	// research.md are written in. 300 MiB would be the looser reading of the same
	// sentence.
	combinedImageBudget = 300_000_000

	oidcClientID     = "agent-manager"
	oidcClientSecret = "local-only-oidc-client-secret"
	// One of the two redirect URIs the shipped Dex config registers. Nothing
	// listens on it; the flow is stopped at the redirect and the code is read out
	// of the Location header.
	oidcRedirectURI = "http://127.0.0.1:8080/auth/callback"

	// Both directory users share it. glauth.cfg holds its sha256.
	directoryPassword = "local-only-directory-password"
)

var (
	// dexBase is the mapped host base URL, e.g. http://127.0.0.1:49xxx/dex.
	dexBase string

	// dexContainer is kept only so a failure can quote Dex's log. Every one of
	// R1's three attribute-name traps surfaces here as an opaque HTTP 500 whose
	// actual cause — a missing attribute, a group entity with no cn — is written
	// nowhere but that log. Printing it is the difference between this suite
	// naming the mistake and this suite saying "500".
	dexContainer testcontainers.Container

	// discoveryLatency is measured from immediately before the Dex container is
	// created to the first 200 from its discovery path — deliberately including
	// container creation, so the 5 s budget is charged for everything an operator
	// waits through. Image pulls happen before the clock starts.
	discoveryLatency time.Duration

	discovery struct {
		Issuer                      string   `json:"issuer"`
		AuthorizationEndpoint       string   `json:"authorization_endpoint"`
		TokenEndpoint               string   `json:"token_endpoint"`
		JWKSURI                     string   `json:"jwks_uri"`
		DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
		GrantTypesSupported         []string `json:"grant_types_supported"`
		ScopesSupported             []string `json:"scopes_supported"`
	}

	// The two ways this suite can decline to assert, kept apart because
	// conflating them is what made T017 unable to fail.
	//
	// noContainers is a SKIP: no reachable daemon, or an image that cannot be
	// obtained. A machine like that has nothing wrong with it, and a spurious red
	// is a red nobody reads.
	//
	// brokenStack is a FAILURE. The daemon answered, the images are local, and the
	// configuration this repository ships either refused to come up or never
	// answered on the port it publishes. Reporting that as a skip is how moving
	// Dex's listener to :5557 produced six skips and `exit 0` — and tasks.md names
	// T017 as the gate whose failure stops the feature, so it has to be able to
	// fail for the one regression most likely to happen.
	noContainers string
	brokenStack  string
)

func TestMain(m *testing.M) {
	code, err := runLocalIDPSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "local identity provider integration suite:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runLocalIDPSuite(m *testing.M) (int, error) {
	ctx := context.Background()

	docker, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		noContainers = "no reachable Docker daemon: " + err.Error()
		return m.Run(), nil
	}
	defer docker.Close()

	// Before the clock starts. A cold pull is not what the 5 s budget is about.
	for _, ref := range []string{glauthImage, dexImage} {
		if pullErr := ensureImage(ctx, docker.Client, ref); pullErr != nil {
			noContainers = fmt.Sprintf("cannot obtain %s: %v", ref, pullErr)
			return m.Run(), nil
		}
	}

	// A skip, unlike the container starts below: nothing in this repository
	// configures the network, so a daemon that cannot make one is an environment
	// that cannot run containers rather than a stack that is broken.
	net, err := network.New(ctx)
	if err != nil {
		noContainers = "cannot create a Docker network: " + err.Error()
		return m.Run(), nil
	}
	defer func() { _ = net.Remove(ctx) }()

	// glauth first, and its Ryuk reaper with it, so neither is charged to Dex's
	// discovery budget. Dex tolerates a directory that is not yet listening —
	// it dials LDAP per login, not at boot — but starting them in order keeps the
	// first login in a fresh stack from paying for the retry.
	glauth, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          glauthImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"glauth"}},
			// The image's start script reads exactly this path and copies its own
			// example config in if the file is absent — a silent fallback to a
			// directory with none of our users in it, so an unmounted fixture
			// would look like a wrong password rather than a missing file.
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      glauthFixturePath,
				ContainerFilePath: "/app/config/config.cfg",
				FileMode:          0o644,
			}},
			ExposedPorts: []string{"3893/tcp"},
			WaitingFor:   wait.ForLog("LDAP server listening").WithStartupTimeout(30 * time.Second),
		},
	})
	if err != nil {
		brokenStack = "the glauth container refused to start, so deploy/local/glauth/glauth.cfg " +
			"or the mount path it is read from is wrong: " + err.Error()
		return m.Run(), nil
	}
	defer func() { _ = glauth.Terminate(ctx) }()

	startedAt := time.Now()
	dex, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          dexImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"dex"}},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      dexFixturePath,
				ContainerFilePath: "/etc/dex/config.docker.yaml",
				FileMode:          0o644,
			}},
			ExposedPorts: []string{"5556/tcp"},
			WaitingFor:   wait.ForListeningPort("5556/tcp").WithStartupTimeout(30 * time.Second),
		},
	})
	if err != nil {
		brokenStack = "the dex container refused to start, so deploy/local/dex/config.yaml " +
			"or the port it publishes is wrong: " + err.Error()
		return m.Run(), nil
	}
	defer func() { _ = dex.Terminate(ctx) }()
	dexContainer = dex

	endpoint, err := dex.PortEndpoint(ctx, "5556/tcp", "http")
	if err != nil {
		brokenStack = "dex started but 5556 is not published, which is the port the issuer, " +
			"the compose file and every measurement name: " + err.Error()
		return m.Run(), nil
	}
	dexBase = endpoint + "/dex"

	if err := awaitDiscovery(ctx, startedAt); err != nil {
		brokenStack = err.Error()
	}

	return m.Run(), nil
}

func ensureImage(ctx context.Context, cli *client.Client, ref string) error {
	if _, err := cli.ImageInspect(ctx, ref); err == nil {
		return nil
	}

	resp, err := cli.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer resp.Close()

	// The pull is only complete once its progress stream is drained.
	_, err = io.Copy(io.Discard, resp)
	return err
}

// awaitDiscovery polls until the document parses, recording how long that took
// and keeping the document for the assertions to read.
func awaitDiscovery(ctx context.Context, startedAt time.Time) error {
	deadline := time.Now().Add(30 * time.Second)
	var last error

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			dexBase+"/.well-known/openid-configuration", http.NoBody)
		if err != nil {
			return err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("discovery answered %d", resp.StatusCode)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := json.Unmarshal(body, &discovery); err != nil {
			return fmt.Errorf("discovery document did not parse: %w", err)
		}

		discoveryLatency = time.Since(startedAt)
		return nil
	}

	return fmt.Errorf("discovery never answered: %w", last)
}

// quoteDexLogOnFailure is registered by signIn, because a refused login is the
// one failure in this file whose explanation lives in the provider rather than in
// the assertion.
func quoteDexLogOnFailure(t *testing.T) {
	t.Helper()

	t.Cleanup(func() {
		if !t.Failed() || dexContainer == nil {
			return
		}

		logs, err := dexContainer.Logs(context.Background())
		if err != nil {
			return
		}
		defer logs.Close()

		out, err := io.ReadAll(logs)
		if err != nil {
			return
		}

		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		if len(lines) > 15 {
			lines = lines[len(lines)-15:]
		}
		t.Logf("dex log, last %d lines:\n%s", len(lines), strings.Join(lines, "\n"))
	})
}

// requireStack is for every assertion about the running provider. It skips when
// the harness cannot run containers here and FAILS when the stack we ship did
// not come up, which is the distinction the whole suite turns on.
func requireStack(t *testing.T) {
	t.Helper()
	if noContainers != "" {
		t.Skip(noContainers)
	}
	if brokenStack != "" {
		t.Fatal(brokenStack)
	}
}

// requireImages is for the two assertions whose subject is the images alone.
// They are answerable whether or not the stack booted, and saying so keeps a
// broken config from reddening tests that have nothing to do with it.
func requireImages(t *testing.T) {
	t.Helper()
	if noContainers != "" {
		t.Skip(noContainers)
	}
}

// ---------------------------------------------------------------------------
// 1. Discovery, within 5 s of container start.

func TestTheLocalProviderAnswersDiscoveryWithinFiveSeconds(t *testing.T) {
	requireStack(t)

	t.Logf("discovery answered %s after the container was created", discoveryLatency.Round(time.Millisecond))
	require.Less(t, discoveryLatency, 5*time.Second,
		"FR-103: the provider Keycloak replaced took nine seconds, and the whole point of the "+
			"swap was that an operator should not wait through it")
	require.Equal(t, issuer, discovery.Issuer)

	// R2's finding, in its cheapest form: the document is byte-identical whichever
	// host it was fetched through, because Dex ignores the request Host. This was
	// fetched through a mapped port and still names the container host, which is
	// exactly why the issuer must be the container-reachable one and only the
	// browser leg gets an override.
	for _, endpoint := range []string{
		discovery.AuthorizationEndpoint, discovery.TokenEndpoint,
		discovery.JWKSURI, discovery.DeviceAuthorizationEndpoint,
	} {
		require.True(t, strings.HasPrefix(endpoint, issuer),
			"%q does not sit under the issuer; Dex is rewriting hosts after all, and "+
				"AGENT_MANAGER_OIDC_BROWSER_BASE_URL rests on it not doing that", endpoint)
	}
}

// ---------------------------------------------------------------------------
// 2. The device flow the CLI needs (FR-102).

func TestTheLocalProviderAdvertisesTheDeviceEndpointAndTheDeviceCodeGrant(t *testing.T) {
	requireStack(t)

	require.NotEmpty(t, discovery.DeviceAuthorizationEndpoint)
	require.Contains(t, discovery.GrantTypesSupported,
		"urn:ietf:params:oauth:grant-type:device_code",
		"the CLI has no browser redirect to fall back on")

	// Dex requires the scope to be asked for; the Keycloak realm it replaces
	// attached its group mapper to the client, which is why
	// AGENT_MANAGER_OIDC_SCOPES has to gain `groups` (FR-106).
	require.Contains(t, discovery.ScopesSupported, "groups")
}

// ---------------------------------------------------------------------------
// 3. A groups claim, per user, in a token Dex signed.

func TestEachDirectoryUserGetsAGroupsClaimNamingTheGroupTheSeedMapsToARole(t *testing.T) {
	requireStack(t)

	for _, user := range seed.DirectoryUsers {
		t.Run(user.Username, func(t *testing.T) {
			c := signIn(t, user.Email)

			require.Equal(t, user.Email, c.Email)
			require.NotEmpty(t, c.Groups, "FR-101. This is the failure Keycloak was adopted to "+
				"avoid and the one the group search's attribute names reintroduce silently: the "+
				"login succeeds and the claim is simply absent")
			require.Contains(t, c.Groups, user.Group,
				"the group internal/seed maps to this user's role")
		})
	}
}

// ---------------------------------------------------------------------------
// 4. The assertion this file exists for.

func TestTheTwoDirectoryUsersGetDifferentGroups(t *testing.T) {
	requireStack(t)

	platform := signIn(t, seed.DirectoryEmailPlatform)
	security := signIn(t, seed.DirectoryEmailSecurity)

	require.NotEqual(t, platform.Sub, security.Sub, "two people, two subjects")
	require.NotEqual(t, platform.Groups, security.Groups,
		"SC-104 turns on these two differing. A connector that hands every user the same "+
			"hard-coded group — Dex's mockCallback does exactly that — satisfies every other "+
			"assertion in this file, and then both users resolve to the same role and the "+
			"product cannot demonstrate a role boundary at all")

	require.Equal(t, []string{seed.GroupEngPlatform}, platform.Groups)
	require.Equal(t, []string{seed.GroupEngSecurity}, security.Groups)
}

// ---------------------------------------------------------------------------
// T024: the footprint and the platform (FR-103, SC-103).

func TestTheTwoIdentityImagesStayUnderTheCombinedFootprintBudget(t *testing.T) {
	requireImages(t)

	ctx := context.Background()
	docker, err := testcontainers.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)
	defer docker.Close()

	var total int64
	for _, ref := range []string{dexImage, glauthImage} {
		// The image SUMMARY, not the inspect record. Both carry a `Size` and they
		// are different quantities under the containerd snapshotter; this is the
		// one `docker image ls` prints and the one combinedImageBudget explains.
		listed, err := docker.ImageList(ctx, client.ImageListOptions{
			Filters: client.Filters{}.Add("reference", ref),
		})
		require.NoError(t, err)
		require.Lenf(t, listed.Items, 1, "%s: %d images match that exact tag", ref, len(listed.Items))

		t.Logf("%s: %.1f MB unpacked", ref, float64(listed.Items[0].Size)/1e6)
		total += listed.Items[0].Size
	}

	require.LessOrEqualf(t, total, int64(combinedImageBudget),
		"the identity provider is %.1f MB unpacked against a %d MB budget",
		float64(total)/1e6, combinedImageBudget/1_000_000)
}

func TestBothIdentityImagesPublishLinuxArm64(t *testing.T) {
	requireImages(t)

	ctx := context.Background()
	docker, err := testcontainers.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)
	defer docker.Close()

	for _, ref := range []string{dexImage, glauthImage} {
		t.Run(ref, func(t *testing.T) {
			// The registry's manifest list, so this holds on an amd64 host too.
			dist, err := docker.DistributionInspect(ctx, ref, client.DistributionInspectOptions{})
			require.NoError(t, err, "the registry has to be reachable to answer this")

			var platforms []string
			for _, p := range dist.Platforms {
				platforms = append(platforms, p.OS+"/"+p.Architecture)
			}
			require.Contains(t, platforms, "linux/arm64",
				"every measurement in research.md was taken on aarch64")

			// And the copy this machine pulled is native. On an arm64 host a
			// missing arm64 variant does not fail the pull, it silently lands the
			// amd64 one under emulation — which then makes every timing number in
			// research.md a measurement of qemu.
			info, err := docker.ImageInspect(ctx, ref)
			require.NoError(t, err)
			require.Equal(t, "linux", info.Os)
			require.Equal(t, runtime.GOARCH, info.Architecture,
				"the pulled image is not native to this host, so it is running emulated")
		})
	}
}

// ---------------------------------------------------------------------------
// The real credential grant.

type idTokenClaims struct {
	Iss    string   `json:"iss"`
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
}

var formActionPattern = regexp.MustCompile(`<form[^>]*\saction="([^"]+)"`)

// signIn drives the authorization-code flow the product actually uses, through
// Dex's own LDAP login form, and returns the claims of a signature-verified ID
// token.
//
// Not the password grant, which would have been three lines. Dex does support it
// — `oauth2.passwordConnector: ldap` turns it on and it does yield the groups
// claim, measured — but it is a global switch, not the per-client setting it
// looks like: it enables ROPC for every registered client, the public CLI one
// included. Buying test convenience with a permanent widening of the shipped
// config is a bad trade, and a test that took that path would exercise a grant
// the product never uses and leave the login form — the thing an operator
// actually meets — unasserted.
func signIn(t *testing.T, email string) idTokenClaims {
	t.Helper()
	quoteDexLogOnFailure(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	// Stop at the first hop that leaves Dex. That hop is the redirect carrying the
	// authorization code, and nothing is listening on the redirect URI's port.
	stopAtRedirectURI := func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), oidcRedirectURI) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	c := &http.Client{Jar: jar, CheckRedirect: stopAtRedirectURI, Timeout: 20 * time.Second}

	const state = "localidp-integration-state"
	authURL := dexBase + "/auth?" + url.Values{
		"client_id":     {oidcClientID},
		"redirect_uri":  {oidcRedirectURI},
		"response_type": {"code"},
		// From compose.yaml, not from a literal here: this suite is the only thing
		// that would notice `groups` leaving the list the product actually sends,
		// and it cannot notice it while asking for a list of its own.
		"scope": {composeOIDCScopes(t)},
		"state": {state},
	}.Encode()

	// One connector, so Dex redirects straight past its chooser to the login page.
	page, err := c.Get(authURL)
	require.NoError(t, err)
	body, err := io.ReadAll(page.Body)
	_ = page.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, page.StatusCode, "login page: %s", body)

	action := formActionPattern.FindSubmatch(body)
	require.NotNil(t, action, "no login form in Dex's response:\n%s", body)
	loginURL, err := page.Request.URL.Parse(html.UnescapeString(string(action[1])))
	require.NoError(t, err)

	// skipApprovalScreen collapses the consent hop, so this lands on the redirect
	// directly; the client would follow an approval hop on its own if it appeared.
	submitted, err := c.PostForm(loginURL.String(), url.Values{
		"login":    {email},
		"password": {directoryPassword},
	})
	require.NoError(t, err)
	_ = submitted.Body.Close()

	redirect, err := submitted.Location()
	require.NoErrorf(t, err,
		"Dex answered %d with no redirect, so the login never produced a code. The flow is not "+
			"the suspect — the connector is: the bind DN or password, the user search, the "+
			"attribute names, or the password hash in the glauth fixture. The dex log quoted "+
			"below says which", submitted.StatusCode)
	require.Equal(t, state, redirect.Query().Get("state"), "state must come back unchanged")
	code := redirect.Query().Get("code")
	require.NotEmpty(t, code, "no authorization code in %s", redirect)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {oidcRedirectURI},
	}
	req, err := http.NewRequest(http.MethodPost, dexBase+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(oidcClientID, oidcClientSecret)

	tokenResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	tokenBody, err := io.ReadAll(tokenResp.Body)
	_ = tokenResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token endpoint: %s", tokenBody)

	var token struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(tokenBody, &token))
	require.NotEmpty(t, token.IDToken)

	// Verified, not merely decoded — an unverified payload would let a fixture
	// masquerade as a token. The key set is fetched through the mapped port while
	// the issuer checked against the `iss` claim stays the published one, which is
	// the split this whole arrangement rests on.
	ctx := context.Background()
	verifier := oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(ctx, dexBase+"/keys"),
		&oidc.Config{ClientID: oidcClientID})
	verified, err := verifier.Verify(ctx, token.IDToken)
	require.NoError(t, err)

	var claims idTokenClaims
	require.NoError(t, verified.Claims(&claims))
	require.Equal(t, issuer, claims.Iss)
	return claims
}
