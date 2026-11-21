//go:build integration

// The local identity provider asserted against the pinned Dex and glauth images,
// the shipped deploy/local config, and tokens Dex actually signed. The key check
// is that users get DIFFERENT groups: a presence-only check passes against a
// connector handing everyone the same hard-coded group.
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

	"agent-manager/internal/auth"
	"agent-manager/internal/seed"
)

// dexImage, glauthImage and issuer live in localidp_fixture_test.go, where the
// ordinary build can check them against the compose files that declare them.
const (
	// Unpacked on-disk size as `docker image ls` prints it, in decimal MB.
	// `docker image inspect` reports compressed size under containerd, which gave
	// 4x false slack and made the check host-dependent.
	combinedImageBudget = 300_000_000

	oidcClientID     = "agent-manager"
	oidcClientSecret = "local-only-oidc-client-secret"
	// Nothing listens here; the code is read from the Location header.
	oidcRedirectURI = "http://127.0.0.1:8080/auth/callback"

	// glauth.cfg holds its sha256.
	directoryPassword = "local-only-directory-password"
)

var (
	dexBase string

	// dexContainer is kept so a failure can quote Dex's log: LDAP attribute
	// mistakes surface only as an opaque HTTP 500 whose cause is logged there.
	dexContainer testcontainers.Container

	// discoveryLatency includes container creation but not image pulls.
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

	// noContainers is a skip (no daemon or image: nothing wrong with the machine);
	// brokenStack is a failure (the shipped config didn't come up). Conflating them
	// once turned a moved Dex listener into six skips and exit 0.
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

	for _, ref := range []string{glauthImage, dexImage} {
		if pullErr := ensureImage(ctx, docker.Client, ref); pullErr != nil {
			noContainers = fmt.Sprintf("cannot obtain %s: %v", ref, pullErr)
			return m.Run(), nil
		}
	}

	// A skip: nothing in this repository configures the network.
	net, err := network.New(ctx)
	if err != nil {
		noContainers = "cannot create a Docker network: " + err.Error()
		return m.Run(), nil
	}
	defer func() { _ = net.Remove(ctx) }()

	// glauth first, so its startup and Ryuk aren't charged to Dex's discovery budget.
	glauth, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          glauthImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"glauth"}},
			// The image copies in its own example config if this path is absent, which
			// would look like a wrong password rather than a missing mount.
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

	_, err = io.Copy(io.Discard, resp)
	return err
}

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

// requireStack skips when containers can't run here and fails when the shipped
// stack didn't come up.
func requireStack(t *testing.T) {
	t.Helper()
	if noContainers != "" {
		t.Skip(noContainers)
	}
	if brokenStack != "" {
		t.Fatal(brokenStack)
	}
}

// requireImages is for assertions about the images alone, so a broken config
// doesn't redden them.
func requireImages(t *testing.T) {
	t.Helper()
	if noContainers != "" {
		t.Skip(noContainers)
	}
}

func TestTheLocalProviderAnswersDiscoveryWithinFiveSeconds(t *testing.T) {
	requireStack(t)

	t.Logf("discovery answered %s after the container was created", discoveryLatency.Round(time.Millisecond))
	require.Less(t, discoveryLatency, 5*time.Second,
		"the provider Keycloak replaced took nine seconds, and the whole point of the "+
			"swap was that an operator should not wait through it")
	require.Equal(t, issuer, discovery.Issuer)

	// Dex ignores the request Host, so the document names the container host even
	// via a mapped port; hence only the browser leg gets an override.
	for _, endpoint := range []string{
		discovery.AuthorizationEndpoint, discovery.TokenEndpoint,
		discovery.JWKSURI, discovery.DeviceAuthorizationEndpoint,
	} {
		require.True(t, strings.HasPrefix(endpoint, issuer),
			"%q does not sit under the issuer; Dex is rewriting hosts after all, and "+
				"AGENT_MANAGER_OIDC_BROWSER_BASE_URL rests on it not doing that", endpoint)
	}
}

func TestTheLocalProviderAdvertisesTheDeviceEndpointAndTheDeviceCodeGrant(t *testing.T) {
	requireStack(t)

	require.NotEmpty(t, discovery.DeviceAuthorizationEndpoint)
	require.Contains(t, discovery.GrantTypesSupported,
		"urn:ietf:params:oauth:grant-type:device_code",
		"the CLI has no browser redirect to fall back on")

	// Dex only emits `groups` when the scope is requested.
	require.Contains(t, discovery.ScopesSupported, "groups")
}

func TestEachDirectoryUserGetsAGroupsClaimNamingTheirOwnGroup(t *testing.T) {
	requireStack(t)

	for _, user := range seed.DirectoryUsers {
		t.Run(user.Username, func(t *testing.T) {
			c := signIn(t, user.Email)

			require.Equal(t, user.Email, c.Email)
			require.NotEmpty(t, c.Groups, "This is the failure Keycloak was adopted to "+
				"avoid and the one the group search's attribute names reintroduce silently: the "+
				"login succeeds and the claim is simply absent")
			require.Contains(t, c.Groups, user.Group,
				"the group seed.DirectoryUsers puts this user in")

			// Group search working and the group NAME matching a role are independent failures.
			if user.Group == seed.GroupUnmapped {
				require.Empty(t, seed.RoleOf(user.Group),
					"this is the account that reaches the no-role screen; a role here removes "+
						"the only route to it")
				return
			}
			require.NotEmpty(t, seed.RoleOf(user.Group))
		})
	}
}

func TestTheTwoDirectoryUsersGetDifferentGroups(t *testing.T) {
	requireStack(t)

	platform := signIn(t, seed.DirectoryEmailPlatform)
	security := signIn(t, seed.DirectoryEmailSecurity)

	require.NotEqual(t, platform.Sub, security.Sub, "two people, two subjects")
	require.NotEqual(t, platform.Groups, security.Groups,
		"These two must differ. A connector that hands every user the same "+
			"hard-coded group — Dex's mockCallback does exactly that — satisfies every other "+
			"assertion in this file, and then both users resolve to the same role and the "+
			"product cannot demonstrate a role boundary at all")

	require.ElementsMatch(t, []string{seed.GroupEngPlatform, seed.GroupEngAll}, platform.Groups)
	require.ElementsMatch(t, []string{seed.GroupEngSecurity, seed.GroupEngAll}, security.Groups)
}

// Nothing in Dex's config says whether a group search returns glauth's
// othergroups as well as the primary group; this pins that both arrive.
func TestBothRoleHoldingDirectoryUsersArriveInTheGroupTheyShare(t *testing.T) {
	requireStack(t)

	for _, user := range seed.DirectoryUsers {
		t.Run(user.Username, func(t *testing.T) {
			groups := signIn(t, user.Email).Groups

			if user.Shared == "" {
				require.NotContains(t, groups, seed.GroupEngAll,
					"this is the account that must resolve NO role, and %q maps to one",
					seed.GroupEngAll)
				require.Len(t, groups, 1)
				return
			}
			require.Contains(t, groups, user.Shared,
				"glauth's othergroups did not reach the claim, so the group a profile is shared "+
					"with contains nobody who can sign in")
			require.Contains(t, groups, user.Group, "and the primary membership is still there")
		})
	}
}

// eng-all maps to a second role, harmless only because HighestRole picks the most
// privileged; changing that precedence would silently demote the local admin.
func TestTheSharedDirectoryGroupDoesNotChangeEitherUsersRole(t *testing.T) {
	requireStack(t)

	for _, user := range seed.DirectoryUsers {
		if user.Shared == "" {
			continue
		}
		t.Run(user.Username, func(t *testing.T) {
			var mapped []string
			for _, group := range signIn(t, user.Email).Groups {
				if role := seed.RoleOf(group); role != "" {
					mapped = append(mapped, role)
				}
			}

			require.Contains(t, mapped, seed.RoleOf(user.Shared),
				"the shared group resolves to no role, so this test is asserting nothing")
			require.Equal(t, seed.RoleOf(user.Group), string(auth.HighestRole(mapped)),
				"the role this person resolves has to be the one their primary group grants, "+
					"not the one the group they merely share with a colleague grants")
		})
	}
}

func TestTheTwoIdentityImagesStayUnderTheCombinedFootprintBudget(t *testing.T) {
	requireImages(t)

	ctx := context.Background()
	docker, err := testcontainers.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)
	defer docker.Close()

	var total int64
	for _, ref := range []string{dexImage, glauthImage} {
		// The image summary size, not the inspect record; see combinedImageBudget.
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
			dist, err := docker.DistributionInspect(ctx, ref, client.DistributionInspectOptions{})
			require.NoError(t, err, "the registry has to be reachable to answer this")

			var platforms []string
			for _, p := range dist.Platforms {
				platforms = append(platforms, p.OS+"/"+p.Architecture)
			}
			require.Contains(t, platforms, "linux/arm64",
				"every measurement in research.md was taken on aarch64")

			// On arm64 a missing arm64 variant silently pulls amd64 under emulation,
			// skewing every timing measurement.
			info, err := docker.ImageInspect(ctx, ref)
			require.NoError(t, err)
			require.Equal(t, "linux", info.Os)
			require.Equal(t, runtime.GOARCH, info.Architecture,
				"the pulled image is not native to this host, so it is running emulated")
		})
	}
}

type idTokenClaims struct {
	Iss    string   `json:"iss"`
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
}

var formActionPattern = regexp.MustCompile(`<form[^>]*\saction="([^"]+)"`)

// signIn drives the product's authorization-code flow through Dex's login form.
// Not the password grant: enabling it in Dex turns on ROPC for every client,
// the public CLI one included.
func signIn(t *testing.T, email string) idTokenClaims {
	t.Helper()
	quoteDexLogOnFailure(t)

	const state = "localidp-integration-state"
	authURL := dexBase + "/auth?" + url.Values{
		"client_id":     {oidcClientID},
		"redirect_uri":  {oidcRedirectURI},
		"response_type": {"code"},
		// From compose.yaml so this suite notices `groups` leaving the shipped scope list.
		"scope": {composeOIDCScopes(t)},
		"state": {state},
	}.Encode()
	code := authorizationCode(t, authURL, email, state)

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

	// Verified, not merely decoded, so a fixture can't masquerade as a token.
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

// authorizationCode drives a browser through Dex's LDAP login form and returns
// the code from the redirect.
func authorizationCode(t *testing.T, authorizationURL, email, wantState string) string {
	t.Helper()
	quoteDexLogOnFailure(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	// Stop at the redirect leaving Dex; nothing listens on the redirect URI.
	stopAtRedirectURI := func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), oidcRedirectURI) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	c := &http.Client{Jar: jar, CheckRedirect: stopAtRedirectURI, Timeout: 20 * time.Second}

	page, err := c.Get(authorizationURL)
	require.NoError(t, err)
	body, err := io.ReadAll(page.Body)
	_ = page.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, page.StatusCode, "login page: %s", body)

	action := formActionPattern.FindSubmatch(body)
	require.NotNil(t, action, "no login form in Dex's response:\n%s", body)
	loginURL, err := page.Request.URL.Parse(html.UnescapeString(string(action[1])))
	require.NoError(t, err)

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
	require.Equal(t, wantState, redirect.Query().Get("state"), "state must come back unchanged")
	code := redirect.Query().Get("code")
	require.NotEmpty(t, code, "no authorization code in %s", redirect)
	return code
}
