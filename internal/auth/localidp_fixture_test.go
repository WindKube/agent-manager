// The local identity provider's configuration — the two files under deploy/local
// and the two compose files that point the hub at them — checked against the Go
// constants they all have to agree with. No Docker, no build tag: this runs in
// the ordinary `go test ./...` because the drift it catches is invisible at run
// time.
//
// internal/seed/groups.go states the failure mode in full. The short version:
// when the group names in deploy/local/glauth/glauth.cfg and the group_role_map
// rows the seed writes disagree, nothing fails. Discovery answers, the password
// is accepted, the token carries a `groups` claim, the session row is written,
// and the resolve statement's `group_name = any (i.groups)` matches nothing. The
// operator lands on a working page with no role and no error anywhere. So the
// fixture is parsed and compared rather than annotated with a comment claiming
// it matches.
//
// The compose half is here for the same reason, and it is the same failure. The
// `groups` scope is load-bearing and its absence is silent: measured on the
// shipped stack, the same client against the same directory gets
// `groups=['eng-platform']` when the scope is asked for and no `groups` key at
// all when it is not. So an explicit `AGENT_MANAGER_OIDC_SCOPES` without it
// would produce a working login with no role and no error, and until this file
// read that list nothing did — the integration suite spelled the scopes it
// wanted in a literal of its own, which is precisely how a pinning test stops
// pinning anything.
//
// The live half — that Dex actually emits these names, per user, in a real token
// — is localidp_integration_test.go.
package auth_test

import (
	"os"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"agent-manager/internal/seed"
)

const (
	glauthFixturePath = "../../deploy/local/glauth/glauth.cfg"
	dexFixturePath    = "../../deploy/local/dex/config.yaml"
	composeAppPath    = "../../compose.yaml"
	composeInfraPath  = "../../compose.infra.yaml"
)

// The issuer Dex publishes and the two image versions plan.md pins. Every one of
// them is also written in a compose file, and the tests below are what make that
// a coupling rather than a claim: a comment saying two files agree is worth
// nothing, which this layer has now learned twice.
//
// The issuer is container-reachable on purpose (R2), which is why the integration
// suite reaches Dex on a mapped port and does not let go-oidc discover its own
// endpoints — the discovery document names a host only containers resolve.
const (
	issuer = "http://dex:5556/dex"

	dexImage    = "ghcr.io/dexidp/dex:v2.44.0"
	glauthImage = "glauth/glauth:v2.4.0"
)

// glauthFixture is the subset of glauth.cfg that the coupling turns on. Fields
// absent here (listen addresses, password hashes) are deliberately unasserted —
// they are free to change.
type glauthUser struct {
	Name         string `toml:"name"`
	Mail         string `toml:"mail"`
	PrimaryGroup int    `toml:"primarygroup"`
	Capabilities []struct {
		Action string `toml:"action"`
		Object string `toml:"object"`
	} `toml:"capabilities"`
}

type glauthFixture struct {
	Backend struct {
		BaseDN      string `toml:"baseDN"`
		NameFormat  string `toml:"nameformat"`
		GroupFormat string `toml:"groupformat"`
	} `toml:"backend"`
	Users  []glauthUser `toml:"users"`
	Groups []struct {
		Name      string `toml:"name"`
		GIDNumber int    `toml:"gidnumber"`
	} `toml:"groups"`
}

type dexFixture struct {
	Issuer  string `yaml:"issuer"`
	Storage struct {
		Type string `yaml:"type"`
	} `yaml:"storage"`
	OAuth2 struct {
		SkipApprovalScreen bool `yaml:"skipApprovalScreen"`
	} `yaml:"oauth2"`
	StaticClients []struct {
		ID           string   `yaml:"id"`
		Secret       string   `yaml:"secret"`
		Public       bool     `yaml:"public"`
		RedirectURIs []string `yaml:"redirectURIs"`
	} `yaml:"staticClients"`
	// A map, not a typed struct: the only assertion this file makes about static
	// passwords is that there are none.
	StaticPasswords []map[string]any `yaml:"staticPasswords"`
	Connectors      []struct {
		Type   string `yaml:"type"`
		ID     string `yaml:"id"`
		Config struct {
			Host       string `yaml:"host"`
			BindDN     string `yaml:"bindDN"`
			UserSearch struct {
				BaseDN    string `yaml:"baseDN"`
				Username  string `yaml:"username"`
				IDAttr    string `yaml:"idAttr"`
				EmailAttr string `yaml:"emailAttr"`
				NameAttr  string `yaml:"nameAttr"`
			} `yaml:"userSearch"`
			GroupSearch struct {
				BaseDN       string `yaml:"baseDN"`
				UserMatchers []struct {
					UserAttr  string `yaml:"userAttr"`
					GroupAttr string `yaml:"groupAttr"`
				} `yaml:"userMatchers"`
				NameAttr string `yaml:"nameAttr"`
			} `yaml:"groupSearch"`
		} `yaml:"config"`
	} `yaml:"connectors"`
}

func loadGlauthFixture(t *testing.T) glauthFixture {
	t.Helper()

	raw, err := os.ReadFile(glauthFixturePath)
	require.NoError(t, err)

	var f glauthFixture
	require.NoError(t, toml.Unmarshal(raw, &f))
	return f
}

func loadDexFixture(t *testing.T) dexFixture {
	t.Helper()

	raw, err := os.ReadFile(dexFixturePath)
	require.NoError(t, err)

	var f dexFixture
	require.NoError(t, yaml.Unmarshal(raw, &f))
	return f
}

// The compose files are read as raw YAML rather than through `docker compose
// config`, because what these assertions compare is what the files SAY against
// what the Go constants say, and the ordinary build cannot assume a docker CLI.
// internal/cli/compose_test.go owns the questions only Compose can answer.
func loadComposeOIDCEnv(t *testing.T) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(composeAppPath)
	require.NoError(t, err)

	var doc struct {
		OIDC map[string]string `yaml:"x-oidc"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &doc))
	require.NotEmptyf(t, doc.OIDC, "%s declares no x-oidc anchor, so everything read from it "+
		"below is asserting nothing", composeAppPath)

	return doc.OIDC
}

func loadComposeInfraImages(t *testing.T) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(composeInfraPath)
	require.NoError(t, err)

	var doc struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &doc))
	require.NotEmptyf(t, doc.Services, "%s declares no services", composeInfraPath)

	images := make(map[string]string, len(doc.Services))
	for name, service := range doc.Services {
		images[name] = service.Image
	}

	return images
}

// composeOIDCScopes is the scope list the shipped stack asks for, read from the
// one file it is written in so that the integration suite can drive its logins
// with it instead of with a literal of its own.
func composeOIDCScopes(t *testing.T) string {
	t.Helper()

	return loadComposeOIDCEnv(t)["AGENT_MANAGER_OIDC_SCOPES"]
}

func TestTheGlauthFixtureSpellsTheGroupNamesTheSeedMapsToRoles(t *testing.T) {
	f := loadGlauthFixture(t)

	byGID := map[int]string{}
	names := map[string]bool{}
	for _, g := range f.Groups {
		byGID[g.GIDNumber] = g.Name
		names[g.Name] = true
	}

	for _, want := range []string{seed.GroupEngPlatform, seed.GroupEngSecurity} {
		require.Truef(t, names[want],
			"%s defines no group named %q, which internal/seed/groups.go maps to a role. "+
				"Dex passes glauth's group names through into the `groups` claim verbatim, so a "+
				"group missing here resolves to no role and reports nothing.",
			glauthFixturePath, want)
	}

	// The users, their mails and the group each one resolves a role through, all
	// read off seed.DirectoryUsers rather than spelled a second time. The mail
	// matters as much as the group: Dex's user search is `username: mail`, so the
	// mail is the login, and internal/seed asserts that no seeded identity row
	// collides with these addresses.
	for _, want := range seed.DirectoryUsers {
		t.Run(want.Username, func(t *testing.T) {
			var found bool
			for _, u := range f.Users {
				if u.Name != want.Username {
					continue
				}
				found = true
				require.Equal(t, want.Email, u.Mail,
					"the login Dex searches on. seed.DirectoryUsers says %q", want.Email)
				require.Equal(t, want.Group, byGID[u.PrimaryGroup],
					"%s's primarygroup gid %d names group %q, but seed.DirectoryUsers resolves "+
						"this user's role through %q",
					want.Username, u.PrimaryGroup, byGID[u.PrimaryGroup], want.Group)
			}
			require.Truef(t, found, "%s defines no user named %q", glauthFixturePath, want.Username)
		})
	}
}

// The three attribute names in R1 that each cost an iteration to find. Every
// wrong value here fails somewhere else entirely, so they are pinned rather than
// left to a reader's judgement about which spelling looks more natural.
func TestTheDexConnectorUsesTheAttributeNamesGlauthActuallyReturns(t *testing.T) {
	f := loadDexFixture(t)

	require.Len(t, f.Connectors, 1, "the LDAP connector is the only mechanism that yields groups")
	c := f.Connectors[0].Config
	require.Equal(t, "ldap", f.Connectors[0].Type)

	require.Equal(t, "uidNumber", c.UserSearch.IDAttr,
		"camelCase. glauth's attribute names are camelCase and Dex's lookup is case-sensitive; "+
			"`uidnumber` fails with `missing following required attribute(s): [\"uidnumber\"]`, "+
			"which reads like a missing directory field rather than a spelling mistake")

	require.Len(t, c.GroupSearch.UserMatchers, 1)
	require.Equal(t, "DN", c.GroupSearch.UserMatchers[0].UserAttr)
	require.Equal(t, "uniqueMember", c.GroupSearch.UserMatchers[0].GroupAttr,
		"glauth answers a group search with full member DNs in uniqueMember. The textbook POSIX "+
			"pairing, memberUid against the username, matches nothing and produces a SUCCESSFUL "+
			"login carrying no groups — the silent claim loss this feature exists to prevent")

	require.Equal(t, "ou", c.GroupSearch.NameAttr,
		"glauth's group entries carry no cn at all, so `cn` fails with `group entity "+
			"\"ou=eng-platform,…\" missing required attribute \"cn\"` AFTER the group was found, "+
			"which is misleading because the search itself worked")

	// The login. Anything else here and the two mails in glauth.cfg stop being
	// credentials, and seed.DirectoryEmail* stops describing anything.
	require.Equal(t, "mail", c.UserSearch.Username)
	require.Equal(t, "mail", c.UserSearch.EmailAttr)
}

// A `groups:` key on a staticPasswords entry is accepted at boot with no warning,
// logged nowhere, and silently ignored — 001's R6 measured it and 003's R1
// re-measured it on v2.44.0. The cheapest way to keep someone from reaching for
// it is to have no staticPasswords block to add it to.
func TestTheDexFixtureDefinesNoStaticPasswords(t *testing.T) {
	require.Empty(t, loadDexFixture(t).StaticPasswords)
}

// Dex's bindDN is assembled by hand out of four things — glauth's nameformat,
// groupformat and baseDN, plus the bind account's primary group — and a wrong
// bind fails with an HTTP 500 on login that names none of them.
//
// The DNs glauth actually SERVES interpose an ou=users component:
// cn=kwiatrzyk,ou=eng-platform,ou=users,dc=example,dc=dev, as Dex's own error
// messages show. Its bind handler is lenient about that component — both
// spellings of the service account's DN authenticate, measured 2026-08-31 — which
// is why this asserts the parts rather than one exact string. Do not "correct"
// the bindDN in either direction expecting a behaviour change; there isn't one.
func TestTheDexBindDNNamesTheBindAccountGlauthDefines(t *testing.T) {
	g := loadGlauthFixture(t)
	d := loadDexFixture(t)

	require.Equal(t, "dc=example,dc=dev", g.Backend.BaseDN)
	require.Equal(t, "cn", g.Backend.NameFormat)
	require.Equal(t, "ou", g.Backend.GroupFormat)
	require.Equal(t, g.Backend.BaseDN, d.Connectors[0].Config.UserSearch.BaseDN)
	require.Equal(t, g.Backend.BaseDN, d.Connectors[0].Config.GroupSearch.BaseDN)

	byGID := map[int]string{}
	for _, grp := range g.Groups {
		byGID[grp.GIDNumber] = grp.Name
	}

	bindDN := d.Connectors[0].Config.BindDN
	require.True(t, strings.HasSuffix(bindDN, ","+g.Backend.BaseDN),
		"%q does not sit under glauth's baseDN %q", bindDN, g.Backend.BaseDN)

	var bind *glauthUser
	for i, u := range g.Users {
		if !strings.HasPrefix(bindDN, g.Backend.NameFormat+"="+u.Name+",") {
			continue
		}
		require.Containsf(t, bindDN, g.Backend.GroupFormat+"="+byGID[u.PrimaryGroup]+",",
			"%q names user %q, whose primary group is %q", bindDN, u.Name, byGID[u.PrimaryGroup])
		bind = &g.Users[i]
	}
	require.NotNilf(t, bind, "%s binds as %q, and %s defines no such user",
		dexFixturePath, bindDN, glauthFixturePath)

	var canSearch bool
	for _, capability := range bind.Capabilities {
		canSearch = canSearch || capability.Action == "search"
	}
	require.True(t, canSearch, "Dex's bind account must be able to search the directory")

	// No mail, so this account can never authenticate a person and can never
	// collide with a seeded identity row — the user search is `username: mail`.
	require.Empty(t, bind.Mail, "the bind account must not be a login")
}

// The reverse of the Keycloak arrangement this replaces, and the reason it is the
// reverse is worth a test rather than a comment: Dex ignores the request Host
// entirely, so a browser-reachable issuer would publish a token_endpoint and a
// jwks_uri naming a host no container can resolve (R2).
func TestTheDexIssuerIsTheContainerReachableURL(t *testing.T) {
	f := loadDexFixture(t)

	require.Equal(t, issuer, f.Issuer)
	require.Equal(t, "memory", f.Storage.Type)
	require.True(t, f.OAuth2.SkipApprovalScreen)

	byID := map[string]int{}
	for i, c := range f.StaticClients {
		byID[c.ID] = i
	}

	confidential, ok := byID["agent-manager"]
	require.True(t, ok, "the web and api roles' client")
	require.NotEmpty(t, f.StaticClients[confidential].Secret)
	require.False(t, f.StaticClients[confidential].Public)
	require.Contains(t, f.StaticClients[confidential].RedirectURIs, "http://localhost:8080/auth/callback")

	cli, ok := byID["agent-manager-cli"]
	require.True(t, ok, "the device-flow client")
	require.True(t, f.StaticClients[cli].Public, "the CLI ships no secret")
	require.Empty(t, f.StaticClients[cli].Secret)
}

// The scope list, which is the one piece of this configuration that fails
// silently in both directions: Dex emits `groups` only for a client that asked
// for it, and a client that asks for a scope the provider does not know is not
// refused. So dropping `groups` from AGENT_MANAGER_OIDC_SCOPES yields a signed
// token, a written session, a resolved identity and no role — measured, on the
// shipped stack, same client and same directory. Nothing in the repository read
// this list until now; the integration suite hard-coded the scopes it wanted.
func TestTheComposeStackAsksForTheGroupsScope(t *testing.T) {
	scopes := strings.Fields(composeOIDCScopes(t))

	require.Contains(t, scopes, "groups",
		"%s must request `groups`, because it is the sole input to group_role_map (FR-101) "+
			"and the only claim in the token with authorisation weight. Without the scope the "+
			"login still succeeds and the claim is simply absent, which is the hardest failure "+
			"in this stack to diagnose — internal/seed/groups.go says why", composeAppPath)
	require.Contains(t, scopes, "openid", "without it this is not an OpenID Connect request at all")
	require.Contains(t, scopes, "email",
		"the email is the login the directory searches on and the identity row's key")
}

// The issuer is written twice, because the two files are read by different things
// — Dex mints tokens from its own, the roles check the `iss` claim against
// compose's — and a comment promising the two agree is what this file exists to
// replace. The two clauses after it are what make the agreement mean the split R2
// measured rather than a coincidence.
func TestTheComposeStackAndTheDexFixtureNameTheSameIssuer(t *testing.T) {
	oidc := loadComposeOIDCEnv(t)

	require.Equal(t, loadDexFixture(t).Issuer, oidc["AGENT_MANAGER_OIDC_ISSUER"],
		"the `iss` claim is checked against AGENT_MANAGER_OIDC_ISSUER and minted from Dex's "+
			"own `issuer`, so a difference here refuses every token the local stack issues")

	// The browser override exists because the issuer above is container-reachable
	// and a browser cannot resolve it (R2). If the two were equal the override
	// would be dead configuration, and the split it documents would be gone.
	browser := oidc["AGENT_MANAGER_OIDC_BROWSER_BASE_URL"]
	require.NotEmpty(t, browser, "the browser leg has no host it can reach without this")
	require.NotEqual(t, oidc["AGENT_MANAGER_OIDC_ISSUER"], browser,
		"equal means the split R2 measured is not being made, and one of the two legs is wrong")

	require.Empty(t, oidc["AGENT_MANAGER_OIDC_DISCOVERY_URL"],
		"the local provider serves discovery from the URL its issuer names, so setting this "+
			"would put the local stack back on the split-metadata path kept for real providers")
}

// The versions every measurement in research.md was taken against. They are
// pinned as constants because the integration suite pulls them and charges the
// discovery budget to them; compose.infra.yaml is what actually runs. If the two
// drift, the numbers in research.md stop describing the stack.
func TestTheComposeStackRunsTheImageVersionsTheMeasurementsDescribe(t *testing.T) {
	images := loadComposeInfraImages(t)

	require.Equal(t, dexImage, images["dex"])
	require.Equal(t, glauthImage, images["glauth"])
}
