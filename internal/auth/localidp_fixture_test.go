// Checks the local IdP's config files (deploy/local, compose) against the Go
// constants they must agree with. Drift here is silent at run time: mismatched
// group names or a missing `groups` scope give a working login with no role.
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

// The issuer is container-reachable, so the integration suite reaches Dex on a
// mapped port instead of letting go-oidc discover its endpoints.
const (
	issuer = "http://dex:5556/dex"

	dexImage    = "ghcr.io/dexidp/dex:v2.44.0"
	glauthImage = "glauth/glauth:v2.4.0"
)

type glauthUser struct {
	Name         string `toml:"name"`
	Mail         string `toml:"mail"`
	PrimaryGroup int    `toml:"primarygroup"`
	OtherGroups  []int  `toml:"othergroups"`
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

// Raw YAML rather than `docker compose config`: the ordinary build can't assume a docker CLI.
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

	// The unmapped group must exist and map to nothing so the no-role screen is reachable.
	require.Truef(t, names[seed.GroupUnmapped],
		"%s defines no group named %q, so the directory user who is supposed to hold no role "+
			"either fails to log in or arrives with no groups at all — which is the silent "+
			"claim loss this fixture exists to rule out, not the no-role state",
		glauthFixturePath, seed.GroupUnmapped)
	require.Empty(t, seed.RoleOf(seed.GroupUnmapped),
		"internal/seed now maps %q to a role, so nobody in the local directory reaches the "+
			"no-role screen", seed.GroupUnmapped)

	// The mail is the login (Dex searches `username: mail`), so it matters as much as the group.
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

				// A wrong secondary gid fails nowhere; it only makes the eng-all profile unreachable.
				secondary := make([]string, 0, len(u.OtherGroups))
				for _, gid := range u.OtherGroups {
					secondary = append(secondary, byGID[gid])
				}
				if want.Shared == "" {
					require.Emptyf(t, secondary,
						"seed.DirectoryUsers puts %s in no second group, and %s carries %v. For "+
							"the unmapped user that is not cosmetic: every group in this fixture "+
							"except theirs maps to a role",
						want.Username, glauthFixturePath, secondary)
					return
				}
				require.Containsf(t, secondary, want.Shared,
					"%s's othergroups %v do not include %q, which seed.DirectoryUsers says they "+
						"share with the other role-holder", want.Username, secondary, want.Shared)
			}
			require.Truef(t, found, "%s defines no user named %q", glauthFixturePath, want.Username)
		})
	}
}

// Each of these attribute spellings fails somewhere unrelated when wrong.
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

	require.Equal(t, "mail", c.UserSearch.Username)
	require.Equal(t, "mail", c.UserSearch.EmailAttr)
}

// Dex silently ignores `groups:` on staticPasswords entries, so the fixture has
// no staticPasswords block to add it to.
func TestTheDexFixtureDefinesNoStaticPasswords(t *testing.T) {
	require.Empty(t, loadDexFixture(t).StaticPasswords)
}

// A wrong bindDN fails login with a bare HTTP 500. glauth accepts the DN with or
// without its served ou=users component, so this asserts the parts, not one string.
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

	// No mail, so the bind account can never be a login (the user search is on mail).
	require.Empty(t, bind.Mail, "the bind account must not be a login")
}

// Dex ignores the request Host, so a browser-reachable issuer would publish
// endpoints no container can resolve.
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

// Dropping `groups` from the scopes still yields a working login, just with no role.
func TestTheComposeStackAsksForTheGroupsScope(t *testing.T) {
	scopes := strings.Fields(composeOIDCScopes(t))

	require.Contains(t, scopes, "groups",
		"%s must request `groups`, because it is the sole input to group_role_map "+
			"and the only claim in the token with authorisation weight. Without the scope the "+
			"login still succeeds and the claim is simply absent, which is the hardest failure "+
			"in this stack to diagnose — internal/seed/groups.go says why", composeAppPath)
	require.Contains(t, scopes, "openid", "without it this is not an OpenID Connect request at all")
	require.Contains(t, scopes, "email",
		"the email is the login the directory searches on and the identity row's key")
}

func TestTheComposeStackAndTheDexFixtureNameTheSameIssuer(t *testing.T) {
	oidc := loadComposeOIDCEnv(t)

	require.Equal(t, loadDexFixture(t).Issuer, oidc["AGENT_MANAGER_OIDC_ISSUER"],
		"the `iss` claim is checked against AGENT_MANAGER_OIDC_ISSUER and minted from Dex's "+
			"own `issuer`, so a difference here refuses every token the local stack issues")

	// The browser override exists because a browser can't resolve the container-reachable issuer.
	browser := oidc["AGENT_MANAGER_OIDC_BROWSER_BASE_URL"]
	require.NotEmpty(t, browser, "the browser leg has no host it can reach without this")
	require.NotEqual(t, oidc["AGENT_MANAGER_OIDC_ISSUER"], browser,
		"equal means the split R2 measured is not being made, and one of the two legs is wrong")

	require.Empty(t, oidc["AGENT_MANAGER_OIDC_DISCOVERY_URL"],
		"the local provider serves discovery from the URL its issuer names, so setting this "+
			"would put the local stack back on the split-metadata path kept for real providers")
}

// The image versions the integration suite pulls must match what compose.infra.yaml runs.
func TestTheComposeStackRunsTheImageVersionsTheMeasurementsDescribe(t *testing.T) {
	images := loadComposeInfraImages(t)

	require.Equal(t, dexImage, images["dex"])
	require.Equal(t, glauthImage, images["glauth"])
}
