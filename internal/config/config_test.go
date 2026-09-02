package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The credential boundary is a property of the type, so it is tested as one.
// Principle II: web must not even be able to read a datastore credential.
//
// The whole type is walked, embedded blocks included, so a field added to
// Observability or OIDC is caught as well as one added to Web itself. Both the
// field name and the variable it reads are checked, because the boundary is the
// variable: a field called Store tagged `env:"DATABASE_URL"` hands web the
// credential while passing any check that only looks at identifiers.
func TestWebHasNoDatastoreCredentialFields(t *testing.T) {
	forbiddenFields := []string{"DatabaseURL", "RiverDatabaseURL", "BlobURL"}
	forbiddenVars := []string{"DATABASE_URL", "RIVER_DATABASE_URL", "BLOB_URL"}

	pending := []reflect.Type{reflect.TypeOf(Web{})}
	for len(pending) > 0 {
		typ := pending[0]
		pending = pending[1:]

		for i := range typ.NumField() {
			field := typ.Field(i)
			if field.Anonymous && field.Type.Kind() == reflect.Struct {
				pending = append(pending, field.Type)
				continue
			}

			require.NotContainsf(t, forbiddenFields, field.Name,
				"config.Web must not carry %s — that is the credential boundary, not an omission", field.Name)

			variable := strings.Split(field.Tag.Get("env"), ",")[0]
			require.NotContainsf(t, forbiddenVars, variable,
				"config.Web must not read AGENT_MANAGER_%s (as %s) — web reaches data only through the api role", variable, field.Name)
		}
	}
}

func TestScannerAndFetcherCarryTheirOwnCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"Fetcher", reflect.TypeOf(Fetcher{})},
		{"Scanner", reflect.TypeOf(Scanner{})},
		{"API", reflect.TypeOf(API{})},
	} {
		for _, field := range []string{"DatabaseURL", "BlobURL"} {
			_, found := tc.typ.FieldByName(field)
			require.Truef(t, found, "%s needs %s", tc.name, field)
		}
	}
}

// The mint secret is the one value two roles must hold. If their tags drift
// apart, both roles start, both look correctly configured, and every sign-in
// fails at the mint — so the two tags are asserted to be the same variable.
func TestBothRolesReadTheSessionMintSecretFromOneVariable(t *testing.T) {
	api, found := reflect.TypeOf(API{}).FieldByName("SessionMintSecret")
	require.True(t, found, "config.API must hold the session mint secret — it verifies it")
	web, found := reflect.TypeOf(Web{}).FieldByName("SessionMintSecret")
	require.True(t, found, "config.Web must hold the session mint secret — it presents it")

	require.Equal(t, "SESSION_MINT_SECRET", api.Tag.Get("env"))
	require.Equal(t, api.Tag.Get("env"), web.Tag.Get("env"))
}

// An unset secret is refused at the mint, not at startup: a missing
// web-integration secret must not also take down the reads, the health endpoint
// and the device flow. That contract is only meaningful if an empty secret
// reaches the mint, so loading without one has to succeed.
func TestTheSessionMintSecretHasNoDefaultAndDoesNotStopARoleStarting(t *testing.T) {
	t.Setenv("AGENT_MANAGER_API_BASE_URL", "http://api:8081")
	t.Setenv("AGENT_MANAGER_DATABASE_URL", "postgres://app/agent_manager")
	t.Setenv("AGENT_MANAGER_RIVER_DATABASE_URL", "postgres://queue/agent_manager_queue")
	t.Setenv("AGENT_MANAGER_BLOB_URL", "mem://")

	web, err := Load[Web]()
	require.NoError(t, err)
	require.Empty(t, web.SessionMintSecret)

	api, err := Load[API]()
	require.NoError(t, err)
	require.Empty(t, api.SessionMintSecret)
}

// FR-119: the hint is stated or it is off. Nothing infers it.
func TestTheDevelopmentCredentialHintIsOffUnlessItIsAsked(t *testing.T) {
	t.Setenv("AGENT_MANAGER_API_BASE_URL", "http://api:8081")
	t.Setenv("AGENT_MANAGER_OIDC_ISSUER", "http://localhost:5556/dex")

	cfg, err := Load[Web]()
	require.NoError(t, err)
	require.False(t, cfg.DevCredentialHint, "a local issuer must not switch the credential hint on")

	t.Setenv("AGENT_MANAGER_WEB_DEV_CREDENTIAL_HINT", "true")

	cfg, err = Load[Web]()
	require.NoError(t, err)
	require.True(t, cfg.DevCredentialHint)
}

func TestTheBrowserBaseURLIsOptionalAndEmptyMeansTheIssuerIsBrowserReachable(t *testing.T) {
	t.Setenv("AGENT_MANAGER_API_BASE_URL", "http://api:8081")

	cfg, err := Load[Web]()
	require.NoError(t, err)
	require.Empty(t, cfg.BrowserBaseURL)

	t.Setenv("AGENT_MANAGER_OIDC_BROWSER_BASE_URL", "http://localhost:5556/dex")

	cfg, err = Load[Web]()
	require.NoError(t, err)
	require.Equal(t, "http://localhost:5556/dex", cfg.BrowserBaseURL)
}

func TestLoadReadsPrefixedEnvironment(t *testing.T) {
	t.Setenv("AGENT_MANAGER_API_BASE_URL", "http://api:8081")
	t.Setenv("AGENT_MANAGER_LOG_LEVEL", "debug")

	cfg, err := Load[Web]()
	require.NoError(t, err)
	require.Equal(t, "http://api:8081", cfg.APIBaseURL)
	require.Equal(t, "debug", cfg.LogLevel)
	require.Equal(t, ":8080", cfg.Addr)
}

func TestLoadFailsWithoutRequiredCredential(t *testing.T) {
	_, err := Load[Web]()
	require.Error(t, err)
}
