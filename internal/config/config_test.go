package config

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// The credential boundary is a property of the type, so it is tested as one.
// Principle II: web must not even be able to read a datastore credential.
func TestWebHasNoDatastoreCredentialFields(t *testing.T) {
	forbidden := []string{"DatabaseURL", "RiverDatabaseURL", "BlobURL"}
	typ := reflect.TypeOf(Web{})

	for _, name := range forbidden {
		_, found := typ.FieldByName(name)
		require.Falsef(t, found, "config.Web must not carry %s — that is the credential boundary, not an omission", name)
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
