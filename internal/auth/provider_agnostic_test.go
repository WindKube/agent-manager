package auth_test

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/auth"
)

// The ID-token path must know the protocol, not the vendor. A provider-specific
// constant works at run time against its provider, so only a source scan in the
// ordinary `go test ./...` can catch it. Only non-test files are scanned.

// forbiddenNames are things a vendor-neutral verifier never needs to say.
var forbiddenNames = []struct {
	pattern *regexp.Regexp
	why     string
}{
	{
		regexp.MustCompile(`(?i)\b(keycloak|dex|glauth|okta|auth0|onelogin|authentik|zitadel|` +
			`gluu|forgerock|pingfederate|pingidentity|adfs|entra|azuread|cognito)\b`),
		"names an identity provider. Which provider a deployment runs is configuration; " +
			"a verifier that can say the name is a verifier that can grow a branch on it.",
	},
	{
		regexp.MustCompile(`(?i)\brealms?/|/dex\b|\.well-known/openid-configuration/`),
		"names a provider's URL layout. The discovery document publishes every endpoint " +
			"this package needs; deriving one from a path shape is how a swap becomes a rewrite.",
	},
	{
		regexp.MustCompile(`realm_access|resource_access|cognito:|extension_[A-Za-z]`),
		"names a claim only one provider emits. Replacing the provider must not " +
			"change the claims the hub requires, so the hub reads only claims any provider can send.",
	},
	{
		regexp.MustCompile(`(?i)uniquemember|memberuid|uidnumber|objectclass|\bbinddn\b`),
		"names a directory schema. The connector between a provider and its user store is " +
			"the provider's business; this package sees a signed token and nothing behind it.",
	},
}

func TestNothingInTheIDTokenPathNamesAnIdentityProvider(t *testing.T) {
	for _, name := range packageSourceFiles(t) {
		t.Run(name, func(t *testing.T) { requireNoForbiddenName(t, name) })
	}
}

// Also sweep internal/web, where browser-facing URL rewrites are the likeliest
// place for a provider quirk to land; the other assertions stay package-scoped.
func TestNothingInTheWebRoleNamesAnIdentityProviderEither(t *testing.T) {
	for _, name := range sourceFilesIn(t, "../web", "web.go", 5) {
		t.Run(filepath.Base(name), func(t *testing.T) { requireNoForbiddenName(t, name) })
	}
}

func requireNoForbiddenName(t *testing.T, name string) {
	t.Helper()

	raw, err := os.ReadFile(name)
	require.NoError(t, err)

	// Comments are scanned too: a comment naming a vendor means the code was written for it.
	for _, forbidden := range forbiddenNames {
		require.Nilf(t, forbidden.pattern.Find(raw),
			"%s matches %s, which %s", name, forbidden.pattern, forbidden.why)
	}
}

// The discovery path is fixed by OpenID Connect Discovery 1.0, not by a provider.
const specifiedDiscoveryPath = "/.well-known/openid-configuration"

func TestNothingInTheIDTokenPathHardcodesAHostAProviderIsReachedAt(t *testing.T) {
	hostShaped := regexp.MustCompile(`://|\blocalhost\b|\b127\.0\.0\.\d|:\d{2,5}\b`)

	forEachStringLiteral(t, func(t *testing.T, file, value string) {
		if value == specifiedDiscoveryPath || isImportPath(file, value) {
			return
		}
		require.Nilf(t, hostShaped.Find([]byte(value)), "%s holds the host-shaped literal %q.\n\n"+
			"Every URL this package uses comes from the configured issuer or from the discovery "+
			"document it publishes. A literal host or port here is the quirk of one deployment "+
			"compiled in, and it is invisible until the deployment changes.", file, value)
	})
}

func TestNoBranchInTheIDTokenPathTurnsOnAStringOnlyAProviderWouldSet(t *testing.T) {
	// A provider branch must compare against a value identifying the provider, so
	// this package may compare strings only against "".
	forEachFile(t, func(t *testing.T, file *ast.File, fset *token.FileSet, name string) {
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.BinaryExpr:
				if n.Op != token.EQL && n.Op != token.NEQ {
					return true
				}
				for _, operand := range []ast.Expr{n.X, n.Y} {
					requireOnlyEmptyString(t, fset, name, operand)
				}
			case *ast.CaseClause:
				for _, operand := range n.List {
					requireOnlyEmptyString(t, fset, name, operand)
				}
			}
			return true
		})
	})
}

func requireOnlyEmptyString(t *testing.T, fset *token.FileSet, name string, operand ast.Expr) {
	t.Helper()

	lit, ok := operand.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return
	}
	value, err := strconv.Unquote(lit.Value)
	require.NoError(t, err)
	require.Emptyf(t, value, "%s branches on the literal %q at %s.\n\n"+
		"This package may ask whether a configured value is set. It may not ask which value it "+
		"is: that is a provider-specific branch, and it is how the next swap "+
		"stops being a configuration change.", name, value, fset.Position(lit.Pos()))
}

func TestTheClaimsTheHubReadsAreTheStandardOnesEveryProviderCanEmit(t *testing.T) {
	portable := regexp.MustCompile(`^[a-z][a-z_]*$`)

	claims := reflect.TypeFor[auth.Claims]()
	read := make([]string, 0, claims.NumField())
	for i := range claims.NumField() {
		tag, ok := claims.Field(i).Tag.Lookup("json")
		require.Truef(t, ok, "auth.Claims.%s has no json tag, so which claim it reads "+
			"depends on Go's field-name casing rather than on the specification", claims.Field(i).Name)

		name := strings.Split(tag, ",")[0]
		require.Regexpf(t, portable, name, "auth.Claims reads %q. A namespaced or prefixed claim "+
			"name is one provider's dialect, and requiring it of a customer's provider is the "+
			"lock-in", name)
		read = append(read, name)
	}

	require.ElementsMatch(t, []string{"sub", "email", "name", "preferred_username", "groups"}, read,
		"the claim set changed. Adding one is a change to what this project demands of every "+
			"customer's identity provider, so it belongs in the spec before it belongs here")
}

// The lexical checks above miss quirks that name nothing, e.g. stripping an
// "ldap:" prefix from groups, so the last two assertions are behavioural.

func TestTheVerifierReturnsTheClaimsTheTokenCarriedAndNotAVersionOfThem(t *testing.T) {
	idp := newProvider(t)
	ctx := context.Background()

	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:     idp.server.URL,
		ClientID:   "agent-manager",
		HTTPClient: idp.server.Client(),
	})
	require.NoError(t, err)

	// Shapes a well-meaning normalisation would change; group names must reach
	// group_role_map exactly as they arrived.
	groups := []string{
		"ldap:eng-platform", " eng-security ", "Eng-Platform",
		"zz-last", "", "aa-first", "eng-platform", "eng-platform",
	}

	const (
		email    = "  KWiatrzyk@Example.COM "
		fullName = "  Krzysztof   Wiatrzyk  "
		username = "KWiatrzyk"
	)

	got, err := verifier.Verify(ctx, idp.sign(t, idp.key, idp.claims("agent-manager", map[string]any{
		"email":              email,
		"name":               fullName,
		"preferred_username": username,
		"groups":             groups,
	})))
	require.NoError(t, err)

	require.Equal(t, groups, got.Groups,
		"the groups claim came back changed. It is the sole input to group_role_map, so "+
			"a prefix stripped, a value trimmed, a case folded, a duplicate collapsed or an order "+
			"sorted here is this hub deciding what a group name means. That decision is taken for "+
			"one provider, it is invisible to every other assertion in this file, and what it "+
			"changes is which role a person resolves to.")

	require.Equal(t, email, got.Email)
	require.Equal(t, fullName, got.Name)
	require.Equal(t, username, got.PreferredUsername)
	require.Equal(t, localDirectorySubject, got.Subject)
}

// The discovery document is fetched from the configured URL verbatim, with only
// the spec-fixed well-known path appended.
func TestTheDiscoveryDocumentIsFetchedFromTheConfiguredURLVerbatim(t *testing.T) {
	const unreachableIssuer = "https://idp.example.dev"

	for _, tc := range []struct {
		name          string
		basePath      string
		split         bool
		trailingSlash bool
	}{
		{name: "the issuer's own URL", basePath: "/idp"},
		{name: "a discovery URL of its own", basePath: "/metadata", split: true},
		{name: "a discovery URL with a trailing slash", basePath: "/metadata", split: true, trailingSlash: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantPath := tc.basePath + specifiedDiscoveryPath

			var (
				mu    sync.Mutex
				asked []string
				self  string
			)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				asked = append(asked, r.URL.RequestURI())
				base := self
				mu.Unlock()

				if r.URL.RequestURI() != wantPath {
					http.NotFound(w, r)
					return
				}

				advertised := base + tc.basePath
				if tc.split {
					advertised = unreachableIssuer
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer":                                advertised,
					"authorization_endpoint":                base + "/auth",
					"token_endpoint":                        base + "/token",
					"jwks_uri":                              base + "/keys",
					"id_token_signing_alg_values_supported": []string{"RS256"},
				})
			}))
			t.Cleanup(server.Close)

			mu.Lock()
			self = server.URL
			mu.Unlock()

			cfg := auth.VerifierConfig{
				Issuer:     server.URL + tc.basePath,
				ClientID:   "agent-manager",
				HTTPClient: server.Client(),
			}
			if tc.split {
				cfg.Issuer = unreachableIssuer
				cfg.DiscoveryURL = server.URL + tc.basePath
			}
			if tc.trailingSlash {
				cfg.DiscoveryURL += "/"
			}

			_, err := auth.NewVerifier(context.Background(), cfg)

			mu.Lock()
			defer mu.Unlock()

			// Asserted before the error: the request list explains a failure, the error is only a 404.
			require.Equal(t, []string{wantPath}, asked,
				"the process fetched something other than the configured URL plus the path the "+
					"discovery specification fixes. A segment prepended, a query appended or a "+
					"second document fetched is one provider's URL layout compiled in, and "+
					"which provider runs must stay a configuration choice.")
			require.NoError(t, err)
		})
	}
}

func packageSourceFiles(t *testing.T) []string {
	t.Helper()

	return sourceFilesIn(t, ".", "oidc.go", 3)
}

// sourceFilesIn lists the directory so new files are scanned automatically;
// mustContain and atLeast stop a broken filter from passing vacuously.
func sourceFilesIn(t *testing.T, dir, mustContain string, atLeast int) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, filepath.Join(dir, name))
	}

	require.Containsf(t, names, filepath.Join(dir, mustContain), "%s was not scanned", mustContain)
	require.GreaterOrEqual(t, len(names), atLeast)

	return names
}

func forEachFile(t *testing.T, assert func(*testing.T, *ast.File, *token.FileSet, string)) {
	t.Helper()

	for _, name := range packageSourceFiles(t) {
		t.Run(name, func(t *testing.T) {
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
			require.NoError(t, err)
			assert(t, parsed, fset, name)
		})
	}
}

func forEachStringLiteral(t *testing.T, assert func(*testing.T, string, string)) {
	t.Helper()

	forEachFile(t, func(t *testing.T, file *ast.File, _ *token.FileSet, name string) {
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			require.NoError(t, err)
			assert(t, name, value)
			return true
		})
	})
}

// Import paths look host-shaped; they're excluded by identity rather than by
// weakening the pattern, since internal/archcheck already governs imports.
func isImportPath(file, value string) bool {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly|parser.SkipObjectResolution)
	if err != nil {
		return false
	}
	for _, spec := range parsed.Imports {
		if path, err := strconv.Unquote(spec.Path.Value); err == nil && path == value {
			return true
		}
	}
	return false
}
