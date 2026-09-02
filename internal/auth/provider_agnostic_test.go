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

// T025 — FR-105 and FR-107: the ID-token path knows the protocol and not the
// vendor. This is the property that made swapping the local provider a change to
// two configuration files rather than a change to this package, and it is worth a
// test rather than a habit because every violation of it is easy, local and
// individually reasonable.
//
// Untagged and container-free on purpose. A provider-specific constant does not
// fail anywhere at run time — it works perfectly against the provider it was
// written for — so the only place it can be caught is the source, and it has to
// be caught in the ordinary `go test ./...` that a change to this package runs.
//
// Only NON-test files are scanned. The tests next door name images, hostnames and
// LDAP attribute spellings by necessity: their whole job is to stand up one
// specific provider and prove the configuration this repository ships is the
// working one. That is the correct place for a vendor name; twelve lines away, in
// the code, it is a defect.

// forbiddenNames are things a vendor-neutral verifier cannot need to say.
//
// Each entry says what a match would mean, because a failure here is not obvious:
// the code will be working when it fails, against whichever provider prompted it.
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
		"names a claim only one provider emits. FR-107: replacing the provider must not " +
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

// The same list over internal/web's own source, and only this list.
//
// That package is where the next provider-specific quirk is most likely to land:
// the browser-facing base URL is rewritten there, and a rewrite assuming a path
// prefix, a port or a `Host` behaviour is exactly the shape this list names. It
// holds no auth code yet, which is what makes the sweep cheap now and expensive
// to retrofit later.
//
// The other three assertions stay scoped to this package on purpose. A web server
// legitimately holds a default listen address and legitimately branches on its own
// query parameters, so extending those here would mean loosening them, and a
// loosened assertion buys less than a narrow one that still bites.
func TestNothingInTheWebRoleNamesAnIdentityProviderEither(t *testing.T) {
	for _, name := range sourceFilesIn(t, "../web", "web.go", 5) {
		t.Run(filepath.Base(name), func(t *testing.T) { requireNoForbiddenName(t, name) })
	}
}

func requireNoForbiddenName(t *testing.T, name string) {
	t.Helper()

	raw, err := os.ReadFile(name)
	require.NoError(t, err)

	// The whole file, comments included. A comment that has to name a vendor is
	// evidence the code below it was written for that vendor — and the comment is
	// what a reader believes, so it is part of the property.
	for _, forbidden := range forbiddenNames {
		require.Nilf(t, forbidden.pattern.Find(raw),
			"%s matches %s, which %s", name, forbidden.pattern, forbidden.why)
	}
}

// The one URL-shaped literal this package is allowed to hold: the discovery path
// is fixed by OpenID Connect Discovery 1.0, not by any provider, and go-oidc only
// appends it for the single-URL case.
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
	// The structural form of FR-105. A branch on which provider is running has to
	// compare something to a value that identifies it, so the rule is that this
	// package compares strings only against emptiness: `is this configured?`, never
	// `is this that provider?`. It costs nothing today — every comparison in the
	// package is already against "" — and it is the assertion a word list cannot
	// make, because the next provider quirk will be spelled in a word nobody
	// thought to forbid.
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
		"is: that is the provider-specific branch FR-105 forbids, and it is how the next swap "+
		"stops being a configuration change.", name, value, fset.Position(lit.Pos()))
}

// FR-107 in one assertion: this is the entire set of claims the hub asks a real
// production provider for. It is short, and every name in it is either registered
// in the OIDC core specification or, in the case of `groups`, the de-facto
// spelling every provider that emits group membership at all uses. Nothing here
// is namespaced, prefixed or vendor-scoped, which is what makes the set portable.
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
			"lock-in FR-107 forbids", name)
		read = append(read, name)
	}

	require.ElementsMatch(t, []string{"sub", "email", "name", "preferred_username", "groups"}, read,
		"the claim set changed. Adding one is a change to what this project demands of every "+
			"customer's identity provider, so it belongs in the spec before it belongs here")
}

// Everything above is lexical: it reads the source and objects to a word, a host,
// a comparison or a claim name. That catches a lot, and it is not enough — a
// provider quirk that spells none of those is invisible to all four. Two that are:
//
//	for i, g := range claims.Groups {
//	    claims.Groups[i] = strings.TrimPrefix(g, "ldap:")
//	}
//
// names no vendor, holds no host-shaped literal, compares no string and changes no
// json tag, while rewriting the value of the only claim with authorisation weight;
// and prepending a segment to the discovery path slips past the "provider URL
// layout" pattern, which matches a segment AFTER the well-known path and not one
// before it.
//
// So the last two assertions are behavioural. Heuristics are what let those
// through, and another heuristic would only move the hole.

// What the verifier returns is what the token carried.
func TestTheVerifierReturnsTheClaimsTheTokenCarriedAndNotAVersionOfThem(t *testing.T) {
	idp := newProvider(t)
	ctx := context.Background()

	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:     idp.server.URL,
		ClientID:   "agent-manager",
		HTTPClient: idp.server.Client(),
	})
	require.NoError(t, err)

	// Shaped to catch a transformation rather than to look realistic: a connector
	// prefix to strip, surrounding space to trim, a case to fold, a duplicate to
	// collapse, an empty value to drop, and an order that is not sorted. Not every
	// one of these is a shape some provider emits; each is a shape a well-meaning
	// normalisation would change, and the hub's job is to hand all of them to
	// group_role_map exactly as they arrived. The mapping rows are the only place a
	// group name is interpreted.
	groups := []string{
		"ldap:eng-platform", " eng-security ", "Eng-Platform",
		"zz-last", "", "aa-first", "eng-platform", "eng-platform",
	}

	// Untidy on purpose too. A verifier that trims or lowercases a display claim
	// is doing the same thing to a value it does not own.
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
		"the groups claim came back changed. It is the sole input to group_role_map (FR-040), so "+
			"a prefix stripped, a value trimmed, a case folded, a duplicate collapsed or an order "+
			"sorted here is this hub deciding what a group name means. That decision is taken for "+
			"one provider, it is invisible to every other assertion in this file, and what it "+
			"changes is which role a person resolves to.")

	require.Equal(t, email, got.Email)
	require.Equal(t, fullName, got.Name)
	require.Equal(t, username, got.PreferredUsername)
	require.Equal(t, localDirectorySubject, got.Subject)
}

// And the discovery document is fetched from the configured URL as configured:
// nothing prepended to its path, nothing interpolated into it, and the only thing
// appended the path OpenID Connect Discovery 1.0 fixes.
//
// A server that answers that path and nothing else, plus a record of what was
// actually asked for, is what makes this behavioural rather than another pattern.
func TestTheDiscoveryDocumentIsFetchedFromTheConfiguredURLVerbatim(t *testing.T) {
	// Named by the configuration and reachable by nothing, which is the whole
	// point of the split: only the discovery URL may be dialled.
	const unreachableIssuer = "https://idp.example.dev"

	for _, tc := range []struct {
		name     string
		basePath string
		// split configures Issuer and DiscoveryURL separately — the real-provider
		// case (FR-106), and the only one whose fetch this package performs itself.
		split bool
		// trailingSlash puts one on the configured URL. Trimming it is the single
		// transformation of a configured value this package makes, so it is pinned
		// rather than left to be discovered by whoever writes the next one.
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

			// Asserted before the error, because when this is what broke, the list of
			// requests is the explanation and the error is only a 404.
			require.Equal(t, []string{wantPath}, asked,
				"the process fetched something other than the configured URL plus the path the "+
					"discovery specification fixes. A segment prepended, a query appended or a "+
					"second document fetched is one provider's URL layout compiled in, and FR-105 "+
					"makes which provider runs a configuration choice.")
			require.NoError(t, err)
		})
	}
}

func packageSourceFiles(t *testing.T) []string {
	t.Helper()

	return sourceFilesIn(t, ".", "oidc.go", 3)
}

// sourceFilesIn is every non-test Go file directly in dir, read from the
// directory rather than from a list, so a file added later is scanned without
// anybody remembering to add it here.
//
// mustContain and atLeast are the guard against the opposite failure: a broken
// filter, a moved file or a renamed directory would otherwise turn every
// assertion built on this into a vacuous pass over nothing.
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

// An import path is a string literal in the AST and looks host-shaped to any
// pattern that matches a dotted name, so it is excluded by identity rather than by
// weakening the pattern: an import is already governed by internal/archcheck,
// which walks the real import graph.
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
