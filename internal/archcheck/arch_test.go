// Package archcheck enforces the import boundaries that express this project's
// security model. An env-var boundary alone erodes the first time someone "just
// needs one query", so the boundary is also compiled.
package archcheck

import (
	"go/ast"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

const module = "agent-manager"

type rule struct {
	// name is what the failure message calls this boundary.
	name string
	// why explains the consequence of breaking it, so a failure teaches.
	why string
	// scope matches the packages the rule governs.
	scope func(pkgPath string) bool
	// forbidden reports whether an import is illegal inside scope.
	forbidden func(importPath string) bool
}

var rules = []rule{
	{
		name: "web holds no datastore credential",
		why: "constitution principle II: serve web reaches data only through serve api. " +
			"Importing the store or the blob package means the role links code that needs a " +
			"credential it is deliberately never given.",
		scope: under("internal/web"),
		forbidden: anyOf(
			under(module+"/internal/store"),
			under(module+"/internal/blob"),
			exact("github.com/uptrace/bun"),
			under("github.com/jackc/pgx"),
			under("gocloud.dev/blob"),
		),
	},
	{
		name: "domain is pure",
		why: "internal/domain holds entities and rules with no I/O. A dependency on the store, " +
			"the blob client or the fetcher makes the rules untestable without infrastructure.",
		scope: under("internal/domain"),
		forbidden: anyOf(
			under(module+"/internal/store"),
			under(module+"/internal/blob"),
			under(module+"/internal/fetch"),
			under(module+"/internal/api"),
			under(module+"/internal/web"),
			exact("database/sql"),
			exact("net/http"),
		),
	},
	{
		name: "web imports only its own tree, the api client and the domain",
		why: "task T033. The web role's door to data is internal/apiclient (constitution " +
			"principle V: generated, never hand-copied). An import of any other first-party " +
			"package is how a role that must hold no datastore credential acquires one by " +
			"transitive dependency — and a transitive acquisition is invisible in the role's " +
			"own env-var struct. internal/logging is allowed because FR-059 requires every " +
			"role to emit correlated structured logs and a second logging setup would be worse.",
		scope:     under("internal/web"),
		forbidden: firstPartyOutside(webMayImport),
	},
	{
		name: "datastore access is confined to the roles that hold its credential",
		why: "task T033 and constitution principle II. This rule is stated as an allowlist so " +
			"it fails CLOSED: a package added tomorrow cannot reach the store or the bucket " +
			"until it is named here, with a reason. A missing grant fails the first time the " +
			"code runs; an excess one produces no error anywhere, ever, which is why the " +
			"boundary is a list rather than a habit.",
		scope: firstPartyOutsideScope(mayTouchDatastore),
		forbidden: anyOf(
			under(module+"/internal/store"),
			under(module+"/internal/blob"),
			exact("github.com/uptrace/bun"),
			under("github.com/jackc/pgx"),
			under("gocloud.dev/blob"),
		),
	},
	{
		name: "the scanner never executes bundle content",
		why: "constitution principle III and FR-021: static analysis only. os/exec in the scan " +
			"tree is the exact defect that requirement exists to prevent.",
		scope:     under("internal/scan"),
		forbidden: anyOf(exact("os/exec"), exact("plugin"), exact("net/http")),
	},
}

// webMayImport is every first-party package internal/web is allowed to import.
// Each entry carries the reason it is there; anything absent is refused.
var webMayImport = []func(string) bool{
	// The web role's only door to data (constitution principle V).
	under(module + "/internal/apiclient"),
	// Entities and rules, which internal/domain keeps pure by its own rule above.
	under(module + "/internal/domain"),
	// FR-059: a correlation id in every log line, from one logging setup.
	under(module + "/internal/logging"),
	// Its own view models, fixtures and templ components.
	under(module + "/internal/web"),
}

// mayTouchDatastore is every package allowed to link the store, the bucket or a
// database driver, with the reason each one needs it.
var mayTouchDatastore = []func(string) bool{
	// Owns the relational schema and mediates every mutation.
	under("internal/api"),
	// Sessions and the group-to-role map are rows the api reads through it.
	under("internal/auth"),
	// The role bootstraps: runAPI and runWorker are where a connection is opened.
	under("internal/cli"),
	// The outbox rows and the relay that drains them (R5).
	under("internal/outbox"),
	// The one-shot that loads the representative dataset (FR-057). It stands in
	// for the fetcher as well as the api: a seeded version has to have bytes
	// behind its object_key, so this is the only package besides internal/worker
	// that holds the bucket's writer half.
	under("internal/seed"),
	// The store and the bucket themselves.
	under("internal/store"),
	under("internal/blob"),
	// `worker fetcher` is the only role that may write bundle bytes; `worker
	// scanner` reads them and writes verdicts.
	under("internal/worker"),
}

// firstPartyOutside forbids any first-party import not matched by the allowlist,
// and permits every stdlib and third-party import.
func firstPartyOutside(allowed []func(string) bool) func(string) bool {
	return func(importPath string) bool {
		if !strings.HasPrefix(importPath, module+"/") {
			return false
		}
		return !anyOf(allowed...)(importPath)
	}
}

// firstPartyOutsideScope selects every package in this module except the ones the
// allowlist names.
func firstPartyOutsideScope(allowed []func(string) bool) func(string) bool {
	return func(pkgPath string) bool { return !anyOf(allowed...)(pkgPath) }
}

func TestImportBoundaries(t *testing.T) {
	loaded, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedImports}, module+"/...")
	require.NoError(t, err)
	require.NotEmpty(t, loaded, "no packages loaded — is this running from the module root?")

	for _, pkg := range loaded {
		rel := strings.TrimPrefix(pkg.PkgPath, module+"/")

		for _, r := range rules {
			if !r.scope(rel) {
				continue
			}
			for imported := range pkg.Imports {
				require.Falsef(t, r.forbidden(imported),
					"\n%s\n  %s imports %s\n\n%s", r.name, pkg.PkgPath, imported, r.why)
			}
		}
	}
}

func under(prefix string) func(string) bool {
	return func(p string) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }
}

func exact(want string) func(string) bool {
	return func(p string) bool { return p == want }
}

func anyOf(preds ...func(string) bool) func(string) bool {
	return func(p string) bool {
		for _, pred := range preds {
			if pred(p) {
				return true
			}
		}
		return false
	}
}

// unsafeTemplHelpers are the templ entry points that emit their argument without
// escaping it. FR-055 and constitution principle III forbid them on
// package-derived content, and this check bans them outright under internal/web:
// nothing there needs one, so "not used at all" is both stricter and cheaper to
// enforce than "used only on trusted values". T111 is the full version, which has
// to reason about where a value came from.
var unsafeTemplHelpers = map[string]string{
	"Raw":              "emits its argument as markup with no escaping",
	"JSUnsafeFuncCall": "emits its argument into a script context with no escaping",
	"SafeCSS":          "asserts a string is safe CSS without checking",
	"SafeScriptInline": "emits its argument as inline script with no escaping",
}

func TestWebNeverBypassesTemplEscaping(t *testing.T) {
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedCompiledGoFiles,
	}, module+"/internal/web/...")
	require.NoError(t, err)
	require.NotEmpty(t, loaded)

	found := 0
	for _, pkg := range loaded {
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "templ" {
					return true
				}
				why, unsafe := unsafeTemplHelpers[sel.Sel.Name]
				if !unsafe {
					return true
				}
				found++
				require.Failf(t, "unescaped rendering under internal/web",
					"%s calls templ.%s at %s, which %s.\n\n"+
						"FR-055 is absolute: anything from a manifest, an instruction file or scan "+
						"evidence is escaped. templ escapes by default, so the fix is to interpolate "+
						"the value and delete the call.",
					pkg.PkgPath, sel.Sel.Name, pkg.Fset.Position(call.Pos()), why)
				return true
			})
		}
	}
	require.Zero(t, found)
}
