// Package archcheck enforces the import boundaries that express this project's
// security model. An env-var boundary alone erodes the first time someone "just
// needs one query", so the boundary is also compiled.
package archcheck

import (
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
		name: "the scanner never executes bundle content",
		why: "constitution principle III and FR-021: static analysis only. os/exec in the scan " +
			"tree is the exact defect that requirement exists to prevent.",
		scope:     under("internal/scan"),
		forbidden: anyOf(exact("os/exec"), exact("plugin"), exact("net/http")),
	},
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
