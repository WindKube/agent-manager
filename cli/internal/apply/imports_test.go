// These tests compile the CLI's security boundaries: only internal/plan's
// reporting code may import a semver library (the hub resolves, the CLI does
// not), and only internal/apply may both know where the agent tree is and
// mutate it.
//
// The scan is go/parser over this module's source. It sees direct imports
// only, matches call names syntactically (root.Rename and os.Rename alike),
// and exempts _test.go files from the mutation rules. A blanket ban on
// os.Rename and friends would be useless: amctl's own state legitimately
// writes, and internal/apply mutates through *os.Root anyway.

package apply

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const cliModule = "github.com/WindKube/agent-manager/cli"

// semverModule is matched as a prefix so a major-version bump (.../semver/v4)
// does not slip through.
const semverModule = "github.com/Masterminds/semver"

// mutatingCalls are call names that write, replace or unlink; matched by name so
// both os.Rename and root.Rename count.
var mutatingCalls = map[string]bool{
	"Remove": true, "RemoveAll": true, "Rename": true, "WriteFile": true,
	"Create": true, "CreateTemp": true, "Mkdir": true, "MkdirAll": true,
	"Chmod": true, "Chown": true, "Symlink": true, "Link": true, "Truncate": true,
	"OpenFile": true,
}

// destinationDerivation is internal/layout's API for deciding where an entry
// goes. internal/apply must never call it, so containment is checked on one
// given path per entry rather than any path a mutator might invent.
var destinationDerivation = map[string]bool{
	"layout.NewRegistry":      true,
	"layout.NewClaudeCode":    true,
	"layout.NewCodex":         true,
	"layout.KnownTargetNames": true,
}

type pkgInfo struct {
	rel         string
	imports     map[string]bool
	testImports map[string]bool
	mutators    map[string][]string // call name -> files
	selectors   map[string]bool     // "layout.NewRegistry" in non-test files
}

func (p *pkgInfo) mutates() bool { return len(p.mutators) > 0 }

func scanModule(t *testing.T, root, module string) map[string]*pkgInfo {
	t.Helper()
	pkgs := map[string]*pkgInfo{}
	fset := token.NewFileSet()

	require.NoError(t, filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") {
			return nil
		}

		dir := filepath.Dir(path)
		rel, rerr := filepath.Rel(root, dir)
		require.NoError(t, rerr)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			rel = ""
		}
		pkgPath := module
		if rel != "" {
			pkgPath = module + "/" + rel
		}

		info := pkgs[pkgPath]
		if info == nil {
			info = &pkgInfo{
				rel: rel, imports: map[string]bool{}, testImports: map[string]bool{},
				mutators: map[string][]string{}, selectors: map[string]bool{},
			}
			pkgs[pkgPath] = info
		}

		isTest := strings.HasSuffix(name, "_test.go")
		mode := parser.ImportsOnly
		if !isTest {
			mode = parser.SkipObjectResolution
		}
		f, perr := parser.ParseFile(fset, path, nil, mode)
		require.NoError(t, perr, "parse %s", path)

		for _, spec := range f.Imports {
			p, uerr := strconv.Unquote(spec.Path.Value)
			require.NoError(t, uerr)
			if isTest {
				info.testImports[p] = true
			} else {
				info.imports[p] = true
			}
		}
		if !isTest {
			collectCalls(f, info, name)
		}
		return nil
	}))
	require.NotEmpty(t, pkgs, "no packages parsed under %s", root)
	return pkgs
}

// collectCalls records `selectors` as every qualified SelectorExpr, called or
// not, and `mutators` only for a SelectorExpr in call position, so a field read
// like plan's `p.Remove` is not a mutation. A mutating function passed as a
// value is not seen; no such use exists.
func collectCalls(f *ast.File, info *pkgInfo, file string) {
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if ident, isIdent := node.X.(*ast.Ident); isIdent {
				info.selectors[ident.Name+"."+node.Sel.Name] = true
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || !mutatingCalls[sel.Sel.Name] {
				return true
			}
			qualified := sel.Sel.Name
			if ident, isIdent := sel.X.(*ast.Ident); isIdent {
				qualified = ident.Name + "." + sel.Sel.Name
			}
			info.mutators[qualified] = append(info.mutators[qualified], file)
		}
		return true
	})
}

func moduleRootOf(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "cannot locate this source file")
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "walked past the filesystem root looking for go.mod")
		dir = parent
	}
}

type boundary struct {
	name  string
	why   string
	check func(pkgs map[string]*pkgInfo, module string) []string
}

func boundaries() []boundary {
	return []boundary{
		{
			name: "the CLI holds no version-resolution logic",
			why: "The hub resolves; the CLI applies. Masterminds/semver may be imported only by " +
				"internal/plan, whose direction.go is REPORTING — it turns two versions the hub " +
				"already chose into an arrow for a human. Anything that CHOOSES a version is a " +
				"second implementation of the gate, and the two will disagree the first time the " +
				"hub's ordering changes.",
			check: onlyTheseMayImport([]string{"internal/plan"}, func(p string) bool {
				return p == semverModule || strings.HasPrefix(p, semverModule+"/")
			}),
		},
		{
			name: "only internal/cmd may import internal/apply",
			why: "internal/apply is the only package that mutates the agent tree, so the set of " +
				"packages that can reach it is the set of places a write can originate. It is an " +
				"allowlist so it fails CLOSED: a package added tomorrow cannot install anything " +
				"until it is named here, with a reason. Note that Staged.OpenRoot hands out an " +
				"*os.Root over a staged tree — a call-name scan cannot see writes through it, so " +
				"this rule, not that scan, is what bounds them. internal/deliver is the second " +
				"member: a plugin's components can only be placed once its bundle is read, so it " +
				"implements apply.Components and is reached only through Applier.Apply, under the " +
				"same containment, guard and record.",
			check: onlyTheseMayImport([]string{"internal/cmd", "internal/deliver"}, func(p string) bool {
				return p == cliModule+"/internal/apply"
			}),
		},
		{
			name: "the deciding half is pure",
			why: "internal/plan and internal/layout compute what to do and where it goes, with no " +
				"I/O whatsoever: that is what makes --dry-run free and what makes every path " +
				"decision testable without a filesystem. An import of os or net/http there is the " +
				"first step of moving a decision into the mutator's half.",
			check: forbidIn([]string{"internal/plan", "internal/layout"}, map[string]bool{
				"os": true, "os/exec": true, "net/http": true, "net": true,
				cliModule + "/internal/apply": true,
				cliModule + "/internal/hub":   false, // plan reads the lockfile type; see doc.go
			}),
		},
		{
			name: "knowing where the agent tree is AND mutating it is internal/apply's alone",
			why: "This is the conjunction that is actually true, and the reason a blanket ban on " +
				"os.Remove/os.Rename/os.WriteFile is not: internal/cache, internal/record, " +
				"internal/credentials and internal/cmd all write, to ~/.agent-manager and the " +
				"credential file, which are amctl's own state. What none of them may do is write " +
				"to a path derived from internal/layout. internal/archive is the one other member, " +
				"and only because it imports layout for the plugin-adopting subdirectory set while " +
				"writing solely into the staging destination internal/apply hands it. internal/cmd " +
				"is a NARROWED third member: it must construct layout's registry, because layout's " +
				"own package comment puts home and environment resolution in the command layer, " +
				"and it must write amctl's own state root — the per-home sync lock, the " +
				"write probe, the credential file. Its carve-out therefore permits deriving a " +
				"destination and writing under ~/.agent-manager, and still forbids the two calls " +
				"that installing into a layout-derived destination actually requires: a RENAME, " +
				"which is R3's swap, and internal/archive, which is how a tree arrives. A future " +
				"edit that starts installing from the command layer trips this rule rather than " +
				"shipping. internal/deliver places plugin components, whose paths depend on the " +
				"bundle's contents and so cannot come from the pure plan; every write it makes is " +
				"contained by apply.Home and fingerprinted into the record.",
			check: func(pkgs map[string]*pkgInfo, module string) []string {
				allowed := map[string]bool{"internal/apply": true, "internal/archive": true, "internal/deliver": true}
				var bad []string
				for path, info := range pkgs {
					if allowed[info.rel] || !info.imports[module+"/internal/layout"] || !info.mutates() {
						continue
					}
					if info.rel == "internal/cmd" {
						var why []string
						for call := range info.mutators {
							if strings.HasSuffix(call, ".Rename") {
								why = append(why, "calls "+call)
							}
						}
						if info.imports[module+"/internal/archive"] {
							why = append(why, "imports internal/archive")
						}
						if len(why) == 0 {
							continue
						}
						sort.Strings(why)
						bad = append(bad, path+" imports internal/layout and "+strings.Join(why, " and "))
						continue
					}
					bad = append(bad, path+" imports internal/layout and calls "+
						strings.Join(sortedKeys(info.mutators), ", "))
				}
				return bad
			},
		},
		{
			name: "the mutator does not derive a destination",
			why: "internal/apply RECEIVES destinations from internal/plan, which got them from " +
				"internal/layout. If it could build one itself there would be two answers to " +
				"'where does this entry go', and the containment check — which runs on the " +
				"destination it is handed — would be checking the wrong one.",
			check: func(pkgs map[string]*pkgInfo, _ string) []string {
				info := pkgs[cliModule+"/internal/apply"]
				if info == nil {
					return []string{"internal/apply was not scanned at all"}
				}
				var bad []string
				for call := range info.selectors {
					if destinationDerivation[call] {
						bad = append(bad, "internal/apply calls "+call)
					}
				}
				sort.Strings(bad)
				return bad
			},
		},
	}
}

func onlyTheseMayImport(allowedRels []string, forbidden func(string) bool) func(map[string]*pkgInfo, string) []string {
	allowed := map[string]bool{}
	for _, r := range allowedRels {
		allowed[r] = true
	}
	return func(pkgs map[string]*pkgInfo, _ string) []string {
		var bad []string
		for path, info := range pkgs {
			if allowed[info.rel] {
				continue
			}
			for _, set := range []map[string]bool{info.imports, info.testImports} {
				for imported := range set {
					if forbidden(imported) {
						bad = append(bad, path+" imports "+imported)
					}
				}
			}
		}
		sort.Strings(bad)
		return bad
	}
}

func forbidIn(rels []string, forbidden map[string]bool) func(map[string]*pkgInfo, string) []string {
	scope := map[string]bool{}
	for _, r := range rels {
		scope[r] = true
	}
	return func(pkgs map[string]*pkgInfo, _ string) []string {
		var bad []string
		for path, info := range pkgs {
			if !scope[info.rel] {
				continue
			}
			for imported := range info.imports {
				if forbidden[imported] {
					bad = append(bad, path+" imports "+imported)
				}
			}
		}
		sort.Strings(bad)
		return bad
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestImportBoundaries(t *testing.T) {
	pkgs := scanModule(t, moduleRootOf(t), cliModule)
	for _, b := range boundaries() {
		t.Run(b.name, func(t *testing.T) {
			violations := b.check(pkgs, cliModule)
			require.Emptyf(t, violations, "\n%s\n\n  %s\n\n%s",
				b.name, strings.Join(violations, "\n  "), b.why)
		})
	}
}

// TestTheScanSeesWhatTheRulesAreAbout guards against the allowlist rules
// passing vacuously because the scan found nothing.
func TestTheScanSeesWhatTheRulesAreAbout(t *testing.T) {
	pkgs := scanModule(t, moduleRootOf(t), cliModule)

	apply := pkgs[cliModule+"/internal/apply"]
	require.NotNil(t, apply)
	require.True(t, apply.imports[cliModule+"/internal/layout"],
		"the conjunction rule is about packages that import layout AND mutate; if apply stopped "+
			"importing layout the rule would have no member and would pass vacuously")
	require.True(t, apply.mutates(), "the scan must see internal/apply's own mutating calls")
	require.NotEmpty(t, apply.mutators["os.MkdirAll"], "stage.go's os.MkdirAll, seen by name")

	// internal/cmd's carve-out is live: it imports layout and mutates, but
	// renames nothing.
	cmdPkg := pkgs[cliModule+"/internal/cmd"]
	require.NotNil(t, cmdPkg)
	require.True(t, cmdPkg.imports[cliModule+"/internal/layout"],
		"sync.go constructs layout's registry; if it stopped, the carve-out should be removed")
	require.True(t, cmdPkg.mutates(), "the lock and the home write probe are real mutations")
	require.False(t, cmdPkg.imports[cliModule+"/internal/archive"])
	for call := range cmdPkg.mutators {
		require.False(t, strings.HasSuffix(call, ".Rename"),
			"internal/cmd renames nothing; %s would install into a layout-derived destination", call)
	}

	// A Rename through something other than os is what a grep would miss.
	viaRoot := false
	for call := range apply.mutators {
		if strings.HasSuffix(call, ".Rename") && call != "os.Rename" {
			viaRoot = true
		}
	}
	require.True(t, viaRoot, "swap.go renames through an *os.Root; the scan must see it. calls seen: %v",
		sortedKeys(apply.mutators))

	archive := pkgs[cliModule+"/internal/archive"]
	require.NotNil(t, archive)
	require.True(t, archive.imports[cliModule+"/internal/layout"])
	require.True(t, archive.mutates())

	require.NotNil(t, pkgs[cliModule+"/internal/plan"], "the semver rule's one permitted package")
	require.NotNil(t, pkgs[cliModule+"/internal/cmd"], "the apply-import rule's one permitted package")
}

// TestSemverIsNotADependencyYetAndTheRuleIsATripwire: semver is not in go.mod,
// so the rule is a tripwire, armed per TestBoundariesFireOnASyntheticViolation.
func TestSemverIsNotADependencyYetAndTheRuleIsATripwire(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join(moduleRootOf(t), "go.mod"))
	require.NoError(t, err)
	if strings.Contains(string(mod), semverModule) {
		t.Log("Masterminds/semver is now a dependency; the version-resolution rule is a live constraint, " +
			"not a tripwire, and this test's premise is stale")
		return
	}
	pkgs := scanModule(t, moduleRootOf(t), cliModule)
	for path, info := range pkgs {
		for imported := range info.imports {
			require.NotContains(t, imported, semverModule, "%s", path)
		}
	}
}

// TestBoundariesFireOnASyntheticViolation is the negative control for every
// rule and the scan: each case is a module tree with exactly one violation.
func TestBoundariesFireOnASyntheticViolation(t *testing.T) {
	const mod = "example.com/fake"

	cases := []struct {
		name  string
		rule  string
		files map[string]string
		want  string
	}{
		{
			name: "a verb importing semver",
			rule: "the CLI holds no version-resolution logic",
			files: map[string]string{
				"internal/cmd/sync.go": "package cmd\n\nimport semver \"" + semverModule + "/v3\"\n\nvar _ = semver.MustParse\n",
			},
			want: mod + "/internal/cmd imports " + semverModule + "/v3",
		},
		{
			name: "semver inside internal/plan, which is allowed",
			rule: "the CLI holds no version-resolution logic",
			files: map[string]string{
				"internal/plan/direction.go": "package plan\n\nimport semver \"" + semverModule + "/v3\"\n\nvar _ = semver.MustParse\n",
			},
			want: "",
		},
		{
			name: "semver reached from a test file",
			rule: "the CLI holds no version-resolution logic",
			files: map[string]string{
				"internal/hub/hub_test.go": "package hub\n\nimport semver \"" + semverModule + "\"\n\nvar _ = semver.MustParse\n",
			},
			want: mod + "/internal/hub imports " + semverModule,
		},
		{
			name: "a package other than internal/cmd importing internal/apply",
			rule: "only internal/cmd may import internal/apply",
			files: map[string]string{
				"internal/hub/install.go": "package hub\n\nimport \"" + cliModule + "/internal/apply\"\n\nvar _ = apply.Swap\n",
			},
			want: mod + "/internal/hub imports " + cliModule + "/internal/apply",
		},
		{
			name: "the pure half reaching for the filesystem",
			rule: "the deciding half is pure",
			files: map[string]string{
				"internal/plan/compute.go": "package plan\n\nimport \"os\"\n\nvar _ = os.Stat\n",
			},
			want: mod + "/internal/plan imports os",
		},
		{
			name: "a package that knows the agent tree and writes to it",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone",
			files: map[string]string{
				"internal/hub/cleanup.go": "package hub\n\nimport (\n\t\"os\"\n\n\t\"" + mod + "/internal/layout\"\n)\n\n" +
					"func f(d string) { _ = os.RemoveAll(layout.StagingRoot(d)) }\n",
			},
			want: mod + "/internal/hub imports internal/layout and calls os.RemoveAll",
		},
		{
			name: "a package that writes to its own state and does NOT know the agent tree",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone",
			files: map[string]string{
				"internal/cache/cache.go": "package cache\n\nimport \"os\"\n\nfunc f(d string) { _ = os.RemoveAll(d) }\n",
			},
			want: "",
		},
		{
			name: "a FIELD named Remove, read but never called, is not a mutation",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone",
			files: map[string]string{
				"internal/plan/compute.go": "package plan\n\nimport \"" + mod + "/internal/layout\"\n\n" +
					"type P struct{ Remove []string }\n\n" +
					"func f(p P, d string) int { _ = layout.DestCollisionKey(d); return len(p.Remove) }\n",
			},
			want: "",
		},
		{
			name: "the same name CALLED is still a mutation",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone",
			files: map[string]string{
				"internal/plan/compute.go": "package plan\n\nimport (\n\t\"os\"\n\n\t\"" + mod + "/internal/layout\"\n)\n\n" +
					"func f(d string) { _ = os.Remove(layout.StagingRoot(d)) }\n",
			},
			want: mod + "/internal/plan imports internal/layout and calls os.Remove",
		},
		{
			name: "a mutation through an os.Root, which a grep for os.Rename would miss",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone",
			files: map[string]string{
				"internal/hub/swap.go": "package hub\n\nimport (\n\t\"os\"\n\n\t\"" + mod + "/internal/layout\"\n)\n\n" +
					"func f(r *os.Root, d string) { _ = layout.StagingRoot(d); _ = r.Rename(\"a\", \"b\") }\n",
			},
			want: mod + "/internal/hub imports internal/layout and calls r.Rename",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"),
				[]byte("module "+mod+"\n\ngo 1.26\n"), 0o644))
			for rel, body := range tc.files {
				full := filepath.Join(root, filepath.FromSlash(rel))
				require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
				require.NoError(t, os.WriteFile(full, []byte(body), 0o644))
			}

			pkgs := scanModule(t, root, mod)
			var rule boundary
			for _, b := range boundaries() {
				if b.name == tc.rule {
					rule = b
				}
			}
			require.NotEmpty(t, rule.name, "no such rule: %s", tc.rule)

			violations := rule.check(pkgs, mod)
			if tc.want == "" {
				require.Empty(t, violations, "this shape is legal and must not be reported")
				return
			}
			require.Contains(t, violations, tc.want)
		})
	}
}
