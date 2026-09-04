// The boundaries this codebase's security model is made of, compiled
// rather than remembered.
//
// Two of them:
//
//   - The hub resolves; the CLI does not. Masterminds/semver may be
//     imported only by internal/plan's reporting code, never by anything
//     that chooses a version. A second implementation of resolution here
//     would be a second answer, and the two would eventually disagree.
//   - internal/apply is the only package that mutates the agent tree, and
//     it may not decide where the tree is.
//
// # Mechanism, and what it cannot see
//
// The scan is go/parser over this module's source, from the stdlib. The hub's
// internal/archcheck uses golang.org/x/tools/go/packages for the same job;
// x/tools is not a dependency of the CLI module and go.mod is the
// orchestrator's, so the same shape is built on go/parser instead. internal/cmd
// and internal/leakscan already scan this way, so this is the module's
// established mechanism rather than a new one.
//
// What that costs, stated because a boundary nobody knows the limits of is
// worse than none:
//
//   - It sees DIRECT imports only. A package that reaches semver through
//     internal/plan links semver into its binary and is not reported. That is
//     the right granularity for this rule — the question is which package
//     CONTAINS resolution logic, not which binary links the library — but it is
//     not the same question as "who can call semver".
//   - It matches CALL NAMES syntactically and resolves no types. `root.Rename`
//     and `os.Rename` both match; so would a method called Rename on something
//     unrelated. False positives land only inside packages the rules already
//     permit, and the rules are allowlists, so the failure direction is a noisy
//     pass rather than a silent one.
//   - It cannot see a mutation performed through a value another package handed
//     over. Staged.OpenRoot returns an *os.Root over a staged tree, and any
//     holder of one can write through it; what closes that is the rule on who
//     may import internal/apply at all, not a call-name scan.
//   - It exempts _test.go files from the mutation rules. Tests build hostile
//     fixtures and must be able to write anywhere; what covers behaviour is
//     containment_test.go's walk over a real sync, not this file.
//
// A blanket ban on os.Remove/os.Rename/os.WriteFile across the module was
// rejected: internal/cache, internal/record, internal/credentials and
// internal/cmd's lock all legitimately write — to ~/.agent-manager and to
// the credential file, which are amctl's own state and not an agent's
// tree. Exempting four packages of twelve would measure nothing, and the
// three named calls do not cover the writes anyway — internal/apply and
// internal/archive mutate through *os.Root, so a grep for `os.Rename`
// misses `root.Rename` entirely. The rule that is actually true is the
// conjunction below: knowing where the agent tree is and mutating it is
// internal/apply's alone.

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

// semverModule is the version-resolution library kept out of the CLI. The
// prefix is matched rather than the exact path so that a major-version
// bump — .../semver/v4 — does not walk through the boundary.
const semverModule = "github.com/Masterminds/semver"

// mutatingCalls are the call names that write to, replace or unlink something.
// Both spellings are here on purpose: os.Rename and root.Rename are the same
// operation, and the containment-critical packages only ever use the second.
var mutatingCalls = map[string]bool{
	"Remove": true, "RemoveAll": true, "Rename": true, "WriteFile": true,
	"Create": true, "CreateTemp": true, "Mkdir": true, "MkdirAll": true,
	"Chmod": true, "Chown": true, "Symlink": true, "Link": true, "Truncate": true,
	"OpenFile": true,
}

// destinationDerivation is internal/layout's API for deciding where an
// entry goes. internal/apply must never call it: the mutator receives
// destinations, it does not compute them, and that is what keeps the
// containment check on one path per entry rather than on every path a
// mutator might invent.
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

// scanModule parses every .go file under root and groups the results by
// directory, which is one Go package per directory in this module.
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

// collectCalls records two different things from two different node types, and
// the split is load-bearing.
//
// `selectors` is every qualified SelectorExpr, called or not, because the
// destination-derivation rule asks whether internal/apply so much as MENTIONS
// layout.NewRegistry.
//
// `mutators` is only a SelectorExpr in the function position of a
// CallExpr. It used to be every SelectorExpr whose final name matched,
// which counted a field read as a mutation: `p.Remove` in internal/plan's
// compute.go — a read of Plan.Remove, the slice of removals — made the
// pure planning package register as a mutator and therefore unable to
// import internal/layout at all. That is what kept layout.DestCollisionKey,
// written for internal/plan and documented as belonging there, from ever
// being called; the case-folding hazard it closes was open the whole time.
//
// What the narrowing gives up is a mutating function used as a VALUE —
// `defer r.Remove` or passing os.RemoveAll to something. No such use exists in
// this module, and the rule it feeds is a conjunction with an import, so the
// cost is bounded to a package that both knows the agent tree and launders its
// writes through a function value. TestBoundariesFireOnASyntheticViolation
// pins both directions: a call is still seen, a field read is not.
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

// the rules

type boundary struct {
	name string
	why  string
	// check reports every violation as a sentence.
	check func(pkgs map[string]*pkgInfo, module string) []string
}

func boundaries() []boundary {
	return []boundary{
		{
			name: "the CLI holds no version-resolution logic (FR-009, T042b)",
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
			name: "only internal/cmd may import internal/apply (T042)",
			why: "internal/apply is the only package that mutates the agent tree, so the set of " +
				"packages that can reach it is the set of places a write can originate. It is an " +
				"allowlist so it fails CLOSED: a package added tomorrow cannot install anything " +
				"until it is named here, with a reason. Note that Staged.OpenRoot hands out an " +
				"*os.Root over a staged tree — a call-name scan cannot see writes through it, so " +
				"this rule, not that scan, is what bounds them.",
			check: onlyTheseMayImport([]string{"internal/cmd"}, func(p string) bool {
				return p == cliModule+"/internal/apply"
			}),
		},
		{
			name: "the deciding half is pure (T036, T034)",
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
			name: "knowing where the agent tree is AND mutating it is internal/apply's alone (T042)",
			why: "This is the conjunction that is actually true, and the reason a blanket ban on " +
				"os.Remove/os.Rename/os.WriteFile is not: internal/cache, internal/record, " +
				"internal/credentials and internal/cmd all write, to ~/.agent-manager and the " +
				"credential file, which are amctl's own state. What none of them may do is write " +
				"to a path derived from internal/layout. internal/archive is the one other member, " +
				"and only because it imports layout for the plugin-adopting subdirectory set while " +
				"writing solely into the staging destination internal/apply hands it. internal/cmd " +
				"is a NARROWED third member: it must construct layout's registry, because layout's " +
				"own package comment puts home and environment resolution in the command layer " +
				"(FR-039), and it must write amctl's own state root — the per-home sync lock, the " +
				"write probe, the credential file. Its carve-out therefore permits deriving a " +
				"destination and writing under ~/.agent-manager, and still forbids the two calls " +
				"that installing into a layout-derived destination actually requires: a RENAME, " +
				"which is R3's swap, and internal/archive, which is how a tree arrives. A future " +
				"edit that starts installing from the command layer trips this rule rather than " +
				"shipping.",
			check: func(pkgs map[string]*pkgInfo, module string) []string {
				allowed := map[string]bool{"internal/apply": true, "internal/archive": true}
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
			name: "the mutator does not derive a destination (T042, FR-020)",
			why: "internal/apply RECEIVES destinations from internal/plan, which got them from " +
				"internal/layout. If it could build one itself there would be two answers to " +
				"'where does this entry go', and FR-020's containment check — which runs on the " +
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

// the assertions

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

// TestTheScanSeesWhatTheRulesAreAbout is the liveness check, and it is not
// decoration: four of the five rules above are allowlists, and an allowlist is
// vacuously true if the scan finds nothing to test it against. This asserts the
// scan really does see internal/apply importing internal/layout and calling
// mutating functions — so the conjunction rule has a live member — and that
// internal/plan is really there for the semver rule to be about.
func TestTheScanSeesWhatTheRulesAreAbout(t *testing.T) {
	pkgs := scanModule(t, moduleRootOf(t), cliModule)

	apply := pkgs[cliModule+"/internal/apply"]
	require.NotNil(t, apply)
	require.True(t, apply.imports[cliModule+"/internal/layout"],
		"the conjunction rule is about packages that import layout AND mutate; if apply stopped "+
			"importing layout the rule would have no member and would pass vacuously")
	require.True(t, apply.mutates(), "the scan must see internal/apply's own mutating calls")
	require.NotEmpty(t, apply.mutators["os.MkdirAll"], "stage.go's os.MkdirAll, seen by name")

	// internal/cmd's narrowed carve-out has a live premise: it really does
	// import layout and really does mutate, so the carve-out is doing work
	// rather than describing an empty set — and it really does rename nothing,
	// which is the half that makes it safe.
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

	// The receiver's NAME is not asserted, only that a Rename is reached through
	// something other than the os package: that is the call a grep for
	// os.Rename would MISS, and the whole reason this scan is not a grep.
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

// TestSemverIsNotADependencyYetAndTheRuleIsATripwire says out loud what
// this rule is currently worth. Masterminds/semver is not in go.mod at all —
// internal/plan implements semver 2.0.0 §10/§11 ordering itself, in
// direction.go, for reporting — so the rule is a tripwire rather than a
// constraint on existing code. TestBoundariesFireOnASyntheticViolation is what
// proves the tripwire is armed.
func TestSemverIsNotADependencyYetAndTheRuleIsATripwire(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join(moduleRootOf(t), "go.mod"))
	require.NoError(t, err)
	if strings.Contains(string(mod), semverModule) {
		t.Log("Masterminds/semver is now a dependency; the FR-009 rule is a live constraint, " +
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

// TestBoundariesFireOnASyntheticViolation is the negative control for all five
// rules AND for the scan underneath them. Each case is a module-shaped source
// tree containing exactly one violation; the assertion is that the rule reports
// it and names the package.
//
// It exists because a boundary test that has never been seen to fail is
// indistinguishable from one whose predicate is inverted.
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
			rule: "the CLI holds no version-resolution logic (FR-009, T042b)",
			files: map[string]string{
				"internal/cmd/sync.go": "package cmd\n\nimport semver \"" + semverModule + "/v3\"\n\nvar _ = semver.MustParse\n",
			},
			want: mod + "/internal/cmd imports " + semverModule + "/v3",
		},
		{
			name: "semver inside internal/plan, which is allowed",
			rule: "the CLI holds no version-resolution logic (FR-009, T042b)",
			files: map[string]string{
				"internal/plan/direction.go": "package plan\n\nimport semver \"" + semverModule + "/v3\"\n\nvar _ = semver.MustParse\n",
			},
			want: "",
		},
		{
			name: "semver reached from a test file",
			rule: "the CLI holds no version-resolution logic (FR-009, T042b)",
			files: map[string]string{
				"internal/hub/hub_test.go": "package hub\n\nimport semver \"" + semverModule + "\"\n\nvar _ = semver.MustParse\n",
			},
			want: mod + "/internal/hub imports " + semverModule,
		},
		{
			name: "a package other than internal/cmd importing internal/apply",
			rule: "only internal/cmd may import internal/apply (T042)",
			files: map[string]string{
				"internal/hub/install.go": "package hub\n\nimport \"" + cliModule + "/internal/apply\"\n\nvar _ = apply.Swap\n",
			},
			want: mod + "/internal/hub imports " + cliModule + "/internal/apply",
		},
		{
			name: "the pure half reaching for the filesystem",
			rule: "the deciding half is pure (T036, T034)",
			files: map[string]string{
				"internal/plan/compute.go": "package plan\n\nimport \"os\"\n\nvar _ = os.Stat\n",
			},
			want: mod + "/internal/plan imports os",
		},
		{
			name: "a package that knows the agent tree and writes to it",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone (T042)",
			files: map[string]string{
				"internal/hub/cleanup.go": "package hub\n\nimport (\n\t\"os\"\n\n\t\"" + mod + "/internal/layout\"\n)\n\n" +
					"func f(d string) { _ = os.RemoveAll(layout.StagingRoot(d)) }\n",
			},
			want: mod + "/internal/hub imports internal/layout and calls os.RemoveAll",
		},
		{
			name: "a package that writes to its own state and does NOT know the agent tree",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone (T042)",
			files: map[string]string{
				"internal/cache/cache.go": "package cache\n\nimport \"os\"\n\nfunc f(d string) { _ = os.RemoveAll(d) }\n",
			},
			want: "",
		},
		{
			name: "a FIELD named Remove, read but never called, is not a mutation",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone (T042)",
			files: map[string]string{
				"internal/plan/compute.go": "package plan\n\nimport \"" + mod + "/internal/layout\"\n\n" +
					"type P struct{ Remove []string }\n\n" +
					"func f(p P, d string) int { _ = layout.DestCollisionKey(d); return len(p.Remove) }\n",
			},
			want: "",
		},
		{
			name: "the same name CALLED is still a mutation",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone (T042)",
			files: map[string]string{
				"internal/plan/compute.go": "package plan\n\nimport (\n\t\"os\"\n\n\t\"" + mod + "/internal/layout\"\n)\n\n" +
					"func f(d string) { _ = os.Remove(layout.StagingRoot(d)) }\n",
			},
			want: mod + "/internal/plan imports internal/layout and calls os.Remove",
		},
		{
			name: "a mutation through an os.Root, which a grep for os.Rename would miss",
			rule: "knowing where the agent tree is AND mutating it is internal/apply's alone (T042)",
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
