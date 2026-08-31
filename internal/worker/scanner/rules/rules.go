// Package rules is the scanner's rule pack: detection rules as versioned data.
//
// Constitution, Development Workflow: "Detection rules live in a versioned rule
// pack, not in Go control flow. Adding or tuning a rule must not require a code
// change or a deploy." That splits the scanner in two, and the split is the whole
// point of this package. A rule INSTANCE — this command, this pattern, this
// severity, this prose — is a YAML file. A detection CLASS — how a shell AST is
// walked, what "the host is not in the expected set" means — is Go, reached from a
// rule by a named `match.kind`, `extract` and `condition` out of a closed
// vocabulary.
//
// The vocabulary is fixed by specs/001-agent-manager-hub/contracts/rulepack.schema.json
// and every rule is validated against a byte-identical copy of it at load time
// (schema.go). A rule naming a kind, an extractor or a condition this build does
// not implement is a LOAD failure, never a rule that silently matches nothing: a
// rule that matches nothing is indistinguishable from a package that is clean,
// which is the one failure mode a scanner must not have.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// ErrPack is the sentinel behind every rule-pack load failure.
var ErrPack = errors.New("rule pack is not loadable")

// The file layout of a pack directory. It is the same layout embedded in the
// binary and mounted into the scanner container, so a pack can be copied from one
// to the other without translation.
const (
	// ManifestFile carries the pack's declared version and nothing else.
	ManifestFile = "pack.yaml"
	// RulesDir holds one YAML document per rule, named <RULE-ID>.yaml.
	RulesDir = "rules"
	// FixturesDir holds the trip/clean bundle each rule ships (T058).
	FixturesDir = "fixtures"
)

// Severity ranks a finding. It mirrors the `finding_severity` enum.
type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Kind selects the matcher a rule is evaluated by.
type Kind string

const (
	// KindShellAST walks the shell syntax tree of every script in the bundle.
	KindShellAST Kind = "shell-ast"
	// KindRegex applies an RE2 pattern line by line to the files in scope.
	KindRegex Kind = "regex"
	// KindSchemaPath addresses the manifest document by JSON pointer.
	KindSchemaPath Kind = "schema-path"
	// KindDepManifest reads package.json, requirements.txt and go.mod.
	KindDepManifest Kind = "dep-manifest"
)

// Extract names what a match yields as its target value: the thing a condition
// then judges.
type Extract string

const (
	ExtractURLArgument  Extract = "url-argument"
	ExtractPathArgument Extract = "path-argument"
	ExtractPackageSpec  Extract = "package-spec"
	ExtractMatchedText  Extract = "matched-text"
	ExtractPointerValue Extract = "pointer-value"
)

// Condition is the named predicate applied to an extracted value. Adding one is a
// Go change; using one is not.
type Condition string

const (
	// ConditionAlways matches on the presence of what was extracted.
	ConditionAlways Condition = "always"
	// ConditionHostNotInExpected is FR-027: a host outside the version's expected
	// capability set. Where no expected set was recorded every host matches, so
	// nothing passes silently for want of a declaration.
	ConditionHostNotInExpected Condition = "host-not-in-expected"
	// ConditionPathOutsideExpected is a filesystem target that leaves the package
	// tree and is not covered by the expected set.
	ConditionPathOutsideExpected Condition = "path-outside-expected"
	// ConditionVersionUnpinned is a dependency specifier that does not name one
	// release.
	ConditionVersionUnpinned Condition = "version-unpinned"
	// ConditionValueMatches is the extracted value against the rule's own pattern.
	ConditionValueMatches Condition = "value-matches"
)

// Quote is which text a finding's evidence quotes.
type Quote string

const (
	// QuoteMatchedNode is the source text of the matched syntax node.
	QuoteMatchedNode Quote = "matched-node"
	// QuoteMatchedLine is the whole source line the match sits on.
	QuoteMatchedLine Quote = "matched-line"
	// QuoteSchemaError is the validator's own message. It is the only quote a
	// document-level check can produce, because there is no matched text.
	QuoteSchemaError Quote = "schema-error"
)

// Match is a rule's matcher configuration.
type Match struct {
	Kind      Kind      `yaml:"kind"`
	Command   []string  `yaml:"command"`
	Pattern   string    `yaml:"pattern"`
	Paths     []string  `yaml:"paths"`
	Pointer   string    `yaml:"pointer"`
	Extract   Extract   `yaml:"extract"`
	Condition Condition `yaml:"condition"`

	// pattern and scope are compiled at load. A pattern that will not compile, or
	// a glob that will not, is a pack that does not load — not a rule that quietly
	// never fires.
	pattern *regexp.Regexp
	scope   []*regexp.Regexp
}

// Regexp is the compiled RE2 pattern, or nil when the rule carries none.
func (m Match) Regexp() *regexp.Regexp { return m.pattern }

// InScope reports whether a bundle path is one this rule looks at. A rule with no
// `paths` looks at every file its matcher understands.
func (m Match) InScope(filePath string) bool {
	if len(m.scope) == 0 {
		return true
	}
	for _, re := range m.scope {
		if re.MatchString(filePath) {
			return true
		}
	}
	return false
}

// Evidence is what a finding raised by this rule quotes.
type Evidence struct {
	Quote Quote `yaml:"quote"`
	// ContextLines is honoured by the matchers that quote a line. Zero is a
	// meaningful value (quote the matched line alone), so the schema's default of 1
	// is applied at load rather than inferred from the zero value.
	ContextLines *int `yaml:"contextLines"`
}

// Lines is ContextLines with the schema's default applied.
func (e Evidence) Lines() int {
	if e.ContextLines == nil {
		return 1
	}
	return *e.ContextLines
}

// Fixtures are the two bundles every rule ships (constitution, Development
// Workflow): one that must trip it and one that must not. A rule with only a
// positive fixture is how a rule that matches everything ships.
type Fixtures struct {
	Trips string `yaml:"trips"`
	Clean string `yaml:"clean"`
}

// Rule is one detection rule.
type Rule struct {
	ID         string   `yaml:"id"`
	Severity   Severity `yaml:"severity"`
	Check      string   `yaml:"check"`
	Title      string   `yaml:"title"`
	Detail     string   `yaml:"detail"`
	Match      Match    `yaml:"match"`
	Evidence   Evidence `yaml:"evidence"`
	Fixtures   Fixtures `yaml:"fixtures"`
	References []string `yaml:"references"`
}

// Pack is a loaded rule pack.
type Pack struct {
	// version is what every scan records in `scan.pack_version`.
	version  string
	declared string
	origin   string
	rules    []Rule
	fsys     fs.FS
}

// Version is the value written to `scan.pack_version`, and therefore half of the
// scan idempotency key `unique (version_id, pack_version)`.
//
// It is the pack's DECLARED version with a short digest of the rule content
// appended — `2026.08.31+7b1c0f4a92de`. The digest half is what makes "rescan
// needed" a comparison rather than a promise about editing discipline: tuning a
// pattern without bumping the declared version still moves the key, so the next
// scan of an already-scanned version runs instead of being suppressed by its own
// idempotency guard. That is the failure this shape exists to prevent, and it
// costs a sha256 over a few kilobytes at start-up.
func (p *Pack) Version() string { return p.version }

// Declared is the version the pack states for itself, without the content digest.
func (p *Pack) Declared() string { return p.declared }

// Origin says where the pack came from, for the one log line that answers "which
// rules is this scanner actually running?".
func (p *Pack) Origin() string { return p.origin }

// All returns every rule, ordered by id.
func (p *Pack) All() []Rule { return append([]Rule(nil), p.rules...) }

// For returns the rules addressed to one check, ordered by id.
func (p *Pack) For(checkID string) []Rule {
	out := make([]Rule, 0, len(p.rules))
	for i := range p.rules {
		if p.rules[i].Check == checkID {
			out = append(out, p.rules[i])
		}
	}
	return out
}

// Len is how many rules the pack holds.
func (p *Pack) Len() int { return len(p.rules) }

// FS is the pack's own filesystem, so a fixture path can be read back out of the
// pack that declared it.
func (p *Pack) FS() fs.FS { return p.fsys }

// Load reads a pack out of any filesystem: the embedded copy, an
// AGENT_MANAGER_RULEPACK_DIR mount, or a test's fstest.MapFS.
func Load(fsys fs.FS, origin string) (*Pack, error) {
	if fsys == nil {
		return nil, fmt.Errorf("%w: no filesystem", ErrPack)
	}

	declared, err := readManifest(fsys)
	if err != nil {
		return nil, err
	}

	entries, err := fs.ReadDir(fsys, RulesDir)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s/: %w", ErrPack, RulesDir, err)
	}

	validator, err := ruleValidator()
	if err != nil {
		return nil, err
	}

	pack := &Pack{declared: declared, origin: origin, fsys: fsys}
	seen := make(map[string]string, len(entries))
	digest := sha256.New()

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}
		rulePath := path.Join(RulesDir, name)
		raw, readErr := fs.ReadFile(fsys, rulePath)
		if readErr != nil {
			return nil, fmt.Errorf("%w: read %s: %w", ErrPack, rulePath, readErr)
		}

		rule, ruleErr := decodeRule(validator, rulePath, raw)
		if ruleErr != nil {
			return nil, ruleErr
		}
		if previous, dup := seen[rule.ID]; dup {
			return nil, fmt.Errorf("%w: %s declares rule %s, which %s already declares",
				ErrPack, rulePath, rule.ID, previous)
		}
		// The filename carries the id so that `ls rules/` is the rule list and a
		// copied file with an unedited id is caught here rather than by a reviewer
		// wondering why their new rule never fires.
		if base := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml"); base != rule.ID {
			return nil, fmt.Errorf("%w: %s declares rule %s; the file must be named %s.yaml",
				ErrPack, rulePath, rule.ID, rule.ID)
		}
		seen[rule.ID] = rulePath
		pack.rules = append(pack.rules, *rule)

		// The digest covers the id and the file bytes of every rule, read in a
		// deterministic order, so two directories with the same rules produce the
		// same pack version and one edited byte produces a different one.
		_, _ = digest.Write([]byte(rule.ID + "\x00"))
		_, _ = digest.Write(raw)
		_, _ = digest.Write([]byte{'\n'})
	}

	if len(pack.rules) == 0 {
		// A pack with no rules would scan every bundle to `clean` while reporting
		// that every check passed. That is the worst answer this system can give, so
		// it is a load failure rather than an empty pack.
		return nil, fmt.Errorf("%w: %s/ holds no rules", ErrPack, RulesDir)
	}

	sort.Slice(pack.rules, func(i, j int) bool { return pack.rules[i].ID < pack.rules[j].ID })
	pack.version = declared + "+" + hex.EncodeToString(digest.Sum(nil))[:12]
	return pack, nil
}

func readManifest(fsys fs.FS) (string, error) {
	raw, err := fs.ReadFile(fsys, ManifestFile)
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %w", ErrPack, ManifestFile, err)
	}

	var manifest struct {
		PackVersion string `yaml:"packVersion"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return "", fmt.Errorf("%w: %s is not valid yaml: %w", ErrPack, ManifestFile, err)
	}
	if strings.TrimSpace(manifest.PackVersion) == "" {
		return "", fmt.Errorf("%w: %s declares no packVersion", ErrPack, ManifestFile)
	}
	return strings.TrimSpace(manifest.PackVersion), nil
}

// decodeRule turns one YAML document into a Rule, validated against the contract
// schema and then against what this build can actually execute.
func decodeRule(validator *jsonschema.Schema, rulePath string, raw []byte) (*Rule, error) {
	// The YAML is round-tripped through JSON before validation. A JSON Schema
	// validator applies JSON type rules and YAML's are different — `1.0` is a
	// float in YAML and a string in JSON — so validating the YAML decoder's output
	// directly lets the schema and the decoder disagree about a value's type
	// (pkgspec/skill.go makes the same trip for the same reason).
	document, err := yamlAsJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrPack, rulePath, err)
	}
	if err := validator.Validate(document); err != nil {
		return nil, fmt.Errorf("%w: %s does not conform to %s: %w", ErrPack, rulePath, SchemaID, err)
	}

	var rule Rule
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&rule); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrPack, rulePath, err)
	}

	if err := rule.compile(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrPack, rulePath, err)
	}
	return &rule, nil
}

// compile turns the rule's text into the compiled artefacts the engine needs, and
// refuses a combination this build cannot execute.
//
// The schema validates the vocabulary one field at a time; it cannot state that
// `condition: value-matches` is meaningless without a pattern, or that
// `extract: url-argument` has no reading under `dep-manifest`. Those are the
// combinations that produce a rule which loads, runs, and matches nothing — so
// they are refused here, at load, where the failure names the file.
func (r *Rule) compile() error {
	if r.Match.Pattern != "" {
		compiled, err := regexp.Compile(r.Match.Pattern)
		if err != nil {
			return fmt.Errorf("match.pattern does not compile as RE2: %w", err)
		}
		r.Match.pattern = compiled
	}
	for _, glob := range r.Match.Paths {
		compiled, err := globRegexp(glob)
		if err != nil {
			return err
		}
		r.Match.scope = append(r.Match.scope, compiled)
	}

	if r.Match.Condition == "" {
		r.Match.Condition = ConditionAlways
	}
	if err := r.checkCombination(); err != nil {
		return err
	}
	return nil
}

func (r *Rule) checkCombination() error {
	allowed := map[Kind][]Extract{
		KindShellAST:    {ExtractURLArgument, ExtractPathArgument, ExtractMatchedText},
		KindRegex:       {ExtractURLArgument, ExtractPathArgument, ExtractMatchedText},
		KindDepManifest: {ExtractPackageSpec},
		KindSchemaPath:  {ExtractPointerValue, ExtractMatchedText},
	}
	extracts, known := allowed[r.Match.Kind]
	if !known {
		return fmt.Errorf("match.kind %q is not a matcher this build implements", r.Match.Kind)
	}
	if r.Match.Extract == "" {
		return fmt.Errorf("match.extract is required: %s has nothing to judge without it", r.Match.Kind)
	}
	if !containsExtract(extracts, r.Match.Extract) {
		return fmt.Errorf("match.extract %q has no reading under match.kind %s (accepted: %s)",
			r.Match.Extract, r.Match.Kind, joinExtracts(extracts))
	}

	switch r.Match.Condition {
	case ConditionAlways:
	case ConditionValueMatches:
		if r.Match.pattern == nil {
			return errors.New("condition value-matches needs match.pattern to compare against")
		}
	case ConditionHostNotInExpected:
		if r.Match.Extract != ExtractURLArgument {
			return fmt.Errorf("condition host-not-in-expected needs extract url-argument, not %q", r.Match.Extract)
		}
	case ConditionPathOutsideExpected:
		if r.Match.Extract != ExtractPathArgument {
			return fmt.Errorf("condition path-outside-expected needs extract path-argument, not %q", r.Match.Extract)
		}
	case ConditionVersionUnpinned:
		if r.Match.Kind != KindDepManifest {
			return fmt.Errorf("condition version-unpinned is only readable under dep-manifest, not %s", r.Match.Kind)
		}
	default:
		return fmt.Errorf("match.condition %q is not a predicate this build implements", r.Match.Condition)
	}

	switch r.Match.Kind {
	case KindRegex:
		if r.Match.pattern == nil {
			return errors.New("match.kind regex needs match.pattern")
		}
	case KindShellAST:
		// An empty `command` is legitimate — it means every command — but a rule
		// that matches every command with condition `always` fires on every script
		// in the catalog, which is a rule that says nothing.
		if len(r.Match.Command) == 0 && r.Match.Condition == ConditionAlways {
			return errors.New("match.kind shell-ast with no command list and condition always matches every script")
		}
	case KindSchemaPath:
		if r.Evidence.Quote != QuoteSchemaError && r.Match.Pointer == "" {
			return errors.New("match.kind schema-path needs match.pointer unless it quotes a schema-error")
		}
	case KindDepManifest:
	}
	return nil
}

// globRegexp compiles a `paths` glob. `**` crosses directory separators and `*`
// does not, which is the convention every reader already has from .gitignore and
// from tooling configuration; path.Match alone cannot express the first.
func globRegexp(glob string) (*regexp.Regexp, error) {
	if strings.TrimSpace(glob) == "" {
		return nil, errors.New("match.paths holds an empty glob")
	}

	var out strings.Builder
	out.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			out.WriteString("(?:.*/)?")
			i += 2
		case glob[i] == '*':
			out.WriteString("[^/]*")
		case glob[i] == '?':
			out.WriteString("[^/]")
		default:
			out.WriteString(regexp.QuoteMeta(glob[i : i+1]))
		}
	}
	out.WriteString("$")

	compiled, err := regexp.Compile(out.String())
	if err != nil {
		return nil, fmt.Errorf("match.paths glob %q does not compile: %w", glob, err)
	}
	return compiled, nil
}

func containsExtract(haystack []Extract, want Extract) bool {
	for _, candidate := range haystack {
		if candidate == want {
			return true
		}
	}
	return false
}

func joinExtracts(values []Extract) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return strings.Join(out, ", ")
}
