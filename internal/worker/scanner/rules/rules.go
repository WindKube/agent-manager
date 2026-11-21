// Package rules is the scanner's rule pack: detection rules as versioned YAML
// data, so tuning a rule needs no deploy. Detection classes are Go, selected by
// a closed `match.kind`/`extract`/`condition` vocabulary.
//
// A rule naming something this build does not implement fails the load, since a
// rule that silently matches nothing is indistinguishable from a clean package.
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

// Pack directory layout, identical for the embedded and mounted copies.
const (
	ManifestFile = "pack.yaml"
	// RulesDir holds one YAML document per rule, named <RULE-ID>.yaml.
	RulesDir    = "rules"
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
	KindShellAST      Kind = "shell-ast"
	KindRegex         Kind = "regex"
	KindSchemaPath    Kind = "schema-path"
	KindDepManifest   Kind = "dep-manifest"
	KindPluginSurface Kind = "plugin-surface"
)

// Extract names the value a match yields for its condition to judge.
type Extract string

const (
	ExtractURLArgument  Extract = "url-argument"
	ExtractPathArgument Extract = "path-argument"
	ExtractPackageSpec  Extract = "package-spec"
	ExtractMatchedText  Extract = "matched-text"
	ExtractPointerValue Extract = "pointer-value"
	// ExtractLauncherPackage yields `launcher spec` for npx, uvx, docker run and similar.
	ExtractLauncherPackage Extract = "launcher-package"
	// ExtractHookTrigger yields a hook's `Event:matcher`.
	ExtractHookTrigger Extract = "hook-trigger"
	ExtractGrantedTool Extract = "granted-tool"
)

// Condition is the named predicate applied to an extracted value.
type Condition string

const (
	ConditionAlways Condition = "always"
	// ConditionHostNotInExpected matches every host when nothing was declared,
	// so omitting a declaration never passes silently.
	ConditionHostNotInExpected   Condition = "host-not-in-expected"
	ConditionPathOutsideExpected Condition = "path-outside-expected"
	ConditionVersionUnpinned     Condition = "version-unpinned"
	ConditionValueMatches        Condition = "value-matches"
	ConditionLauncherUnpinned    Condition = "launcher-unpinned"
	// ConditionHostNotDeclared is a host outside the manifest's homepage and
	// repository domains and match.allow.
	ConditionHostNotDeclared Condition = "host-not-declared"
)

// Quote is which text a finding's evidence quotes.
type Quote string

const (
	QuoteMatchedNode Quote = "matched-node"
	QuoteMatchedLine Quote = "matched-line"
	// QuoteSchemaError is the validator's message, for document-level checks
	// that have no matched text.
	QuoteSchemaError Quote = "schema-error"
)

// Match is a rule's matcher configuration.
type Match struct {
	Kind    Kind     `yaml:"kind"`
	Command []string `yaml:"command"`
	Pattern string   `yaml:"pattern"`
	Paths   []string `yaml:"paths"`
	Pointer string   `yaml:"pointer"`
	// Allow lists extra hosts host-not-declared accepts.
	Allow     []string  `yaml:"allow"`
	Extract   Extract   `yaml:"extract"`
	Condition Condition `yaml:"condition"`

	// Compiled at load, so a bad pattern or glob fails the load instead of never firing.
	pattern *regexp.Regexp
	scope   []*regexp.Regexp
}

// Regexp is the compiled RE2 pattern, or nil when the rule carries none.
func (m Match) Regexp() *regexp.Regexp { return m.pattern }

// InScope reports whether the rule looks at a path; no `paths` means every file.
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

type Evidence struct {
	Quote Quote `yaml:"quote"`
	// ContextLines is a pointer because zero is meaningful; nil takes the default of 1.
	ContextLines *int `yaml:"contextLines"`
}

// Lines is ContextLines with the schema's default applied.
func (e Evidence) Lines() int {
	if e.ContextLines == nil {
		return 1
	}
	return *e.ContextLines
}

// Fixtures are the bundles that must and must not trip the rule. The negative
// one is what stops a rule that matches everything from shipping.
type Fixtures struct {
	Trips string `yaml:"trips"`
	Clean string `yaml:"clean"`
}

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

type Pack struct {
	version  string
	declared string
	origin   string
	rules    []Rule
	fsys     fs.FS
}

// Version is the declared version plus a digest of the rule content, so tuning
// a pattern without bumping the declared version still triggers rescans.
func (p *Pack) Version() string { return p.version }

// Declared is the pack's own version, without the content digest.
func (p *Pack) Declared() string { return p.declared }

// Origin says where the pack was loaded from.
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

// Len returns the number of rules.
func (p *Pack) Len() int { return len(p.rules) }

// FS returns the filesystem the pack was loaded from.
func (p *Pack) FS() fs.FS { return p.fsys }

// Load reads a pack from any filesystem: embedded, mounted, or a test MapFS.
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
		// Catches a copied rule file whose id was never edited.
		if base := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml"); base != rule.ID {
			return nil, fmt.Errorf("%w: %s declares rule %s; the file must be named %s.yaml",
				ErrPack, rulePath, rule.ID, rule.ID)
		}
		seen[rule.ID] = rulePath
		pack.rules = append(pack.rules, *rule)

		// ReadDir is sorted, so identical rules always produce the same digest.
		_, _ = digest.Write([]byte(rule.ID + "\x00"))
		_, _ = digest.Write(raw)
		_, _ = digest.Write([]byte{'\n'})
	}

	if len(pack.rules) == 0 {
		// An empty pack would clear every bundle, so it is a load failure.
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

func decodeRule(validator *jsonschema.Schema, rulePath string, raw []byte) (*Rule, error) {
	// Round-tripped through JSON because the validator applies JSON type rules,
	// which differ from YAML's.
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

// compile also rejects field combinations the per-field schema cannot express,
// such as `value-matches` without a pattern.
func (r *Rule) compile() error {
	// The schema's minLength does not catch whitespace-only text.
	if strings.TrimSpace(r.Title) == "" {
		return errors.New("rule has no title")
	}
	if strings.TrimSpace(r.Detail) == "" {
		return errors.New("rule has no detail: a finding with no prose cannot be triaged")
	}

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
		KindShellAST:      {ExtractURLArgument, ExtractPathArgument, ExtractMatchedText, ExtractLauncherPackage},
		KindRegex:         {ExtractURLArgument, ExtractPathArgument, ExtractMatchedText},
		KindDepManifest:   {ExtractPackageSpec},
		KindSchemaPath:    {ExtractPointerValue, ExtractMatchedText},
		KindPluginSurface: {ExtractURLArgument, ExtractHookTrigger, ExtractGrantedTool},
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
	case ConditionLauncherUnpinned:
		if r.Match.Extract != ExtractLauncherPackage {
			return fmt.Errorf("condition launcher-unpinned needs extract launcher-package, not %q", r.Match.Extract)
		}
	case ConditionHostNotDeclared:
		if r.Match.Extract != ExtractURLArgument {
			return fmt.Errorf("condition host-not-declared needs extract url-argument, not %q", r.Match.Extract)
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
		// An empty `command` means every command; with `always` it would fire on every script.
		if len(r.Match.Command) == 0 && r.Match.Condition == ConditionAlways {
			return errors.New("match.kind shell-ast with no command list and condition always matches every script")
		}
	case KindSchemaPath:
		if r.Evidence.Quote != QuoteSchemaError && r.Match.Pointer == "" {
			return errors.New("match.kind schema-path needs match.pointer unless it quotes a schema-error")
		}
	case KindDepManifest, KindPluginSurface:
	}
	return nil
}

// globRegexp compiles a `paths` glob where `**` crosses directories and `*` does
// not, which path.Match cannot express.
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
