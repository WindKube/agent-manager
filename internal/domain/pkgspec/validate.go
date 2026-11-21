package pkgspec

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ErrManifestInvalid is the sentinel behind every manifest rejection. It is an
// ingestion failure, not a scan finding: no version is created.
var ErrManifestInvalid = errors.New("manifest does not conform to its published schema")

// Problem is one schema violation, addressed by the schema path that rejected it.
type Problem struct {
	SchemaPath   string
	InstancePath string
	Message      string
}

func (p Problem) String() string {
	instance := p.InstancePath
	if instance == "" {
		instance = "/"
	}
	return fmt.Sprintf("%s at %s: %s", p.SchemaPath, instance, p.Message)
}

type ManifestError struct {
	Manifest string
	SchemaID string
	Problems []Problem
}

func (e *ManifestError) Error() string {
	lines := make([]string, 0, len(e.Problems))
	for _, p := range e.Problems {
		lines = append(lines, p.String())
	}
	msg := e.Manifest + " " + ErrManifestInvalid.Error()
	if e.SchemaID != "" {
		msg = e.Manifest + " does not conform to " + e.SchemaID
	}
	if len(lines) == 0 {
		return msg
	}
	return msg + ": " + strings.Join(lines, "; ")
}

func (e *ManifestError) Unwrap() error { return ErrManifestInvalid }

func manifestError(manifest, schemaID string, problems ...Problem) *ManifestError {
	return &ManifestError{Manifest: manifest, SchemaID: schemaID, Problems: problems}
}

// Validator holds the compiled schemas and is safe for concurrent use.
type Validator struct {
	compiled map[string]*jsonschema.Schema
}

var (
	sharedOnce sync.Once
	shared     *Validator
	sharedErr  error
)

// Default returns the process-wide Validator.
func Default() (*Validator, error) {
	sharedOnce.Do(func() { shared, sharedErr = NewValidator() })
	return shared, sharedErr
}

func NewValidator() (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	// AssertFormat stays off: `format` is annotation-only in 2020-12.
	compiled := make(map[string]*jsonschema.Schema, len(schemaFiles))

	ids := SchemaIDs()
	for _, id := range ids {
		raw, err := RawSchema(id)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("decode embedded schema %s: %w", id, err)
		}

		// RE2 has no lookahead, so the `name` pattern is lifted (name.go); a
		// schema where the lift no longer applies must fail, not silently pass.
		lifted, replacements := liftNameLookahead(doc)
		if carriesNameLookahead(raw) && replacements == 0 {
			return nil, fmt.Errorf("schema %s carries the lookahead `name` pattern but no replacement was made", id)
		}
		if !carriesNameLookahead(raw) && replacements > 0 {
			return nil, fmt.Errorf("schema %s does not carry the lookahead `name` pattern yet %d replacements were made", id, replacements)
		}

		if err := compiler.AddResource(id, lifted); err != nil {
			return nil, fmt.Errorf("add embedded schema %s: %w", id, err)
		}
	}
	for _, id := range ids {
		schema, err := compiler.Compile(id)
		if err != nil {
			return nil, fmt.Errorf("compile embedded schema %s: %w", id, err)
		}
		compiled[id] = schema
	}
	return &Validator{compiled: compiled}, nil
}

// ValidatePluginManifest validates plugin.json against the schema its own
// `$schema` names. A missing or unknown `$schema` is rejected rather than
// defaulted.
func (v *Validator) ValidatePluginManifest(raw []byte) (*Plugin, error) {
	schemaID, err := v.validateAgainstDeclaredSchema(PluginManifest, raw, pluginSchemaIDs)
	if err != nil {
		return nil, err
	}

	plugin, err := decodePlugin(raw, schemaID)
	if err != nil {
		return nil, err
	}
	// The half of the `name` rule RE2 cannot express.
	if problems := CheckName(plugin.Name); len(problems) > 0 {
		return nil, manifestError(PluginManifest, schemaID, problems...)
	}
	return plugin, nil
}

// ValidateMCPConfig validates mcp.json against either published version.
func (v *Validator) ValidateMCPConfig(raw []byte) (*MCPConfig, error) {
	schemaID, err := v.validateAgainstDeclaredSchema(MCPConfigFile, raw, mcpSchemaIDs)
	if err != nil {
		return nil, err
	}
	return decodeMCPConfig(raw, schemaID)
}

// ValidateSkillFrontmatter validates a SKILL.md's YAML frontmatter against
// the project-authored key set.
func (v *Validator) ValidateSkillFrontmatter(raw []byte) (*Skill, error) {
	frontmatter, err := splitFrontmatter(raw)
	if err != nil {
		return nil, err
	}

	// Re-encode as JSON so the validator and decoder agree on value types.
	doc, err := yamlToJSONDocument(frontmatter)
	if err != nil {
		return nil, err
	}

	schema := v.compiled[SkillFrontmatterSchema]
	if schema == nil {
		return nil, fmt.Errorf("no compiled schema for %s", SkillFrontmatterSchema)
	}
	if validateErr := schema.Validate(doc); validateErr != nil {
		return nil, manifestError(SkillManifest, SkillFrontmatterSchema, problemsFrom(validateErr)...)
	}

	skill, err := decodeSkill(frontmatter)
	if err != nil {
		return nil, err
	}
	if problems := CheckName(skill.Name); len(problems) > 0 {
		return nil, manifestError(SkillManifest, SkillFrontmatterSchema, problems...)
	}
	skill.raw = append([]byte(nil), raw...)
	return skill, nil
}

func (v *Validator) validateAgainstDeclaredSchema(manifest string, raw []byte, accepted []string) (string, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return "", manifestError(manifest, "", Problem{
			SchemaPath: "/", Message: "not valid json: " + err.Error(),
		})
	}

	object, ok := doc.(map[string]any)
	if !ok {
		return "", manifestError(manifest, "", Problem{
			SchemaPath: "/type", Message: "top level is not a json object",
		})
	}

	declared, _ := object["$schema"].(string)
	if declared == "" {
		return "", manifestError(manifest, "", Problem{
			SchemaPath:   "/required",
			InstancePath: "/$schema",
			Message:      "$schema is required and names which published schema applies; accepted: " + strings.Join(accepted, ", "),
		})
	}
	if !containsString(accepted, declared) {
		return "", manifestError(manifest, "", Problem{
			SchemaPath:   "/properties/$schema/const",
			InstancePath: "/$schema",
			Message:      fmt.Sprintf("$schema %q is not a schema this build holds; accepted: %s", declared, strings.Join(accepted, ", ")),
		})
	}

	schema := v.compiled[declared]
	if schema == nil {
		return "", fmt.Errorf("no compiled schema for %s", declared)
	}
	if validateErr := schema.Validate(doc); validateErr != nil {
		return declared, manifestError(manifest, declared, problemsFrom(validateErr)...)
	}
	return declared, nil
}

// problemsFrom flattens a jsonschema failure via BasicOutput, whose keyword
// location is the schema path.
func problemsFrom(err error) []Problem {
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return []Problem{{SchemaPath: "/", Message: err.Error()}}
	}

	basic := verr.BasicOutput()
	problems := make([]Problem, 0, len(basic.Errors)+1)
	for _, unit := range basic.Errors {
		if unit.Error == nil {
			continue
		}
		problems = append(problems, Problem{
			SchemaPath:   unit.KeywordLocation,
			InstancePath: unit.InstanceLocation,
			Message:      unit.Error.String(),
		})
	}
	if len(problems) == 0 {
		problems = append(problems, Problem{
			SchemaPath:   basic.KeywordLocation,
			InstancePath: basic.InstanceLocation,
			Message:      verr.Error(),
		})
	}
	sort.SliceStable(problems, func(i, j int) bool {
		if problems[i].InstancePath != problems[j].InstancePath {
			return problems[i].InstancePath < problems[j].InstancePath
		}
		return problems[i].SchemaPath < problems[j].SchemaPath
	})
	return problems
}

func containsString(haystack []string, want string) bool {
	for _, s := range haystack {
		if s == want {
			return true
		}
	}
	return false
}
