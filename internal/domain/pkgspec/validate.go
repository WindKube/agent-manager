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

// ErrManifestInvalid is the sentinel behind every manifest rejection (FR-004,
// US1 scenario 3). It is deliberately NOT a scan finding: a manifest that fails
// its schema means no version is created and nothing is written to object
// storage, so the failure belongs to ingestion.
var ErrManifestInvalid = errors.New("manifest does not conform to its published schema")

// Problem is one schema violation, addressed by the schema path that rejected it.
//
// SchemaPath is the load-bearing field: US1 scenario 3 requires the failure to be
// reported against the specific schema path, so a publisher is told which rule
// they broke rather than "invalid manifest".
type Problem struct {
	// SchemaPath is a JSON pointer into the schema, e.g.
	// "/additionalProperties" or "/properties/name/pattern".
	SchemaPath string

	// InstancePath is a JSON pointer into the manifest, e.g. "/keywords/2".
	InstancePath string

	Message string
}

func (p Problem) String() string {
	instance := p.InstancePath
	if instance == "" {
		instance = "/"
	}
	return fmt.Sprintf("%s at %s: %s", p.SchemaPath, instance, p.Message)
}

// ManifestError carries every problem found in one manifest.
type ManifestError struct {
	// Manifest is the file that failed: "plugin.json", "mcp.json" or "SKILL.md".
	Manifest string

	// SchemaID is the `$id` it was validated against, empty when the manifest
	// named none this project holds.
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

// Validator holds the compiled schemas. It is safe for concurrent use and is
// built once: compiling five schemas per request would be the second most
// expensive thing in the ingestion path.
type Validator struct {
	compiled map[string]*jsonschema.Schema
}

var (
	sharedOnce sync.Once
	shared     *Validator
	sharedErr  error
)

// Default returns the process-wide Validator. The schemas are embedded, so the
// only way this fails is a build that shipped a broken one — which is why the
// error is returned rather than panicked, and why every caller reports it.
func Default() (*Validator, error) {
	sharedOnce.Do(func() { shared, sharedErr = NewValidator() })
	return shared, sharedErr
}

// NewValidator compiles every embedded schema.
func NewValidator() (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	// AssertFormat is left off: `format` is annotation-only in 2020-12 and none of
	// the vendored schemas uses it. Turning it on would add rules the published
	// documents do not state.
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

		// RE2 has no lookahead, so the published `name` pattern cannot be compiled
		// as written (name.go). Lift it here and refuse a schema that was supposed
		// to carry it and no longer does: a dropped security rule must not be a
		// silent success.
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

// ValidatePluginManifest validates plugin.json against the published Agent
// Plugins schema its own `$schema` names (FR-004).
//
// It does not accept a manifest that omits `$schema`, or one that names a version
// this build does not hold: `$schema` is one of the two required fields, and
// choosing a schema for a manifest that did not choose one is how a
// non-conformant document gets in through a default.
func (v *Validator) ValidatePluginManifest(raw []byte) (*Plugin, error) {
	schemaID, err := v.validateAgainstDeclaredSchema(PluginManifest, raw, pluginSchemaIDs)
	if err != nil {
		return nil, err
	}

	plugin, err := decodePlugin(raw, schemaID)
	if err != nil {
		return nil, err
	}
	// The half of the published `name` rule RE2 cannot express, reported at the
	// same schema path the pattern would have used.
	if problems := CheckName(plugin.Name); len(problems) > 0 {
		return nil, manifestError(PluginManifest, schemaID, problems...)
	}
	return plugin, nil
}

// ValidateMCPConfig validates mcp.json.
//
// Measured while vendoring (schemas/PROVENANCE.md): mcp.schema.json is IDENTICAL
// between 1.0.0 and 1.1.0 — both require `{$schema, mcpServers}` — contrary to
// research.md R1, which said 1.1.0 changed it. So the version dispatch here has
// exactly one job: accept either `$id`.
func (v *Validator) ValidateMCPConfig(raw []byte) (*MCPConfig, error) {
	schemaID, err := v.validateAgainstDeclaredSchema(MCPConfigFile, raw, mcpSchemaIDs)
	if err != nil {
		return nil, err
	}
	return decodeMCPConfig(raw, schemaID)
}

// ValidateSkillFrontmatter validates the YAML frontmatter of a SKILL.md against
// the project-authored key set. A key outside the set fails validation (R1).
func (v *Validator) ValidateSkillFrontmatter(raw []byte) (*Skill, error) {
	frontmatter, err := splitFrontmatter(raw)
	if err != nil {
		return nil, err
	}

	// YAML is re-encoded as JSON before validation so the validator sees JSON
	// types — a YAML `1.0` is a float there and a string here, and a schema that
	// disagrees with the decoder about the type of a value is a schema that is not
	// being enforced.
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

// validateAgainstDeclaredSchema decodes raw, reads its `$schema`, and validates
// against that schema when it is one of accepted.
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

// problemsFrom flattens a jsonschema failure into Problems.
//
// BasicOutput's flat list is used rather than the rendered message because the
// keyword location IS the schema path US1 scenario 3 asks for; the rendered
// string buries it in prose.
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
