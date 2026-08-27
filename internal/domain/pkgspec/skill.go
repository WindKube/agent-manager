package pkgspec

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// Skill is the YAML frontmatter of a `SKILL.md`: required `name` and
// `description`, optional `license`, `metadata`, `compatibility`, and the
// experimental `allowed-tools`. A key outside that set fails validation (R1).
type Skill struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	License     string `yaml:"license,omitempty"`

	// AllowedTools is EXPERIMENTAL and is NOT an enforcement mechanism: the Agent
	// Skills spec states it grants pre-approval for the listed tools but does not
	// block others. It is recorded and displayed; nothing reads it as a permission
	// boundary, and the scanner's inferred capabilities are the control (FR-018).
	AllowedTools []string `yaml:"allowed-tools,omitempty"`

	Metadata      map[string]any `yaml:"metadata,omitempty"`
	Compatibility map[string]any `yaml:"compatibility,omitempty"`

	// raw is the whole SKILL.md, which is what gets stored beside the bundle
	// (FR-006): the manifest object for a standalone skill is the file, not the
	// frontmatter.
	raw []byte
}

// Raw is the SKILL.md bytes exactly as read.
func (s *Skill) Raw() []byte { return s.raw }

// ManifestJSON renders the frontmatter as the jsonb `version.manifest` column
// holds. The column is `notnull` jsonb for both kinds, and a Markdown file is not
// json, so a skill's manifest column carries its frontmatter.
func (s *Skill) ManifestJSON() (json.RawMessage, error) {
	encoded, err := json.Marshal(map[string]any{
		"name":          s.Name,
		"description":   s.Description,
		"license":       s.License,
		"allowed-tools": s.AllowedTools,
		"metadata":      s.Metadata,
		"compatibility": s.Compatibility,
	})
	if err != nil {
		return nil, fmt.Errorf("encode skill frontmatter: %w", err)
	}
	return encoded, nil
}

// frontmatterFence is the delimiter, and the only one accepted. A SKILL.md whose
// frontmatter is fenced some other way has no frontmatter as far as the spec is
// concerned, and guessing would admit a file whose first lines happen to look
// like YAML.
var frontmatterFence = []byte("---")

// maxFrontmatterBytes bounds the block before it is parsed. The file itself is
// already under the per-entry extraction cap, but a YAML parser is a poor place
// to discover that a 25 MB file has no closing fence.
const maxFrontmatterBytes = 64 << 10

// splitFrontmatter returns the YAML block between the opening and closing fences.
func splitFrontmatter(raw []byte) ([]byte, error) {
	fail := func(message string) error {
		return manifestError(SkillManifest, SkillFrontmatterSchema, Problem{
			SchemaPath: "/", Message: message,
		})
	}

	// A UTF-8 BOM before the fence is common from Windows editors and is not a
	// reason to reject the file.
	body := bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	body = bytes.TrimLeft(body, " \t\r\n")

	if !bytes.HasPrefix(body, frontmatterFence) {
		return nil, fail("no yaml frontmatter: the file must open with a --- fence")
	}
	rest := body[len(frontmatterFence):]
	if len(rest) > 0 && rest[0] != '\n' && rest[0] != '\r' {
		return nil, fail("no yaml frontmatter: the opening --- must be alone on its line")
	}

	end := bytes.Index(rest, append([]byte("\n"), frontmatterFence...))
	if end < 0 {
		return nil, fail("yaml frontmatter has no closing --- fence")
	}
	block := rest[:end]
	if len(block) > maxFrontmatterBytes {
		return nil, fail(fmt.Sprintf("yaml frontmatter is %d bytes, over the %d byte limit", len(block), maxFrontmatterBytes))
	}
	return block, nil
}

// yamlToJSONDocument re-encodes a YAML block as a JSON document.
//
// The round trip is deliberate: a JSON Schema validator applies JSON type rules,
// and YAML's are different — `1.0` is a float in YAML and a string in JSON, `yes`
// is a bool in YAML 1.1. Validating the YAML decoder's output directly would let
// the schema and the decoder disagree about a value's type, which is a schema that
// is not enforcing what it appears to.
func yamlToJSONDocument(block []byte) (any, error) {
	var intermediate any
	if err := yaml.Unmarshal(block, &intermediate); err != nil {
		return nil, manifestError(SkillManifest, SkillFrontmatterSchema, Problem{
			SchemaPath: "/", Message: "frontmatter is not valid yaml: " + err.Error(),
		})
	}
	if intermediate == nil {
		return nil, manifestError(SkillManifest, SkillFrontmatterSchema, Problem{
			SchemaPath: "/required", Message: "frontmatter is empty",
		})
	}

	encoded, err := json.Marshal(intermediate)
	if err != nil {
		return nil, manifestError(SkillManifest, SkillFrontmatterSchema, Problem{
			SchemaPath: "/type", Message: "frontmatter does not map onto json: " + err.Error(),
		})
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("re-read skill frontmatter as json: %w", err)
	}
	return doc, nil
}

func decodeSkill(block []byte) (*Skill, error) {
	// KnownFields is the yaml half of the schema's additionalProperties: false,
	// for the same reason the plugin decoder disallows unknown fields.
	decoder := yaml.NewDecoder(bytes.NewReader(block))
	decoder.KnownFields(true)

	var skill Skill
	if err := decoder.Decode(&skill); err != nil {
		return nil, manifestError(SkillManifest, SkillFrontmatterSchema, Problem{
			SchemaPath: "/additionalProperties", Message: err.Error(),
		})
	}
	return &skill, nil
}
