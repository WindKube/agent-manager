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
// experimental `allowed-tools`. A key outside that set fails validation.
type Skill struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	License     string `yaml:"license,omitempty"`

	// AllowedTools is experimental and is not an enforcement mechanism: the
	// spec says it grants pre-approval but does not block others. It is
	// recorded and displayed; the scanner's inferred capabilities are the
	// actual control.
	AllowedTools []string `yaml:"allowed-tools,omitempty"`

	Metadata      map[string]any `yaml:"metadata,omitempty"`
	Compatibility map[string]any `yaml:"compatibility,omitempty"`

	// raw is the whole SKILL.md, stored beside the bundle: the manifest
	// object for a standalone skill is the file, not the frontmatter.
	raw []byte
}

func (s *Skill) Raw() []byte { return s.raw }

// ManifestJSON renders the frontmatter as the jsonb `version.manifest`
// column holds, since a Markdown file is not json.
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

// frontmatterFence is the only delimiter accepted: a SKILL.md fenced some
// other way has no frontmatter, and guessing would admit a file whose first
// lines happen to look like YAML.
var frontmatterFence = []byte("---")

// maxFrontmatterBytes bounds the block before parsing: a YAML parser is a
// poor place to discover a 25 MB file has no closing fence.
const maxFrontmatterBytes = 64 << 10

func splitFrontmatter(raw []byte) ([]byte, error) {
	fail := func(message string) error {
		return manifestError(SkillManifest, SkillFrontmatterSchema, Problem{
			SchemaPath: "/", Message: message,
		})
	}

	// A UTF-8 BOM before the fence is common and not a reason to reject.
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

// yamlToJSONDocument re-encodes a YAML block as a JSON document: a JSON
// Schema validator applies JSON type rules, and YAML's differ (`1.0` is a
// float in YAML and a string in JSON, `yes` is a bool in YAML 1.1), so
// validating the YAML decoder's output directly would let schema and
// decoder disagree about a value's type.
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
	// KnownFields is the yaml half of additionalProperties: false.
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
