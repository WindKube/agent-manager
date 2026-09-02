package rules

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// SchemaID is the `$id` of the rule contract.
const SchemaID = "https://agent-manager.dev/schemas/1.0.0/rulepack.schema.json"

// rulepack.schema.json is a COPY of
// specs/001-agent-manager-hub/contracts/rulepack.schema.json, and it is a copy
// because go:embed cannot reach outside its own package directory while the
// contract has to stay where the feature's other contracts live.
//
// TestTheEmbeddedSchemaIsTheContract asserts the two files are byte-identical, so
// the copy cannot drift: a change to the contract that is not copied here fails
// the build rather than producing a loader that validates rules against a schema
// nobody agreed to.
//
//go:embed rulepack.schema.json
var schemaFS embed.FS

var (
	validatorOnce sync.Once
	validator     *jsonschema.Schema
	validatorErr  error
)

// ruleValidator compiles the rule schema once. Compiling it per rule file would
// be the most expensive thing in a pack load.
func ruleValidator() (*jsonschema.Schema, error) {
	validatorOnce.Do(func() {
		raw, err := schemaFS.ReadFile("rulepack.schema.json")
		if err != nil {
			validatorErr = fmt.Errorf("%w: read the embedded rule schema: %w", ErrPack, err)
			return
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			validatorErr = fmt.Errorf("%w: decode the embedded rule schema: %w", ErrPack, err)
			return
		}

		compiler := jsonschema.NewCompiler()
		if addErr := compiler.AddResource(SchemaID, document); addErr != nil {
			validatorErr = fmt.Errorf("%w: add the rule schema: %w", ErrPack, addErr)
			return
		}
		compiled, compileErr := compiler.Compile(SchemaID)
		if compileErr != nil {
			validatorErr = fmt.Errorf("%w: compile the rule schema: %w", ErrPack, compileErr)
			return
		}
		validator = compiled
	})
	return validator, validatorErr
}

// RawSchema returns the embedded contract copy, for the drift test.
func RawSchema() ([]byte, error) { return schemaFS.ReadFile("rulepack.schema.json") }

// yamlAsJSON decodes a YAML document and re-reads it as JSON, which is what makes
// the JSON Schema above apply JSON type rules to it.
func yamlAsJSON(raw []byte) (any, error) {
	var intermediate any
	if err := yaml.Unmarshal(raw, &intermediate); err != nil {
		return nil, fmt.Errorf("not valid yaml: %w", err)
	}
	if intermediate == nil {
		return nil, fmt.Errorf("document is empty")
	}

	encoded, err := json.Marshal(intermediate)
	if err != nil {
		return nil, fmt.Errorf("does not map onto json: %w", err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("re-read as json: %w", err)
	}
	return document, nil
}
