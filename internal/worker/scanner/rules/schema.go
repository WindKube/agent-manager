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

// A copy of the canonical contract, since embed cannot leave the package
// directory; TestTheEmbeddedSchemaIsByteIdenticalToTheContract keeps them byte-identical.
//
//go:embed rulepack.schema.json
var schemaFS embed.FS

var (
	validatorOnce sync.Once
	validator     *jsonschema.Schema
	validatorErr  error
)

// ruleValidator compiles the rule schema once per process.
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
