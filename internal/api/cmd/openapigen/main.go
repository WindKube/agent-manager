// Command openapigen writes the api role's OpenAPI document to a file.
//
// This is the generator half of constitution principle V: `task gen:client` runs
// it and then points oapi-codegen at the result, so the typed client the web role
// uses is generated from the document the api EMITS — not from the frozen
// contract file, and never from a hand-written copy.
//
// It opens no connection: api.Document builds the whole surface from the
// operation definitions with a zero Deps, which is what makes the output
// reproducible on any machine and in CI.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"agent-manager/internal/api"
)

func main() {
	out := flag.String("out", "internal/apiclient/openapi.json", "file to write the document to")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "openapigen:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	// No servers and no deployment-specific anything: the committed document must
	// be byte-identical wherever this runs, or `task gen:check` flaps.
	encoded, err := json.MarshalIndent(api.Document(api.Options{}), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal document: %w", err)
	}
	encoded = append(encoded, '\n')

	if err := os.WriteFile(out, encoded, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("openapigen: wrote %s (%d bytes)\n", out, len(encoded))
	return nil
}
