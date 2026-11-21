// Command openapigen writes the api role's OpenAPI document to a file, which
// `task gen:client` feeds to oapi-codegen. It opens no connection, so the output
// is reproducible anywhere.
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
	// The committed document must be byte-identical wherever this runs, or `task gen:check` flaps.
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
