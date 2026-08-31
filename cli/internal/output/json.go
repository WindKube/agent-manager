package output

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSONRenderer writes exactly one JSON document per run.
//
// The envelope — kind plus result — exists so a script can switch on the verb
// without knowing which one it invoked, and so a future field can be added
// beside the result instead of inside it. Encoder.Encode writes one value and
// one trailing newline; nothing else in this package writes to the result
// stream, which is what makes the document parseable even when the run
// produced warnings (FR-035). Warnings went to the diagnostic stream.
type JSONRenderer struct{}

type envelope struct {
	Kind   string `json:"kind"`
	Result Result `json:"result"`
}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r Result) error {
	if r == nil {
		return nil
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope{Kind: r.Kind(), Result: r}); err != nil {
		return fmt.Errorf("render %s result as json: %w", r.Kind(), err)
	}
	return nil
}
