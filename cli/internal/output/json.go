package output

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSONRenderer writes exactly one JSON document per run: an envelope of kind
// plus result, so a script can switch on the verb without knowing which it ran.
type JSONRenderer struct{}

type envelope struct {
	Kind   string `json:"kind"`
	Result Result `json:"result"`
}

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
