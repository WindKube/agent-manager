// Package output renders each verb's result as prose or as a single JSON document.
// Results go to the result stream and diagnostics to the diagnostic stream, so JSON stays parseable.
package output

import (
	"fmt"
	"io"
)

// Format is the value of --output.
type Format string

const (
	// FormatHuman is prose for a person; its wording is not a contract.
	FormatHuman Format = "human"
	// FormatJSON is one JSON document per run, on the result stream.
	FormatJSON Format = "json"
)

// Formats lists every accepted --output value.
func Formats() []Format { return []Format{FormatHuman, FormatJSON} }

func ParseFormat(s string) (Format, error) {
	for _, f := range Formats() {
		if Format(s) == f {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown output format %q: expected %s or %s", s, FormatHuman, FormatJSON)
}

// Result is what a verb produced. Both renderers work over this interface rather
// than a type switch, so adding a verb cannot silently miss a renderer.
type Result interface {
	// Kind names the verb; it is the "kind" field of the JSON document.
	Kind() string
	// Human writes the operator-facing rendering.
	Human(w io.Writer) error
}

// Renderer writes a Result to a stream and nothing anywhere else: under JSON the
// result stream must carry exactly one document.
type Renderer interface {
	Render(w io.Writer, r Result) error
}

// RendererFor returns the renderer for a format. An unknown format falls back to
// human rather than to nothing; ParseFormat is what rejects bad input.
func RendererFor(f Format) Renderer {
	if f == FormatJSON {
		return JSONRenderer{}
	}
	return HumanRenderer{}
}
