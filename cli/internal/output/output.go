// Package output renders one result type per verb, in either of two formats.
//
// The invariant this package exists to hold (FR-035): a *result* goes to the
// result stream, and every diagnostic — a warning, a progress line, a
// best-effort sync report that failed — goes to the diagnostic stream. Under
// `--output json` that is what makes stdout a single parseable document no
// matter how much went sideways on the way, so a script never has to sieve
// prose out of JSON.
//
// What this package deliberately does not do: it never touches os.Stdout or
// os.Stderr. Every entry point takes an io.Writer, because a renderer that
// reaches for the process's own streams cannot be tested and cannot be
// redirected.
package output

import (
	"fmt"
	"io"
)

// Format is the value of --output.
type Format string

const (
	// FormatHuman is prose for a person at a terminal. Its exact wording is not
	// a contract and must never be parsed.
	FormatHuman Format = "human"
	// FormatJSON is the machine-facing rendering: one JSON document per run, on
	// the result stream.
	FormatJSON Format = "json"
)

// Formats lists every accepted --output value, in the order the flag's help
// text should show them.
func Formats() []Format { return []Format{FormatHuman, FormatJSON} }

// ParseFormat validates an --output value. An unrecognised value is a refusal
// the user can fix, so the error names what was accepted rather than only what
// was rejected.
func ParseFormat(s string) (Format, error) {
	for _, f := range Formats() {
		if Format(s) == f {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown output format %q: expected %s or %s", s, FormatHuman, FormatJSON)
}

// Result is what a verb produced. Every verb has exactly one result type, and
// both renderers work over this interface rather than over a switch on
// concrete types, so adding a verb cannot silently miss a renderer.
type Result interface {
	// Kind names the verb that produced this result. It is the "kind" field of
	// the JSON document and the key a script switches on.
	Kind() string
	// Human writes the operator-facing rendering to w.
	Human(w io.Writer) error
}

// Renderer writes a Result to a stream. Implementations must write nothing
// anywhere else: a renderer that also emits a warning breaks the one guarantee
// the JSON format offers.
type Renderer interface {
	Render(w io.Writer, r Result) error
}

// RendererFor returns the renderer for a format. An unknown format falls back
// to human rather than to nothing, because a silently empty result stream is
// the worst of the three outcomes; ParseFormat is what rejects bad input.
func RendererFor(f Format) Renderer {
	if f == FormatJSON {
		return JSONRenderer{}
	}
	return HumanRenderer{}
}
