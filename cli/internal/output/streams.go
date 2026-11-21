package output

import (
	"fmt"
	"io"
)

// Streams is the result and diagnostic writers plus the renderer chosen by --output.
// Under FormatJSON the result stream carries one document and nothing else.
type Streams struct {
	Result io.Writer
	Diag   io.Writer

	renderer Renderer
	format   Format
	verbose  bool
}

// NewStreams pairs a format with the result and diagnostic writers.
func NewStreams(format Format, result, diag io.Writer) *Streams {
	return &Streams{Result: result, Diag: diag, renderer: RendererFor(format), format: format}
}

func (s *Streams) Format() Format { return s.format }

// SetVerbose enables the Debugf stream (-v).
func (s *Streams) SetVerbose(v bool) { s.verbose = v }

// Emit renders the verb's one result; calling it twice breaks the one-document JSON contract.
func (s *Streams) Emit(r Result) error {
	return s.renderer.Render(s.Result, r)
}

// Warnf reports a non-fatal problem on the diagnostic stream.
func (s *Streams) Warnf(format string, args ...any) {
	s.diagf("warning: ", format, args...)
}

// Errorf reports a failure on the diagnostic stream.
func (s *Streams) Errorf(format string, args ...any) {
	s.diagf("error: ", format, args...)
}

// Debugf is -v output, dropped rather than buffered when verbose is off.
func (s *Streams) Debugf(format string, args ...any) {
	if !s.verbose {
		return
	}
	s.diagf("", format, args...)
}

func (s *Streams) diagf(prefix, format string, args ...any) {
	if s.Diag == nil {
		return
	}
	// A closed stderr must not turn a working sync into a failure.
	_, _ = fmt.Fprintf(s.Diag, prefix+format+"\n", args...)
}
