package output

import (
	"fmt"
	"io"
)

// Streams is the pair of writers a command is given plus the renderer chosen by
// --output. Nothing here writes a result to Diag or a diagnostic to Result:
// under FormatJSON the result stream carries one document and nothing else.
type Streams struct {
	// Result is stdout in production.
	Result io.Writer
	// Diag is stderr in production; a script parsing the result stream never sees it.
	Diag io.Writer

	renderer Renderer
	format   Format
	verbose  bool
}

// NewStreams pairs a format with the two writers; main passes the real os.Stdout and os.Stderr exactly once.
func NewStreams(format Format, result, diag io.Writer) *Streams {
	return &Streams{Result: result, Diag: diag, renderer: RendererFor(format), format: format}
}

func (s *Streams) Format() Format { return s.format }

// SetVerbose enables the Debugf stream (-v).
func (s *Streams) SetVerbose(v bool) { s.verbose = v }

// Emit renders the verb's one result. Calling it twice in one run is a bug:
// under FormatJSON it would produce two documents where the contract promises one.
func (s *Streams) Emit(r Result) error {
	return s.renderer.Render(s.Result, r)
}

// Warnf reports something the user should know about a run that is still
// succeeding. Always the diagnostic stream, in every format.
func (s *Streams) Warnf(format string, args ...any) {
	s.diagf("warning: ", format, args...)
}

// Errorf reports a failure, also on the diagnostic stream.
func (s *Streams) Errorf(format string, args ...any) {
	s.diagf("error: ", format, args...)
}

// Debugf is -v output. Dropped entirely without it, rather than buffered.
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
	// A failed write to the diagnostic stream is swallowed: a closed stderr must
	// not turn a working sync into a failure.
	_, _ = fmt.Fprintf(s.Diag, prefix+format+"\n", args...)
}
