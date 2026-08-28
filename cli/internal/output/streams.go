package output

import (
	"fmt"
	"io"
)

// Streams is the pair of writers a command is given, plus the renderer chosen
// by --output. It is the only thing a verb needs to produce output, and it is
// the reason "results on stdout, diagnostics on stderr" is a property of the
// type rather than a rule people remember.
//
// There is no method here that writes a result to Diag or a diagnostic to
// Result, and adding one would defeat the whole package: under FormatJSON the
// result stream must carry one document and nothing else.
type Streams struct {
	// Result is where the verb's Result lands: stdout, in production.
	Result io.Writer
	// Diag is where warnings, progress and failures land: stderr, in
	// production. Everything written here is invisible to a script parsing the
	// result stream, which is the point.
	Diag io.Writer

	renderer Renderer
	format   Format
	verbose  bool
}

// NewStreams pairs a format with the two writers. Pass the real os.Stdout and
// os.Stderr exactly once, in main; everything below takes Streams.
func NewStreams(format Format, result, diag io.Writer) *Streams {
	return &Streams{Result: result, Diag: diag, renderer: RendererFor(format), format: format}
}

// Format reports which rendering was selected, for the few decisions that
// legitimately differ — a progress spinner is pointless under --output json.
func (s *Streams) Format() Format { return s.format }

// SetVerbose enables the Debugf stream (-v).
func (s *Streams) SetVerbose(v bool) { s.verbose = v }

// Emit renders the verb's one result to the result stream. Calling it twice in
// one run is a bug: under FormatJSON it would produce two documents where the
// contract promises one.
func (s *Streams) Emit(r Result) error {
	return s.renderer.Render(s.Result, r)
}

// Warnf reports something the user should know about a run that is still
// succeeding — a credential store that fell back (FR-003), a sync report the
// hub refused (FR-033). Always the diagnostic stream, in every format.
func (s *Streams) Warnf(format string, args ...any) {
	s.diagf("warning: ", format, args...)
}

// Errorf reports a failure. Also the diagnostic stream: an error rendered into
// stdout would corrupt the JSON document a script is reading.
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
	// A failed write to the diagnostic stream is deliberately swallowed: a
	// closed stderr must not turn a working sync into a failure, and there is
	// nowhere left to report it to anyway.
	_, _ = fmt.Fprintf(s.Diag, prefix+format+"\n", args...)
}
