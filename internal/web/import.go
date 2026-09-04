package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/starfederation/datastar-go/datastar"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// The registration modal's two round trips (US1, FR-001 and FR-005).
//
// The browser posts to the WEB role, which forwards to the api over
// internal/apiclient. It never addresses the api itself: a page that did would
// need the api reachable from the browser's network and would put the api's CORS
// policy in the critical path of a screen.

// maxImportBytes bounds the request at this hop. It is deliberately a shade
// larger than FR-001's 25 MB archive cap, because the real cap belongs to the
// api — the role that unpacks the bytes — and a web role that refused first
// would answer a size violation with a different message than the CLI gets. This
// is here only so a hostile body cannot make the hop buffer without limit.
const maxImportBytes = 27 << 20

// multipartMemory is how much of the form stays in memory before it spills to a
// temporary file. An archive is streamed onwards, so buffering it whole here
// would be paying twice.
const multipartMemory = 1 << 20

func (s *Server) importPreview(c *gin.Context) {
	if !s.parseImportForm(c) {
		return
	}

	file, header, err := c.Request.FormFile("archive")
	if err != nil {
		s.patchImportProblem(c, "attach an archive first")
		return
	}
	defer func() { _ = file.Close() }()

	preview, err := s.deps.Registrar.Preview(session(c), view.Archive{
		Filename: header.Filename,
		Size:     header.Size,
		Content:  file,
	})
	if err != nil {
		logFrom(c).Error().Err(err).Msg("preview archive")
		s.patchImportProblem(c, "the hub could not be reached")
		return
	}
	sse := datastar.NewSSE(c.Writer, c.Request)
	if err := sse.PatchElementTempl(components.ImportPreviewPanel(&preview)); err != nil {
		logFrom(c).Error().Err(err).Msg("patch import preview")
	}
}

func (s *Server) importRegister(c *gin.Context) {
	if !s.parseImportForm(c) {
		return
	}

	registration := view.Registration{
		URL:          c.PostForm("url"),
		Ref:          c.PostForm("ref"),
		Subdirectory: c.PostForm("subdirectory"),
		Publisher:    c.PostForm("publisher"),
		Version:      c.PostForm("version"),
		Category:     c.PostForm("category"),
		Visibility:   c.PostForm("visibility"),
	}
	// Which tab was showing is not sent as a signal — every modal signal is
	// underscore-prefixed and never leaves the browser — so it is inferred from
	// what arrived, which is also the only thing the api can act on.
	if file, header, err := c.Request.FormFile("archive"); err == nil {
		defer func() { _ = file.Close() }()
		registration.Tab = view.ImportUpload
		registration.Archive = &view.Archive{
			Filename: header.Filename, Size: header.Size, Content: file,
		}
	} else {
		registration.Tab = view.ImportURL
	}
	result, err := s.deps.Registrar.Register(session(c), registration)
	if err != nil {
		logFrom(c).Error().Err(err).Msg("register package")
		s.patchImportProblem(c, "the hub could not be reached")
		return
	}

	sse := datastar.NewSSE(c.Writer, c.Request)
	if err := sse.PatchElementTempl(components.ImportResultBanner(&result)); err != nil {
		logFrom(c).Error().Err(err).Msg("patch import result")
		return
	}
	// FR-005 again: a refusal that came with a report shows the report, so the
	// person can see which entry the hub objected to rather than only that it did.
	if result.Preview != nil {
		if err := sse.PatchElementTempl(components.ImportPreviewPanel(result.Preview)); err != nil {
			logFrom(c).Error().Err(err).Msg("patch import preview")
		}
	}
}

// parseImportForm parses the multipart body under a cap and refuses when the role has
// no registrar. Nil is a real state — the screen tests run against the fixture,
// which cannot register — so it is answered with the same banner a refusal uses
// rather than with a panic.
func (s *Server) parseImportForm(c *gin.Context) bool {
	if s.deps.Registrar == nil {
		s.patchImportProblem(c, "this hub is not configured to accept registrations")
		return false
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxImportBytes)
	if err := c.Request.ParseMultipartForm(multipartMemory); err != nil {
		logFrom(c).Warn().Err(err).Msg("parse the registration form")
		s.patchImportProblem(c, "that upload could not be read, or it is too large")
		return false
	}
	return true
}

// patchImportProblem answers with the modal's own banner rather than an HTTP
// status: the request came from datastar, and a bare 400 would leave the person
// looking at a modal that did nothing.
func (s *Server) patchImportProblem(c *gin.Context, message string) {
	sse := datastar.NewSSE(c.Writer, c.Request)
	if err := sse.PatchElementTempl(components.ImportResultBanner(
		&view.ImportResult{Message: message})); err != nil {
		logFrom(c).Error().Err(err).Msg("patch import problem")
	}
}
