package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/starfederation/datastar-go/datastar"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// maxImportBytes is a shade above the api's 25 MB archive cap so the api, not
// this hop, reports size violations; it only stops unbounded buffering.
const maxImportBytes = 27 << 20

// multipartMemory is how much of the form stays in memory before spilling to disk.
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

	preview, err := s.deps.Hub.Preview(session(c), view.Archive{
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
		Name:         c.PostForm("name"),
		Version:      c.PostForm("version"),
		Kind:         c.PostForm("kind"),
		Category:     c.PostForm("category"),
		Visibility:   c.PostForm("visibility"),
		Tags:         c.PostForm("tags"),
	}
	// Modal signals are underscore-prefixed and never sent, so the tab is inferred from what arrived.
	if file, header, err := c.Request.FormFile("archive"); err == nil {
		defer func() { _ = file.Close() }()
		registration.Tab = view.ImportUpload
		registration.Archive = &view.Archive{
			Filename: header.Filename, Size: header.Size, Content: file,
		}
	} else {
		registration.Tab = view.ImportURL
	}
	result, err := s.deps.Hub.Register(session(c), registration)
	if err != nil {
		logFrom(c).Error().Err(err).Msg("register package")
		s.patchImportProblem(c, "the hub could not be reached")
		return
	}

	sse := datastar.NewSSE(c.Writer, c.Request)

	// Close the modal on success: leaving it open invites a duplicate registration.
	if result.Registered {
		if err := sse.PatchElementTempl(components.CatalogNotice(registeredNotice(result))); err != nil {
			logFrom(c).Error().Err(err).Msg("patch the registration notice")
			return
		}
		if err := sse.MarshalAndPatchSignals(closedImportSignals()); err != nil {
			logFrom(c).Error().Err(err).Msg("close the registration modal")
		}
		return
	}

	if err := sse.PatchElementTempl(components.ImportResultBanner(&result)); err != nil {
		logFrom(c).Error().Err(err).Msg("patch import result")
		return
	}
	// A refusal with a report shows it, so the person sees which entry was objected to.
	if result.Preview != nil {
		if err := sse.PatchElementTempl(components.ImportPreviewPanel(result.Preview)); err != nil {
			logFrom(c).Error().Err(err).Msg("patch import preview")
		}
	}
}

// registeredNotice is warn rather than ok: a 202 means nothing has been scanned yet.
func registeredNotice(result view.ImportResult) *view.Notice {
	text := "Registered " + result.ID
	if result.Version != "" {
		text += "@" + result.Version
	}
	return &view.Notice{Tone: "warn", Text: text + ". The fetch is queued; the scan follows it."}
}

// closedImportSignals also resets every field, so reopening cannot resubmit the last registration.
func closedImportSignals() map[string]any {
	return map[string]any{
		"_importOpen":      false,
		"_importFile":      "",
		"_importURL":       "",
		"_importRef":       "",
		"_importSubdir":    "",
		"_importPublisher": "",
		"_importName":      "",
		"_importVersion":   "",
		"_importKind":      "",
		"_importTags":      "",
	}
}

func (s *Server) parseImportForm(c *gin.Context) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxImportBytes)
	if err := c.Request.ParseMultipartForm(multipartMemory); err != nil {
		logFrom(c).Warn().Err(err).Msg("parse the registration form")
		s.patchImportProblem(c, "that upload could not be read, or it is too large")
		return false
	}
	return true
}

// patchImportProblem answers in the modal's banner: a bare 400 would leave a modal that did nothing.
func (s *Server) patchImportProblem(c *gin.Context, message string) {
	sse := datastar.NewSSE(c.Writer, c.Request)
	if err := sse.PatchElementTempl(components.ImportResultBanner(
		&view.ImportResult{Message: message})); err != nil {
		logFrom(c).Error().Err(err).Msg("patch import problem")
	}
}
