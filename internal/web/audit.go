package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

func (s *Server) audit(c *gin.Context) {
	query := auditQueryFromURL(c)
	screen := view.Audit{Query: query, Page: query.Page, ExportAvailable: true}
	entries, err := s.deps.Hub.Audit(session(c), query.Page, query.Filter)
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "audit log"); !ok {
		screen.ExportAvailable = false
		s.renderAudit(c, status, screen)
		return
	}

	screen.Rows, screen.Total, screen.Page, screen.PageSize = entries.Rows, entries.Total, entries.Page, entries.PageSize

	if query.Selected != "" {
		if row := findAuditRow(screen.Rows, query.Selected); row != nil {
			screen.Selected = row
		} else {
			screen.Missing = true
		}
	}
	s.renderAudit(c, http.StatusOK, screen)
}

func auditQueryFromURL(c *gin.Context) view.AuditQuery {
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		page = 1
	}
	return view.AuditQuery{Page: page, Selected: c.Query("entry"), Filter: auditFilterFromURL(c)}.Normalise()
}

func auditFilterFromURL(c *gin.Context) view.AuditFilter {
	return view.AuditFilter{
		SubjectKind: c.Query("subjectKind"), SubjectID: c.Query("subjectId"), Namespace: c.Query("namespace"),
	}
}

func findAuditRow(rows []view.AuditRow, id string) *view.AuditRow {
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
		}
	}
	return nil
}

func (s *Server) renderAudit(c *gin.Context, status int, screen view.Audit) {
	s.render(c, status, "Audit log", "audit", components.AuditScreen(screen))
}

// exportMediaType is fixed rather than echoed: another service's header should
// not decide how a browser treats a download.
const exportMediaType = "application/x-ndjson"

// exportFilename matches the api's own Content-Disposition.
const exportFilename = "audit-log.ndjson"

// auditExport streams rather than buffering: the audit log grows without bound.
func (s *Server) auditExport(c *gin.Context) {
	query := view.AuditQuery{Filter: auditFilterFromURL(c)}.Normalise()
	body, mediaType, err := s.deps.Hub.AuditExport(session(c), query.Filter)
	switch {
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
		return
	case errors.Is(err, hub.ErrForbidden):
		logFrom(c).Info().Msg("audit export refused by role")
		c.Status(http.StatusForbidden)
		return
	case err != nil:
		logFrom(c).Error().Err(err).Msg("export the audit log")
		c.Status(http.StatusBadGateway)
		return
	}
	defer func() { _ = body.Close() }()

	if mediaType != "" && mediaType != exportMediaType {
		logFrom(c).Warn().Str("media_type", mediaType).Msg("the audit export arrived as an unexpected type")
	}

	c.Header("Content-Type", exportMediaType)
	c.Header("Content-Disposition", `attachment; filename="`+exportFilename+`"`)
	// A shared cache would serve one organisation's log to the next request.
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Status(http.StatusOK)

	complete, err := streamExport(c.Writer, body)
	switch {
	case err != nil:
		// The 200 is already sent; the reader has a truncated file.
		logFrom(c).Error().Err(err).Msg("the audit export was cut short mid-stream")
	case !complete:
		// The sentinel's absence is the only signal that a 200 was truncated.
		logFrom(c).Error().Msg("the audit export ended without its completeness sentinel")
	}
}

// exportTailBytes bounds the tail kept to find the completeness sentinel.
const exportTailBytes = 512

// streamExport flushes as it copies and reports whether the stream ended with
// the api's completeness sentinel.
func streamExport(w io.Writer, body io.Reader) (bool, error) {
	flusher, _ := w.(http.Flusher)
	tail := make([]byte, 0, exportTailBytes)
	buffer := make([]byte, 32*1024)

	for {
		n, readErr := body.Read(buffer)
		if n > 0 {
			written, writeErr := w.Write(buffer[:n])
			tail = keepTail(tail, buffer[:written])
			if writeErr != nil {
				return false, writeErr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr == io.EOF {
			return sentinelSeen(tail), nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

func keepTail(tail, chunk []byte) []byte {
	tail = append(tail, chunk...)
	if len(tail) > exportTailBytes {
		tail = tail[len(tail)-exportTailBytes:]
	}
	return tail
}

// sentinelSeen decodes the last line: a substring match could be satisfied by
// an audit row quoting `"complete":true`.
func sentinelSeen(tail []byte) bool {
	lines := bytes.Split(tail, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		var sentinel struct {
			Complete bool `json:"complete"`
		}
		return json.Unmarshal(line, &sentinel) == nil && sentinel.Complete
	}
	return false
}
