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

// The audit log screen and its export.

func (s *Server) audit(c *gin.Context) {
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil || page < 1 {
		page = 1
	}

	screen := view.Audit{Page: page, ExportAvailable: s.deps.Audit != nil}
	if s.deps.Audit == nil {
		screen.Unavailable = true
		s.renderAudit(c, http.StatusBadGateway, screen)
		return
	}

	entries, err := s.deps.Audit.Audit(session(c), page)
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "audit log"); !ok {
		// The export is offered only beside rows that could be read.
		screen.ExportAvailable = false
		s.renderAudit(c, status, screen)
		return
	}

	screen.Total, screen.Page, screen.PageSize = entries.Total, entries.Page, entries.PageSize
	for _, entry := range entries.Entries {
		screen.Rows = append(screen.Rows, auditRow(entry))
	}
	s.renderAudit(c, http.StatusOK, screen)
}

func (s *Server) renderAudit(c *gin.Context, status int, screen view.Audit) {
	s.render(c, status, "Audit log", "audit", components.AuditScreen(screen))
}

func auditRow(from hub.AuditEntry) view.AuditRow {
	return view.AuditRow{
		ID:    from.ID,
		At:    view.Timestamp(from.OccurredAt),
		Actor: from.Actor,
		// From actor_kind, never inferred from the name.
		System: from.ActorKind == view.ActorKindSystem,
		Kind:   from.Kind,
		Text:   from.Text,
		Source: from.Source,
	}
}

// ---- the export -----------------------------------------------------------

// exportMediaType is what this role sends, a constant rather than the
// upstream's header echoed back: a response header from another service
// should not decide how a browser treats a download.
const exportMediaType = "application/x-ndjson"

// exportFilename matches the api's own Content-Disposition, so a file saved
// through this hop and one saved from the api directly are the same file.
const exportFilename = "audit-log.ndjson"

// auditExport streams the whole current scope to the browser. It does NOT
// read the body into memory first: the audit table is the one designed to
// grow without bound, and an io.ReadAll here would undo the api's own streaming.
func (s *Server) auditExport(c *gin.Context) {
	if s.deps.Audit == nil {
		c.Status(http.StatusBadGateway)
		return
	}

	body, mediaType, err := s.deps.Audit.AuditExport(session(c))
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
	// A stream left open is a connection held for the life of the process.
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
		// The status is already sent and cannot be taken back: the reader has
		// a truncated file and a 200.
		logFrom(c).Error().Err(err).Msg("the audit export was cut short mid-stream")
	case !complete:
		// The sentinel's absence is the only signal that a 200 was truncated.
		logFrom(c).Error().Msg("the audit export ended without its completeness sentinel")
	}
}

// exportTailBytes bounds how much of the stream's end is kept to read the
// sentinel back, so completeness-checking never becomes the buffering this
// path avoids.
const exportTailBytes = 512

// streamExport copies the export to the browser and reports whether it ended
// with the api's completeness sentinel. It flushes as it goes, so a long
// export arrives while being read rather than after the api finishes producing it.
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

// sentinelSeen decodes the stream's last line rather than matching text on
// it: a substring match on `"complete":true` could be satisfied by an audit
// row that happened to quote those bytes in its own text.
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
