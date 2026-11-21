package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// scannerWindow of zero lets the api apply its own window.
const scannerWindow = 0

func (s *Server) scanner(c *gin.Context) {
	query := scannerQueryFromURL(c)
	screen := view.Scanner{
		Query:  query,
		Review: view.ReviewFor(viewerFor(c)),
		Notice: decisionNotice(c.Query("decided")),
	}

	ctx := session(c)

	summary, err := s.deps.Hub.ScannerSummary(ctx, scannerWindow)
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "scanner summary"); !ok {
		s.renderScanner(c, status, screen)
		return
	}
	screen.Summary = summary

	page, err := s.deps.Hub.Findings(ctx, hub.FindingQuery{State: query.APIState(), Page: query.Page})
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "findings"); !ok {
		s.renderScanner(c, status, screen)
		return
	}
	screen.Findings, screen.Total, screen.Page, screen.PageSize = page.Rows, page.Total, page.Page, page.PageSize

	// Default to the first row, still addressed by id so a copied URL names the finding.
	selected := query.Selected
	if selected == "" && len(page.Rows) > 0 {
		selected = page.Rows[0].ID
	}
	if selected == "" {
		s.renderScanner(c, http.StatusOK, screen)
		return
	}

	detail, err := s.deps.Hub.Finding(ctx, selected)
	switch {
	case errors.Is(err, view.ErrNotFound):
		screen.Missing = true
		s.renderScanner(c, http.StatusNotFound, screen)
		return
	case err != nil:
		if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "finding detail"); !ok {
			s.renderScanner(c, status, screen)
			return
		}
	}

	detail.Affected = s.affectedMachines(c, detail.PackageID, detail.Version)
	screen.Selected = &detail
	s.renderScanner(c, http.StatusOK, screen)
}

func (s *Server) renderScanner(c *gin.Context, status int, screen view.Scanner) {
	s.render(c, status, "Scanner", "scanner", components.ScannerScreen(screen))
}

func scannerQueryFromURL(c *gin.Context) view.ScannerQuery {
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		page = 1
	}
	return view.ScannerQuery{
		State:    c.Query("state"),
		Page:     page,
		Selected: c.Query("finding"),
	}.Normalise()
}

// governanceFailure keeps signed-out, refused and unavailable distinct, and
// reports whether the caller may carry on. A 401 shown as a 403 would send
// someone to sign in again for a role they will not get.
func (s *Server) governanceFailure(c *gin.Context, err error, state *view.GovernanceState, what string) (int, bool) {
	switch {
	case err == nil:
		return http.StatusOK, true
	case errors.Is(err, view.ErrSignedOut):
		logFrom(c).Debug().Str("read", what).Msg("governance read without a session")
		state.SignedOut = true
		return http.StatusOK, false
	case errors.Is(err, hub.ErrForbidden):
		logFrom(c).Info().Str("read", what).Msg("governance read refused by role")
		state.Refused = true
		return http.StatusForbidden, false
	default:
		logFrom(c).Error().Err(err).Str("read", what).Msg("governance read failed")
		state.Unavailable = true
		return http.StatusBadGateway, false
	}
}

// decisionOutcome travels in the redirect query and the copy is looked up here,
// so a token cannot become a sentence the hub did not write. The banner is a
// forgeable hint; the pane below is read fresh and is the record.
type decisionOutcome string

const (
	decisionApproved     decisionOutcome = "approved"
	decisionRejected     decisionOutcome = "rejected"
	decisionNoteRequired decisionOutcome = "note-required"
	decisionNoteTooLong  decisionOutcome = "note-too-long"
	decisionBadExpiry    decisionOutcome = "bad-expiry"
	decisionRefused      decisionOutcome = "refused"
	decisionFailed       decisionOutcome = "failed"
)

func decisionNotice(raw string) *view.Notice {
	switch decisionOutcome(raw) {
	case decisionApproved:
		return &view.Notice{Tone: "ok", Text: "Approved. Your note is on record against this " +
			"finding. The version stays flagged — an override is an accepted risk, not a new verdict."}
	case decisionRejected:
		return &view.Notice{Tone: "dan", Text: "Rejected. This version is quarantined for good: " +
			"no profile can resolve it regardless of gate, and its bundle download now refuses."}
	case decisionNoteRequired:
		return &view.Notice{Tone: "warn", Text: "Approving a finding needs a note. It is what a " +
			"later reader has instead of the conversation you are having now, so it is recorded " +
			"or the approval is not."}
	case decisionNoteTooLong:
		return &view.Notice{Tone: "warn", Text: "That note is longer than the hub records. " +
			"Shorten it to " + strconv.Itoa(view.MaxReviewNote) + " characters or fewer."}
	case decisionBadExpiry:
		return &view.Notice{Tone: "warn", Text: "An override expires between 1 and " +
			strconv.Itoa(view.MaxOverrideDays) + " days from now. Leave the field blank for the " +
			"default of " + strconv.Itoa(view.DefaultOverrideDays) + " days — an override that " +
			"never lapses is not something this hub can record."}
	case decisionRefused:
		return &view.Notice{Tone: "dan", Text: "Your role may not decide findings, so nothing " +
			"was recorded. Approving or rejecting needs the scanner reviewer or the catalog admin role."}
	case decisionFailed:
		return &view.Notice{Tone: "dan", Text: "The hub refused that decision and recorded " +
			"nothing. The likeliest cause is a screen that has gone stale — this finding may " +
			"already have been decided. Reload before deciding again."}
	default:
		return nil
	}
}

func (s *Server) acceptFinding(c *gin.Context) { s.decideFinding(c, true) }

func (s *Server) rejectFinding(c *gin.Context) { s.decideFinding(c, false) }

// decideFinding serves both decisions so the role gate, note validation and redirect cannot diverge.
func (s *Server) decideFinding(c *gin.Context, accept bool) {
	id := c.Param("id")
	back := scannerReturn(c.PostForm("return"), id)

	// The screen disables this already; a request arriving anyway is refused without an api round trip.
	if review := view.ReviewFor(viewerFor(c)); !review.Allowed {
		logFrom(c).Warn().Bool("accept", accept).Msg("finding decision from an identity without the role")
		s.backToScanner(c, back, decisionRefused)
		return
	}

	note := strings.TrimSpace(c.PostForm("note"))
	if len(note) > view.MaxReviewNote {
		s.backToScanner(c, back, decisionNoteTooLong)
		return
	}
	// Mirrors the api's check, which remains authoritative.
	if accept && note == "" {
		s.backToScanner(c, back, decisionNoteRequired)
		return
	}

	days, ok := expiryDays(c.PostForm("expires"))
	if !ok {
		s.backToScanner(c, back, decisionBadExpiry)
		return
	}

	var err error
	if accept {
		// days of 0 sends no expiry, so the api applies its default.
		err = s.deps.Hub.AcceptFinding(session(c), id, note, days)
	} else {
		err = s.deps.Hub.RejectFinding(session(c), id, note)
	}

	switch {
	case err == nil:
		if accept {
			s.backToScanner(c, back, decisionApproved)
			return
		}
		s.backToScanner(c, back, decisionRejected)
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, hub.ErrForbidden):
		// The local role mirror and the api disagree: a mapping change mid-visit, or drift.
		logFrom(c).Warn().Msg("the api refused a decision this screen offered")
		s.backToScanner(c, back, decisionRefused)
	case errors.Is(err, view.ErrNotFound):
		logFrom(c).Info().Msg("decision on a finding that does not exist")
		s.backToScanner(c, back, decisionFailed)
	default:
		// 409, 422 and transport failures are indistinguishable here; all mean nothing was recorded.
		logFrom(c).Error().Err(err).Bool("accept", accept).Msg("decide finding")
		s.backToScanner(c, back, decisionFailed)
	}
}

// expiryDays treats blank as "api default", distinct from unparseable.
func expiryDays(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, true
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 1 || days > view.MaxOverrideDays {
		return 0, false
	}
	return days, true
}

// scannerReturn accepts only a path on this screen, so a decision form is not a general redirector.
func scannerReturn(raw, id string) string {
	target := localPath(raw)
	if target == "/scanner" || strings.HasPrefix(target, "/scanner?") {
		return target
	}
	return view.ScannerQuery{Selected: id}.Normalise().SelectHref(id)
}

func (s *Server) backToScanner(c *gin.Context, target string, outcome decisionOutcome) {
	parsed, err := url.Parse(target)
	if err != nil {
		parsed = &url.URL{Path: "/scanner"}
	}
	values := parsed.Query()
	values.Set("decided", string(outcome))
	parsed.RawQuery = values.Encode()

	// A cached copy would replay the one-time notice to the next reader.
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, parsed.String())
}
