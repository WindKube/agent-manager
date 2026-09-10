package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The Scanner screen and its two decisions: a plain server render and two
// plain form posts. No datastar here — a decision changes stored state, and
// post-redirect-get is what makes the browser's reload button safe. The
// redirect carries a token naming what happened, never the message itself.

// scannerWindow is the summary period this screen asks for: zero, meaning the
// api applies its own window and reports what it used.
const scannerWindow = 0

func (s *Server) scanner(c *gin.Context) {
	query := scannerQueryFromURL(c)
	screen := view.Scanner{
		Query:  query,
		Review: s.reviewFor(c),
		Notice: decisionNotice(c.Query("decided")),
	}

	if s.deps.Scanner == nil {
		// A screen test that did not wire one gets the unavailable state
		// rather than a nil dereference.
		screen.Unavailable = true
		s.renderScanner(c, http.StatusBadGateway, screen)
		return
	}

	ctx := session(c)
	now := time.Now().UTC()

	summary, err := s.deps.Scanner.ScannerSummary(ctx, scannerWindow)
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "scanner summary"); !ok {
		s.renderScanner(c, status, screen)
		return
	}
	screen.Summary = scannerSummary(summary, now)

	page, err := s.deps.Scanner.Findings(ctx, hub.FindingQuery{State: query.APIState(), Page: query.Page})
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "findings"); !ok {
		s.renderScanner(c, status, screen)
		return
	}
	screen.Total, screen.Page, screen.PageSize = page.Total, page.Page, page.PageSize
	for i := range page.Findings {
		screen.Findings = append(screen.Findings, findingRow(&page.Findings[i], now))
	}

	// With no explicit selection the first row of the page is shown, so the
	// screen's first paint is a finding being triaged. Still addressed by id,
	// so a copied URL names the finding and not the position.
	selected := query.Selected
	if selected == "" && len(page.Findings) > 0 {
		selected = page.Findings[0].ID
	}
	if selected == "" {
		s.renderScanner(c, http.StatusOK, screen)
		return
	}

	detail, err := s.deps.Scanner.Finding(ctx, selected)
	switch {
	case errors.Is(err, view.ErrNotFound):
		// A finding id that names nothing readable. The list beside it still
		// rendered, so this is the pane's state, not the screen's.
		screen.Missing = true
		s.renderScanner(c, http.StatusNotFound, screen)
		return
	case err != nil:
		if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "finding detail"); !ok {
			s.renderScanner(c, status, screen)
			return
		}
	}

	resolved := findingDetail(detail, now)
	screen.Selected = &resolved
	s.renderScanner(c, http.StatusOK, screen)
}

// reviewFor asks both halves: may this identity decide, and can this process
// record a decision at all. The second matters because a control offered
// against a nil reviewer is offered and then refused. The role reason wins
// when both apply — it is the one the reader can do something about.
func (s *Server) reviewFor(c *gin.Context) view.Review {
	review := view.ReviewFor(viewerFor(c))
	if review.Allowed && s.deps.Reviewer == nil {
		return view.Review{Reason: "This hub cannot record a decision: no reviewing api is " +
			"wired into this web role, so nothing here can be approved or rejected. That is a " +
			"deployment fault rather than a permission."}
	}
	return review
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

// governanceFailure maps the three refusals these screens share onto the
// three states they render as, and reports whether the caller may carry on.
// One function because collapsing any two of them is the defect worth
// guarding: a 401 rendered as a 403 sends somebody to sign in again to
// acquire a role they will not get.
func (s *Server) governanceFailure(c *gin.Context, err error, state *view.GovernanceState, what string) (int, bool) {
	switch {
	case err == nil:
		return http.StatusOK, true
	case errors.Is(err, view.ErrSignedOut):
		logFrom(c).Debug().Str("read", what).Msg("governance read without a session")
		state.SignedOut = true
		return http.StatusOK, false
	case errors.Is(err, hub.ErrForbidden):
		// Signed in, but not permitted: a distinct status and copy, since only
		// one of the two refusals is fixed by signing in again.
		logFrom(c).Info().Str("read", what).Msg("governance read refused by role")
		state.Refused = true
		return http.StatusForbidden, false
	default:
		logFrom(c).Error().Err(err).Str("read", what).Msg("governance read failed")
		state.Unavailable = true
		return http.StatusBadGateway, false
	}
}

// ---- the two decisions ---------------------------------------------------------

// decisionOutcome is the closed set of things a decision can end in. It
// travels in the redirect's query string, and the COPY is looked up here
// rather than carried: a token cannot be edited into a sentence this hub did
// not write. A token IS forgeable, so the banner is a hint about what just
// happened, never the record of it — the pane below it is read fresh from the
// api on the same request and contradicts a forged banner rather than
// agreeing with it.
type decisionOutcome string

const (
	decisionApproved     decisionOutcome = "approved"
	decisionRejected     decisionOutcome = "rejected"
	decisionNoteRequired decisionOutcome = "note-required"
	decisionNoteTooLong  decisionOutcome = "note-too-long"
	decisionBadExpiry    decisionOutcome = "bad-expiry"
	decisionRefused      decisionOutcome = "refused"
	decisionFailed       decisionOutcome = "failed"
	decisionUnavailable  decisionOutcome = "unavailable"
)

func decisionNotice(raw string) *view.Notice {
	switch decisionOutcome(raw) {
	case decisionApproved:
		// It says the version stays flagged, because it does: an accept
		// records an exception, not a clean bill of health.
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
	case decisionUnavailable:
		return &view.Notice{Tone: "dan", Text: "The hub's api could not be reached, so nothing " +
			"was recorded. Nothing about this finding has changed."}
	default:
		return nil
	}
}

func (s *Server) acceptFinding(c *gin.Context) { s.decideFinding(c, true) }

func (s *Server) rejectFinding(c *gin.Context) { s.decideFinding(c, false) }

// decideFinding is both decisions: the differences are three lines, and the
// rest — role gate, note validation, redirect target — must not diverge.
func (s *Server) decideFinding(c *gin.Context, accept bool) {
	id := c.Param("id")
	back := scannerReturn(c.PostForm("return"), id)

	// The screen already disables what this viewer may not do; this is a
	// request that arrived anyway (old page, second tab, hand-written form),
	// refused HERE rather than round-tripped to the api for a role already known.
	if review := view.ReviewFor(viewerFor(c)); !review.Allowed {
		logFrom(c).Warn().Bool("accept", accept).Msg("finding decision from an identity without the role")
		s.backToScanner(c, back, decisionRefused)
		return
	}

	if s.deps.Reviewer == nil {
		// The screen already disabled both controls; this is the post that
		// arrived anyway.
		s.backToScanner(c, back, decisionUnavailable)
		return
	}

	note := strings.TrimSpace(c.PostForm("note"))
	if len(note) > view.MaxReviewNote {
		s.backToScanner(c, back, decisionNoteTooLong)
		return
	}
	// Mirrored from the api, which still decides: a blank note on an accept is
	// a 422 there, and this must never be the only check.
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
		// days of 0 sends no expiry, and the api applies its own default —
		// never an override that lapses never, which nothing here can record.
		_, err = s.deps.Reviewer.AcceptFinding(session(c), id, note, days)
	} else {
		_, err = s.deps.Reviewer.RejectFinding(session(c), id, note)
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
		// The role this side read and the role the api resolved disagree — a
		// mapping change mid-visit, or this role's gate mirror has drifted.
		logFrom(c).Warn().Msg("the api refused a decision this screen offered")
		s.backToScanner(c, back, decisionRefused)
	case errors.Is(err, view.ErrNotFound):
		logFrom(c).Info().Msg("decision on a finding that does not exist")
		s.backToScanner(c, back, decisionFailed)
	default:
		// Everything else collapses into one notice: this side cannot tell a
		// 409, a 422, or a transport failure apart through the hub's sentinel
		// set, but all of them mean nothing was recorded and the screen may be stale.
		logFrom(c).Error().Err(err).Bool("accept", accept).Msg("decide finding")
		s.backToScanner(c, back, decisionFailed)
	}
}

// expiryDays reads the override lifetime. Blank means "let the api apply its
// default" and is distinct from unparseable — neither can request an
// override that never expires.
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

// scannerReturn is where the browser lands after a decision: the form's own
// return path, but only if it names this screen. localPath already refuses
// another origin; this refuses another SCREEN, since a decision form is not
// a general-purpose redirector.
func scannerReturn(raw, id string) string {
	target := localPath(raw)
	if target == "/scanner" || strings.HasPrefix(target, "/scanner?") {
		return target
	}
	return view.ScannerQuery{Selected: id}.Normalise().SelectHref(id)
}

// backToScanner is the redirect half of post-redirect-get, carrying the outcome as
// a token the screen looks the copy up from.
func (s *Server) backToScanner(c *gin.Context, target string, outcome decisionOutcome) {
	parsed, err := url.Parse(target)
	if err != nil {
		parsed = &url.URL{Path: "/scanner"}
	}
	values := parsed.Query()
	values.Set("decided", string(outcome))
	parsed.RawQuery = values.Encode()

	// no-store: the page this lands on carries a one-time notice, and a
	// cached copy would tell the next reader they had approved something.
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, parsed.String())
}

// ---- mapping the hub's answers onto the screen's models -----------------------

// The hub hands over instants, counts and canonical vocabulary. These four
// functions are the only place in this role that decides how a figure reads.

func scannerSummary(from hub.ScannerSummary, now time.Time) view.ScannerSummary {
	out := view.ScannerSummary{
		PeriodDays:      from.PeriodDays,
		VersionsScanned: from.VersionsScanned,
		Quarantined:     from.Quarantined,
		OverridesActive: from.OverridesActive,
	}
	if from.NearestExpiry != nil {
		out.NearestExpiry = view.Until(*from.NearestExpiry, now)
	}
	if from.MedianScan != nil {
		// nil stays empty ("nothing finished in the window"); a median that
		// rounds to nothing is still a measurement and gets its unit.
		out.MedianScan = view.Duration(*from.MedianScan)
		if out.MedianScan == "" {
			out.MedianScan = "0ms"
		}
	}
	return out
}

func findingRow(from *hub.Finding, now time.Time) view.FindingRow {
	return view.FindingRow{
		ID:       from.ID,
		RuleID:   from.RuleID,
		Title:    from.Title,
		Subject:  from.Subject,
		Severity: view.Severity(from.Severity),
		State:    view.FindingState(from.State),
		Verdict:  view.Verdict(from.Verdict),
		Raised:   view.Relative(from.RaisedAt, now),
	}
}

func findingDetail(from hub.FindingDetail, now time.Time) view.FindingDetail {
	out := view.FindingDetail{
		FindingRow:  findingRow(&from.Finding, now),
		Explanation: from.Explanation,
		PackageID:   from.PackageID,
		Scan: view.ScanMeta{
			PackVersion: from.Scan.PackVersion,
			Started:     view.Timestamp(from.Scan.StartedAt),
			Verdict:     view.Verdict(from.Scan.Verdict),
			TimedOut:    from.Scan.TimedOut,
		},
	}
	if from.Scan.FinishedAt != nil {
		out.Scan.Finished = view.Timestamp(*from.Scan.FinishedAt)
	}

	// The primary location is found by ROLE, never position: the hub promises
	// nothing about slice order, and reading index 0 would silently promote a
	// supporting location the day that ordering changes.
	for _, item := range from.Evidence {
		evidence := view.Evidence{Path: item.Path, Line: item.Line, Quote: item.Quote}
		if item.Role == evidencePrimary && out.Primary == nil {
			out.Primary = &evidence
			continue
		}
		out.Supporting = append(out.Supporting, evidence)
	}

	for _, check := range from.Checks {
		out.Checks = append(out.Checks, view.Check{
			ID:        check.ID,
			Label:     check.Label,
			Result:    view.CheckResult(check.Result),
			WarnCount: check.WarnCount,
		})
	}

	if from.Override != nil {
		override := view.Override{
			Reviewer: from.Override.Reviewer,
			Note:     from.Override.Note,
			Decided:  view.Timestamp(from.Override.DecidedAt),
		}
		if from.Override.ExpiresAt != nil {
			override.Expires = view.Until(*from.Override.ExpiresAt, now)
		}
		out.Override = &override
	}
	return out
}

// evidencePrimary is the role the api gives the location a finding denormalises
// onto its own row. Every finding has exactly one.
const evidencePrimary = "primary"
