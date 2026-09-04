package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The Organization screen.
//
// Plain server renders and POST forms that redirect, the same shape the Scanner
// screen uses and for the same reason: every action here is a mutation, not a
// filter, and post-redirect-get is what keeps a browser's reload button safe.

// maxOrgDetailLength bounds what a failed save's reason carries into a redirect's
// query string. The api's own detail text is normally a short sentence; anything
// longer is dropped in favour of a generic notice rather than carried unbounded
// into every link on the next page.
const maxOrgDetailLength = 300

func (s *Server) org(c *gin.Context) {
	screen := view.Org{
		Access: view.OrgAccessFor(viewerFor(c)),
		Notice: view.OrgNoticeFrom(c.Query("saved"), orgDetailFromURL(c)),
	}

	if s.deps.Organization == nil {
		screen.Unavailable = true
		s.renderOrg(c, http.StatusBadGateway, screen)
		return
	}

	ctx := session(c)
	data, err := s.deps.Organization.Organization(ctx)
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "organization"); !ok {
		s.renderOrg(c, status, screen)
		return
	}
	screen.Data = data

	if c.Query("tested") == "1" && screen.Access.Allowed {
		result, testErr := s.deps.Organization.TestIdentityConnection(ctx)
		switch {
		case testErr == nil:
			screen.Connected = &result
		case errors.Is(testErr, view.ErrSignedOut), errors.Is(testErr, hub.ErrForbidden):
			// Already reflected in GovernanceState above from the main read; nothing
			// further to say about the probe specifically.
		default:
			logFrom(c).Warn().Err(testErr).Msg("test the identity provider connection")
			screen.Connected = &view.IdentityConnectionTest{Detail: "the hub's api could not run the test"}
		}
	}

	s.renderOrg(c, http.StatusOK, screen)
}

func (s *Server) renderOrg(c *gin.Context, status int, screen view.Org) {
	s.render(c, status, "Organization", "org", components.OrgScreen(screen))
}

func orgDetailFromURL(c *gin.Context) string {
	detail := c.Query("detail")
	if len(detail) > maxOrgDetailLength {
		return ""
	}
	return detail
}

// backToOrg is post-redirect-get's redirect half, carrying the outcome and an
// optional detail as tokens the screen looks its copy up from — never as
// rendered prose from this handler, which is what backToScanner's own comment
// explains.
func (s *Server) backToOrg(c *gin.Context, notice view.OrgNotice, detail string) {
	values := url.Values{}
	values.Set("saved", string(notice))
	if detail != "" && len(detail) <= maxOrgDetailLength {
		values.Set("detail", detail)
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/org?"+values.Encode())
}

// orgAccessGuard refuses a request from an identity the screen already hides
// or disables the action for. It must be refused HERE, before any call to the
// api, for the same reason decideFinding's own guard is not merely a courtesy.
func (s *Server) orgAccessGuard(c *gin.Context) bool {
	if view.OrgAccessFor(viewerFor(c)).Allowed {
		return true
	}
	logFrom(c).Warn().Str("path", c.Request.URL.Path).Msg("organization action from an identity without the role")
	s.backToOrg(c, view.OrgNoticeRefused, "")
	return false
}

func (s *Server) testConnection(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/org?tested=1")
}

// rotateSecret always refuses: the screen already renders the action disabled
// with view.SecretRotationReason, so a request here is one that arrived anyway
// — an old page, a hand-written form. It is answered the same way the screen
// already explained itself, not with a round trip to the api to learn the
// same fixed sentence.
func (s *Server) rotateSecret(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}
	s.backToOrg(c, view.OrgNoticeConflict, view.SecretRotationReason)
}

func (s *Server) savePolicy(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}
	if s.deps.Organization == nil {
		s.backToOrg(c, view.OrgNoticeUnavailable, "")
		return
	}

	policy := view.OrganizationPolicy{
		ScanGate:              c.PostForm("scanGate"),
		RequireSignedBundles:  c.PostForm("requireSignedBundles") != "",
		CommunityNeedsReview:  c.PostForm("communityNeedsReview") != "",
		RescanOnNewVersion:    c.PostForm("rescanOnNewVersion") != "",
		AllowPersonalProfiles: c.PostForm("allowPersonalProfiles") != "",
	}
	if _, err := s.deps.Organization.UpdatePolicy(session(c), policy); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticePolicySaved, "")
}

func (s *Server) createMapping(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}
	if s.deps.Organization == nil {
		s.backToOrg(c, view.OrgNoticeUnavailable, "")
		return
	}

	groupName := strings.TrimSpace(c.PostForm("groupName"))
	role := c.PostForm("role")
	if _, err := s.deps.Organization.CreateMapping(session(c), groupName, role); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticeMappingSaved, "")
}

func (s *Server) deleteMapping(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}
	// The screen already renders this action disabled with view.DeleteMappingReason:
	// no DELETE grant on group_role_map. Answered the same way, not with a round
	// trip that can only ever come back 409.
	s.backToOrg(c, view.OrgNoticeConflict, view.DeleteMappingReason)
}

func (s *Server) createCategory(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}
	if s.deps.Organization == nil {
		s.backToOrg(c, view.OrgNoticeUnavailable, "")
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	if _, err := s.deps.Organization.CreateCategory(session(c), name); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticeCategorySaved, "")
}

func (s *Server) renameCategory(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}
	if s.deps.Organization == nil {
		s.backToOrg(c, view.OrgNoticeUnavailable, "")
		return
	}

	id := c.Param("id")
	name := strings.TrimSpace(c.PostForm("name"))
	if _, err := s.deps.Organization.UpdateCategory(session(c), id, name); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticeCategoryRenamed, "")
}

func (s *Server) deleteCategory(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}
	// Same reasoning as deleteMapping: no DELETE grant on category either.
	s.backToOrg(c, view.OrgNoticeConflict, view.DeleteCategoryReason)
}

// orgSaveFailed maps a write's refusal onto the redirect's notice token.
func (s *Server) orgSaveFailed(c *gin.Context, err error) {
	switch {
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, hub.ErrForbidden):
		logFrom(c).Warn().Msg("the api refused an organisation change this screen offered")
		s.backToOrg(c, view.OrgNoticeRefused, "")
	case errors.Is(err, view.ErrNotFound):
		s.backToOrg(c, view.OrgNoticeFailed, "")
	default:
		// This role cannot tell a 422 from a 409 from here — hub/org.go's orgError
		// already reduced both to the api's own detail text — so both land as the
		// same notice, worded for either.
		logFrom(c).Info().Err(err).Msg("organization save refused")
		s.backToOrg(c, orgNoticeFor(err), err.Error())
	}
}

// orgNoticeFor guesses nothing it does not have to: everything that reaches here
// already carries the api's own explanation, so both notices render the same
// text and differ only in tone. "invalid" is the default because a save a
// person can retry after fixing their input is the common case.
func orgNoticeFor(err error) view.OrgNotice {
	if strings.Contains(err.Error(), "already exists") {
		return view.OrgNoticeConflict
	}
	return view.OrgNoticeInvalid
}
