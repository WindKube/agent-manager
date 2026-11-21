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

// maxOrgDetailLength bounds a failed save's reason in the redirect query; longer
// text falls back to a generic notice.
const maxOrgDetailLength = 300

func (s *Server) org(c *gin.Context) {
	screen := view.Org{
		Access: view.OrgAccessFor(viewerFor(c)),
		Notice: view.OrgNoticeFrom(c.Query("saved"), orgDetailFromURL(c)),
	}

	ctx := session(c)
	data, err := s.deps.Hub.Organization(ctx)
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "organization"); !ok {
		s.renderOrg(c, status, screen)
		return
	}
	screen.Data = data

	if c.Query("tested") == "1" && screen.Access.Allowed {
		result, testErr := s.deps.Hub.TestIdentityConnection(ctx)
		switch {
		case testErr == nil:
			screen.Connected = &result
		case errors.Is(testErr, view.ErrSignedOut), errors.Is(testErr, hub.ErrForbidden):
			// Already reflected in GovernanceState from the main read.
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

func (s *Server) backToOrg(c *gin.Context, notice view.OrgNotice, detail string) {
	values := url.Values{}
	values.Set("saved", string(notice))
	if detail != "" && len(detail) <= maxOrgDetailLength {
		values.Set("detail", detail)
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/org?"+values.Encode())
}

// orgAccessGuard refuses, before any api call, an identity the screen already hides the action from.
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

// rotateSecret always refuses with view.SecretRotationReason; the screen renders the action disabled.
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

	policy := view.OrganizationPolicy{
		ScanGate:              c.PostForm("scanGate"),
		RequireSignedBundles:  c.PostForm("requireSignedBundles") != "",
		CommunityNeedsReview:  c.PostForm("communityNeedsReview") != "",
		RescanOnNewVersion:    c.PostForm("rescanOnNewVersion") != "",
		AllowPersonalProfiles: c.PostForm("allowPersonalProfiles") != "",
	}
	if _, err := s.deps.Hub.UpdatePolicy(session(c), policy); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticePolicySaved, "")
}

func (s *Server) createMapping(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}

	groupName := strings.TrimSpace(c.PostForm("groupName"))
	role := c.PostForm("role")
	if _, err := s.deps.Hub.CreateMapping(session(c), groupName, role); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticeMappingSaved, "")
}

func (s *Server) deleteMapping(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}

	groupName := c.Param("id")
	if err := s.deps.Hub.DeleteMapping(session(c), groupName); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticeMappingDeleted, "")
}

func (s *Server) createCategory(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	if _, err := s.deps.Hub.CreateCategory(session(c), name); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticeCategorySaved, "")
}

func (s *Server) renameCategory(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}

	id := c.Param("id")
	name := strings.TrimSpace(c.PostForm("name"))
	if _, err := s.deps.Hub.UpdateCategory(session(c), id, name); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticeCategoryRenamed, "")
}

func (s *Server) deleteCategory(c *gin.Context) {
	if !s.orgAccessGuard(c) {
		return
	}

	id := c.Param("id")
	if err := s.deps.Hub.DeleteCategory(session(c), id); err != nil {
		s.orgSaveFailed(c, err)
		return
	}
	s.backToOrg(c, view.OrgNoticeCategoryDeleted, "")
}

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
		// hub's orgError already reduced 409 and 422 to the api's detail text.
		logFrom(c).Info().Err(err).Msg("organization save refused")
		s.backToOrg(c, orgNoticeFor(err), err.Error())
	}
}

// orgNoticeFor only picks the tone; both notices render the api's own text.
func orgNoticeFor(err error) view.OrgNotice {
	if strings.Contains(err.Error(), "already exists") {
		return view.OrgNoticeConflict
	}
	return view.OrgNoticeInvalid
}
