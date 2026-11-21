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

// maxPackageNoticeDetailLength bounds a failed delete's reason in the redirect query string.
const maxPackageNoticeDetailLength = 300

func (s *Server) packageDetail(c *gin.Context) {
	namespace, name := c.Param("namespace"), c.Param("name")
	detail, err := s.deps.Hub.Package(session(c), namespace, name)

	status := http.StatusOK
	switch {
	case errors.Is(err, view.ErrSignedOut):
		logFrom(c).Debug().Msg("package requested without a session")
		detail = view.Package{SignedOut: true}
	case errors.Is(err, view.ErrNotFound):
		// Missing and unreadable are one answer on purpose; see view.ErrNotFound.
		detail = view.Package{Missing: true}
		status = http.StatusNotFound
	case err != nil:
		// A 502 rather than an empty page, so an outage doesn't look like an empty package.
		logFrom(c).Error().Err(err).Str("package", namespace+"/"+name).Msg("load package")
		c.Status(http.StatusBadGateway)
		return
	}

	if !detail.SignedOut && !detail.Missing {
		s.loadProfileOptions(c, &detail)
		s.loadFiles(c, &detail, namespace, name)
		s.loadScan(c, &detail, namespace, name)
		detail.Affected = s.affectedMachines(c, detail.ID, "")
		detail.DeleteAccess = view.PackageDeleteAccessFor(viewerFor(c))
		// Delete and visibility notices share the banner; each returns nil for the other's tokens.
		detail.Notice = view.PackageNoticeFrom(c.Query("notice"), packageNoticeDetailFromURL(c), c.Query("version"))
		if detail.Notice == nil {
			detail.Notice = packageNotice(c.Query("notice"))
		}
	}

	title := detail.Name
	if title == "" {
		title = "Package"
	}
	s.render(c, status, title, "catalog", components.PackageScreen(detail))
}

func packageNoticeDetailFromURL(c *gin.Context) string {
	detail := c.Query("detail")
	if len(detail) > maxPackageNoticeDetailLength {
		return ""
	}
	return detail
}

// packageAccessGuard refuses, before any api call, an identity the screen
// already hides the action from.
func (s *Server) packageAccessGuard(c *gin.Context, namespace, name string) bool {
	if view.PackageDeleteAccessFor(viewerFor(c)).Allowed {
		return true
	}
	logFrom(c).Warn().Str("package", namespace+"/"+name).
		Msg("catalog delete requested by an identity without the role")
	s.backToPackage(c, namespace, name, view.PackageNoticeRefused, "", "")
	return false
}

// backToPackage redirects with notice tokens the screen maps to its own copy,
// never prose a forged link could inject.
func (s *Server) backToPackage(c *gin.Context, namespace, name string, notice view.PackageNotice, detail, version string) {
	values := url.Values{}
	values.Set("notice", string(notice))
	if detail != "" && len(detail) <= maxPackageNoticeDetailLength {
		values.Set("detail", detail)
	}
	if version != "" {
		values.Set("version", version)
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, view.PackageHref(namespace+"/"+name)+"?"+values.Encode())
}

// backToCatalogAfterDelete lands on the catalog because the deleted package's page now 404s.
func (s *Server) backToCatalogAfterDelete(c *gin.Context, id string) {
	values := url.Values{}
	values.Set("notice", "package-deleted")
	values.Set("id", id)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/catalog?"+values.Encode())
}

func (s *Server) deleteVersion(c *gin.Context) {
	namespace, name, version := c.Param("namespace"), c.Param("name"), c.Param("version")
	if !s.packageAccessGuard(c, namespace, name) {
		return
	}
	if _, err := s.deps.Hub.DeleteVersion(session(c), namespace, name, version); err != nil {
		s.packageDeleteFailed(c, namespace, name, err)
		return
	}
	s.backToPackage(c, namespace, name, view.PackageNoticeVersionDeleted, "", version)
}

func (s *Server) deletePackage(c *gin.Context) {
	namespace, name := c.Param("namespace"), c.Param("name")
	if !s.packageAccessGuard(c, namespace, name) {
		return
	}
	if _, err := s.deps.Hub.DeletePackage(session(c), namespace, name); err != nil {
		s.packageDeleteFailed(c, namespace, name, err)
		return
	}
	s.backToCatalogAfterDelete(c, namespace+"/"+name)
}

func (s *Server) packageDeleteFailed(c *gin.Context, namespace, name string, err error) {
	switch {
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, hub.ErrForbidden):
		logFrom(c).Warn().Msg("the api refused a catalog delete this screen offered")
		s.backToPackage(c, namespace, name, view.PackageNoticeRefused, "", "")
	case errors.Is(err, view.ErrNotFound):
		s.notFound(c)
	default:
		logFrom(c).Info().Err(err).Msg("catalog delete refused")
		s.backToPackage(c, namespace, name, view.PackageNoticeFailed, err.Error(), "")
	}
}

// loadProfileOptions uses the bulk profile list and Dependents to mark which
// profiles already hold this package, avoiding a request per profile.
func (s *Server) loadProfileOptions(c *gin.Context, detail *view.Package) {
	rows, err := s.deps.Hub.Profiles(session(c))
	if err != nil {
		logFrom(c).Error().Err(err).Msg("load profiles for the add-to-profile control")
		detail.ProfilesUnavailable = true
		return
	}

	options := make([]view.ProfileOption, 0, len(rows))
	for _, row := range rows {
		options = append(options, view.ProfileOption{
			Slug: row.Slug, Name: row.Name, Visibility: row.Visibility, CanCurate: row.CanCurate,
		})
	}
	detail.ProfileOptions = view.ProfileOptionsHeld(options, detail.Dependents)
}

// loadFiles fills in the files panel. A refused version stops at FilesRejected,
// and an unknown path renders FileMissing rather than failing the page.
func (s *Server) loadFiles(c *gin.Context, detail *view.Package, namespace, name string) {
	list, err := s.deps.Hub.PackageFiles(session(c), namespace, name)
	switch {
	case errors.Is(err, hub.ErrForbidden):
		detail.FilesRejected = true
		return
	case err != nil:
		logFrom(c).Error().Err(err).Msg("load package files")
		detail.FilesUnavailable = true
		return
	}
	detail.Files = list.Files
	detail.FilesDefault = list.Default

	// Closed until a file is named: defaulting to list.Default would make the
	// close link (this same clean URL) appear to do nothing.
	path := strings.TrimSpace(c.Query("file"))
	if path == "" {
		return
	}
	detail.SelectedFilePath = path

	content, err := s.deps.Hub.PackageFile(session(c), namespace, name, path)
	switch {
	case errors.Is(err, view.ErrNotFound):
		detail.FileMissing = true
	case errors.Is(err, hub.ErrFileTooLarge):
		detail.FileTooLarge = true
	case errors.Is(err, hub.ErrFileNotRenderable):
		detail.FileNotRenderable = true
	case errors.Is(err, hub.ErrForbidden):
		// Only reachable on a race with a fetch, so offer a retry rather than a rejection.
		detail.FilesUnavailable = true
	case err != nil:
		logFrom(c).Error().Err(err).Msg("load package file content")
		detail.FilesUnavailable = true
	default:
		detail.SelectedFile = &content
	}
}

func (s *Server) setPackageVisibility(c *gin.Context) {
	id := strings.TrimSpace(c.PostForm("id"))
	visibility := strings.TrimSpace(c.PostForm("visibility"))

	namespace, name, ok := view.SplitPackageID(id)
	if !ok {
		c.Redirect(http.StatusSeeOther, "/catalog")
		return
	}

	if _, err := s.deps.Hub.SetVisibility(session(c), namespace, name, visibility); err != nil {
		s.packageVisibilityWriteFailed(c, namespace, name, err)
		return
	}
	s.backToPackageAfterVisibility(c, namespace, name, packageVisibilityChanged)
}

func (s *Server) setPackageTracking(c *gin.Context) {
	namespace, name, ok := view.SplitPackageID(strings.TrimSpace(c.PostForm("id")))
	if !ok {
		c.Redirect(http.StatusSeeOther, "/catalog")
		return
	}

	track := c.PostForm("track") == "on"
	pattern := strings.TrimSpace(c.PostForm("pattern"))
	if _, err := s.deps.Hub.SetTracking(session(c), namespace, name, track, pattern); err != nil {
		switch {
		case errors.Is(err, view.ErrSignedOut):
			s.toSignIn(c)
		case errors.Is(err, view.ErrNotFound):
			s.backToPackageAfterVisibility(c, namespace, name, packageVisibilityMissing)
		default:
			var refused *hub.PackageRefusedError
			if errors.As(err, &refused) {
				s.backToPackageAfterVisibility(c, namespace, name, packageTrackingRefused)
				return
			}
			logFrom(c).Error().Err(err).Msg("set package tracking")
			s.backToPackageAfterVisibility(c, namespace, name, packageVisibilityFailed)
		}
		return
	}
	s.backToPackageAfterVisibility(c, namespace, name, packageTrackingChanged)
}

// setPackageSigner clears the signer when both fields are blank; the api refuses half a signer.
func (s *Server) setPackageSigner(c *gin.Context) {
	namespace, name, ok := view.SplitPackageID(strings.TrimSpace(c.PostForm("id")))
	if !ok {
		c.Redirect(http.StatusSeeOther, "/catalog")
		return
	}

	issuer := strings.TrimSpace(c.PostForm("issuer"))
	identity := strings.TrimSpace(c.PostForm("identity"))
	if _, err := s.deps.Hub.SetSigner(session(c), namespace, name, issuer, identity); err != nil {
		switch {
		case errors.Is(err, view.ErrSignedOut):
			s.toSignIn(c)
		case errors.Is(err, view.ErrNotFound):
			s.backToPackageAfterVisibility(c, namespace, name, packageVisibilityMissing)
		default:
			var refused *hub.PackageRefusedError
			if errors.As(err, &refused) {
				s.backToPackageAfterVisibility(c, namespace, name, packageSignerRefused)
				return
			}
			logFrom(c).Error().Err(err).Msg("set package signer")
			s.backToPackageAfterVisibility(c, namespace, name, packageVisibilityFailed)
		}
		return
	}
	s.backToPackageAfterVisibility(c, namespace, name, packageSignerChanged)
}

// packageVisibilityWriteFailed redirects even on a refusal: unlike profile
// curation, this control echoes nothing typed that a forged link could reproduce.
func (s *Server) packageVisibilityWriteFailed(c *gin.Context, namespace, name string, err error) {
	switch {
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, view.ErrNotFound):
		s.backToPackageAfterVisibility(c, namespace, name, packageVisibilityMissing)
	default:
		var refused *hub.PackageRefusedError
		if errors.As(err, &refused) {
			s.backToPackageAfterVisibility(c, namespace, name, packageVisibilityRefused)
			return
		}
		logFrom(c).Error().Err(err).Msg("set package visibility")
		s.backToPackageAfterVisibility(c, namespace, name, packageVisibilityFailed)
	}
}

type packageOutcome string

const (
	packageVisibilityChanged packageOutcome = "visibility-changed"
	packageVisibilityRefused packageOutcome = "visibility-refused"
	packageVisibilityMissing packageOutcome = "visibility-missing"
	packageVisibilityFailed  packageOutcome = "visibility-failed"
	packageTrackingChanged   packageOutcome = "tracking-changed"
	packageTrackingRefused   packageOutcome = "tracking-refused"
	packageSignerChanged     packageOutcome = "signer-changed"
	packageSignerRefused     packageOutcome = "signer-refused"
)

func packageNotice(raw string) *view.Notice {
	switch packageOutcome(raw) {
	case packageVisibilityChanged:
		return &view.Notice{Tone: "ok", Text: "Visibility changed."}
	case packageVisibilityRefused:
		return &view.Notice{Tone: "dan", Text: "The hub refused that change: only this package's " +
			"owner or a catalog admin may change its visibility, or it has no recorded owner to " +
			"narrow it safely."}
	case packageTrackingChanged:
		return &view.Notice{Tone: "ok", Text: "Upstream tracking saved."}
	case packageTrackingRefused:
		return &view.Notice{Tone: "dan", Text: "The hub refused that change: the tag pattern must be " +
			"a glob such as v*, and only this package's owner or a catalog admin may change its " +
			"upstream tracking."}
	case packageSignerChanged:
		return &view.Notice{Tone: "ok", Text: "Expected signer saved. Every version is judged " +
			"against it from now on."}
	case packageSignerRefused:
		return &view.Notice{Tone: "dan", Text: "The hub refused that change: give both an issuer " +
			"and an identity pattern (a valid regular expression), or neither to clear it, and only " +
			"this package's owner or a catalog admin may change its expected signer."}
	case packageVisibilityMissing:
		return &view.Notice{Tone: "dan", Text: "No such package, or it is not readable by your " +
			"identity."}
	case packageVisibilityFailed:
		return &view.Notice{Tone: "dan", Text: "The hub refused that change and recorded " +
			"nothing. Reload — this screen may be stale."}
	default:
		return nil
	}
}

func (s *Server) backToPackageAfterVisibility(c *gin.Context, namespace, name string, outcome packageOutcome) {
	s.backToPackage(c, namespace, name, view.PackageNotice(outcome), "", "")
}
