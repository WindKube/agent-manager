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

// maxPackageNoticeDetailLength bounds what a failed delete's reason carries
// into a redirect's query string, mirroring org.go's maxOrgDetailLength.
const maxPackageNoticeDetailLength = 300

// The package detail screen (US3). It is a plain server render with no signals:
// nothing on it filters, sorts or pages, so there is nothing for datastar to do
// and no round trip to debounce.
func (s *Server) packageDetail(c *gin.Context) {
	if s.deps.Packages == nil {
		// A deployment always has one. A screen test that wired only the catalog
		// gets a 404 rather than a nil dereference, which is a failure that names
		// itself.
		s.notFound(c)
		return
	}

	namespace, name := c.Param("namespace"), c.Param("name")
	detail, err := s.deps.Packages.Package(session(c), namespace, name)

	status := http.StatusOK
	switch {
	case errors.Is(err, view.ErrSignedOut):
		logFrom(c).Debug().Msg("package requested without a session")
		detail = view.Package{SignedOut: true}
	case errors.Is(err, view.ErrNotFound):
		// A 404 with the screen rendered, not a bare status: the person followed a
		// link, and "no such package, or not readable by you" is the answer. The
		// two are one answer on purpose — see view.ErrNotFound.
		detail = view.Package{Missing: true}
		status = http.StatusNotFound
	case err != nil:
		// The same split the catalog makes: an unreachable api is a 502, because
		// the person cannot act on it, and collapsing it into an empty page would
		// render an outage as a package that happens to have nothing in it.
		logFrom(c).Error().Err(err).Str("package", namespace+"/"+name).Msg("load package")
		c.Status(http.StatusBadGateway)
		return
	}

	if !detail.SignedOut && !detail.Missing {
		s.loadProfileOptions(c, &detail)
		s.loadFiles(c, &detail, namespace, name)
		s.loadScan(c, &detail, namespace, name)
		detail.DeleteAccess = view.PackageDeleteAccessFor(viewerFor(c))
		// Two vocabularies land on the same banner: a delete's tokens and a
		// visibility change's. Each returns nil for the other's, so asking in
		// turn is what keeps them from having to know about each other.
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

// packageAccessGuard refuses a request from an identity the screen already
// hides or disables the action for. Refused HERE, before any call to the
// api, mirroring org.go's orgAccessGuard and for the same reason.
func (s *Server) packageAccessGuard(c *gin.Context, namespace, name string) bool {
	if view.PackageDeleteAccessFor(viewerFor(c)).Allowed {
		return true
	}
	logFrom(c).Warn().Str("package", namespace+"/"+name).
		Msg("catalog delete requested by an identity without the role")
	s.backToPackage(c, namespace, name, view.PackageNoticeRefused, "", "")
	return false
}

// backToPackage is post-redirect-get's redirect half, carrying the outcome
// and an optional detail or subject as tokens the screen looks its copy up
// from, never as rendered prose this handler wrote — the same idiom
// backToOrg follows.
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

// backToCatalogAfterDelete is deletePackage's own redirect: the package's
// own detail page 404s the instant latest_version_id clears, so the
// acknowledgement belongs on the catalog instead of on a page that just
// stopped resolving.
func (s *Server) backToCatalogAfterDelete(c *gin.Context, id string) {
	values := url.Values{}
	values.Set("notice", "package-deleted")
	values.Set("id", id)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/catalog?"+values.Encode())
}

// deleteVersion withdraws one version (US-catalog-delete). The archive
// itself, and why it is one rather than a hard delete, is
// commands.DeleteVersion's own comment.
func (s *Server) deleteVersion(c *gin.Context) {
	namespace, name, version := c.Param("namespace"), c.Param("name"), c.Param("version")
	if !s.packageAccessGuard(c, namespace, name) {
		return
	}
	if s.deps.PackageCurator == nil {
		s.backToPackage(c, namespace, name, view.PackageNoticeFailed,
			"this hub is not configured to delete from the catalog", "")
		return
	}
	if _, err := s.deps.PackageCurator.DeleteVersion(session(c), namespace, name, version); err != nil {
		s.packageDeleteFailed(c, namespace, name, err)
		return
	}
	s.backToPackage(c, namespace, name, view.PackageNoticeVersionDeleted, "", version)
}

// deletePackage withdraws every version of a package.
func (s *Server) deletePackage(c *gin.Context) {
	namespace, name := c.Param("namespace"), c.Param("name")
	if !s.packageAccessGuard(c, namespace, name) {
		return
	}
	if s.deps.PackageCurator == nil {
		s.backToPackage(c, namespace, name, view.PackageNoticeFailed,
			"this hub is not configured to delete from the catalog", "")
		return
	}
	if _, err := s.deps.PackageCurator.DeletePackage(session(c), namespace, name); err != nil {
		s.packageDeleteFailed(c, namespace, name, err)
		return
	}
	s.backToCatalogAfterDelete(c, namespace+"/"+name)
}

// packageDeleteFailed maps a delete's refusal onto the redirect's notice
// token, following orgSaveFailed's own split.
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

// loadProfileOptions fills in the add-to-profile control (US5) from the same
// bulk profile list the Profiles screen reads — one request, not one per
// profile — and marks which of them already hold this package by
// cross-referencing Dependents rather than reading each profile's entries
// again.
func (s *Server) loadProfileOptions(c *gin.Context, detail *view.Package) {
	if s.deps.Profiles == nil {
		return
	}

	rows, err := s.deps.Profiles.Profiles(session(c))
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

// loadFiles fills in the files panel (US3/US5: read a skill's files before
// using it). The list read and the content read are independent: a version
// FR-029 refuses to serve answers the list with FilesRejected and never
// attempts the content read that would follow, and a path the query names
// that the list does not contain answers FileMissing rather than a raw 404
// bubbling up as a page-load failure.
func (s *Server) loadFiles(c *gin.Context, detail *view.Package, namespace, name string) {
	if s.deps.Files == nil {
		return
	}

	list, err := s.deps.Files.PackageFiles(session(c), namespace, name)
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

	// The panel is closed until the reader names a file: falling back to
	// list.Default here is the exact bug the owner reported — the panel
	// then opens on every load, and the close link (which navigates to
	// this same clean URL) looks like it does nothing.
	path := strings.TrimSpace(c.Query("file"))
	if path == "" {
		return
	}
	detail.SelectedFilePath = path

	content, err := s.deps.Files.PackageFile(session(c), namespace, name, path)
	switch {
	case errors.Is(err, view.ErrNotFound):
		detail.FileMissing = true
	case errors.Is(err, hub.ErrFileTooLarge):
		detail.FileTooLarge = true
	case errors.Is(err, hub.ErrFileNotRenderable):
		detail.FileNotRenderable = true
	case errors.Is(err, hub.ErrForbidden):
		// The list above already succeeded against the same version, so
		// this is only reachable on a genuine race with a fetch; the
		// generic unavailable state says a retry might help, which a
		// rejection never would.
		detail.FilesUnavailable = true
	case err != nil:
		logFrom(c).Error().Err(err).Msg("load package file content")
		detail.FilesUnavailable = true
	default:
		detail.SelectedFile = &content
	}
}

// setPackageVisibility is FR-126's one write on this screen. Post-redirect-get,
// like the profile curation writes, so a reload cannot resubmit the change.
func (s *Server) setPackageVisibility(c *gin.Context) {
	id := strings.TrimSpace(c.PostForm("id"))
	visibility := strings.TrimSpace(c.PostForm("visibility"))

	namespace, name, ok := view.SplitPackageID(id)
	if !ok {
		c.Redirect(http.StatusSeeOther, "/catalog")
		return
	}

	if s.deps.PackageCurator == nil {
		s.backToPackage(c, namespace, name, packageVisibilityUnavailable)
		return
	}

	if _, err := s.deps.PackageCurator.SetVisibility(session(c), namespace, name, visibility); err != nil {
		s.packageVisibilityWriteFailed(c, namespace, name, err)
		return
	}
	s.backToPackage(c, namespace, name, packageVisibilityChanged)
}

// packageVisibilityWriteFailed maps the write's error onto a redirect,
// mirroring profileWriteFailed: a refusal the api understood
// (hub.PackageRefusedError) still redirects, since — unlike a profile
// curation refusal — this control never echoes anything a person typed
// that a forged link could reproduce.
func (s *Server) packageVisibilityWriteFailed(c *gin.Context, namespace, name string, err error) {
	switch {
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, view.ErrNotFound):
		s.backToPackage(c, namespace, name, packageVisibilityMissing)
	default:
		var refused *hub.PackageRefusedError
		if errors.As(err, &refused) {
			s.backToPackage(c, namespace, name, packageVisibilityRefused)
			return
		}
		logFrom(c).Error().Err(err).Msg("set package visibility")
		s.backToPackage(c, namespace, name, packageVisibilityFailed)
	}
}

type packageOutcome string

const (
	packageVisibilityChanged     packageOutcome = "visibility-changed"
	packageVisibilityRefused     packageOutcome = "visibility-refused"
	packageVisibilityMissing     packageOutcome = "visibility-missing"
	packageVisibilityUnavailable packageOutcome = "visibility-unavailable"
	packageVisibilityFailed      packageOutcome = "visibility-failed"
)

func packageNotice(raw string) *view.Notice {
	switch packageOutcome(raw) {
	case packageVisibilityChanged:
		return &view.Notice{Tone: "ok", Text: "Visibility changed."}
	case packageVisibilityRefused:
		return &view.Notice{Tone: "dan", Text: "The hub refused that change: only this package's " +
			"owner or a catalog admin may change its visibility, or it has no recorded owner to " +
			"narrow it safely."}
	case packageVisibilityMissing:
		return &view.Notice{Tone: "dan", Text: "No such package, or it is not readable by your " +
			"identity."}
	case packageVisibilityUnavailable:
		return &view.Notice{Tone: "dan", Text: "The hub's api could not be reached, so nothing " +
			"was recorded."}
	case packageVisibilityFailed:
		return &view.Notice{Tone: "dan", Text: "The hub refused that change and recorded " +
			"nothing. Reload — this screen may be stale."}
	default:
		return nil
	}
}

func (s *Server) backToPackage(c *gin.Context, namespace, name string, outcome packageOutcome) {
	target := &url.URL{Path: "/packages/" + url.PathEscape(namespace) + "/" + url.PathEscape(name)}
	values := target.Query()
	values.Set("notice", string(outcome))
	target.RawQuery = values.Encode()

	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, target.String())
}
