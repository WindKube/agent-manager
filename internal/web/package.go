package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

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
	}

	title := detail.Name
	if title == "" {
		title = "Package"
	}
	s.render(c, status, title, "catalog", components.PackageScreen(detail))
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

	path := strings.TrimSpace(c.Query("file"))
	if path == "" {
		path = list.Default
	}
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
