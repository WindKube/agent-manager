package web

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
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
