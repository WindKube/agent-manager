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

	title := detail.Name
	if title == "" {
		title = "Package"
	}
	s.render(c, status, title, "catalog", components.PackageScreen(detail))
}
