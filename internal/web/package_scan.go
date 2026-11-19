package web

import (
	"errors"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/view"
)

// loadScan fills the package detail screen's security section (the owner's
// "collapsible section, default hidden, showing the security scan result
// and approval and comment"): the latest visible version's scan, its
// findings and any reviewer decision.
//
// Read independently of everything loadFiles and the rest of packageDetail
// load, following the same precedent: a deployment can answer the rest of
// the page while this one read is unavailable, and the two must fail on
// their own terms.
func (s *Server) loadScan(c *gin.Context, detail *view.Package, namespace, name string) {
	scan, err := s.deps.Hub.PackageScan(session(c), namespace, name)
	switch {
	case err == nil:
		detail.ScanDetail = scan
	case errors.Is(err, view.ErrNotFound):
		// The package existed a moment ago, for the read that rendered the
		// rest of this page — a race rather than a state this screen has
		// copy for, so it collapses into Unavailable like any other failed read.
		detail.ScanDetail.Unavailable = true
	default:
		logFrom(c).Error().Err(err).Msg("load package scan")
		detail.ScanDetail.Unavailable = true
	}
}
