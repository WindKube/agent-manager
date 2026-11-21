package web

import (
	"errors"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/view"
)

// loadScan fills the security section independently, so the rest of the page
// still renders when the scan read fails.
func (s *Server) loadScan(c *gin.Context, detail *view.Package, namespace, name string) {
	scan, err := s.deps.Hub.PackageScan(session(c), namespace, name)
	switch {
	case err == nil:
		detail.ScanDetail = scan
	case errors.Is(err, view.ErrNotFound):
		// A race with the read that rendered the page; treated as unavailable.
		detail.ScanDetail.Unavailable = true
	default:
		logFrom(c).Error().Err(err).Msg("load package scan")
		detail.ScanDetail.Unavailable = true
	}
}
