package web

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

func (s *Server) storage(c *gin.Context) {
	screen, err := s.deps.Hub.Storage(session(c))
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "storage report"); !ok {
		s.renderStorage(c, status, screen)
		return
	}
	s.renderStorage(c, http.StatusOK, screen)
}

func (s *Server) renderStorage(c *gin.Context, status int, screen view.Storage) {
	s.render(c, status, "Storage", "storage", components.StorageScreen(screen))
}
