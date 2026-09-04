package web

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// The Storage screen (US7 scenario 2; 001 FR-053, US8 scenario 3).

func (s *Server) storage(c *gin.Context) {
	if s.deps.Storage == nil {
		s.renderStorage(c, http.StatusBadGateway, view.Storage{GovernanceState: view.GovernanceState{Unavailable: true}})
		return
	}

	screen, err := s.deps.Storage.Storage(session(c))
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "storage report"); !ok {
		s.renderStorage(c, status, screen)
		return
	}
	s.renderStorage(c, http.StatusOK, screen)
}

func (s *Server) renderStorage(c *gin.Context, status int, screen view.Storage) {
	s.render(c, status, "Storage", "storage", components.StorageScreen(screen))
}
