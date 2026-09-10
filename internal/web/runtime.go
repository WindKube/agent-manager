package web

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

func (s *Server) runtime(c *gin.Context) {
	if s.deps.Runtime == nil {
		s.renderRuntime(c, http.StatusBadGateway, view.Runtime{GovernanceState: view.GovernanceState{Unavailable: true}})
		return
	}

	screen, err := s.deps.Runtime.Runtime(session(c))
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "runtime report"); !ok {
		s.renderRuntime(c, status, screen)
		return
	}
	s.renderRuntime(c, http.StatusOK, screen)
}

func (s *Server) renderRuntime(c *gin.Context, status int, screen view.Runtime) {
	s.render(c, status, "Runtime", "runtime", components.RuntimeScreen(screen))
}
