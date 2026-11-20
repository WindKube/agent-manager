package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// The fleet inventory: which machines reported a sync and what each holds.

func (s *Server) machines(c *gin.Context) {
	page, _ := strconv.Atoi(c.Query("page"))
	screen := view.Machines{
		Query: view.MachineQuery{
			Package: c.Query("package"), Version: c.Query("version"), Profile: c.Query("profile"),
			Stale: c.Query("stale"), Page: page,
		}.Normalise(),
		Notice: machinesNotice(c.Query("outcome")),
	}

	list, err := s.deps.Hub.Machines(session(c), screen.Query)
	if errors.Is(err, view.ErrNotFound) {
		screen.Missing = true
		s.renderMachines(c, http.StatusNotFound, screen)
		return
	}
	status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "machines")
	if ok {
		list.Query, list.Notice = screen.Query, screen.Notice
		screen = list
	}
	s.renderMachines(c, status, screen)
}

func (s *Server) renderMachines(c *gin.Context, status int, screen view.Machines) {
	if screen.SignedOut {
		s.toSignIn(c)
		return
	}
	s.render(c, status, "Machines", "machines", components.MachinesScreen(screen))
}

func (s *Server) machineDetail(c *gin.Context) {
	detail, err := s.deps.Hub.Machine(session(c), c.Param("id"))
	status := http.StatusNotFound
	if errors.Is(err, view.ErrNotFound) {
		detail = view.MachineDetail{Missing: true}
	} else {
		status, _ = s.governanceFailure(c, err, &detail.GovernanceState, "machine")
	}
	if detail.SignedOut {
		s.toSignIn(c)
		return
	}
	title := detail.Machine.Hostname
	if title == "" {
		title = "Machine"
	}
	s.render(c, status, title, "machines", components.MachineScreen(detail))
}

func (s *Server) forgetMachine(c *gin.Context) {
	err := s.deps.Hub.ForgetMachine(session(c), c.Param("id"))
	outcome := "forgotten"
	switch {
	case err == nil:
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
		return
	case errors.Is(err, view.ErrNotFound):
		outcome = "missing"
	default:
		logFrom(c).Error().Err(err).Msg("forget machine")
		outcome = "unavailable"
	}
	c.Redirect(http.StatusSeeOther, "/machines?outcome="+outcome)
}

func machinesNotice(outcome string) *view.Notice {
	switch outcome {
	case "forgotten":
		return &view.Notice{Tone: "ok", Text: "Forgotten. The machine reappears if it reports another sync."}
	case "missing":
		return &view.Notice{Tone: "dan", Text: "That machine does not exist, or it is not one you may see."}
	case "unavailable":
		return &view.Notice{Tone: "dan", Text: "The hub's api could not be reached, so nothing was forgotten."}
	default:
		return nil
	}
}

// affectedMachines is the Affected machines panel's read. A package the
// viewer cannot filter by gets no panel; any other failure says so.
func (s *Server) affectedMachines(c *gin.Context, pkg, version string) *view.AffectedMachines {
	affected, err := s.deps.Hub.AffectedMachines(session(c), pkg, version)
	switch {
	case err == nil:
		return &affected
	case errors.Is(err, view.ErrNotFound), errors.Is(err, view.ErrSignedOut):
		return nil
	default:
		logFrom(c).Error().Err(err).Str("package", pkg).Msg("count affected machines")
		return &view.AffectedMachines{Package: pkg, Version: version, Unavailable: true}
	}
}
