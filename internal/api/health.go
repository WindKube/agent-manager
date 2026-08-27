package api

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/logging"
)

type healthOutput struct {
	Status int
	Body   contract.Health
}

// health probes every declared dependency and reports 503 if any is unreachable
// (FR-058). Liveness and readiness are one endpoint on purpose: a role that
// cannot reach its database is not serving, whatever its process state says.
//
// Probes run concurrently and share one deadline, so an unreachable dependency
// costs one timeout rather than one per probe.
//
// The body names the dependency but never quotes the driver's error. This
// endpoint is unauthenticated, and a connection error's text carries the host,
// the user and sometimes the whole DSN — the detail goes to the log, where the
// operator already has credentials.
func (s *Server) health(ctx context.Context, _ *struct{}) (*healthOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, s.opts.HealthTimeout)
	defer cancel()

	log := logging.From(ctx)
	checks := make([]contract.HealthCheck, len(s.deps.Probes))
	failures := make([]error, len(s.deps.Probes))

	var wg sync.WaitGroup
	for i, probe := range s.deps.Probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checks[i] = contract.HealthCheck{Name: probe.Name, OK: true}
			if probe.Check == nil {
				checks[i].OK, failures[i] = false, errors.New("probe has no check")
				return
			}
			if err := probe.Check(ctx); err != nil {
				checks[i].OK, failures[i] = false, err
			}
		}()
	}
	wg.Wait()

	out := &healthOutput{Status: http.StatusOK, Body: contract.Health{Status: "ok", Checks: checks}}
	for i, check := range checks {
		if check.OK {
			continue
		}
		out.Status = http.StatusServiceUnavailable
		out.Body.Status = "unavailable"
		out.Body.Checks[i].Error = "unreachable"
		log.Warn().Str("dependency", check.Name).Err(failures[i]).Msg("dependency unreachable")
	}
	return out, nil
}
