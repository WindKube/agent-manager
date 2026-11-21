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

// health probes every dependency concurrently under one deadline and reports 503
// if any is unreachable; liveness and readiness are deliberately one endpoint. The
// body never quotes driver errors (they may carry the DSN) since this endpoint is unauthenticated.
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
