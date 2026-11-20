// Package notifier is the `worker notifier` role: it turns audit rows into
// signed webhook deliveries. It holds a database credential narrowed to the
// webhook tables, the audit log and the waiver columns, and the SSRF-guarded
// outbound client; it holds no object-store credential at all.
package notifier

import (
	"errors"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"agent-manager/internal/config"
	"agent-manager/internal/outbox"
	"agent-manager/internal/worker"
)

// RoleName is the argument `agent-manager worker run` takes.
const RoleName = "notifier"

// Concurrency is how many deliveries run at once.
const Concurrency = 8

// Definition is the whole description of the role.
func Definition() worker.Definition {
	return worker.Definition{
		Name:   RoleName,
		Queues: map[string]int{outbox.QueueNotify: Concurrency},
		Needs: worker.Needs{
			DB:       worker.AccessReadWrite,
			Blob:     worker.AccessNone,
			Outbound: true,
		},
		Register: register,
		Periodic: periodic,
	}
}

func register(deps worker.Deps, workers *river.Workers) error {
	cfg, err := config.Load[config.Notifier]()
	if err != nil {
		return fmt.Errorf("notifier: %w", err)
	}
	if err := checkDeps(deps); err != nil {
		return err
	}
	if err := river.AddWorkerSafely(workers, &Pruner{db: deps.DB, retention: cfg.WebhookDeliveryRetention}); err != nil {
		return err
	}
	if err := river.AddWorkerSafely(workers, &Dispatcher{db: deps.DB, enqueue: outbox.NewWriter()}); err != nil {
		return err
	}
	if err := river.AddWorkerSafely(workers, &WaiverChecker{db: deps.DB, notice: cfg.WaiverNotice}); err != nil {
		return err
	}
	return river.AddWorkerSafely(workers, NewDeliverer(deps.DB, deps.Fetch, cfg.WebhookTimeout))
}

func periodic(worker.Config) ([]*river.PeriodicJob, error) {
	cfg, err := config.Load[config.Notifier]()
	if err != nil {
		return nil, fmt.Errorf("notifier: %w", err)
	}
	if cfg.WebhookDispatchInterval < time.Second {
		return nil, fmt.Errorf("%sWEBHOOK_DISPATCH_INTERVAL is %s; it must be at least 1s", config.EnvPrefix, cfg.WebhookDispatchInterval)
	}
	if cfg.WaiverCheckInterval < time.Minute || cfg.WaiverNotice <= 0 {
		return nil, fmt.Errorf("%sWAIVER_CHECK_INTERVAL must be at least 1m and %sWAIVER_NOTICE positive",
			config.EnvPrefix, config.EnvPrefix)
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(cfg.WebhookDispatchInterval),
			func() (river.JobArgs, *river.InsertOpts) { return Dispatch{}, nil },
			&river.PeriodicJobOpts{ID: Dispatch{}.Kind(), RunOnStart: true}),
		river.NewPeriodicJob(river.PeriodicInterval(cfg.WaiverCheckInterval),
			func() (river.JobArgs, *river.InsertOpts) { return WaiverCheck{}, nil },
			&river.PeriodicJobOpts{ID: WaiverCheck{}.Kind(), RunOnStart: true}),
		river.NewPeriodicJob(river.PeriodicInterval(pruneInterval),
			func() (river.JobArgs, *river.InsertOpts) { return Prune{}, nil },
			&river.PeriodicJobOpts{ID: Prune{}.Kind(), RunOnStart: true}),
	}, nil
}

// checkDeps refuses what the role did not declare as much as what it lacks.
func checkDeps(deps worker.Deps) error {
	switch {
	case deps.DB == nil:
		return errors.New("notifier: no database handle")
	case deps.Fetch == nil:
		return errors.New("notifier: no outbound client")
	case deps.BlobRead != nil || deps.BlobWrite != nil:
		return errors.New("notifier: handed an object-store credential it never uses")
	}
	return nil
}
