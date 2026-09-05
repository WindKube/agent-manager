// Package store owns the relational handles. It hands out a bun.IDB for the
// application schema and a raw pgx pool for the queue, and nothing else.
//
// Two databases, two pools, two URLs: `agent_manager` holds the application
// schema, `river` holds the queue and nothing else. No foreign key crosses
// between them and no migration tool sees both, so Open refuses to start when
// the two URLs address the same database — that misconfiguration is what
// would put Atlas, a diff tool with DROP TABLE in its vocabulary, in front of
// River's tables.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/extra/bundebug"

	"agent-manager/internal/store/models"
)

// Handle is the pair of pools a role holds open for its lifetime.
type Handle struct {
	bun   *bun.DB
	sqldb *sql.DB
	app   *pgxpool.Pool
	queue *pgxpool.Pool
}

// Open connects both databases and verifies both are reachable. appURL
// addresses `agent_manager`, queueURL addresses `river` — separate parameters
// on purpose, so one URL for both is a defect this signature cannot express.
func Open(ctx context.Context, appURL, queueURL string) (*Handle, error) {
	if appURL == "" {
		return nil, errors.New("application database url is empty")
	}
	if queueURL == "" {
		return nil, errors.New("queue database url is empty")
	}

	appCfg, err := pgxpool.ParseConfig(appURL)
	if err != nil {
		return nil, fmt.Errorf("parse application database url: %w", err)
	}
	queueCfg, err := pgxpool.ParseConfig(queueURL)
	if err != nil {
		return nil, fmt.Errorf("parse queue database url: %w", err)
	}
	if sameDatabase(appCfg, queueCfg) {
		return nil, fmt.Errorf("application and queue databases are both %s: the queue must live in its own database",
			describe(appCfg))
	}

	app, err := pgxpool.NewWithConfig(ctx, appCfg)
	if err != nil {
		return nil, fmt.Errorf("open application pool: %w", err)
	}
	queue, err := pgxpool.NewWithConfig(ctx, queueCfg)
	if err != nil {
		app.Close()
		return nil, fmt.Errorf("open queue pool: %w", err)
	}

	h := &Handle{app: app, queue: queue}
	h.sqldb = stdlib.OpenDBFromPool(app)
	h.bun = bun.NewDB(h.sqldb, pgdialect.New())
	// Every table, so relations resolve on first use rather than on first
	// query that happens to need one.
	h.bun.RegisterModel(models.All()...)
	h.bun.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv("AGENT_MANAGER_BUNDEBUG"),
	))

	if err := h.Ping(ctx); err != nil {
		_ = h.Close()
		return nil, err
	}
	return h, nil
}

// DB is the application-schema handle the worker Deps contract carries.
// bun.IDB already covers RunInTx and BeginTx, so nothing needs the concrete
// *bun.DB.
func (h *Handle) DB() bun.IDB { return h.bun }

// Queue is the pool River owns. It deliberately exposes no bun.IDB: nothing
// in the application schema references the queue.
func (h *Handle) Queue() *pgxpool.Pool { return h.queue }

func (h *Handle) Ping(ctx context.Context) error {
	if err := h.app.Ping(ctx); err != nil {
		return fmt.Errorf("ping application database: %w", err)
	}
	if err := h.queue.Ping(ctx); err != nil {
		return fmt.Errorf("ping queue database: %w", err)
	}
	return nil
}

// Close drains both pools. The sql.DB rides the application pool, so it
// closes first and the pool second.
func (h *Handle) Close() error {
	var errs []error
	if h.sqldb != nil {
		if err := h.sqldb.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close application sql handle: %w", err))
		}
	}
	if h.app != nil {
		h.app.Close()
	}
	if h.queue != nil {
		h.queue.Close()
	}
	return errors.Join(errs...)
}

// sameDatabase reports whether two pool configs address one database.
// Comparing the URLs as strings would miss two spellings of the same target.
func sameDatabase(a, b *pgxpool.Config) bool {
	return a.ConnConfig.Host == b.ConnConfig.Host &&
		a.ConnConfig.Port == b.ConnConfig.Port &&
		a.ConnConfig.Database == b.ConnConfig.Database
}

func describe(cfg *pgxpool.Config) string {
	return fmt.Sprintf("%s:%d/%s", cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database)
}
