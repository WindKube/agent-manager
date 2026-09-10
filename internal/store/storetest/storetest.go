//go:build integration

// Package storetest is the shared Postgres testcontainers harness for this
// module's integration suites: one container running postgres:16-alpine,
// migrations replayed from the checked-in directory, wired to either a raw
// pool or a bun.DB with every model registered.
package storetest

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/store/migrations"
	"agent-manager/internal/store/models"
)

// Postgres is one running container plus its bootstrap-database endpoint.
type Postgres struct {
	Endpoint string
}

// Run starts a postgres:16-alpine container with the bootstrap database,
// user and password every suite in this module shares. Call the returned
// func to terminate it.
func Run(ctx context.Context) (*Postgres, func(), error) {
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("agent_manager"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("start postgres: %w", err)
	}
	cleanup := func() {
		if termErr := container.Terminate(ctx); termErr != nil {
			fmt.Fprintln(os.Stderr, "terminate postgres:", termErr)
		}
	}

	endpoint, err := container.PortEndpoint(ctx, "5432/tcp", "")
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("container endpoint: %w", err)
	}

	return &Postgres{Endpoint: endpoint}, cleanup, nil
}

// DSN builds a connection string for the named database on this container.
func (p *Postgres) DSN(database string) string {
	return fmt.Sprintf("postgres://postgres:postgres@%s/%s?sslmode=disable", p.Endpoint, database)
}

// Pool opens a pgxpool.Pool to the named database on this container.
func (p *Postgres) Pool(ctx context.Context, database string) (*pgxpool.Pool, error) {
	return pgxpool.New(ctx, p.DSN(database))
}

// CreateDatabase runs `create database <name>`, using admin as a connection
// to a database that already exists on the same container.
func CreateDatabase(ctx context.Context, admin *pgxpool.Pool, name string) error {
	_, err := admin.Exec(ctx, "create database "+name)
	return err
}

// ApplyMigrations replays the checked-in migration directory against pool:
// what ships to production, not the desired state in internal/store/schema.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	return migrations.Apply(ctx, func(ctx context.Context, sql string) error {
		_, execErr := pool.Exec(ctx, sql)
		return execErr
	})
}

// BunDB wraps pool in a bun.DB with every model registered.
func BunDB(pool *pgxpool.Pool) *bun.DB {
	db := bun.NewDB(stdlib.OpenDBFromPool(pool), pgdialect.New())
	db.RegisterModel(models.All()...)
	return db
}
