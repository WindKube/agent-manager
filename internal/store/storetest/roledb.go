// Package storetest holds test-only helpers for exercising a database role's
// actual grants, rather than the superuser connection a testcontainers suite
// hands out by default.
package storetest

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/store/models"
)

// RoleDB opens a bun.DB whose every connection has run `set role` before it
// is used. A test that ran its statements over the superuser connection
// testcontainers hands out would never see a grant the role is missing —
// e.g. bun appending RETURNING against an INSERT-only role.
//
// dsn connects as a superuser, or as anything already a member of role; no
// password is provisioned for the application roles, and `set role` needs
// none. The caller must call the returned close func to release the pool.
func RoleDB(ctx context.Context, dsn, role string) (db *bun.DB, closeFn func(), err error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("parse dsn for role %s: %w", role, err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, execErr := conn.Exec(ctx, "set role "+pgx.Identifier{role}.Sanitize())
		return execErr
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("open pool for role %s: %w", role, err)
	}

	sqldb := stdlib.OpenDBFromPool(pool)
	db = bun.NewDB(sqldb, pgdialect.New())
	db.RegisterModel(models.All()...)

	return db, func() {
		_ = sqldb.Close()
		pool.Close()
	}, nil
}
