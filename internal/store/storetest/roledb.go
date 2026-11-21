// Package storetest holds test helpers that exercise a database role's real
// grants instead of the testcontainers superuser.
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

// RoleDB opens a bun.DB whose connections all `set role` first, so missing
// grants (e.g. RETURNING on an INSERT-only role) surface in tests. dsn must be
// a superuser or a member of role; the caller must call closeFn.
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
