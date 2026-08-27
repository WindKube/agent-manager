//go:build integration

// These tests exist to prove that the constraints and grants in
// internal/store/migrations actually fire. Every assertion here is a behaviour
// the schema is supposed to enforce on its own, without help from Go: if one of
// them starts failing, the guarantee is gone even though the application code
// still compiles.
//
// Nothing here asserts shape for its own sake. A test that only checked "the
// column exists" would pass against a schema that had lost its check constraint.
package store_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"agent-manager/internal/store"
	"agent-manager/internal/store/migrations"
	"agent-manager/internal/store/models"
)

// The suite shares one container and one migrated database. Tests seed their own
// publisher and package so they never collide, which is what lets them stay
// sequential and cheap rather than needing a database each.
var (
	pool     *pgxpool.Pool
	appURL   string
	queueURL string
)

func TestMain(m *testing.M) {
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store integration suite:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runSuite(m *testing.M) (int, error) {
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("agent_manager"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return 0, fmt.Errorf("start postgres: %w", err)
	}
	defer func() {
		if termErr := container.Terminate(ctx); termErr != nil {
			fmt.Fprintln(os.Stderr, "terminate postgres:", termErr)
		}
	}()

	endpoint, err := container.PortEndpoint(ctx, "5432/tcp", "")
	if err != nil {
		return 0, fmt.Errorf("container endpoint: %w", err)
	}
	appURL = fmt.Sprintf("postgres://postgres:postgres@%s/agent_manager?sslmode=disable", endpoint)
	queueURL = fmt.Sprintf("postgres://postgres:postgres@%s/river?sslmode=disable", endpoint)

	pool, err = pgxpool.New(ctx, appURL)
	if err != nil {
		return 0, fmt.Errorf("open pool: %w", err)
	}
	defer pool.Close()

	// The queue's own database, so store.Open has two real targets. Nothing in
	// this suite puts a table in it: that is the point of principle IX.
	if _, err = pool.Exec(ctx, "create database river"); err != nil {
		return 0, fmt.Errorf("create queue database: %w", err)
	}

	// Replay the checked-in migrations rather than the desired state in
	// internal/store/schema. What ships to production is the migration
	// directory, so that is what has to be under test.
	err = migrations.Apply(ctx, func(ctx context.Context, sql string) error {
		_, execErr := pool.Exec(ctx, sql)
		return execErr
	})
	if err != nil {
		return 0, err
	}

	return m.Run(), nil
}

// ---------------------------------------------------------------------------
// FR-007 — a version is immutable
// ---------------------------------------------------------------------------

func TestRepublishingTheSameSemverWithDifferentBytesIsRejectedAndLeavesTheStoredRowIntact(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)

	original := bytes.Repeat([]byte{0xa1}, 32)
	originalKey := "skills/ex/p/1.4.2/bundle.tar.zst"
	verID := seedVersion(t, ctx, pkgID, "1.4.2", original, originalKey)

	// The republish carries a different digest and a different object key: this is
	// the "someone rebuilt and re-pushed 1.4.2" case, not a duplicate submit.
	_, err := insertVersion(ctx, models.NewID(), pkgID, "1.4.2",
		bytes.Repeat([]byte{0xff}, 32), "skills/ex/p/1.4.2/tampered.tar.zst")
	requirePgError(t, err, "23505", "version_package_semver")

	// The rejection is only half the guarantee. The other half is that the bytes
	// already on record did not move, which is what makes a digest published
	// yesterday still mean the same bundle today.
	var (
		gotDigest  []byte
		gotKey     string
		gotVerdict string
	)
	require.NoError(t, pool.QueryRow(ctx,
		`select digest, object_key, verdict from version where id = $1`, verID,
	).Scan(&gotDigest, &gotKey, &gotVerdict))

	require.Equal(t, original, gotDigest, "the stored digest must survive a rejected republish")
	require.Equal(t, originalKey, gotKey, "the stored object key must survive a rejected republish")
	require.Equal(t, "clean", gotVerdict)

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`select count(*) from version where package_id = $1 and semver = '1.4.2'`, pkgID,
	).Scan(&n))
	require.Equal(t, 1, n, "the rejected insert must not have left a second row")
}

// ---------------------------------------------------------------------------
// FR-052 — audit_event is append-only, enforced by the grant and nothing else
// ---------------------------------------------------------------------------

func TestAuditEventRejectsUpdateAndDeleteFromEveryRole(t *testing.T) {
	ctx := context.Background()

	// Seed as the owner so the denied statements have a row to aim at. A statement
	// that matches nothing could be reported as succeeding with zero rows, which
	// would make this test pass for the wrong reason.
	id := models.NewID()
	_, err := pool.Exec(ctx,
		`insert into audit_event (id, actor, actor_kind, kind, "text") values ($1, 'system', 'system', 'login', 'seed')`, id)
	require.NoError(t, err)

	// Every role, not just the request path. am_migrate is included because
	// `grant all on all tables` hands it UPDATE, DELETE and TRUNCATE and the
	// revoke has to take all three back — and because in a real deployment
	// am_migrate is the table owner, where a revoke is easy to assume is a no-op.
	for _, role := range []string{"am_api", "am_fetcher", "am_scanner", "am_migrate"} {
		t.Run(role, func(t *testing.T) {
			asRole(t, role, func(ctx context.Context, conn *pgxpool.Conn) {
				for _, tc := range []struct {
					name, stmt string
					args       []any
				}{
					{name: "update is denied", stmt: `update audit_event set "text" = 'tampered' where id = $1`, args: []any{id}},
					{name: "delete is denied", stmt: `delete from audit_event where id = $1`, args: []any{id}},
					// TRUNCATE is a separate privilege and is not implied by DELETE, so a
					// schema that revoked only UPDATE and DELETE would still be one
					// statement away from an empty audit log.
					{name: "truncate is denied", stmt: `truncate audit_event`},
					// UPDATE ... FROM is a different parse tree reaching the same write.
					{name: "update from another table is denied", stmt: `update audit_event set "text" = 'tampered' from pg_class where audit_event.id = $1`, args: []any{id}},
					// The upsert route: INSERT is granted, so the DO UPDATE half is the
					// only thing standing between an append-only log and an editable one.
					{name: "insert on conflict do update is denied", stmt: `insert into audit_event (id, actor, actor_kind, kind, "text")
						values ($1, 'x', 'system', 'login', 'y') on conflict (id) do update set "text" = 'pwned'`, args: []any{id}},
				} {
					t.Run(tc.name, func(t *testing.T) {
						_, err := conn.Exec(ctx, tc.stmt, tc.args...)
						requirePgError(t, err, "42501", "")
					})
				}

				t.Run("insert is allowed, because the log must still be writable", func(t *testing.T) {
					_, err := conn.Exec(ctx,
						`insert into audit_event (id, actor, actor_kind, kind, "text") values ($1, 'a@example.com', 'identity', 'login', 'signed in')`,
						models.NewID())
					require.NoError(t, err)
				})

				// A role that could grant itself back would make the revoke advisory.
				// Postgres answers a grant with no privilege to give as a warning, not
				// an error, so the assertion has to read the resulting privilege.
				t.Run("the role cannot grant the privilege back to itself", func(t *testing.T) {
					_, _ = conn.Exec(ctx, "grant update on table audit_event to "+role)
					var granted bool
					require.NoError(t, conn.QueryRow(ctx,
						`select has_table_privilege($1, 'audit_event', 'update')`, role).Scan(&granted))
					require.False(t, granted, "%s must not be able to grant itself UPDATE on audit_event", role)
				})
			})
		})
	}

	var text string
	require.NoError(t, pool.QueryRow(ctx, `select "text" from audit_event where id = $1`, id).Scan(&text))
	require.Equal(t, "seed", text, "the seeded row must be byte-identical after every denied attempt")
}

// ---------------------------------------------------------------------------
// contracts/worker.md — the scanner does not produce bundle bytes
// ---------------------------------------------------------------------------

func TestScannerMayWriteTheVerdictButNotTheBundleBytes(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)
	digest := bytes.Repeat([]byte{0x7e}, 32)
	objectKey := "skills/ex/p/2.0.0/bundle.tar.zst"
	verID := seedVersion(t, ctx, pkgID, "2.0.0", digest, objectKey)

	asRole(t, "am_scanner", func(ctx context.Context, conn *pgxpool.Conn) {
		t.Run("verdict is writable, because that is the scanner's whole output", func(t *testing.T) {
			_, err := conn.Exec(ctx, `update version set verdict = 'flagged' where id = $1`, verID)
			require.NoError(t, err)
		})

		t.Run("verdict is writable through update ... from too", func(t *testing.T) {
			_, err := conn.Exec(ctx,
				`update version v set verdict = 'clean' from package p where p.id = v.package_id and v.id = $1`, verID)
			require.NoError(t, err)
		})

		// Every route to the bundle bytes, not just the obvious one. Postgres checks
		// UPDATE privilege against the target column list, so each of these is a
		// different statement shape aimed at the same column.
		for _, tc := range []struct {
			name, stmt string
			// DDL takes no bind parameter. Postgres refuses a parameter in a utility
			// statement with a different error than it refuses the privilege, which
			// would make those cases pass for the wrong reason.
			args []any
		}{
			{name: "digest is not writable", stmt: `update version set digest = decode(repeat('0', 64), 'hex') where id = $1`, args: []any{verID}},
			{name: "object_key is not writable", stmt: `update version set object_key = 'skills/attacker/bundle.tar.zst' where id = $1`, args: []any{verID}},
			{name: "size_bytes is not writable", stmt: `update version set size_bytes = 1 where id = $1`, args: []any{verID}},
			{name: "manifest is not writable", stmt: `update version set manifest = '{}' where id = $1`, args: []any{verID}},
			{name: "visible is not writable, because commit-last is not the scanner's call", stmt: `update version set visible = true where id = $1`, args: []any{verID}},
			// A whole-row UPDATE that re-states digest with its current value still
			// names the column, so it is refused. Worth pinning: this is the shape an
			// ORM produces when it writes a model back rather than one field.
			{name: "verdict and digest in one statement is refused whole", stmt: `update version set verdict = 'clean', digest = digest where id = $1`, args: []any{verID}},
			{name: "digest is not writable through update ... from", stmt: `update version v set digest = decode(repeat('0', 64), 'hex') from package p where p.id = v.package_id and v.id = $1`, args: []any{verID}},
			// INSERT would let the sandbox mint a version row carrying bytes of its
			// choosing, which is the same forgery through another door.
			{name: "a new version row cannot be inserted", stmt: `insert into version (id, package_id, semver, semver_sort, object_key, digest, manifest, dist_tag, verdict)
				select gen_random_uuid(), package_id, '9.9.9', 'z', 'k', digest, manifest, 'none', 'clean' from version where id = $1`, args: []any{verID}},
			{name: "a version row cannot be deleted", stmt: `delete from version where id = $1`, args: []any{verID}},
			// No CREATE on schema public, so the scanner cannot build itself a view or
			// a function to launder the write through.
			{name: "the scanner cannot create a view over the table", stmt: `create view scanner_escape as select digest from version`},
			{name: "the scanner cannot create a function", stmt: `create function scanner_escape() returns void as $fn$ begin return; end $fn$ language plpgsql`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := conn.Exec(ctx, tc.stmt, tc.args...)
				requirePgError(t, err, "42501", "")
			})
		}

		// A rule would rewrite an allowed UPDATE into a forbidden one, and it is the
		// one route that fails with a different sqlstate: rules need ownership.
		t.Run("the scanner cannot install a rule on the table", func(t *testing.T) {
			_, err := conn.Exec(ctx, `create rule scanner_escape as on update to version do instead nothing`)
			requirePgError(t, err, "42501", "")
		})
	})

	var (
		gotVerdict string
		gotDigest  []byte
		gotKey     string
		gotVisible bool
	)
	require.NoError(t, pool.QueryRow(ctx,
		`select verdict, digest, object_key, visible from version where id = $1`, verID,
	).Scan(&gotVerdict, &gotDigest, &gotKey, &gotVisible))

	require.Equal(t, "clean", gotVerdict, "the permitted writes must have landed")
	require.Equal(t, digest, gotDigest, "the denied writes must not have landed")
	require.Equal(t, objectKey, gotKey, "the denied writes must not have landed")
	require.True(t, gotVisible, "visible must still be what the publisher set it to")
}

func TestWebRoleHasNoDatabaseRoleAtAll(t *testing.T) {
	ctx := context.Background()

	var exists bool
	require.NoError(t, pool.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = 'am_web')`).Scan(&exists))
	require.False(t, exists,
		"am_web must not exist: the web role reaches data only through the api over HTTP, so a role for it would make that boundary configuration rather than structure")

	rows, err := pool.Query(ctx, `select rolname from pg_roles where rolname like 'am\_%' order by 1`)
	require.NoError(t, err)
	defer rows.Close()

	var got []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		got = append(got, name)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []string{"am_api", "am_fetcher", "am_migrate", "am_scanner"}, got)
}

// ---------------------------------------------------------------------------
// The check constraints
// ---------------------------------------------------------------------------

func TestOrgPolicyRejectsASecondRow(t *testing.T) {
	ctx := context.Background()

	// The table is a singleton, so a row left by anything else would make either
	// half of this test pass for the wrong reason.
	_, err := pool.Exec(ctx, `delete from org_policy`)
	require.NoError(t, err)

	insert := func(id int) error {
		_, err := pool.Exec(ctx, `insert into org_policy
			(id, scan_gate, default_version_policy, require_signed_bundles, community_needs_review, rescan_on_new_version, allow_personal_profiles)
			values ($1, 'block', 'pinned', false, true, true, false)`, id)
		return err
	}

	require.NoError(t, insert(int(models.OrgPolicySingletonID)), "the singleton row itself must be insertable")

	// id = 2 is refused by the check, not by the primary key: a second policy row
	// is a second set of org-wide rules that half the queries would never see.
	requirePgError(t, insert(2), "23514", "org_policy_singleton")

	// And id = 1 again is refused by the primary key, so there is no way in.
	requirePgError(t, insert(1), "23505", "org_policy_pkey")

	var n int
	require.NoError(t, pool.QueryRow(ctx, `select count(*) from org_policy`).Scan(&n))
	require.Equal(t, 1, n)
}

func TestProfileEntryRejectsPinnedWithoutAPinnedVersion(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)
	verID := seedVersion(t, ctx, pkgID, "3.1.0", bytes.Repeat([]byte{0x11}, 32), "skills/ex/p/3.1.0/bundle.tar.zst")
	profileID := seedProfile(t, ctx)

	insert := func(mode string, pinned *uuid.UUID) error {
		_, err := pool.Exec(ctx, `insert into profile_entry
			(profile_id, package_id, mode, pinned_version_id, "position")
			values ($1, $2, $3, $4, 0)`, profileID, pkgID, mode, pinned)
		return err
	}

	requirePgError(t, insert("pinned", nil), "23514", "profile_entry_pinned_has_version")

	// The positive case matters: a check that rejected everything would also pass
	// the assertion above.
	require.NoError(t, insert("pinned", &verID))
}

func TestVersionRejectsANonScanningVerdictWithoutADigest(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)

	// FR-008 commit-last: a publish that lost its bytes is stuck at 'scanning'
	// rather than advertising a clean version with nothing behind it.
	_, err := pool.Exec(ctx, `insert into version
		(id, package_id, semver, semver_sort, object_key, digest, manifest, dist_tag, verdict)
		values ($1, $2, '4.0.0', $3, 'skills/ex/p/4.0.0/bundle.tar.zst', null, '{}', 'latest', 'clean')`,
		models.NewID(), pkgID, mustSemverSort(t, "4.0.0"))
	requirePgError(t, err, "23514", "version_digest_present_unless_scanning")

	// The same row at verdict 'scanning' is legal, digest still null.
	_, err = pool.Exec(ctx, `insert into version
		(id, package_id, semver, semver_sort, object_key, digest, manifest, dist_tag, verdict)
		values ($1, $2, '4.0.0', $3, 'skills/ex/p/4.0.0/bundle.tar.zst', null, '{}', 'latest', 'scanning')`,
		models.NewID(), pkgID, mustSemverSort(t, "4.0.0"))
	require.NoError(t, err)
}

func TestVersionRejectsADigestThatIsNotSha256Sized(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)

	for _, tc := range []struct {
		name string
		size int
	}{
		{"one byte short", 31},
		{"one byte long", 33},
		{"empty", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := insertVersion(ctx, models.NewID(), pkgID, fmt.Sprintf("5.0.%d", tc.size),
				bytes.Repeat([]byte{0x01}, tc.size), "skills/ex/p/5/bundle.tar.zst")
			requirePgError(t, err, "23514", "version_digest_is_sha256")
		})
	}
}

// ---------------------------------------------------------------------------
// R5 — the scan idempotency key
// ---------------------------------------------------------------------------

// A scan job is delivered at least once (principle IX), so the second delivery
// has to be stopped by the schema rather than by the worker remembering. The
// unique key is also what makes "rescan needed" a comparison against
// pack_version instead of a guess.
func TestARedeliveredScanForTheSameVersionAndPackVersionIsRejected(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)
	verID := seedVersion(t, ctx, pkgID, "6.0.0", bytes.Repeat([]byte{0x22}, 32), "skills/ex/p/6.0.0/bundle.tar.zst")
	otherVerID := seedVersion(t, ctx, pkgID, "6.0.1", bytes.Repeat([]byte{0x23}, 32), "skills/ex/p/6.0.1/bundle.tar.zst")

	insert := func(versionID uuid.UUID, packVersion string) error {
		_, err := pool.Exec(ctx,
			`insert into scan (id, version_id, pack_version, verdict) values ($1, $2, $3, 'clean')`,
			models.NewID(), versionID, packVersion)
		return err
	}

	require.NoError(t, insert(verID, "2026.08.1"))
	requirePgError(t, insert(verID, "2026.08.1"), "23505", "scan_version_pack_version")

	// The two cases the key must NOT block, because a constraint that refused
	// them would break rescans and every other version in the catalog.
	require.NoError(t, insert(verID, "2026.09.1"), "a new rule-pack version must be allowed to rescan")
	require.NoError(t, insert(otherVerID, "2026.08.1"), "another version at the same pack version is a different scan")

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`select count(*) from scan where version_id = $1`, verID).Scan(&n))
	require.Equal(t, 2, n, "the redelivery must not have left a third scan row")
}

// ---------------------------------------------------------------------------
// A publisher cannot own two packages of the same name
// ---------------------------------------------------------------------------

func TestAPublisherCannotOwnTwoPackagesOfTheSameName(t *testing.T) {
	ctx := context.Background()

	pubA, pubB := seedPublisher(t, ctx), seedPublisher(t, ctx)

	insert := func(pubID uuid.UUID, name string) error {
		_, err := pool.Exec(ctx,
			`insert into package (id, publisher_id, name, kind, visibility) values ($1, $2, $3, 'skill', 'organisation')`,
			models.NewID(), pubID, name)
		return err
	}

	require.NoError(t, insert(pubA, "deploy-helper"))
	requirePgError(t, insert(pubA, "deploy-helper"), "23505", "package_publisher_name")

	// The key is scoped to the publisher, so the same name under another
	// publisher is a different package and must be allowed.
	require.NoError(t, insert(pubB, "deploy-helper"))
}

// ---------------------------------------------------------------------------
// Sequential revisions with no gap
// ---------------------------------------------------------------------------

func TestTwoConcurrentRevisionPublishesProduceSeq1And2WithNoGap(t *testing.T) {
	ctx := context.Background()

	// Repeated because a race that only shows up on some interleavings is exactly
	// the failure this constraint exists to prevent.
	for round := range 5 {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			profileID := seedProfile(t, ctx)

			var (
				start = make(chan struct{})
				wg    sync.WaitGroup
				mu    sync.Mutex
				seqs  []int
				errs  []error
			)

			for range 2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					seq, err := publishRevision(ctx, profileID)
					mu.Lock()
					defer mu.Unlock()
					if err != nil {
						errs = append(errs, err)
						return
					}
					seqs = append(seqs, seq)
				}()
			}
			close(start)
			wg.Wait()

			require.Empty(t, errs, "both publishes must succeed: the row lock serialises them, it does not fail one")
			sort.Ints(seqs)
			require.Equal(t, []int{1, 2}, seqs,
				"seq is allocated as max(seq)+1 under a lock on the parent profile row, so two racing publishes must land on 1 and 2 — a sequence would leave a gap on rollback")

			var count, maxSeq int
			require.NoError(t, pool.QueryRow(ctx,
				`select count(*), coalesce(max(seq), 0) from revision where profile_id = $1`, profileID,
			).Scan(&count, &maxSeq))
			require.Equal(t, 2, count)
			require.Equal(t, 2, maxSeq, "no gap: the highest seq equals the row count")
		})
	}
}

// publishRevision allocates seq the way data-model.md specifies: under a row lock
// on the parent profile, inside the transaction that writes the revision. The
// `for update` is the whole mechanism — without it both transactions read the
// same max(seq) and one loses to the unique constraint.
func publishRevision(ctx context.Context, profileID uuid.UUID) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `select id from profile where id = $1 for update`, profileID).Scan(&locked); err != nil {
		return 0, fmt.Errorf("lock profile: %w", err)
	}

	var seq int
	if err := tx.QueryRow(ctx,
		`select coalesce(max(seq), 0) + 1 from revision where profile_id = $1`, profileID,
	).Scan(&seq); err != nil {
		return 0, fmt.Errorf("allocate seq: %w", err)
	}

	if _, err := tx.Exec(ctx, `insert into revision
		(id, profile_id, seq, lockfile, object_key, created_by)
		values ($1, $2, $3, '{}', $4, 'integration-test')`,
		models.NewID(), profileID, seq, fmt.Sprintf("profiles/p/r%d.json", seq)); err != nil {
		return 0, fmt.Errorf("insert revision: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return seq, nil
}

// ---------------------------------------------------------------------------
// The migrated schema against the Go source of truth
// ---------------------------------------------------------------------------

// TestEnumTypesInTheDatabaseMatchTheGoConstSets is the guard the comment at the
// top of internal/store/schema/01-enums.sql promises. That file is a hand-written
// copy of models.EnumDDL(), so without this test a value added in Go would reach
// production as a failed insert.
func TestEnumTypesInTheDatabaseMatchTheGoConstSets(t *testing.T) {
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		select t.typname, e.enumlabel
		from pg_type t
		join pg_enum e on e.enumtypid = t.oid
		join pg_namespace n on n.oid = t.typnamespace
		where n.nspname = 'public'
		order by t.typname, e.enumsortorder`)
	require.NoError(t, err)
	defer rows.Close()

	got := map[string][]string{}
	for rows.Next() {
		var name, label string
		require.NoError(t, rows.Scan(&name, &label))
		got[name] = append(got[name], label)
	}
	require.NoError(t, rows.Err())

	require.Equal(t, models.EnumTypes(), got,
		"every enum type and its value order must match the Go const sets in both directions")
}

// TestEveryModelColumnExistsInTheMigratedSchema closes the loop between the Bun
// models and the checked-in SQL. internal/store/schema/02-tables.sql is generated
// from the models but committed, so it can go stale; this fails when it has.
func TestEveryModelColumnExistsInTheMigratedSchema(t *testing.T) {
	ctx := context.Background()

	handle, err := store.Open(ctx, appURL, queueURL)
	require.NoError(t, err)
	defer func() { require.NoError(t, handle.Close()) }()

	tables := handle.DB().Dialect().Tables()

	actual := map[string]map[string]bool{}
	rows, err := pool.Query(ctx,
		`select table_name, column_name from information_schema.columns where table_schema = 'public'`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var table, column string
		require.NoError(t, rows.Scan(&table, &column))
		if actual[table] == nil {
			actual[table] = map[string]bool{}
		}
		actual[table][column] = true
	}
	require.NoError(t, rows.Err())

	require.Len(t, actual, len(models.All()), "the migrated schema must hold exactly one table per registered model")

	for _, model := range models.All() {
		table := tables.Get(reflect.TypeOf(model).Elem())
		require.NotNil(t, table)

		t.Run(table.Name, func(t *testing.T) {
			require.Contains(t, actual, table.Name)
			for _, field := range table.Fields {
				require.True(t, actual[table.Name][field.Name],
					"column %s.%s is mapped by a Bun model but missing from the migrated schema", table.Name, field.Name)
			}
		})
	}
}

// TestIndexDefinitionsAreExactlyAsSpecified pins the whole definition, not the
// existence. Every index T017 asks for has a predicate or a sort order that is
// the point of it: widen `state = 'open'` and the planner stops using the index
// for the open-findings query, drop the DESC and the audit log's first page goes
// back to sorting. An existence check would pass through all of that.
func TestIndexDefinitionsAreExactlyAsSpecified(t *testing.T) {
	ctx := context.Background()

	want := map[string]string{
		"version_tags_gin":                "CREATE INDEX version_tags_gin ON public.version USING gin (tags)",
		"version_package_semver_sort_idx": "CREATE INDEX version_package_semver_sort_idx ON public.version USING btree (package_id, semver_sort DESC)",
		"version_verdict_visible_idx":     "CREATE INDEX version_verdict_visible_idx ON public.version USING btree (verdict) WHERE visible",
		"version_created_at_idx":          "CREATE INDEX version_created_at_idx ON public.version USING btree (created_at DESC)",
		"finding_open_version_idx":        "CREATE INDEX finding_open_version_idx ON public.finding USING btree (version_id) WHERE (state = 'open'::finding_state)",
		"outbox_pending_created_at_idx":   "CREATE INDEX outbox_pending_created_at_idx ON public.outbox USING btree (created_at) WHERE (state = 'pending'::outbox_state)",
		"audit_event_occurred_at_idx":     "CREATE INDEX audit_event_occurred_at_idx ON public.audit_event USING btree (occurred_at DESC)",
	}

	for name, def := range want {
		t.Run(name, func(t *testing.T) {
			var got string
			require.NoError(t, pool.QueryRow(ctx,
				`select indexdef from pg_indexes where schemaname = 'public' and indexname = $1`, name).Scan(&got))
			require.Equal(t, def, got)
		})
	}
}

// pgDeleteActions is pg_constraint.confdeltype's whole alphabet. It is a single
// char there, which is why this reads pg_constraint rather than
// information_schema, where the delete action is a join away instead of a column.
var pgDeleteActions = map[string]string{
	"a": "no action",
	"r": "restrict",
	"c": "cascade",
	"n": "set null",
	"d": "set default",
}

// TestEveryForeignKeyIsPresent asserts the whole set, each entry carrying its
// delete action, and asserts it by exact equality: a missing foreign key and an
// unexpected extra one both fail.
//
// The delete action is here because existence alone is not the guarantee anyone
// wants. Every one of these is NO ACTION, uniformly: the catalog is append-only,
// no role holds DELETE on the tables these point at, and a delete that would
// cascade is a bug to surface rather than to propagate. An FK created ON DELETE
// CASCADE satisfies every other check in this repo — the models, the generated
// SQL, the design — and then quietly deletes rows nobody asked it to, so it is
// pinned per foreign key here.
func TestEveryForeignKeyIsPresent(t *testing.T) {
	ctx := context.Background()

	want := make([]string, 0, len(wantForeignKeys))
	for _, fk := range wantForeignKeys {
		want = append(want, fk+" on delete no action")
	}
	sort.Strings(want)

	rows, err := pool.Query(ctx, `
		select conrelid::regclass::text || '(' ||
		       (select string_agg(a.attname, ',' order by k.ord)
		          from unnest(c.conkey) with ordinality k(att, ord)
		          join pg_attribute a on a.attrelid = c.conrelid and a.attnum = k.att) ||
		       ') -> ' || confrelid::regclass::text,
		       c.confdeltype::text
		from pg_constraint c
		where contype = 'f' and connamespace = 'public'::regnamespace`)
	require.NoError(t, err)
	defer rows.Close()

	var got []string
	for rows.Next() {
		var fk, delType string
		require.NoError(t, rows.Scan(&fk, &delType))

		action, ok := pgDeleteActions[delType]
		require.True(t, ok, "unknown confdeltype %q on %s", delType, fk)
		got = append(got, fk+" on delete "+action)
	}
	require.NoError(t, rows.Err())
	sort.Strings(got)

	require.Equal(t, want, got)
}

// TestPostgresOrdersSemverSortAsSemverPrecedence is the half of SemverSort that
// Go cannot test. The Go unit test proves the keys sort correctly as Go strings;
// the ordering that ships happens in Postgres, under the column's `collate "C"`
// and inside an index. If the collation were lost, or if a locale reordered the
// key alphabet, `order by semver_sort` would silently disagree with semver here
// and nowhere else.
func TestPostgresOrdersSemverSortAsSemverPrecedence(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)

	// Semver's own precedence example, plus the two decimal traps a naive text
	// sort fails (1.9.0 < 1.10.0) and a numeric prerelease identifier, which
	// semver ranks below any alphanumeric one.
	ascending := []string{
		"1.0.0-1", "1.0.0-2", "1.0.0-11",
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
		"1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
		"1.0.0-rc.1", "1.0.0",
		"1.0.1", "1.9.0", "1.10.0", "2.0.0",
	}

	for _, semver := range ascending {
		_, err := pool.Exec(ctx, `insert into version
			(id, package_id, semver, semver_sort, object_key, digest, manifest, dist_tag, verdict)
			values ($1, $2, $3, $4, 'k', decode(repeat('7', 64), 'hex'), '{}', 'none', 'clean')`,
			models.NewID(), pkgID, semver, mustSemverSort(t, semver))
		require.NoError(t, err)
	}

	rows, err := pool.Query(ctx,
		`select semver from version where package_id = $1 order by semver_sort`, pkgID)
	require.NoError(t, err)
	defer rows.Close()

	var got []string
	for rows.Next() {
		var semver string
		require.NoError(t, rows.Scan(&semver))
		got = append(got, semver)
	}
	require.NoError(t, rows.Err())

	require.Equal(t, ascending, got)

	var collation string
	require.NoError(t, pool.QueryRow(ctx, `
		select coalesce(co.collname, '<database default>')
		from pg_attribute a
		join pg_class c on c.oid = a.attrelid and c.relname = 'version'
		left join pg_collation co on co.oid = a.attcollation
		where a.attname = 'semver_sort'`).Scan(&collation))
	require.Equal(t, "C", collation,
		"semver_sort must be collate \"C\" so the order above is independent of the cluster's locale")
}

// ---------------------------------------------------------------------------
// Two databases, never one (principle IX, R11)
// ---------------------------------------------------------------------------
// These three need no container. They live here because the guard they cover is
// the R11 defect — one URL used for both — and there is nowhere else in this
// package to put them.

func TestOpenRefusesAMisconfiguredPair(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name       string
		app, queue string
		wantErr    string
	}{
		{"empty application url", "", queueURL, "application database url is empty"},
		{"empty queue url", appURL, "", "queue database url is empty"},
		{
			// The same target spelled two ways. Comparing the URLs as strings would
			// miss this, which is why Open compares the parsed host, port and database.
			name:    "both urls address the same database",
			app:     appURL,
			queue:   appURL + "&application_name=river",
			wantErr: "the queue must live in its own database",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handle, err := store.Open(ctx, tc.app, tc.queue)
			require.Nil(t, handle)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestQueueDatabaseHoldsNoApplicationTables(t *testing.T) {
	ctx := context.Background()

	queue, err := pgxpool.New(ctx, queueURL)
	require.NoError(t, err)
	defer queue.Close()

	var n int
	require.NoError(t, queue.QueryRow(ctx,
		`select count(*) from pg_tables where schemaname = 'public'`).Scan(&n))
	require.Zero(t, n,
		"the queue database must hold nothing from the application schema: Atlas is pointed at agent_manager only, and that is what keeps the isolation structural")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// asRole runs fn on a dedicated connection with `set role`, which is how the
// grants are exercised without needing a password for each role. Postgres checks
// privileges against the role in effect, so a superuser session that has set role
// to am_api is denied exactly what am_api is denied.
func asRole(t *testing.T, role string, fn func(ctx context.Context, conn *pgxpool.Conn)) {
	t.Helper()
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	_, err = conn.Exec(ctx, "set role "+role)
	require.NoError(t, err)
	// Resetting is correctness, not tidiness: a released connection goes back to
	// the pool carrying whatever role it last had.
	defer func() {
		_, err := conn.Exec(ctx, "reset role")
		require.NoError(t, err)
	}()

	fn(ctx, conn)
}

func requirePgError(t *testing.T, err error, sqlState, constraint string) {
	t.Helper()

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, sqlState, pgErr.Code, "sqlstate (message was %q)", pgErr.Message)
	if constraint != "" {
		require.Equal(t, constraint, pgErr.ConstraintName,
			"the violated constraint must be the named one, so a handler can translate it")
	}
}

func seedPublisher(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()

	id := models.NewID()
	_, err := pool.Exec(ctx,
		`insert into publisher (id, slug, display_name) values ($1, $2, 'Example')`,
		id, "example/"+id.String())
	require.NoError(t, err)

	return id
}

func seedPackage(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()

	pubID, pkgID := seedPublisher(t, ctx), models.NewID()
	_, err := pool.Exec(ctx,
		`insert into package (id, publisher_id, name, kind, visibility) values ($1, $2, $3, 'skill', 'organisation')`,
		pkgID, pubID, "p-"+pkgID.String())
	require.NoError(t, err)

	return pkgID
}

func seedProfile(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()

	id := models.NewID()
	_, err := pool.Exec(ctx,
		`insert into profile (id, slug, name, visibility, default_policy) values ($1, $2, 'Platform', 'organisation', 'floating-latest')`,
		id, "profile-"+id.String())
	require.NoError(t, err)

	return id
}

func seedVersion(t *testing.T, ctx context.Context, pkgID uuid.UUID, semver string, digest []byte, objectKey string) uuid.UUID {
	t.Helper()

	id := models.NewID()
	_, err := insertVersion(ctx, id, pkgID, semver, digest, objectKey)
	require.NoError(t, err)

	return id
}

func insertVersion(ctx context.Context, id, pkgID uuid.UUID, semver string, digest []byte, objectKey string) (uuid.UUID, error) {
	sortKey, err := models.SemverSort(semver)
	if err != nil {
		return id, err
	}
	_, err = pool.Exec(ctx, `insert into version
		(id, package_id, semver, semver_sort, object_key, digest, size_bytes, manifest, dist_tag, verdict, visible)
		values ($1, $2, $3, $4, $5, $6, 2048, '{"name":"p"}', 'latest', 'clean', true)`,
		id, pkgID, semver, sortKey, objectKey, digest)
	return id, err
}

func mustSemverSort(t *testing.T, semver string) string {
	t.Helper()

	key, err := models.SemverSort(semver)
	require.NoError(t, err)

	return key
}

// ---------------------------------------------------------------------------
// Principle II — the fetcher's grant has to cover the whole ingestion write
// ---------------------------------------------------------------------------

// The grant table is a list of tables, which makes it easy to grant a parent and
// forget a child that the same transaction touches. This drives the real
// ingestion write end to end in one transaction so a missing grant shows up as a
// failed publish rather than as a runtime error in production. It caught
// version_tag and publisher missing from am_fetcher.
func TestFetcherCanPerformTheWholeIngestionWriteInOneTransaction(t *testing.T) {
	asRole(t, "am_fetcher", func(ctx context.Context, conn *pgxpool.Conn) {
		tx, err := conn.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()

		pubID, pkgID, verID := models.NewID(), models.NewID(), models.NewID()
		slug := "pub-" + pubID.String()

		// Registering the first package under a new publisher creates the
		// publisher row; package.publisher_id is NOT NULL, so there is no order
		// in which the fetcher can skip this.
		_, err = tx.Exec(ctx,
			`insert into publisher (id, slug, display_name) values ($1, $2, 'Fetcher Test')`, pubID, slug)
		require.NoError(t, err, "publisher")

		_, err = tx.Exec(ctx,
			`insert into package (id, publisher_id, name, kind, visibility)
			 values ($1, $2, $3, 'skill', 'organisation')`, pkgID, pubID, "p-"+pkgID.String())
		require.NoError(t, err, "package")

		// verdict starts at 'scanning' and visible at false: commit-last (FR-008)
		// means the fetcher publishes an invisible row and the scanner's verdict
		// is what reveals it.
		_, err = tx.Exec(ctx,
			`insert into version (id, package_id, semver, semver_sort, object_key, digest, size_bytes, manifest, dist_tag, verdict, visible)
			 values ($1, $2, '1.0.0', $3, $4, $5, 4096, '{"name":"p"}', 'latest', 'scanning', false)`,
			verID, pkgID, semverSort(t, "1.0.0"), "skills/"+slug+"/p/1.0.0/bundle.tar.zst",
			bytes.Repeat([]byte{0x11}, 32))
		require.NoError(t, err, "version")

		// The pair that made this test necessary. version.tags is a
		// denormalisation of version_tag and both are written here, so a grant on
		// one without the other cannot commit.
		_, err = tx.Exec(ctx,
			`insert into version_tag (version_id, tag) values ($1, 'terraform'), ($1, 'iac')`, verID)
		require.NoError(t, err, "version_tag")

		_, err = tx.Exec(ctx, `update version set tags = array['terraform','iac'] where id = $1`, verID)
		require.NoError(t, err, "version.tags")

		_, err = tx.Exec(ctx,
			`insert into component (version_id, path, kind, name) values ($1, 'SKILL.md', 'skill', 'p')`, verID)
		require.NoError(t, err, "component")

		_, err = tx.Exec(ctx,
			`insert into signature (version_id, kind) values ($1, 'none')`, verID)
		require.NoError(t, err, "signature")

		// The outbox row and its audit row are part of the same transaction by
		// construction (principle IX): the fetch is not published until the
		// scan job is durably enqueued.
		_, err = tx.Exec(ctx,
			`insert into outbox (id, job_kind, payload, idempotency_key, state)
			 values ($1, 'scan', $2, $3, 'pending')`,
			models.NewID(), fmt.Sprintf(`{"version_id":%q}`, verID), "scan:"+verID.String())
		require.NoError(t, err, "outbox")

		_, err = tx.Exec(ctx,
			`insert into audit_event (id, actor, actor_kind, kind, text)
			 values ($1, 'fetcher', 'system', 'fetch', 'fetched 1.0.0')`, models.NewID())
		require.NoError(t, err, "audit_event")

		require.NoError(t, tx.Commit(ctx), "the whole ingestion write must commit as one transaction")

		var tagCount int
		require.NoError(t, pool.QueryRow(ctx,
			`select count(*) from version_tag where version_id = $1`, verID).Scan(&tagCount))
		require.Equal(t, 2, tagCount)
	})
}

// capability is the table the fetcher must NOT have. It could derive the `expected`
// set — it already parses the manifest — but it is the most exposed role here, the
// one fetching attacker-supplied archives over the network and unpacking them. The
// scanner runs offline with no outbound client and writes both sources instead.
func TestFetcherCannotWriteCapabilitiesOrReachPastItsTables(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)
	verID := seedVersion(t, ctx, pkgID, "3.0.0", bytes.Repeat([]byte{0x33}, 32), "skills/ex/p/3.0.0/bundle.tar.zst")

	asRole(t, "am_fetcher", func(ctx context.Context, conn *pgxpool.Conn) {
		for _, tc := range []struct {
			name, stmt string
			args       []any
		}{
			{name: "capability is not writable", stmt: `insert into capability (version_id, source, name, level) values ($1, 'expected', 'network', 'review')`, args: []any{verID}},
			{name: "finding is not writable", stmt: `insert into finding (id, scan_id, version_id, rule_id, severity, state, title)
				values (gen_random_uuid(), gen_random_uuid(), $1, 'SH-NET-002', 'high', 'open', 'x')`, args: []any{verID}},
			{name: "org_policy is not writable", stmt: `update org_policy set scan_gate = 'block'`},
			{name: "session is not readable, because it holds bearer tokens at rest", stmt: `select token_hash from session limit 1`},
			{name: "device_authorization is not readable for the same reason", stmt: `select device_code_hash from device_authorization limit 1`},
			{name: "audit_event cannot be rewritten", stmt: `update audit_event set text = 'clean' where true`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := conn.Exec(ctx, tc.stmt, tc.args...)
				requirePgError(t, err, "42501", "")
			})
		}
	})
}

func semverSort(t *testing.T, semver string) string {
	t.Helper()
	key, err := models.SemverSort(semver)
	require.NoError(t, err)
	return key
}

// ---------------------------------------------------------------------------
// Principle IX — the outbox relay, whose write set no handler-shaped test reaches
// ---------------------------------------------------------------------------

// A role's write set is the union of its handlers AND its goroutines. The relay
// (T022) is hosted in api and is a goroutine, so every handler-shaped test in
// this suite misses it. Its loop is three statements and only the third needs a
// privilege nothing else asks for, which is why this drives all three rather than
// asserting the grant exists: claim and mark pass under the blanket
// select/insert/update grant, so a missing DELETE leaves the relay delivering
// every job while the table grows forever. A leak, never an error.
func TestAPIRoleCanRunTheWholeOutboxRelayLoopIncludingThePrune(t *testing.T) {
	ctx := context.Background()

	claimable := seedOutboxRow(t, ctx, "pending", "")
	unclaimed := seedOutboxRow(t, ctx, "pending", "")
	stale := seedOutboxRow(t, ctx, "delivered", "48 hours")
	fresh := seedOutboxRow(t, ctx, "delivered", "1 hour")

	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		tx, err := conn.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()

		// Claim. The relay's own statement carries no id filter; this one is scoped
		// to the row seeded above so that a pending row left by another test cannot
		// be the row claimed here. The privileges exercised are the same.
		var claimed uuid.UUID
		require.NoError(t, tx.QueryRow(ctx, `select id from outbox
			where state = 'pending' and id = any($1)
			order by id
			for update skip locked
			limit 1`, []uuid.UUID{claimable}).Scan(&claimed), "claim")
		require.Equal(t, claimable, claimed)

		// Mark.
		_, err = tx.Exec(ctx,
			`update outbox set state = 'delivered', delivered_at = now() where id = $1`, claimed)
		require.NoError(t, err, "mark")
		require.NoError(t, tx.Commit(ctx))

		// Prune — the statement the grant exists for, verbatim.
		tag, err := conn.Exec(ctx, `delete from outbox
			where state = 'delivered' and delivered_at < now() - interval '24 hours'`)
		require.NoError(t, err,
			"am_api must be able to prune the outbox: data-model.md specifies delivered rows pruned after 24 h and the relay doing it runs inside api")

		// Exactly one: this is the only test that marks a row delivered, and the
		// other three seeded rows are either inside the window or still pending. A
		// prune that removed more would be reaching rows the relay must not touch.
		require.EqualValues(t, 1, tag.RowsAffected())
	})

	_, exists := outboxStateOf(t, ctx, stale)
	require.False(t, exists, "a delivered row older than 24 h must be gone")

	state, exists := outboxStateOf(t, ctx, fresh)
	require.True(t, exists, "a delivered row inside the 24 h window must survive")
	require.Equal(t, "delivered", state)

	state, exists = outboxStateOf(t, ctx, unclaimed)
	require.True(t, exists, "a pending row must survive: the prune is keyed on state as well as age")
	require.Equal(t, "pending", state)

	state, exists = outboxStateOf(t, ctx, claimable)
	require.True(t, exists, "the row just delivered must survive its own prune")
	require.Equal(t, "delivered", state)
}

// TestAPIRoleCannotDeleteWhereDeletionIsUnspecified is the other half of the
// outbox decision: that grant is exactly one table wide. Every table here is a
// plausible candidate somebody will widen to by neighbourhood, so each case
// carries the reason it was withheld — the same reasons as the withheld-grant list
// in data-model.md.
//
// Each case asserts sqlstate 42501 and not merely `err != nil`. A negative case
// that accepts any error stops testing the privilege the moment the statement
// acquires a defect: a mistyped column (42703) or an invalid enum literal (22P02)
// would read as a pass forever. So every statement runs again as the owner and
// must remove exactly one row, which proves it was valid apart from the privilege
// and had a real row to aim at.
func TestAPIRoleCannotDeleteWhereDeletionIsUnspecified(t *testing.T) {
	ctx := context.Background()

	entryProfile, entryPackage := seedProfile(t, ctx), seedPackage(t, ctx)
	_, err := pool.Exec(ctx,
		`insert into profile_entry (profile_id, package_id, mode, position) values ($1, $2, 'latest', 1)`,
		entryProfile, entryPackage)
	require.NoError(t, err)

	memberProfile := seedProfile(t, ctx)
	_, err = pool.Exec(ctx,
		`insert into membership (profile_id, subject_kind, subject_ref, role) values ($1, 'user', 'a@example.com', 'owner')`,
		memberProfile)
	require.NoError(t, err)

	sessionID, identityID := models.NewID(), seedIdentity(t, ctx)
	_, err = pool.Exec(ctx,
		`insert into session (id, token_hash, identity_id, expires_at) values ($1, $2, $3, now() + interval '1 hour')`,
		sessionID, sessionID[:], identityID)
	require.NoError(t, err)

	deviceID := models.NewID()
	_, err = pool.Exec(ctx, `insert into device_authorization
		(id, device_code_hash, user_code, requesting_host, state, expires_at)
		values ($1, $2, $3, 'laptop.example.com', 'pending', now() + interval '10 minutes')`,
		deviceID, deviceID[:], "code-"+deviceID.String())
	require.NoError(t, err)

	revisionProfile, revisionID := seedProfile(t, ctx), models.NewID()
	_, err = pool.Exec(ctx, `insert into revision (id, profile_id, seq, lockfile, object_key, created_by)
		values ($1, $2, 1, '{}', $3, 'a@example.com')`,
		revisionID, revisionProfile, "profiles/"+revisionProfile.String()+"/r1.json")
	require.NoError(t, err)

	for _, tc := range []struct {
		name, stmt string
		args       []any
	}{
		{
			// FR-032's per-package policy and the openapi inventory's pin / unpin /
			// reorder are all update-shaped: "unpin" is mode pinned -> latest, an
			// UPDATE. Removing a package from a profile is unspecified, and the design
			// screens contain no removal affordance at all.
			name: "profile_entry, where pin, unpin and reorder are all updates",
			stmt: `delete from profile_entry where profile_id = $1 and package_id = $2`,
			args: []any{entryProfile, entryPackage},
		},
		{
			// FR-037 is about per-member and per-group roles; changing or demoting a
			// member is an UPDATE of `role`.
			name: "membership, where a role change is an update",
			stmt: `delete from membership where profile_id = $1`,
			args: []any{memberProfile},
		},
		{
			// The row carries expires_at. No requirement says signing out deletes it,
			// and an expired session is one whose expiry has passed.
			name: "session, which expires rather than being removed",
			stmt: `delete from session where id = $1`,
			args: []any{sessionID},
		},
		{
			// device_auth_state contains `expired`, so expiry is a state transition
			// the flow already models (FR-042). A delete would also destroy the
			// evidence of a code that was issued.
			name: "device_authorization, whose state enum already contains expired",
			stmt: `delete from device_authorization where id = $1`,
			args: []any{deviceID},
		},
		{
			// FR-034 forbids it outright: previously published revisions must remain
			// readable after a new one is published.
			name: "revision, which FR-034 forbids deleting",
			stmt: `delete from revision where id = $1`,
			args: []any{revisionID},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
				_, err := conn.Exec(ctx, tc.stmt, tc.args...)
				requirePgError(t, err, "42501", "")
			})

			tag, err := pool.Exec(ctx, tc.stmt, tc.args...)
			require.NoError(t, err,
				"the same statement must succeed as the owner, or the denial above was about something other than the privilege")
			require.EqualValues(t, 1, tag.RowsAffected(),
				"the denied statement must have had exactly one real row to delete")
		})
	}
}

func seedIdentity(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()

	id := models.NewID()
	_, err := pool.Exec(ctx,
		`insert into identity (id, subject, email) values ($1, $2, 'a@example.com')`,
		id, "oidc|"+id.String())
	require.NoError(t, err)

	return id
}

// seedOutboxRow computes delivered_at in Postgres rather than in Go: the prune
// compares it against the server's now(), so a client clock must not be able to
// move the boundary the test is about. deliveredAgo is "" for a row that has not
// been delivered.
func seedOutboxRow(t *testing.T, ctx context.Context, state, deliveredAgo string) uuid.UUID {
	t.Helper()

	id := models.NewID()
	_, err := pool.Exec(ctx, `insert into outbox (id, job_kind, payload, idempotency_key, state, delivered_at)
		values ($1, 'scan', '{}', $2, $3::outbox_state,
		        case when $4 = '' then null else now() - $4::interval end)`,
		id, "relay:"+id.String(), state, deliveredAgo)
	require.NoError(t, err)

	return id
}

// outboxStateOf reads a row's state through a scalar subquery, so a pruned row
// comes back as "not there" rather than as no rows to scan.
func outboxStateOf(t *testing.T, ctx context.Context, id uuid.UUID) (string, bool) {
	t.Helper()

	var state *string
	require.NoError(t, pool.QueryRow(ctx,
		`select (select state::text from outbox where id = $1)`, id).Scan(&state))
	if state == nil {
		return "", false
	}

	return *state, true
}
