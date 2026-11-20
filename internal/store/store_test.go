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
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/store"
	"agent-manager/internal/store/models"
	"agent-manager/internal/store/storetest"
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

	pg, cleanup, err := storetest.Run(ctx)
	if err != nil {
		return 0, err
	}
	defer cleanup()

	appURL = pg.DSN("agent_manager")
	queueURL = pg.DSN("river")

	pool, err = pg.Pool(ctx, "agent_manager")
	if err != nil {
		return 0, fmt.Errorf("open pool: %w", err)
	}
	defer pool.Close()

	// The queue's own database, so store.Open has two real targets. Nothing in
	// this suite puts a table in it, since Atlas must never see River's tables.
	if err = storetest.CreateDatabase(ctx, pool, "river"); err != nil {
		return 0, fmt.Errorf("create queue database: %w", err)
	}

	// Replay the checked-in migrations rather than the desired state in
	// internal/store/schema. What ships to production is the migration
	// directory, so that is what has to be under test.
	if err := storetest.ApplyMigrations(ctx, pool); err != nil {
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
		`insert into audit_event (id, actor, actor_kind, kind, "text", subject_kind, subject_id)
		 values ($1, 'system', 'system', 'login', 'seed', 'identity', 'seed')`, id)
	require.NoError(t, err)

	// Every role, not just the request path. am_migrate is included because
	// `grant all on all tables` hands it UPDATE, DELETE and TRUNCATE and the
	// revoke has to take all three back — and because in a real deployment
	// am_migrate is the table owner, where a revoke is easy to assume is a no-op.
	for _, role := range []string{"am_api", "am_fetcher", "am_scanner", "am_notifier", "am_migrate"} {
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
					{name: "insert on conflict do update is denied", stmt: `insert into audit_event (id, actor, actor_kind, kind, "text", subject_kind, subject_id)
						values ($1, 'x', 'system', 'login', 'y', 'identity', 'x') on conflict (id) do update set "text" = 'pwned'`, args: []any{id}},
				} {
					t.Run(tc.name, func(t *testing.T) {
						_, err := conn.Exec(ctx, tc.stmt, tc.args...)
						requirePgError(t, err, "42501", "")
					})
				}

				t.Run("insert is allowed, because the log must still be writable", func(t *testing.T) {
					_, err := conn.Exec(ctx,
						`insert into audit_event (id, actor, actor_kind, kind, "text", subject_kind, subject_id)
						 values ($1, 'a@example.com', 'identity', 'login', 'signed in', 'identity', 'a')`,
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

// Every role that writes audit rows can write the subject columns, and none
// can write a row without a subject. The check is NOT VALID, so rows from
// before the columns existed stay legal without a backfill.
func TestAuditEventRequiresASubjectFromEveryWritingRole(t *testing.T) {
	var validated bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`select convalidated from pg_constraint where conname = 'audit_event_subject_required'`).Scan(&validated))
	require.False(t, validated, "the check must stay NOT VALID, or migrating a hub with history fails")

	for _, role := range []string{"am_api", "am_fetcher", "am_scanner", "am_notifier"} {
		t.Run(role, func(t *testing.T) {
			asRole(t, role, func(ctx context.Context, conn *pgxpool.Conn) {
				_, err := conn.Exec(ctx,
					`insert into audit_event (id, actor, actor_kind, kind, "text", subject_kind, subject_id, namespace, data)
					 values ($1, 'fetcher', 'system', 'fetch', 'stored', 'version', 'example/a@1.0.0', 'example', '{"semver":"1.0.0"}')`,
					models.NewID())
				require.NoError(t, err, "the subject columns must be insertable by every writing role")

				_, err = conn.Exec(ctx,
					`insert into audit_event (id, actor, actor_kind, kind, "text") values ($1, 'x', 'system', 'fetch', 'y')`,
					models.NewID())
				requirePgError(t, err, "23514", "audit_event_subject_required")

				_, err = conn.Exec(ctx,
					`insert into audit_event (id, actor, actor_kind, kind, "text", subject_kind)
					 values ($1, 'x', 'system', 'fetch', 'y', 'version')`, models.NewID())
				requirePgError(t, err, "23514", "audit_event_subject_required")
			})
		})
	}
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
			{name: "source_commit is not writable, because provenance is the fetcher's record", stmt: `update version set source_commit = repeat('0', 40) where id = $1`, args: []any{verID}},
			{name: "source_url is not writable", stmt: `update version set source_url = 'https://attacker.example' where id = $1`, args: []any{verID}},
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
	require.Equal(t, []string{"am_api", "am_fetcher", "am_migrate", "am_notifier", "am_scanner"}, got)
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

func TestVersionRejectsASourceCommitThatIsNotAFullLowercaseSha(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)
	verID := seedVersion(t, ctx, pkgID, "7.0.0", bytes.Repeat([]byte{0x7a}, 32), "skills/ex/p/7.0.0/bundle.tar.zst")

	for _, commit := range []string{"3f9c2e1", strings.Repeat("A", 40), strings.Repeat("0", 41)} {
		_, err := pool.Exec(ctx, `update version set source_commit = $1 where id = $2`, commit, verID)
		requirePgError(t, err, "23514", "version_source_commit_is_a_sha")
	}
	_, err := pool.Exec(ctx, `update version set source_commit = $1 where id = $2`, strings.Repeat("0", 40), verID)
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
// The namespace, and the object-key collision the old key allowed
// ---------------------------------------------------------------------------

// uniqueNamespace returns a namespace no other test in this suite will use. It is
// spelled out of a whole uuid rather than uuid.ID(), whose value is the high bits
// of a v7 timestamp and is therefore the same for ids minted in the same
// millisecond — which is every publisher this suite creates.
func uniqueNamespace() string { return "ns" + models.NewID().String() }

// seedPublisherIn creates a publisher whose slug is `<namespace>/<team>`, which is
// the shape the check constraint now requires.
func seedPublisherIn(t *testing.T, ctx context.Context, namespace, team string) uuid.UUID {
	t.Helper()

	id := models.NewID()
	_, err := pool.Exec(ctx,
		`insert into publisher (id, slug, display_name) values ($1, $2, 'Example')`,
		id, namespace+"/"+team)
	require.NoError(t, err)

	return id
}

// insertPackageIn writes the namespace the caller asks for rather than the one the
// publisher has, because half these cases are about the two disagreeing.
func insertPackageIn(ctx context.Context, pubID uuid.UUID, namespace, name string) error {
	_, err := pool.Exec(ctx,
		`insert into package (id, publisher_id, namespace, name, kind, visibility)
		 values ($1, $2, $3, $4, 'skill', 'organisation')`,
		models.NewID(), pubID, namespace, name)
	return err
}

// This is the defect `unique (publisher_id, name)` allowed and `unique (namespace,
// name)` does not. Two teams in one namespace, one package name: both render as
// the id example/pii-redactor and both resolve to the object key
// skills/example/pii-redactor/…, so one bundle overwrites the other. Against
// FR-007 that is a correctness bug, and the second insert below is the one the old
// key accepted.
func TestTwoPublishersInOneNamespaceCannotBothOwnAPackageOfTheSameName(t *testing.T) {
	ctx := context.Background()

	ns := uniqueNamespace()
	platform := seedPublisherIn(t, ctx, ns, "platform")
	security := seedPublisherIn(t, ctx, ns, "security")

	require.NoError(t, insertPackageIn(ctx, platform, ns, "pii-redactor"))
	requirePgError(t, insertPackageIn(ctx, security, ns, "pii-redactor"), "23505", "package_namespace_name")

	// The same publisher twice is still refused, which is everything the old key
	// caught: the new one is strictly stronger, not different.
	requirePgError(t, insertPackageIn(ctx, platform, ns, "pii-redactor"), "23505", "package_namespace_name")

	// And a different namespace is a different package, or the key would make
	// community/slack-digest and example/slack-digest the same thing.
	other := uniqueNamespace()
	require.NoError(t, insertPackageIn(ctx, seedPublisherIn(t, ctx, other, "platform"), other, "pii-redactor"))
}

// The uniqueness above is only worth the honesty of the column it indexes. If a
// package could name a namespace its publisher does not have, `unique (namespace,
// name)` would be enforcing uniqueness over a value the application picks.
func TestAPackageCannotClaimANamespaceItsPublisherDoesNotHave(t *testing.T) {
	ctx := context.Background()

	ns := uniqueNamespace()
	pubID := seedPublisherIn(t, ctx, ns, "platform")

	requirePgError(t, insertPackageIn(ctx, pubID, "community", "borrowed"),
		"23503", "package_publisher_id_namespace_fkey")

	require.NoError(t, insertPackageIn(ctx, pubID, ns, "borrowed"))

	// An UPDATE is checked too, which is the half a trigger written for INSERT
	// would have missed.
	_, err := pool.Exec(ctx, `update package set namespace = 'community' where publisher_id = $1`, pubID)
	requirePgError(t, err, "23503", "package_publisher_id_namespace_fkey")
}

// publisher.namespace is a stored generated column, so it is not a value anybody
// writes. That is the whole reason it cannot drift from the slug — no trigger, no
// application check, and no way to get it wrong by writing to it.
func TestPublisherNamespaceIsDerivedFromTheSlugAndCannotBeWrittenDirectly(t *testing.T) {
	ctx := context.Background()

	ns := uniqueNamespace()
	pubID := seedPublisherIn(t, ctx, ns, "platform")

	namespaceOf := func() string {
		var got string
		require.NoError(t, pool.QueryRow(ctx, `select namespace from publisher where id = $1`, pubID).Scan(&got))
		return got
	}
	require.Equal(t, ns, namespaceOf())

	_, err := pool.Exec(ctx, `update publisher set namespace = 'evil' where id = $1`, pubID)
	requirePgError(t, err, "428C9", "")

	// Renaming the slug moves the namespace with it, in the same statement. A
	// denormalised copy maintained by application code is what this replaces.
	_, err = pool.Exec(ctx, `update publisher set slug = 'renamed/platform' where id = $1`, pubID)
	require.NoError(t, err)
	require.Equal(t, "renamed", namespaceOf())
}

// One segment (a namespace on its own) or two (namespace and team) are both
// accepted, because split_part's first field is the whole string when there is
// no slash: `lonely` and `lonely/platform` both give the object key a
// non-empty namespace. What's refused is a segment split_part would leave
// empty, or a third segment split_part would silently drop.
func TestAPublisherSlugIsOneOrTwoNonEmptySegments(t *testing.T) {
	ctx := context.Background()

	insert := func(slug string) error {
		_, err := pool.Exec(ctx,
			`insert into publisher (id, slug, display_name) values ($1, $2, 'Example')`,
			models.NewID(), slug)
		return err
	}

	for _, slug := range []string{
		"a/b/c",     // split_part would happily return "a" and lose b/c
		"/platform", // empty namespace: the object key would start skills//
		"example/",  // empty team
		"",          //
	} {
		t.Run("rejects "+strconv.Quote(slug), func(t *testing.T) {
			requirePgError(t, insert(slug), "23514", "publisher_slug_is_one_or_two_segments")
		})
	}

	for _, slug := range []string{
		"lonely", // the namespace on its own
		"example/platform-" + models.NewID().String(), // namespace and team
	} {
		t.Run("accepts "+strconv.Quote(slug), func(t *testing.T) {
			require.NoError(t, insert(slug))
		})
	}
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
		"version_tags_gin":                    "CREATE INDEX version_tags_gin ON public.version USING gin (tags)",
		"version_package_semver_sort_idx":     "CREATE INDEX version_package_semver_sort_idx ON public.version USING btree (package_id, semver_sort DESC)",
		"version_verdict_visible_idx":         "CREATE INDEX version_verdict_visible_idx ON public.version USING btree (verdict) WHERE visible",
		"version_created_at_idx":              "CREATE INDEX version_created_at_idx ON public.version USING btree (created_at DESC)",
		"finding_open_version_idx":            "CREATE INDEX finding_open_version_idx ON public.finding USING btree (version_id) WHERE (state = 'open'::finding_state)",
		"outbox_pending_created_at_idx":       "CREATE INDEX outbox_pending_created_at_idx ON public.outbox USING btree (created_at) WHERE (state = 'pending'::outbox_state)",
		"audit_event_occurred_at_idx":         "CREATE INDEX audit_event_occurred_at_idx ON public.audit_event USING btree (occurred_at DESC)",
		"finding_evidence_finding_idx":        "CREATE INDEX finding_evidence_finding_idx ON public.finding_evidence USING btree (finding_id)",
		"finding_evidence_one_primary_idx":    "CREATE UNIQUE INDEX finding_evidence_one_primary_idx ON public.finding_evidence USING btree (finding_id) WHERE (role = 'primary'::evidence_role)",
		"fetch_attempt_occurred_at_idx":       "CREATE INDEX fetch_attempt_occurred_at_idx ON public.fetch_attempt USING btree (occurred_at DESC)",
		"service_token_created_by_idx":        "CREATE INDEX service_token_created_by_idx ON public.service_token USING btree (created_by_identity_id, created_at DESC)",
		"machine_install_package_version_idx": "CREATE INDEX machine_install_package_version_idx ON public.machine_install USING btree (package_id, version_id)",
		"machine_skip_machine_profile_idx":    "CREATE INDEX machine_skip_machine_profile_idx ON public.machine_skip USING btree (machine_id, profile_id)",
		"machine_last_identity_idx":           "CREATE INDEX machine_last_identity_idx ON public.machine USING btree (last_identity_id)",
		"webhook_delivery_subscription_idx":   "CREATE INDEX webhook_delivery_subscription_idx ON public.webhook_delivery USING btree (subscription_id, occurred_at DESC)",
		"webhook_delivery_occurred_at_idx":    "CREATE INDEX webhook_delivery_occurred_at_idx ON public.webhook_delivery USING btree (occurred_at)",
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
	// namespace is read back off the publisher rather than recomputed here: it is
	// a generated column, so the database is the only place it is ever decided.
	_, err := pool.Exec(ctx,
		`insert into package (id, publisher_id, namespace, name, kind, visibility)
		 select $1, p.id, p.namespace, $3, 'skill', 'organisation' from publisher p where p.id = $2`,
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
		// The slug is the whole two-segment owner and the namespace is its first
		// segment. Those are different strings, and the object key below is built
		// from the namespace: this test used to build it from the slug, which is the
		// same confusion the composite key now makes unrepresentable.
		namespace := uniqueNamespace()
		slug := namespace + "/platform"

		// Registering the first package under a new publisher creates the
		// publisher row; package.publisher_id is NOT NULL, so there is no order
		// in which the fetcher can skip this.
		_, err = tx.Exec(ctx,
			`insert into publisher (id, slug, display_name) values ($1, $2, 'Fetcher Test')`, pubID, slug)
		require.NoError(t, err, "publisher")

		_, err = tx.Exec(ctx,
			`insert into package (id, publisher_id, namespace, name, kind, visibility)
			 values ($1, $2, $3, $4, 'skill', 'organisation')`, pkgID, pubID, namespace, "p-"+pkgID.String())
		require.NoError(t, err, "package")

		// verdict starts at 'scanning' and visible at false: commit-last (FR-008)
		// means the fetcher publishes an invisible row and the scanner's verdict
		// is what reveals it.
		_, err = tx.Exec(ctx,
			`insert into version (id, package_id, semver, semver_sort, object_key, digest, size_bytes, manifest, dist_tag, verdict, visible)
			 values ($1, $2, '1.0.0', $3, $4, $5, 4096, '{"name":"p"}', 'latest', 'scanning', false)`,
			verID, pkgID, semverSort(t, "1.0.0"), "skills/"+namespace+"/p/1.0.0/bundle.tar.zst",
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
			`insert into audit_event (id, actor, actor_kind, kind, text, subject_kind, subject_id, namespace)
			 values ($1, 'fetcher', 'system', 'fetch', 'fetched 1.0.0', 'version', 'example/a@1.0.0', 'example')`, models.NewID())
		require.NoError(t, err, "audit_event")

		require.NoError(t, tx.Commit(ctx), "the whole ingestion write must commit as one transaction")

		var tagCount int
		require.NoError(t, pool.QueryRow(ctx,
			`select count(*) from version_tag where version_id = $1`, verID).Scan(&tagCount))
		require.Equal(t, 2, tagCount)
	})
}

// The upstream check is a registration the fetcher performs itself: lock the
// tracked package, add the invisible version, its fetch job and audit row, and
// stamp the check, in one transaction. No grant beyond the ingestion write is
// needed, and this is what says so.
func TestFetcherCanRegisterAnUpstreamTagInOneTransaction(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)
	_, err := pool.Exec(ctx, `update package set source_kind = 'git', source_url = 'https://github.com/acme/skills',
	  track_upstream = true where id = $1`, pkgID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `update package set source_kind = 'upload' where id = $1`, pkgID)
	requirePgError(t, err, "23514", "package_tracks_only_git")

	asRole(t, "am_fetcher", func(ctx context.Context, conn *pgxpool.Conn) {
		tx, err := conn.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()

		var semvers []string
		require.NoError(t, tx.QueryRow(ctx,
			`select array(select semver from version where package_id = p.id)
			   from package p where p.id = $1 and p.track_upstream for update`, pkgID).Scan(&semvers))

		verID := models.NewID()
		_, err = tx.Exec(ctx,
			`insert into version (id, package_id, semver, semver_sort, object_key, manifest, dist_tag, verdict, source_ref)
			 values ($1, $2, '8.0.0', $3, 'skills/ex/p/8.0.0/bundle.tar.zst', '{}', 'none', 'scanning', 'v8.0.0')`,
			verID, pkgID, semverSort(t, "8.0.0"))
		require.NoError(t, err, "version")

		_, err = tx.Exec(ctx,
			`insert into outbox (id, job_kind, payload, idempotency_key, state) values ($1, 'fetch', '{}', $2, 'pending')`,
			models.NewID(), "fetch:"+verID.String()+":8.0.0")
		require.NoError(t, err, "outbox")

		_, err = tx.Exec(ctx,
			`insert into audit_event (id, actor, actor_kind, kind, text, subject_kind, subject_id, namespace)
			 values ($1, 'fetcher', 'system', 'fetch', 'registered', 'version', 'ex/p@8.0.0', 'ex')`, models.NewID())
		require.NoError(t, err, "audit_event")

		_, err = tx.Exec(ctx,
			`update package set source_ref = 'v8.0.0', last_checked_at = now(), last_check_error = null where id = $1`, pkgID)
		require.NoError(t, err, "package")

		require.NoError(t, tx.Commit(ctx))
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
// FR-024 — a finding has more than one location
// ---------------------------------------------------------------------------

// seedFinding writes the chain a finding needs: package, version, scan, finding.
// It returns the finding id.
func seedFinding(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()

	pkgID := seedPackage(t, ctx)
	verID := seedVersion(t, ctx, pkgID, "1.0.0", bytes.Repeat([]byte{0x55}, 32),
		"skills/ex/p/1.0.0/bundle.tar.zst")

	scanID, findingID := models.NewID(), models.NewID()
	_, err := pool.Exec(ctx,
		`insert into scan (id, version_id, pack_version, verdict) values ($1, $2, $3, 'flagged')`,
		scanID, verID, "2026.08."+scanID.String())
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `insert into finding
		(id, scan_id, version_id, rule_id, severity, title, evidence_path, evidence_line, evidence_quote, state)
		values ($1, $2, $3, 'SH-FS-007', 'high', 'writes escape the sandbox',
		        'scripts/explain-costs.sh', 9, 'set -o allexport', 'open')`,
		findingID, scanID, verID)
	require.NoError(t, err)

	return findingID
}

func insertEvidence(ctx context.Context, findingID uuid.UUID, path string, line int32, role string) error {
	_, err := pool.Exec(ctx,
		`insert into finding_evidence (id, finding_id, path, line, quote, role)
		 values ($1, $2, $3, $4, 'aws s3 cp "$f" s3://bucket/', $5::evidence_role)`,
		models.NewID(), findingID, path, line, role)
	return err
}

// The concrete case the child table exists for: SH-FS-007's cause is
// scripts/explain-costs.sh:9 while the writes it lets escape are on lines 28, 34
// and 36. One location per finding either drops three of those or formats them
// into a string, which is the option this table refuses.
func TestAFindingCarriesEveryLocationButOnlyOnePrimaryOne(t *testing.T) {
	ctx := context.Background()
	findingID := seedFinding(t, ctx)

	require.NoError(t, insertEvidence(ctx, findingID, "scripts/explain-costs.sh", 9, "primary"))
	for _, line := range []int32{28, 34, 36} {
		require.NoError(t, insertEvidence(ctx, findingID, "scripts/explain-costs.sh", line, "supporting"),
			"supporting locations are many per finding by definition")
	}

	// finding.evidence_path/line/quote is a denormalised copy of the primary row.
	// Two rows claiming to be primary would leave no way to say which one the
	// triple copies, so the partial unique index refuses the second.
	requirePgError(t, insertEvidence(ctx, findingID, "scripts/other.sh", 1, "primary"),
		"23505", "finding_evidence_one_primary_idx")

	var supporting int
	require.NoError(t, pool.QueryRow(ctx,
		`select count(*) from finding_evidence where finding_id = $1 and role = 'supporting'`,
		findingID).Scan(&supporting))
	require.Equal(t, 3, supporting, "the refusal above must not have cost the supporting rows")

	// A location without a line is legal — a finding can name a file — and it is
	// why the primary key is a uuid rather than (finding_id, path, line).
	_, err := pool.Exec(ctx,
		`insert into finding_evidence (id, finding_id, path, role) values ($1, $2, 'mcp.json', 'supporting')`,
		models.NewID(), findingID)
	require.NoError(t, err)
}

// The scanner raises findings, so the scanner writes their evidence. Nothing else
// does: api does not run checks, and the fetcher does not scan. am_api's grant on
// this table is deliberately narrower than its blanket select/insert/update on
// every other one, which is exactly the kind of narrowing that erodes silently
// unless a test names it.
func TestOnlyTheScannerCanWriteFindingEvidence(t *testing.T) {
	ctx := context.Background()
	findingID := seedFinding(t, ctx)

	stmt := `insert into finding_evidence (id, finding_id, path, line, quote, role)
	         values ($1, $2, 'scripts/explain-costs.sh', 28, 'aws s3 cp', 'supporting')`

	asRole(t, "am_scanner", func(ctx context.Context, conn *pgxpool.Conn) {
		_, err := conn.Exec(ctx, stmt, models.NewID(), findingID)
		require.NoError(t, err, "the scanner writes the evidence for the finding it raised")
	})

	// Each denial is checked as 42501 and then run again as the owner, so a
	// statement that had quietly acquired a defect could not read as a pass.
	for _, tc := range []struct{ role, why string }{
		{role: "am_api", why: "api does not run checks; a reviewer writes override and finding.state"},
		{role: "am_fetcher", why: "the fetcher does not scan"},
	} {
		t.Run(tc.role+" cannot insert, because "+tc.why, func(t *testing.T) {
			asRole(t, tc.role, func(ctx context.Context, conn *pgxpool.Conn) {
				_, err := conn.Exec(ctx, stmt, models.NewID(), findingID)
				requirePgError(t, err, "42501", "")
			})

			id := models.NewID()
			_, err := pool.Exec(ctx, stmt, id, findingID)
			require.NoError(t, err,
				"the same statement must succeed as the owner, or the denial was about something other than the privilege")
		})
	}

	// The scanner cannot rewrite one either. An evidence row quotes the bundle's
	// bytes at the instant they were scanned; a rescan makes a new scan and new
	// findings rather than editing old ones.
	asRole(t, "am_scanner", func(ctx context.Context, conn *pgxpool.Conn) {
		_, err := conn.Exec(ctx, `update finding_evidence set quote = 'harmless' where finding_id = $1`, findingID)
		requirePgError(t, err, "42501", "")
	})
	tag, err := pool.Exec(ctx, `update finding_evidence set quote = 'harmless' where finding_id = $1`, findingID)
	require.NoError(t, err)
	require.Positive(t, tag.RowsAffected(), "the denied update must have had real rows to aim at")
}

// ---------------------------------------------------------------------------
// FR-053 — a refused fetch produces no object key, and must still be reportable
// ---------------------------------------------------------------------------

// The storage panel's rows used to be object keys, which a refused fetch never
// produces: an SSRF block, a bad ref and a zip bomb could not appear in the one
// panel required to report fetch outcomes, and those are the security-relevant
// ones. This proves the row exists with no version and no object key behind it.
func TestARefusedFetchIsRecordedWithNoVersionAndNoObjectKey(t *testing.T) {
	ctx := context.Background()

	ref := "https://169.254.169.254/latest/meta-data/" + models.NewID().String()
	_, err := pool.Exec(ctx, `insert into fetch_attempt (id, source_kind, requested_ref, outcome, detail)
		values ($1, 'archive-url', $2, 'blocked', $3)`,
		models.NewID(), ref,
		"outbound request to 169.254.169.254:443 refused: link-local address")
	require.NoError(t, err)

	var outcome, detail string
	require.NoError(t, pool.QueryRow(ctx,
		`select outcome::text, detail from fetch_attempt where requested_ref = $1`, ref).Scan(&outcome, &detail))
	require.Equal(t, "blocked", outcome)
	require.Contains(t, detail, "link-local")

	// Nothing about this row needed a version to exist, which is the whole point:
	// version.object_key can only describe the fetches that succeeded.
	var versions int
	require.NoError(t, pool.QueryRow(ctx,
		`select count(*) from version where object_key like '%' || $1 || '%'`, ref).Scan(&versions))
	require.Zero(t, versions)

	// A successful fetch is the same table, so the panel is one query rather than
	// a union of object keys and errors.
	_, err = pool.Exec(ctx, `insert into fetch_attempt (id, source_kind, requested_ref, outcome)
		values ($1, 'git', $2, 'ok')`, models.NewID(), "github.com/example/plugin@v1.3.0")
	require.NoError(t, err, "detail is null for an outcome that has nothing to explain")
}

// The fetcher writes this table and reads nothing back, exactly as it does for
// audit_event and outbox. api reads it because FR-053's panel is served over HTTP,
// and writes nothing: no handler produces a fetch outcome today, and a grant on a
// prediction is the excess nothing ever surfaces.
func TestOnlyTheFetcherRecordsFetchAttemptsAndNoRoleCanRewriteOne(t *testing.T) {
	ctx := context.Background()

	insert := `insert into fetch_attempt (id, source_kind, requested_ref, outcome)
	           values ($1, 'git', $2, 'invalid-ref')`
	ref := "not a repository " + models.NewID().String()

	asRole(t, "am_fetcher", func(ctx context.Context, conn *pgxpool.Conn) {
		_, err := conn.Exec(ctx, insert, models.NewID(), ref)
		require.NoError(t, err)

		// It never reads its own history, so it holds no select.
		_, err = conn.Exec(ctx, `select outcome from fetch_attempt limit 1`)
		requirePgError(t, err, "42501", "")
	})

	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`select count(*) from fetch_attempt where requested_ref = $1`, ref).Scan(&n),
			"FR-053's panel is served by api")
		require.Equal(t, 1, n)

		_, err := conn.Exec(ctx, insert, models.NewID(), ref+"-api")
		requirePgError(t, err, "42501", "")
	})
	// The withheld INSERT was refused for the privilege and not for a defect in the
	// statement, which the owner running the same statement is what proves.
	_, ownerErr := pool.Exec(ctx, insert, models.NewID(), ref+"-api")
	require.NoError(t, ownerErr)

	// An attempt is a record of something that already happened, so no role rewrites
	// or removes one. This is NOT FR-052's revoke, which names audit_event and only
	// audit_event: it is the absence of a grant, and a table owner can still grant
	// itself back.
	for _, role := range []string{"am_api", "am_fetcher", "am_scanner"} {
		for _, stmt := range []string{
			`update fetch_attempt set outcome = 'ok' where requested_ref = $1`,
			`delete from fetch_attempt where requested_ref = $1`,
		} {
			t.Run(role+" cannot run "+stmt[:6], func(t *testing.T) {
				asRole(t, role, func(ctx context.Context, conn *pgxpool.Conn) {
					_, err := conn.Exec(ctx, stmt, ref)
					requirePgError(t, err, "42501", "")
				})
			})
		}
	}
	tag, ownerErr := pool.Exec(ctx, `delete from fetch_attempt where requested_ref = $1`, ref)
	require.NoError(t, ownerErr)
	require.EqualValues(t, 1, tag.RowsAffected(),
		"the denied statements must have had exactly one real row to aim at")

	// am_scanner holds nothing at all here: it does not fetch.
	asRole(t, "am_scanner", func(ctx context.Context, conn *pgxpool.Conn) {
		_, err := conn.Exec(ctx, `select count(*) from fetch_attempt`)
		requirePgError(t, err, "42501", "")
	})
}

// ---------------------------------------------------------------------------
// FR-050 — every state-changing action writes exactly one audit row
// ---------------------------------------------------------------------------

// The Organization screen's mutations had no representable kind, so they wrote
// nothing and raised nothing: no row to repair afterwards and no gap to detect.
// This drives one insert per admin mutation, which is what proves the values are
// usable and not merely present in pg_enum.
func TestEveryOrganizationScreenMutationHasAnAuditKindToRecordItWith(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct{ kind, action string }{
		{kind: "policy", action: "set the scan gate to block"},          // FR-046
		{kind: "policy", action: "set the default version policy"},      // FR-047
		{kind: "policy", action: "require signed bundles"},              // FR-048
		{kind: "role", action: "map platform-eng to catalog-admin"},     // FR-040
		{kind: "category", action: "add the category Observability"},    // FR-049
		{kind: "secret", action: "rotate the identity-provider secret"}, // US7
	} {
		t.Run(tc.kind+": "+tc.action, func(t *testing.T) {
			_, err := pool.Exec(ctx, `insert into audit_event (id, actor, actor_kind, kind, text, subject_kind, subject_id)
				values ($1, 'admin@example.com', 'identity', $2::audit_kind, $3, 'policy', '1')`,
				models.NewID(), tc.kind, tc.action)
			require.NoError(t, err)
		})
	}

	// Four values rather than one `admin` bucket, because the audit screen filters
	// by kind: "who changed the scan gate" and "who rotated the IdP secret" are not
	// the same question, and a single bucket cannot answer either.
	var kinds int
	require.NoError(t, pool.QueryRow(ctx,
		`select count(distinct kind) from audit_event where kind in ('policy','role','category','secret')`).Scan(&kinds))
	require.Equal(t, 4, kinds)
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

// TestAPIRoleCanDeleteProfileEntryMembershipSyncTargetAndProfile is the
// positive half of "003" widening the outbox-only DELETE grant: the profile
// screen grew a "Remove" control on each entry and a "Delete this profile"
// control, and both reach through am_api. profile_entry's grant is the
// Remove control alone. membership and sync_target's grants exist for no
// reason but clearing a profile's own dependents before deleting it — there
// is still no "unshare one member" or "remove one sync target" endpoint, so
// this only proves the delete-profile path, not a new membership surface.
func TestAPIRoleCanDeleteProfileEntryMembershipSyncTargetAndProfile(t *testing.T) {
	ctx := context.Background()

	profileID, pkg := seedProfile(t, ctx), seedPackage(t, ctx)
	_, err := pool.Exec(ctx,
		`insert into profile_entry (profile_id, package_id, mode, position) values ($1, $2, 'latest', 1)`,
		profileID, pkg)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`insert into membership (profile_id, subject_kind, subject_ref, role) values ($1, 'user', 'a@example.com', 'owner')`,
		profileID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`insert into sync_target (profile_id, target, enabled) values ($1, 'codex', true)`, profileID)
	require.NoError(t, err)

	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		tag, err := conn.Exec(ctx,
			`delete from profile_entry where profile_id = $1 and package_id = $2`, profileID, pkg)
		require.NoError(t, err, "the Remove control's own statement")
		require.EqualValues(t, 1, tag.RowsAffected())

		// The order commands.DeleteProfile itself uses: entries, membership and
		// sync targets cleared before the profile row, so its own FK never fires.
		tag, err = conn.Exec(ctx, `delete from membership where profile_id = $1`, profileID)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())

		tag, err = conn.Exec(ctx, `delete from sync_target where profile_id = $1`, profileID)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())

		tag, err = conn.Exec(ctx, `delete from profile where id = $1`, profileID)
		require.NoError(t, err, "the Delete-profile control's own statement")
		require.EqualValues(t, 1, tag.RowsAffected())
	})
}

// TestAPIRoleCannotDeleteWhereDeletionIsUnspecified is the other half of the
// outbox decision: that grant is exactly one table wide. Every table here is a
// plausible candidate somebody will widen to by neighbourhood, so each case
// carries the reason it was withheld — the same reasons as the withheld-grant list
// in data-model.md. profile_entry, membership and sync_target moved off this
// list in "003" (see the test above) once the profile screen grew controls
// that need them; revision and sync_event are still here, and always will be:
// FR-034 forbids deleting a revision outright, so no FR will ever ask for this.
//
// Each case asserts sqlstate 42501 and not merely `err != nil`. A negative case
// that accepts any error stops testing the privilege the moment the statement
// acquires a defect: a mistyped column (42703) or an invalid enum literal (22P02)
// would read as a pass forever. So every statement runs again as the owner and
// must remove exactly one row, which proves it was valid apart from the privilege
// and had a real row to aim at.
func TestAPIRoleCannotDeleteWhereDeletionIsUnspecified(t *testing.T) {
	ctx := context.Background()

	sessionID, identityID := models.NewID(), seedIdentity(t, ctx)
	_, err := pool.Exec(ctx,
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

func TestOnlyTheFetcherRecordsAVerifiedSignatureAndOnlyWithItsSigner(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)
	verID := seedVersion(t, ctx, pkgID, "8.0.0", bytes.Repeat([]byte{0x8a}, 32), "skills/ex/p/8.0.0/bundle.tar.zst")
	artifact := bytes.Repeat([]byte{0x8b}, 32)

	asRole(t, "am_fetcher", func(ctx context.Context, conn *pgxpool.Conn) {
		_, err := conn.Exec(ctx, `insert into signature (version_id, kind, result, bundle, artifact_digest)
			values ($1, 'cosign-bundle', 'verified', '{}', $2)`, verID, artifact)
		requirePgError(t, err, "23514", "signature_verified_names_a_signer")

		_, err = conn.Exec(ctx, `insert into signature (version_id, kind, result) values ($1, 'none', 'invalid')`, verID)
		requirePgError(t, err, "23514", "signature_none_has_no_result")

		_, err = conn.Exec(ctx, `insert into signature
			(version_id, ref, kind, result, verified_at, bundle, artifact_digest, signer_issuer, signer_identity, signed_at, log_index)
			values ($1, 'https://cdn.example.dev/p.zip.sigstore.json', 'cosign-bundle', 'verified', now(), '{}', $2,
			        'https://token.actions.githubusercontent.com', 'https://github.com/example/p/.github/workflows/release.yaml@refs/tags/v8.0.0',
			        now(), 42)`, verID, artifact)
		require.NoError(t, err)
	})

	asRole(t, "am_scanner", func(ctx context.Context, conn *pgxpool.Conn) {
		_, err := conn.Exec(ctx, `update signature set signer_identity = 'attacker' where version_id = $1`, verID)
		requirePgError(t, err, "42501", "")
	})

	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		var identity string
		require.NoError(t, conn.QueryRow(ctx,
			`select signer_identity from signature where version_id = $1`, verID).Scan(&identity))
		require.Contains(t, identity, "release.yaml")
	})
}

func TestAnExpectedSignerIsWholeAndBounded(t *testing.T) {
	ctx := context.Background()
	pkgID := seedPackage(t, ctx)

	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		set := func(issuer, identity any) error {
			_, err := conn.Exec(ctx, `update package set expected_signer_issuer = $1, expected_signer_identity = $2 where id = $3`,
				issuer, identity, pkgID)
			return err
		}
		requirePgError(t, set("https://issuer.example", nil), "23514", "package_expected_signer_is_whole")
		requirePgError(t, set("https://issuer.example", strings.Repeat("a", 513)), "23514", "package_expected_signer_is_whole")
		require.NoError(t, set("https://issuer.example", `release@example\.dev`))
		require.NoError(t, set(nil, nil))
	})
}

// ---------------------------------------------------------------------------
// Service tokens — only the api reads or writes them
// ---------------------------------------------------------------------------

func insertServiceToken(ctx context.Context, conn interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, creator uuid.UUID, scopes []string, lifetime string) (uuid.UUID, error) {
	id := models.NewID()
	_, err := conn.Exec(ctx, `insert into service_token
		(id, name, token_hash, scopes, created_by_identity_id, created_at, expires_at)
		values ($1, 'ci', $2, $3, $4, now(), now() + $5::interval)`,
		id, append(id[:], id[:]...), scopes, creator, lifetime)
	return id, err
}

func TestOnlyTheAPIRoleReachesServiceTokensAndNoRoleDeletesOne(t *testing.T) {
	ctx := context.Background()
	creator := seedIdentity(t, ctx)

	var id uuid.UUID
	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		var err error
		id, err = insertServiceToken(ctx, conn, creator, []string{"read:catalog"}, "90 days")
		require.NoError(t, err)

		var hash []byte
		require.NoError(t, conn.QueryRow(ctx, `select token_hash from service_token where id = $1`, id).Scan(&hash))
		_, err = conn.Exec(ctx, `update service_token set revoked_at = now(), last_used_at = now() where id = $1`, id)
		require.NoError(t, err)

		_, err = conn.Exec(ctx, `delete from service_token where id = $1`, id)
		requirePgError(t, err, "42501", "")
	})

	for _, role := range []string{"am_fetcher", "am_scanner"} {
		for _, stmt := range []string{
			`select token_hash from service_token where id = $1`,
			`update service_token set revoked_at = null where id = $1`,
			`delete from service_token where id = $1`,
		} {
			t.Run(role+" cannot run "+stmt[:6], func(t *testing.T) {
				asRole(t, role, func(ctx context.Context, conn *pgxpool.Conn) {
					_, err := conn.Exec(ctx, stmt, id)
					requirePgError(t, err, "42501", "")
				})
			})
		}
		t.Run(role+" cannot insert", func(t *testing.T) {
			asRole(t, role, func(ctx context.Context, conn *pgxpool.Conn) {
				_, err := insertServiceToken(ctx, conn, creator, []string{"read:catalog"}, "1 day")
				requirePgError(t, err, "42501", "")
			})
		})
	}

	// The refused statements were refused for the privilege, not the SQL.
	tag, err := pool.Exec(ctx, `delete from service_token where id = $1`, id)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}

func TestAServiceTokenNeedsAScopeAndAnExpiryWithinAYear(t *testing.T) {
	ctx := context.Background()
	creator := seedIdentity(t, ctx)

	_, err := insertServiceToken(ctx, pool, creator, []string{}, "1 day")
	requirePgError(t, err, "23514", "service_token_has_a_scope")

	_, err = insertServiceToken(ctx, pool, creator, []string{"read:catalog"}, "1 year 1 day")
	requirePgError(t, err, "23514", "service_token_expiry_is_bounded")

	_, err = insertServiceToken(ctx, pool, creator, []string{"read:catalog"}, "-1 second")
	requirePgError(t, err, "23514", "service_token_expiry_is_bounded")

	_, err = insertServiceToken(ctx, pool, creator, []string{"read:catalog"}, "1 year")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Fleet inventory — only the api reports and reads it
// ---------------------------------------------------------------------------

func TestOnlyTheAPIRoleReachesTheFleetInventory(t *testing.T) {
	ctx := context.Background()
	identity, profile, pkg := seedIdentity(t, ctx), seedProfile(t, ctx), seedPackage(t, ctx)
	version := seedVersion(t, ctx, pkg, "1.0.0", bytes.Repeat([]byte{7}, 32), "bundles/inv/"+pkg.String())
	revision := models.NewID()
	_, err := pool.Exec(ctx, `insert into revision (id, profile_id, seq, lockfile, object_key, created_by)
		values ($1, $2, 1, '{}', $3, 'a@example.com')`, revision, profile, "profiles/"+profile.String()+"/r1.json")
	require.NoError(t, err)

	machine := models.NewID()
	insertMachine := `insert into machine (id, hostname, last_identity_id, last_profile_id, last_revision_id)
		values ($1, 'laptop', $2, $3, $4)`
	insertInstall := `insert into machine_install (machine_id, profile_id, target, package_id, version_id)
		values ($1, $2, 'claude-code', $3, $4)`
	insertSkip := `insert into machine_skip (id, machine_id, profile_id, entry, target, component, reason)
		values ($1, $2, $3, 'acme/x', 'codex', 'mcp-server lint', 'no claude CLI')`

	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		_, err := conn.Exec(ctx, insertMachine, machine, identity, profile, revision)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `update machine set last_seen_at = now(), hostname = 'laptop-2' where id = $1`, machine)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, insertInstall, machine, profile, pkg, version)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, insertSkip, models.NewID(), machine, profile)
		require.NoError(t, err)
		for _, stmt := range []string{
			`select count(*) from machine_install where machine_id = $1`,
			`select count(*) from machine_skip where machine_id = $1`,
		} {
			var n int
			require.NoError(t, conn.QueryRow(ctx, stmt, machine).Scan(&n))
			require.Equal(t, 1, n)
		}
	})

	for _, role := range []string{"am_fetcher", "am_scanner"} {
		for _, stmt := range []string{
			`select hostname from machine where id = $1`,
			`select version_id from machine_install where machine_id = $1`,
			`select reason from machine_skip where machine_id = $1`,
			`delete from machine_install where machine_id = $1`,
			`update machine set hostname = 'x' where id = $1`,
		} {
			t.Run(role+" cannot run "+stmt, func(t *testing.T) {
				asRole(t, role, func(ctx context.Context, conn *pgxpool.Conn) {
					_, err := conn.Exec(ctx, stmt, machine)
					requirePgError(t, err, "42501", "")
				})
			})
		}
	}

	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		for _, stmt := range []string{
			`delete from machine_install where machine_id = $1`,
			`delete from machine_skip where machine_id = $1`,
			`delete from machine where id = $1`,
		} {
			tag, err := conn.Exec(ctx, stmt, machine)
			require.NoError(t, err, stmt)
			require.EqualValues(t, 1, tag.RowsAffected(), stmt)
		}
	})
}

func TestAMachineSkipIsAWholeEntryOrAWholeComponent(t *testing.T) {
	ctx := context.Background()
	identity, profile := seedIdentity(t, ctx), seedProfile(t, ctx)
	revision, machine := models.NewID(), models.NewID()
	_, err := pool.Exec(ctx, `insert into revision (id, profile_id, seq, lockfile, object_key, created_by)
		values ($1, $2, 1, '{}', $3, 'a@example.com')`, revision, profile, "profiles/"+profile.String()+"/r1.json")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `insert into machine (id, hostname, last_identity_id, last_profile_id, last_revision_id)
		values ($1, '  ', $2, $3, $4)`, machine, identity, profile, revision)
	requirePgError(t, err, "23514", "machine_fields_are_bounded")
	_, err = pool.Exec(ctx, `insert into machine (id, hostname, last_identity_id, last_profile_id, last_revision_id)
		values ($1, 'laptop', $2, $3, $4)`, machine, identity, profile, revision)
	require.NoError(t, err)

	skip := func(target, component, reason *string) error {
		_, err := pool.Exec(ctx, `insert into machine_skip (id, machine_id, profile_id, entry, target, component, reason)
			values ($1, $2, $3, 'acme/x', $4::sync_target_kind, $5, $6)`, models.NewID(), machine, profile, target, component, reason)
		return err
	}
	target, component, reason := "codex", "mcp-server lint", "no CLI"
	require.NoError(t, skip(nil, nil, nil))
	require.NoError(t, skip(&target, &component, &reason))
	requirePgError(t, skip(&target, &component, nil), "23514", "machine_skip_component_is_whole")
	requirePgError(t, skip(nil, &component, &reason), "23514", "machine_skip_component_is_whole")
}

// ---------------------------------------------------------------------------
// Webhooks — the api writes the secret, only the notifier reads it
// ---------------------------------------------------------------------------

func insertWebhook(ctx context.Context, conn interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, creator uuid.UUID) (uuid.UUID, error) {
	id := models.NewID()
	_, err := conn.Exec(ctx, `insert into webhook_subscription (id, name, url, event_types, secret, created_by_identity_id)
		values ($1, 'siem', 'https://hooks.example.com/x', '{scan.completed}', $2, $3)`,
		id, append(id[:], id[:]...), creator)
	return id, err
}

func TestTheWebhookSecretIsWrittenByTheAPIAndReadOnlyByTheNotifier(t *testing.T) {
	ctx := context.Background()
	creator := seedIdentity(t, ctx)

	var id uuid.UUID
	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		var err error
		id, err = insertWebhook(ctx, conn, creator)
		require.NoError(t, err)

		var name string
		require.NoError(t, conn.QueryRow(ctx, `select name from webhook_subscription where id = $1`, id).Scan(&name))
		_, err = conn.Exec(ctx, `update webhook_subscription set secret = $2, enabled = false where id = $1`,
			id, append(creator[:], creator[:]...))
		require.NoError(t, err, "rotating writes the secret without reading it")

		_, err = conn.Exec(ctx, `select secret from webhook_subscription where id = $1`, id)
		requirePgError(t, err, "42501", "")
		_, err = conn.Exec(ctx, `select * from webhook_subscription where id = $1`, id)
		requirePgError(t, err, "42501", "")
		_, err = conn.Exec(ctx, `insert into webhook_delivery (id, subscription_id, event_id, event_type, attempt, duration_ms)
			values ($1, $2, $1, 'scan.completed', 1, 5)`, models.NewID(), id)
		requirePgError(t, err, "42501", "")
	})

	asRole(t, "am_notifier", func(ctx context.Context, conn *pgxpool.Conn) {
		var secret []byte
		require.NoError(t, conn.QueryRow(ctx, `select secret from webhook_subscription where id = $1`, id).Scan(&secret))
		require.Len(t, secret, 32)

		_, err := conn.Exec(ctx, `update webhook_subscription set enabled = false, disabled_reason = 'gone',
			last_delivery_at = now(), last_delivery_status = 410, updated_at = now() where id = $1`, id)
		require.NoError(t, err)

		delivery := models.NewID()
		_, err = conn.Exec(ctx, `insert into webhook_delivery (id, subscription_id, event_id, event_type, attempt, status_code, duration_ms)
			values ($1, $2, $1, 'scan.completed', 1, 410, 5)`, delivery, id)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `delete from webhook_delivery where id = $1`, delivery)
		require.NoError(t, err, "the notifier prunes its own log")

		for _, stmt := range []string{
			`update webhook_subscription set url = 'https://elsewhere.example.com' where id = $1`,
			`update webhook_subscription set secret = '\x00' where id = $1`,
			`update webhook_subscription set event_types = '{*}' where id = $1`,
			`delete from webhook_subscription where id = $1`,
		} {
			_, err = conn.Exec(ctx, stmt, id)
			requirePgError(t, err, "42501", "")
		}
		_, err = insertWebhook(ctx, conn, creator)
		requirePgError(t, err, "42501", "")
	})

	for _, role := range []string{"am_fetcher", "am_scanner"} {
		t.Run(role, func(t *testing.T) {
			asRole(t, role, func(ctx context.Context, conn *pgxpool.Conn) {
				for _, stmt := range []string{
					`select name from webhook_subscription where id = $1`,
					`select id from webhook_delivery where subscription_id = $1`,
				} {
					_, err := conn.Exec(ctx, stmt, id)
					requirePgError(t, err, "42501", "")
				}
			})
		})
	}

	asRole(t, "am_api", func(ctx context.Context, conn *pgxpool.Conn) {
		_, err := conn.Exec(ctx, `delete from webhook_delivery where subscription_id = $1`, id)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `delete from webhook_subscription where id = $1`, id)
		require.NoError(t, err)
	})
}

func TestAWebhookIsHTTPSWithA32ByteSecretAndAnEventType(t *testing.T) {
	ctx := context.Background()
	creator := seedIdentity(t, ctx)
	key := bytes.Repeat([]byte{1}, 32)

	_, err := pool.Exec(ctx, `insert into webhook_subscription (id, name, url, event_types, secret, created_by_identity_id)
		values ($1, 'x', 'http://hooks.example.com', '{*}', $2, $3)`, models.NewID(), key, creator)
	requirePgError(t, err, "23514", "webhook_subscription_url_is_https")
	_, err = pool.Exec(ctx, `insert into webhook_subscription (id, name, url, event_types, secret, created_by_identity_id)
		values ($1, 'x', 'https://hooks.example.com', '{}', $2, $3)`, models.NewID(), key, creator)
	requirePgError(t, err, "23514", "webhook_subscription_has_an_event_type")
	_, err = pool.Exec(ctx, `insert into webhook_subscription (id, name, url, event_types, secret, created_by_identity_id)
		values ($1, 'x', 'https://hooks.example.com', '{*}', $2, $3)`, models.NewID(), key[:16], creator)
	requirePgError(t, err, "23514", "webhook_subscription_secret_is_32_bytes")
}

func TestTheNotifierReachesOnlyWhatItSignsRecordsOrNotices(t *testing.T) {
	ctx := context.Background()
	findingID := seedFinding(t, ctx)
	reviewer := seedIdentity(t, ctx)
	_, err := pool.Exec(ctx, `insert into override (finding_id, reviewer_identity_id, note, expires_at)
		values ($1, $2, 'accepted', now() + interval '3 days')`, findingID, reviewer)
	require.NoError(t, err)

	asRole(t, "am_notifier", func(ctx context.Context, conn *pgxpool.Conn) {
		var ruleID string
		require.NoError(t, conn.QueryRow(ctx, `select fnd.rule_id from override ovr
			join finding fnd on fnd.id = ovr.finding_id
			join version ver on ver.id = fnd.version_id
			join package pkg on pkg.id = ver.package_id
			where ovr.finding_id = $1`, findingID).Scan(&ruleID))

		_, err := conn.Exec(ctx, `update override set expiring_notified_at = now(), expired_notified_at = now()
			where finding_id = $1`, findingID)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `insert into outbox (id, job_kind, payload, idempotency_key, state)
			values ($1, 'notify', '{}', 'k', 'pending')`, models.NewID())
		require.NoError(t, err)

		for _, stmt := range []string{
			`update override set expires_at = now() + interval '1 year' where finding_id = $1`,
			`update finding set state = 'approved' where id = $1`,
			`delete from override where finding_id = $1`,
			`select token_hash from session where id = $1`,
			`select token_hash from service_token where id = $1`,
			`select id from outbox where id = $1`,
			`select id from machine where id = $1`,
			`update version set verdict = 'clean' where id = $1`,
		} {
			_, err = conn.Exec(ctx, stmt, findingID)
			requirePgError(t, err, "42501", "")
		}
	})
}
