//go:build integration

// The seed against a real Postgres and a real bucket (003 T009, T010).
//
// Three properties, and the first two are why the compose service that runs this
// holds the object-store writer key: the seed writes ROWS AND BYTES, and it may
// run again on every `docker compose up`, so it has to be idempotent in both
// stores at once. The third is 001 SC-004 — every package the design draws is on
// the catalog with the verdict the design gives it.
//
// The expectation in TestEverySeededPackage... is a HAND-TRANSCRIBED literal, not
// a walk over the dataset this package exports. A test that reads the same
// variable the production code reads asserts that the variable equals itself, and
// the whole point of SC-004 is that the rows a person sees match a document
// neither side generated.
package seed_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/api/queries"
	"agent-manager/internal/blob"
	"agent-manager/internal/seed"
	"agent-manager/internal/store/migrations"
	"agent-manager/internal/store/models"
)

var (
	pool   *pgxpool.Pool
	db     *bun.DB
	bucket *blob.Bucket

	// The suite shares one database AND one bucket, because idempotence is a
	// property of the pair: a second run against a fresh bucket would rewrite every
	// object and prove nothing.
	seedOnce   sync.Once
	seedReport seed.Report
	seedErr    error
)

func TestMain(m *testing.M) {
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed integration suite:", err)
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

	pool, err = pgxpool.New(ctx, fmt.Sprintf(
		"postgres://postgres:postgres@%s/agent_manager?sslmode=disable", endpoint))
	if err != nil {
		return 0, fmt.Errorf("open pool: %w", err)
	}
	defer pool.Close()

	// The checked-in migrations, not the desired state: the grants the seed has to
	// live inside are hand-written SQL that only the migration directory carries.
	if applyErr := migrations.Apply(ctx, func(ctx context.Context, statement string) error {
		_, execErr := pool.Exec(ctx, statement)
		return execErr
	}); applyErr != nil {
		return 0, applyErr
	}

	sqldb := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqldb.Close() }()

	db = bun.NewDB(sqldb, pgdialect.New())
	db.RegisterModel(models.All()...)

	bucket, err = blob.Open(ctx, "mem://")
	if err != nil {
		return 0, fmt.Errorf("open bucket: %w", err)
	}
	defer func() { _ = bucket.Close() }()

	return m.Run(), nil
}

// seededTables is every table the seed writes. It is enumerated rather than
// discovered so that a table the seed stops writing fails this suite instead of
// quietly dropping out of the comparison.
var seededTables = []string{
	"publisher", "category", "package", "version", "version_tag", "component",
	"signature", "capability", "scan", "scan_check", "finding", "override",
	"identity", "group_role_map", "org_policy", "profile", "profile_entry",
	"revision", "membership", "sync_target", "sync_event", "audit_event",
}

func seeded(t *testing.T) seed.Report {
	t.Helper()

	seedOnce.Do(func() {
		seedReport, seedErr = seed.Run(context.Background(), deps())
	})
	require.NoError(t, seedErr)
	return seedReport
}

func deps() seed.Deps {
	return seed.Deps{DB: db, BlobRead: bucket.Reader(), BlobWrite: bucket.Writer()}
}

func TestRunningTheSeedTwiceLeavesTheSameRowsAndTheSameObjects(t *testing.T) {
	first := seeded(t)
	ctx := t.Context()

	rowsBefore := rowCounts(t)
	objectsBefore := objects(t)

	for table, count := range rowsBefore {
		require.NotZerof(t, count, "the seed wrote no %s row", table)
	}
	require.NotZero(t, first.Bundles, "the first run committed no bundles")
	require.NotZero(t, first.Lockfiles, "the first run wrote no revision lockfiles")

	second, err := seed.Run(ctx, deps())
	require.NoError(t, err)

	require.Equal(t, rowsBefore, rowCounts(t))
	require.Equal(t, objectsBefore, objects(t))
	require.Zero(t, second.Bundles, "the second run rewrote bundles that were already committed")
	require.Zero(t, second.Lockfiles, "the second run rewrote revision lockfiles")
	require.Equal(t, first.Versions, second.Versions)
}

func TestTheSeedWritesBundleBytesForEveryVersionItRecords(t *testing.T) {
	seeded(t)
	ctx := t.Context()

	var versions []struct {
		Namespace string `bun:"namespace"`
		Name      string `bun:"name"`
		Semver    string `bun:"semver"`
		ObjectKey string `bun:"object_key"`
		Digest    []byte `bun:"digest"`
		SizeBytes int64  `bun:"size_bytes"`
	}
	require.NoError(t, db.NewSelect().
		ColumnExpr("pkg.namespace, pkg.name, ver.semver, ver.object_key, ver.digest, ver.size_bytes").
		TableExpr("version as ver").
		Join("join package as pkg on pkg.id = ver.package_id").
		Scan(ctx, &versions))
	require.NotEmpty(t, versions)

	read := bucket.Reader()
	for _, version := range versions {
		body, err := read.ReadAll(ctx, version.ObjectKey)
		require.NoErrorf(t, err, "%s@%s names %s", version.Name, version.Semver, version.ObjectKey)

		digest := sha256.Sum256(body)
		require.Equalf(t, version.Digest, digest[:],
			"the stored digest of %s@%s is not the digest of the bytes at its key",
			version.Name, version.Semver)
		require.Equal(t, version.SizeBytes, int64(len(body)))

		// The manifest rides beside the bundle (FR-006), and index.json is what
		// makes the version resolvable at all.
		manifests, err := read.List(ctx, strings.TrimSuffix(version.ObjectKey, blob.BundleObject))
		require.NoError(t, err)
		require.Len(t, manifests, 2, "a version's prefix holds its bundle and its manifest")

		index := blob.PackageRef{Namespace: version.Namespace, Name: version.Name}.IndexKey()
		exists, err := read.Exists(ctx, index)
		require.NoError(t, err)
		require.Truef(t, exists, "%s/%s has no index.json", version.Namespace, version.Name)
	}

	// Every revision's lockfile is at the key its row names, so a profile the CLI
	// asks for resolves to bytes rather than to a row alone.
	var keys []string
	require.NoError(t, db.NewSelect().
		ColumnExpr("object_key").TableExpr("revision").Scan(ctx, &keys))
	require.NotEmpty(t, keys)
	for _, key := range keys {
		exists, err := read.Exists(ctx, key)
		require.NoError(t, err)
		require.Truef(t, exists, "revision object %s is missing", key)
	}

	staging, err := read.List(ctx, blob.StagingPrefix)
	require.NoError(t, err)
	require.Empty(t, staging, "the commit left objects in staging")
}

// designCatalog is the design's ten packages: its id, its kind and the verdict of
// the version the catalog shows. Transcribed from
// docs/design/agent-manager.dc.html items() at lines 867-920, where `scan:
// 'pending'` is the `scanning` verdict.
var designCatalog = []struct {
	id      string
	kind    string
	verdict string
}{
	{"example/platform-toolkit", "plugin", "clean"},
	{"example/security-review-kit", "plugin", "clean"},
	{"community/release-toolkit", "plugin", "scanning"},
	{"community/slack-digest", "plugin", "flagged"},
	{"example/terraform-module-review", "skill", "clean"},
	{"example/k8s-incident-triage", "skill", "clean"},
	{"community/postgres-migration-guard", "skill", "flagged"},
	{"example/adr-writer", "skill", "clean"},
	{"community/aws-cost-explainer", "skill", "clean"},
	{"example/pii-redactor", "skill", "clean"},
}

func TestEverySeededPackageIsOnTheCatalogWithTheVerdictTheDesignSpecifies(t *testing.T) {
	seeded(t)

	page, err := queries.Catalog(t.Context(), db, queries.CatalogFilter{PageSize: 100})
	require.NoError(t, err)
	require.Len(t, page.Packages, len(designCatalog))
	require.Equal(t, len(designCatalog), page.Total)

	rendered := map[string]string{}
	kinds := map[string]int{}
	for _, entry := range page.Packages {
		rendered[entry.ID] = entry.Verdict
		kinds[entry.Kind]++
		require.NotEmptyf(t, entry.Category, "%s is on the catalog with no category", entry.ID)
		require.NotEmptyf(t, entry.Tags, "%s is on the catalog with no tags", entry.ID)
	}

	for _, want := range designCatalog {
		verdict, ok := rendered[want.id]
		require.Truef(t, ok, "%s is not on the catalog", want.id)
		require.Equalf(t, want.verdict, verdict, "the verdict of %s", want.id)
	}
	require.Equal(t, map[string]int{"plugin": 4, "skill": 6}, kinds)

	// The whole curated vocabulary is offered, in curated order, whatever the
	// counts are (FR-012).
	var names []string
	for _, option := range page.Categories {
		names = append(names, option.Value)
	}
	require.Equal(t, []string{
		"Infrastructure", "Security & compliance", "Data", "Developer workflow", "Documentation",
	}, names)
}

// TestTheSeedLeavesNoIdentityRowForSomeoneWhoCanSignIn asserts against the stored
// rows what the dataset's own tests assert against the dataset (identities_test.go,
// and seed.DirectoryUsers for why it matters). Both are worth having: the unit
// test names the offending literal, and this one covers the whole write path — an
// identity row reaching the table from a membership, an override or anywhere else
// the seed grows a second identity writer.
func TestTheSeedLeavesNoIdentityRowForSomeoneWhoCanSignIn(t *testing.T) {
	seeded(t)
	ctx := t.Context()

	var stored []struct {
		Subject string `bun:"subject"`
		Email   string `bun:"email"`
		Name    string `bun:"display_name"`
	}
	require.NoError(t, db.NewSelect().
		ColumnExpr("subject, email, display_name").TableExpr("identity").Scan(ctx, &stored))
	require.NotEmpty(t, stored, "the seed wrote no identity, so this test asserts nothing")

	for _, user := range seed.DirectoryUsers {
		for _, row := range stored {
			require.NotContainsf(t, strings.ToLower(row.Subject), user.Email,
				"identity %q holds a subject naming %q", row.Email, user.Username)
			require.NotEqualf(t, user.Email, strings.ToLower(row.Email),
				"the seed wrote an identity for %q, who signs in for real", user.Username)
			require.NotEqualf(t, user.Username, strings.ToLower(row.Name),
				"identity %q is displayed as %q, which is a directory user's name", row.Email, row.Name)
		}
	}

	// The mapping is seeded whole even though no seeded identity can sign in: the
	// two directory users resolve their roles through it on first login (SC-104).
	var mapped []string
	require.NoError(t, db.NewSelect().
		ColumnExpr("group_name").TableExpr("group_role_map").Scan(ctx, &mapped))
	for _, user := range seed.DirectoryUsers {
		require.Containsf(t, mapped, user.Group,
			"%q has no group_role_map row, so %q would sign in with no role", user.Group, user.Username)
	}
}

// TestTheSeedRunsWithTheGrantsTheApiRoleHolds is the constraint the compose
// service states: the seed connects as am_api. A table it must write but that
// am_api holds no grant on is a permission error at run time and nowhere else, so
// the whole load is replayed under `set role` rather than trusted to review.
func TestTheSeedRunsWithTheGrantsTheApiRoleHolds(t *testing.T) {
	seeded(t)
	ctx := t.Context()

	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()

	_, err = conn.ExecContext(ctx, "set role am_api")
	require.NoError(t, err)

	_, err = seed.Run(ctx, seed.Deps{
		DB: conn, BlobRead: bucket.Reader(), BlobWrite: bucket.Writer(),
	})
	require.NoError(t, err)
}

func rowCounts(t *testing.T) map[string]int {
	t.Helper()

	out := make(map[string]int, len(seededTables))
	for _, table := range seededTables {
		var count int
		require.NoError(t, db.QueryRowContext(t.Context(),
			"select count(*) from "+table).Scan(&count))
		out[table] = count
	}
	return out
}

func objects(t *testing.T) map[string]int64 {
	t.Helper()

	listed, err := bucket.Reader().List(t.Context(), "")
	require.NoError(t, err)

	out := make(map[string]int64, len(listed))
	for _, attributes := range listed {
		out[attributes.Key] = attributes.Size
	}
	return out
}
