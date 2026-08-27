//go:build integration

// T055 — the R12 gate, and SC-003.
//
// This is a measurement, not a smoke test. R12 says the `catalog_entry`
// projection — principle VIII's single sanctioned projection — is built ONLY if
// the base tables miss SC-003's 300 ms p95 at 10,000 packages and 50,000
// versions. So the dataset is generated at that size, against the checked-in
// migrations with the data-model.md indexes, and the R4 pair is timed.
//
// It stays in the suite afterwards, because the answer is only true of the query
// as it stands: a filter added later that cannot use an index turns the decision
// over without anybody noticing, and this is what would notice.
package queries

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/store/migrations"
	"agent-manager/internal/store/models"
)

// The R12 dataset. These numbers are R12's, not a guess: changing one changes
// what the gate below is evidence for.
const (
	benchPackages = 10_000
	benchVersions = 50_000
	benchPerPkg   = benchVersions / benchPackages

	// benchTags is the size of the tag vocabulary. It matters more than it looks:
	// the tag facet unnests every matching version's tags and groups them, so a
	// vocabulary of five would measure a group-by nobody will ever run.
	benchTags = 200

	// benchProfiles and benchEntriesPerProfile drive `uses`, which is aggregated
	// over profile_entry on every catalog read.
	benchProfiles         = 50
	benchEntriesPerProfil = 200
)

// scP95 is SC-003.
const scP95 = 300 * time.Millisecond

var benchDB *bun.DB

func TestMain(m *testing.M) {
	code, err := runBenchSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalog measurement suite:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runBenchSuite(m *testing.M) (int, error) {
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

	pool, err := pgxpool.New(ctx, fmt.Sprintf(
		"postgres://postgres:postgres@%s/agent_manager?sslmode=disable", endpoint))
	if err != nil {
		return 0, fmt.Errorf("open pool: %w", err)
	}
	defer pool.Close()

	// The checked-in migrations, so the indexes measured are the ones that ship.
	if err := migrations.Apply(ctx, func(ctx context.Context, statement string) error {
		_, execErr := pool.Exec(ctx, statement)
		return execErr
	}); err != nil {
		return 0, err
	}

	sqldb := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqldb.Close() }()
	benchDB = bun.NewDB(sqldb, pgdialect.New())
	benchDB.RegisterModel(models.All()...)

	if err := generateCatalog(ctx, pool); err != nil {
		return 0, err
	}
	return m.Run(), nil
}

// generateCatalog builds the R12 dataset in SQL rather than row by row from Go:
// 60,000 round trips would measure the driver, and the shape of the data is what
// this is about.
func generateCatalog(ctx context.Context, pool *pgxpool.Pool) error {
	started := time.Now()

	statements := []string{
		`insert into category (id, name, slug)
		 select gen_random_uuid(), 'Category ' || g, 'category-' || g
		 from generate_series(1, 5) as g`,

		// Half the publishers verified, so the Verified filter is a real
		// discriminator rather than a full scan that matches everything. Slugs are
		// two-segment because that is what the design's are: the id is derived with
		// split_part over this column, so a single-segment slug would time an
		// expression the real data never produces.
		`insert into publisher (id, slug, display_name, verified)
		 select gen_random_uuid(), 'ns' || (g % 4) || '/pub' || g, 'Publisher ' || g, (g % 2 = 0)
		 from generate_series(1, 40) as g`,

		fmt.Sprintf(`
		 with pubs as (select array_agg(id order by slug) as ids from publisher),
		      cats as (select array_agg(id order by name) as ids from category)
		 insert into package (id, publisher_id, name, kind, category_id, visibility)
		 select gen_random_uuid(),
		        pubs.ids[1 + (g %% 40)],
		        'package-' || lpad(g::text, 5, '0'),
		        (case when g %% 3 = 0 then 'plugin' else 'skill' end)::package_kind,
		        cats.ids[1 + (g %% 5)],
		        'organisation'::package_visibility
		 from generate_series(0, %d) as g, pubs, cats`, benchPackages-1),

		// Five versions per package. Tags are drawn so that a filter on one is
		// selective and a filter on two is more so, which is the shape FR-013's
		// conjunctive facet actually produces.
		fmt.Sprintf(`
		 insert into version (id, package_id, semver, semver_sort, object_key, digest, size_bytes,
		                      manifest, tags, dist_tag, verdict, visible, created_at)
		 select gen_random_uuid(),
		        p.id,
		        '1.' || v || '.0',
		        '0000000001' || lpad(v::text, 10, '0') || '00000000001',
		        'skills/x/' || p.name || '/1.' || v || '.0/bundle.tar.zst',
		        decode(repeat('ab', 32), 'hex'),
		        4096,
		        jsonb_build_object('name', p.name),
		        array[
		          'topic-' || lpad(((hashtext(p.name::text) %% %d + %d) %% %d)::text, 3, '0'),
		          'lang-' || ((abs(hashtext(p.name::text)) + v) %% 7),
		          'tier-' || (abs(hashtext(p.name::text)) %% 3)
		        ],
		        (case when v = %d then 'latest' else 'archived' end)::dist_tag,
		        (case when abs(hashtext(p.name::text)) %% 10 = 0 then 'flagged'
		              when abs(hashtext(p.name::text)) %% 17 = 0 then 'scanning'
		              else 'clean' end)::verdict,
		        true,
		        now() - (abs(hashtext(p.name::text)) %% 900) * interval '1 hour'
		 from package as p, generate_series(0, %d) as v`,
			benchTags, benchTags, benchTags, benchPerPkg-1, benchPerPkg-1),

		`update package as p
		 set latest_version_id = v.id
		 from version as v
		 where v.package_id = p.id and v.dist_tag = 'latest'`,

		`insert into version_tag (version_id, tag)
		 select v.id, t from version as v, unnest(v.tags) as t`,

		fmt.Sprintf(`
		 insert into profile (id, slug, name, visibility, default_policy)
		 select gen_random_uuid(), 'profile-' || g, 'Profile ' || g,
		        'organisation'::profile_visibility, 'floating-latest'::version_policy
		 from generate_series(1, %d) as g`, benchProfiles),

		// Overlapping membership, so `uses` is not uniform: a sort by uses that
		// cannot distinguish its rows is not measuring a sort.
		fmt.Sprintf(`
		 with profiles as (select array_agg(id order by slug) as ids from profile),
		      packages as (select array_agg(id order by name) as ids from package)
		 insert into profile_entry (profile_id, package_id, mode, position)
		 select distinct on (profiles.ids[1 + (p %% %d)], packages.ids[1 + ((p * 7 + e * 13) %% %d)])
		        profiles.ids[1 + (p %% %d)],
		        packages.ids[1 + ((p * 7 + e * 13) %% %d)],
		        'latest'::entry_mode,
		        e
		 from generate_series(0, %d) as p, generate_series(0, %d) as e, profiles, packages`,
			benchProfiles, benchPackages, benchProfiles, benchPackages,
			benchProfiles-1, benchEntriesPerProfil-1),

		// The planner needs statistics before the first query, not after the
		// hundredth. Without this the first measurements are of a cold planner.
		`analyze`,
	}

	for i, statement := range statements {
		if _, err := pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("generate the R12 dataset (statement %d): %w", i+1, err)
		}
	}

	fmt.Printf("R12 dataset generated in %s\n", time.Since(started).Round(time.Millisecond))
	return nil
}

// TestTheCatalogMeetsSC003AtTenThousandPackages is the gate.
//
// It measures the R4 pair the way a request issues it — both statements
// concurrently, through queries.Catalog — and then each half on its own, because
// "the pair is fast enough" and "which half would need the projection" are
// different questions and only the second one is actionable.
func TestTheCatalogMeetsSC003AtTenThousandPackages(t *testing.T) {
	ctx := t.Context()

	require.Equal(t, benchPackages, count(t, "package"))
	require.Equal(t, benchVersions, count(t, "version"))

	workloads := []struct {
		name   string
		filter CatalogFilter
	}{
		{"the default view, sorted by uses", CatalogFilter{Sort: CatalogSortUses}},
		{"sorted by name ascending", CatalogFilter{Sort: CatalogSortName, Ascending: true}},
		{"sorted by recency", CatalogFilter{Sort: CatalogSortUpdated}},
		{"free-text search", CatalogFilter{Text: "package-042", Sort: CatalogSortUses}},
		{"free-text search that matches many", CatalogFilter{Text: "pub7", Sort: CatalogSortUses}},
		{"kind and status", CatalogFilter{Kind: models.PackageKindSkill, Status: CatalogStatusVerified}},
		{"flagged only", CatalogFilter{Status: CatalogStatusFlagged}},
		{"one category", CatalogFilter{Categories: []string{"Category 3"}}},
		{"two categories, disjunctive", CatalogFilter{Categories: []string{"Category 1", "Category 4"}}},
		{"one tag", CatalogFilter{Tags: []string{"tier-1"}}},
		{"two tags, conjunctive", CatalogFilter{Tags: []string{"tier-1", "lang-3"}}},
		{"a deep page", CatalogFilter{Sort: CatalogSortName, Page: 500}},
		{"everything at once", CatalogFilter{
			Text: "pub1", Kind: models.PackageKindSkill, Status: CatalogStatusVerified,
			Categories: []string{"Category 1", "Category 2"}, Tags: []string{"tier-0"},
			Sort: CatalogSortUpdated,
		}},
	}

	// Warm the cache once per workload before measuring. The question SC-003 asks
	// is about a running hub, not about the first query after a restart.
	for _, workload := range workloads {
		_, err := Catalog(ctx, benchDB, workload.filter)
		require.NoError(t, err)
	}

	const iterations = 25
	var all []time.Duration

	t.Log("R12 measurement — the R4 pair against the base tables, no projection")
	for _, workload := range workloads {
		samples := make([]time.Duration, 0, iterations)
		var rows, total int
		for range iterations {
			started := time.Now()
			page, err := Catalog(ctx, benchDB, workload.filter)
			samples = append(samples, time.Since(started))
			require.NoError(t, err)
			rows, total = len(page.Packages), page.Total
		}
		all = append(all, samples...)
		t.Logf("  %-36s p50 %6s  p95 %6s  max %6s   (%d rows of %d)",
			workload.name, round(percentile(samples, 0.50)), round(percentile(samples, 0.95)),
			round(percentile(samples, 1.0)), rows, total)
	}

	overall := percentile(all, 0.95)
	t.Logf("  %-36s p50 %6s  p95 %6s  max %6s   (%d samples)", "ALL WORKLOADS",
		round(percentile(all, 0.50)), round(overall), round(percentile(all, 1.0)), len(all))

	// The two halves separately, so a failure names the statement to fix.
	for _, half := range []struct {
		name string
		run  func(CatalogFilter) error
	}{
		{"page statement", func(f CatalogFilter) error {
			_, err := catalogRows(ctx, benchDB, f.normalise())
			return err
		}},
		{"facet statement", func(f CatalogFilter) error {
			_, err := catalogFacetCounts(ctx, benchDB, f.normalise())
			return err
		}},
	} {
		var samples []time.Duration
		for _, workload := range workloads {
			for range iterations {
				started := time.Now()
				require.NoError(t, half.run(workload.filter))
				samples = append(samples, time.Since(started))
			}
		}
		t.Logf("  %-36s p50 %6s  p95 %6s  max %6s", half.name,
			round(percentile(samples, 0.50)), round(percentile(samples, 0.95)),
			round(percentile(samples, 1.0)))
	}

	require.Lessf(t, overall, scP95,
		"SC-003: p95 is %s at %d packages / %d versions, over 300 ms. R12's condition is met and "+
			"catalog_entry must be built — synchronous on structural change, asynchronous on verdict "+
			"change (constitution principle VIII).",
		round(overall), benchPackages, benchVersions)
}

// TestTheTagFilterIsExpressedInAFormTheGinIndexCanAnswer is the R12 gate's
// companion, and it deliberately does not assert what the planner does.
//
// A p95 says nothing about WHY it passed, and asserting that the planner PICKS
// an index is asserting the planner's mood. At 50,000 versions it does not pick
// version_tags_gin — it seq-scans version — and it is right to: two tags match
// ~2,300 rows out of 50,000 in a table that fits in shared_buffers, so the
// bitmap heap scan buys nothing. That is worth knowing (03-constraints.sql says
// the materialised tags column exists so the filter "is a GIN lookup", and at
// this size it is not one) and it is not worth failing a build over.
//
// What is worth pinning is the OPERATOR, which is the part that can regress in
// this package rather than in Postgres. `@>` is what a GIN index over text[]
// answers; the obvious rewrite — tags && array[...] for OR, or unnest with a
// group by for AND — either changes the semantics or cannot use the index at any
// size. So the claim tested here is "the clause this code builds is one the
// index CAN answer", proved by taking the planner's cheaper option away.
func TestTheTagFilterIsExpressedInAFormTheGinIndexCanAnswer(t *testing.T) {
	filter := CatalogFilter{Tags: []string{"tier-1", "lang-3"}}.normalise()
	where := filter.baseFilters()
	clause, args := filter.tagClause("ver.tags")
	where.add(clause, args...)

	t.Logf("the plan the planner picks for the whole catalog query at %d versions:\n%s",
		benchVersions, explain(t, false,
			"select ver.id"+catalogFrom+"\n"+where.where(), where.args...))

	// The predicate alone, against version alone: with the join gone there is no
	// other index for the planner to reach for, so what comes back is an answer
	// about the tag clause and nothing else.
	tagClause, tagArgs := filter.tagClause("tags")
	require.Contains(t, explain(t, true, "select id from version where "+tagClause, tagArgs...),
		"version_tags_gin",
		"the tag filter must be able to reach the GIN index 03-constraints.sql put there for it")
}

// explain returns a plan. Forcing runs inside a transaction because enable_seqscan
// is a session setting and benchDB is a pool: `set` and the statement it was meant
// for can land on different connections, and `set local` cannot.
func explain(t *testing.T, forced bool, statement string, args ...any) string {
	t.Helper()

	ctx := t.Context()
	tx, err := benchDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	if forced {
		_, err = tx.ExecContext(ctx, "set local enable_seqscan = off")
		require.NoError(t, err)
	}

	rows, err := tx.QueryContext(ctx, "explain (format text) "+statement, args...)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var plan strings.Builder
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan.WriteString(line + "\n")
	}
	require.NoError(t, rows.Err())
	return plan.String()
}

func count(t *testing.T, table string) int {
	t.Helper()

	var n int
	require.NoError(t, benchDB.QueryRowContext(t.Context(), "select count(*) from "+table).Scan(&n))
	return n
}

// percentile is nearest-rank on a copy: the caller's slice is reused across
// workloads and sorting it in place would reorder samples that are still being
// appended to.
func percentile(samples []time.Duration, q float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	index := int(q * float64(len(sorted)-1))
	return sorted[index]
}

func round(d time.Duration) time.Duration { return d.Round(100 * time.Microsecond) }
