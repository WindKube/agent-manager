//go:build integration

// Everything this package guarantees is transactional, so all of it is asserted
// against a real Postgres and a real River. A fake would only ever confirm that
// the fake behaves: "a rolled-back transaction enqueues nothing" is a statement
// about Postgres, not about Go.
package outbox_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"

	"agent-manager/internal/outbox"
	"agent-manager/internal/store"
	"agent-manager/internal/store/migrations"
	"agent-manager/internal/store/models"
)

// One container, three databases. agent_manager holds the application schema,
// river holds the queue and nothing else (principle IX), and atlas_dev is the
// throwaway the T025 gate hands to Atlas.
var (
	appURL     string
	queueURL   string
	atlasDevDB string

	handle    *store.Handle
	appPool   *pgxpool.Pool
	queuePool *pgxpool.Pool

	// noInfra explains why the suite could not run. Every test skips on it rather
	// than failing: a machine with no Docker has nothing wrong with it, and a
	// spurious red is a red nobody reads.
	noInfra string
)

func TestMain(m *testing.M) {
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "outbox integration suite:", err)
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
		if !dockerReachable() {
			noInfra = "docker is not available on this machine: " + err.Error()
			return m.Run(), nil
		}
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
	dsn := func(db string) string {
		return fmt.Sprintf("postgres://postgres:postgres@%s/%s?sslmode=disable", endpoint, db)
	}
	appURL, queueURL, atlasDevDB = dsn("agent_manager"), dsn("river"), dsn("atlas_dev")

	appPool, err = pgxpool.New(ctx, appURL)
	if err != nil {
		return 0, fmt.Errorf("open application pool: %w", err)
	}
	defer appPool.Close()

	for _, name := range []string{"river", "atlas_dev"} {
		if _, createErr := appPool.Exec(ctx, "create database "+name); createErr != nil {
			return 0, fmt.Errorf("create database %s: %w", name, createErr)
		}
	}

	err = migrations.Apply(ctx, func(ctx context.Context, sql string) error {
		_, execErr := appPool.Exec(ctx, sql)
		return execErr
	})
	if err != nil {
		return 0, err
	}

	// River's own migrator against its own database — the code path
	// `agent-manager migrate queue` runs (T024).
	applied, err := outbox.MigrateQueue(ctx, queueURL, nil)
	if err != nil {
		return 0, err
	}
	if len(applied) == 0 {
		return 0, fmt.Errorf("the river migrator applied nothing to an empty database")
	}

	handle, err = store.Open(ctx, appURL, queueURL)
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil {
			fmt.Fprintln(os.Stderr, "close store:", closeErr)
		}
	}()
	queuePool = handle.Queue()

	return m.Run(), nil
}

// ---------------------------------------------------------------------------
// Principle IX — the outbox row and the mutation share one transaction
// ---------------------------------------------------------------------------

// The dual-write bug this exists to prevent, from the losing side. A mutation that
// rolls back must leave no job behind — and neither must its notification, or the
// relay would wake up and find nothing while a caller believed a job was queued.
func TestARolledBackTransactionEnqueuesNothing(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	relay := startRelay(t, outbox.RelayConfig{
		AppDatabaseURL: appURL,
		SweepInterval:  50 * time.Millisecond,
	})
	waitForSweep(t, relay)
	before := relay.Stats()

	marker := uuid.NewString()
	tx, err := handle.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	// A failure below must not leave the transaction holding a pooled connection.
	defer func() { _ = tx.Rollback() }()

	ids, err := outbox.NewWriter().Enqueue(ctx, tx, job(outbox.KindScan, marker))
	require.NoError(t, err)
	require.Len(t, ids, 1)

	// The row is visible inside the transaction, so the insert really happened and
	// the rollback below is what removes it.
	// bun formats raw SQL with `?`, not with Postgres placeholders.
	var inTx int
	require.NoError(t, tx.QueryRowContext(ctx,
		"select count(*) from outbox where id = ?", ids[0]).Scan(&inTx))
	require.Equal(t, 1, inTx)

	require.NoError(t, tx.Rollback())

	require.Equal(t, 0, outboxRowCount(t, ctx, ids[0]), "a rolled-back mutation must leave no outbox row")

	// Give the relay a few sweeps to prove it has nothing to find.
	time.Sleep(300 * time.Millisecond)
	require.Zero(t, riverJobCount(t, ctx, marker), "no job may reach the queue for a rolled-back mutation")

	require.Equal(t, before.Notifications, relay.Stats().Notifications,
		"pg_notify inside the transaction must be discarded by the rollback, or the relay is woken by mutations that never happened")
	requireEventually(t, "the relay was running throughout, so its silence means something", func() bool {
		return relay.Stats().Sweeps > before.Sweeps
	})
}

// And from the winning side: a commit publishes the state change and its jobs
// together, and the relay delivers without anything else prompting it.
func TestACommittedTransactionAlwaysDelivers(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	startRelay(t, outbox.RelayConfig{
		AppDatabaseURL: appURL,
		SweepInterval:  time.Hour, // so the delivery below can only be the notification
	})

	marker := uuid.NewString()
	require.NoError(t, handle.DB().RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := outbox.NewWriter().Enqueue(ctx, tx, job(outbox.KindFetch, marker))
		return err
	}))

	requireEventually(t, "the job reaches the queue", func() bool {
		return riverJobCount(t, ctx, marker) == 1
	})

	// The queue insert and the mark are one transaction, so a delivered job always
	// has a delivered row behind it.
	requireEventually(t, "the outbox row is marked delivered", func() bool {
		state, _, ok := outboxState(t, ctx, marker)
		return ok && state == "delivered"
	})

	_, deliveredAt, _ := outboxState(t, ctx, marker)
	require.NotNil(t, deliveredAt)
}

// The property that makes a lost notification survivable, and the one most likely
// to be quietly broken. The row is inserted with raw SQL, so no NOTIFY is ever
// raised — the relay's listener is connected and idle. Only the sweep can deliver
// this, and the notification counter proves that is what happened.
func TestTheSweepAloneDeliversWhenTheNotificationIsMissed(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	relay := startRelay(t, outbox.RelayConfig{
		AppDatabaseURL: appURL,
		SweepInterval:  200 * time.Millisecond,
	})
	waitForSweep(t, relay)

	before := relay.Stats()
	require.Zero(t, before.ListenerDrops, "the listener must be up, or this test proves nothing about a missed notification")

	marker := uuid.NewString()
	insertPendingRowWithoutNotifying(t, ctx, outbox.KindScan, marker)

	requireEventually(t, "the sweep delivers the row nobody was notified about", func() bool {
		return riverJobCount(t, ctx, marker) == 1
	})

	require.Equal(t, before.Notifications, relay.Stats().Notifications,
		"the delivery must have come from the sweep: no notification was raised for this row")
	requireEventually(t, "the sweep ticker is what is driving this relay", func() bool {
		return relay.Stats().Sweeps > before.Sweeps
	})
}

// The relay may run in several api replicas at once. `for update skip locked` is
// what stops two of them delivering the same row, and a duplicate here would be
// invisible in production until somebody counted scans.
func TestTwoRelaysDrainingConcurrentlyDeliverEachRowExactlyOnce(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	const rows = 24
	markers := make([]string, 0, rows)
	require.NoError(t, handle.DB().RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		jobs := make([]outbox.Job, 0, rows)
		for range rows {
			marker := uuid.NewString()
			markers = append(markers, marker)
			jobs = append(jobs, job(outbox.KindScan, marker))
		}
		_, err := outbox.NewWriter().Enqueue(ctx, tx, jobs...)
		return err
	}))

	// Counted rather than assumed: other tests in this suite leave pending rows
	// behind on purpose, and the two relays will claim those too.
	pending := pendingOutboxCount(t, ctx)
	require.GreaterOrEqual(t, pending, int64(rows))

	first := newRelay(t, outbox.RelayConfig{Batch: 4})
	second := newRelay(t, outbox.RelayConfig{Batch: 4})

	var wg sync.WaitGroup
	for _, relay := range []*outbox.Relay{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, relay.Drain(ctx))
		}()
	}
	wg.Wait()

	for _, marker := range markers {
		require.Equal(t, 1, riverJobCount(t, ctx, marker), "marker %s", marker)

		state, _, ok := outboxState(t, ctx, marker)
		require.True(t, ok)
		require.Equal(t, "delivered", state)
	}

	require.Equal(t, pending, first.Stats().Delivered+second.Stats().Delivered,
		"the two relays together must have claimed every pending row exactly once")
	require.Zero(t, pendingOutboxCount(t, ctx), "nothing pending may be left behind")
}

// data-model.md: delivered rows pruned after 24 h. The boundary is computed by
// Postgres, so a client clock cannot move it.
func TestThePruneRemovesDeliveredRowsPastTheRetentionWindowAndNothingElse(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	stale := seedOutboxRow(t, ctx, "delivered", "48 hours")
	fresh := seedOutboxRow(t, ctx, "delivered", "1 hour")
	pending := seedOutboxRow(t, ctx, "pending", "")

	relay := newRelay(t, outbox.RelayConfig{})
	removed, err := relay.Prune(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, removed, int64(1))

	require.Equal(t, 0, outboxRowCount(t, ctx, stale), "a delivered row older than 24 h must be gone")
	require.Equal(t, 1, outboxRowCount(t, ctx, fresh), "a delivered row inside the window must survive")
	require.Equal(t, 1, outboxRowCount(t, ctx, pending), "the prune is keyed on state as well as age")
}

// ---------------------------------------------------------------------------
// R5 — the idempotency key lives on the job's target row
// ---------------------------------------------------------------------------

// Delivery is at-least-once, so the handler must be able to recognise a
// redelivery from the data. These are the two predicates that do it, and they
// live in this package so the fetcher's answer and the scanner's cannot drift
// apart. Nothing in the queue is consulted: the queue has no memory to consult.
func TestARedeliveredJobIsANoOpBecauseItsTargetRowAlreadySaysSo(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()
	db := handle.DB()

	unfetched := seedVersion(t, ctx, "1.0.0", nil)
	fetched := seedVersion(t, ctx, "1.0.1", make([]byte, 32))

	scanned := seedVersion(t, ctx, "1.0.2", make([]byte, 32))
	_, err := appPool.Exec(ctx,
		`insert into scan (id, version_id, pack_version, verdict) values ($1, $2, '2026.08.1', 'clean')`,
		models.NewID(), scanned)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		job  outbox.Job
		want bool
	}{
		{
			name: "a fetch for a version with no committed bytes is work to do",
			job:  outbox.Job{Kind: outbox.KindFetch, SubjectID: unfetched, SubjectVersion: "1.0.0"},
			want: false,
		},
		{
			name: "a redelivered fetch for a version with committed bytes is a no-op",
			job:  outbox.Job{Kind: outbox.KindFetch, SubjectID: fetched, SubjectVersion: "1.0.1"},
			want: true,
		},
		{
			name: "a scan for a version with no scan at this pack version is work to do",
			job:  outbox.Job{Kind: outbox.KindScan, SubjectID: fetched, SubjectVersion: "2026.08.1"},
			want: false,
		},
		{
			name: "a redelivered scan at the same pack version is a no-op",
			job:  outbox.Job{Kind: outbox.KindScan, SubjectID: scanned, SubjectVersion: "2026.08.1"},
			want: true,
		},
		{
			// The case a unique key on the queue would get wrong: a new rule pack must
			// rescan the same version.
			name: "a scan at a newer pack version is work to do again",
			job:  outbox.Job{Kind: outbox.KindScan, SubjectID: scanned, SubjectVersion: "2026.09.1"},
			want: false,
		},
		{
			name: "a sweep is never suppressed: its fan-out is what carries the guard",
			job:  outbox.Job{Kind: outbox.KindRescanSweep},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done, err := outbox.Delivered(ctx, db, tc.job)
			require.NoError(t, err)
			require.Equal(t, tc.want, done)
		})
	}

	// And the redelivery really is a redelivery: the second row reaches the queue,
	// which is exactly why the handler needs the guard above.
	marker := uuid.NewString()
	require.NoError(t, db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		scanJob := job(outbox.KindScan, marker)
		scanJob.SubjectID = scanned
		scanJob.SubjectVersion = "2026.08.1"
		_, err := outbox.NewWriter().Enqueue(ctx, tx, scanJob, scanJob)
		return err
	}))

	relay := newRelay(t, outbox.RelayConfig{})
	require.NoError(t, relay.Drain(ctx))
	require.Equal(t, 2, riverJobCount(t, ctx, marker),
		"the queue does not deduplicate, and it must not: the target row is the key")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// requireInfra skips when the container never came up. It is called by every test
// in this package, including the R11 gate.
func requireInfra(t *testing.T) {
	t.Helper()
	if noInfra != "" {
		t.Skip("skipping: " + noInfra)
	}
}

// dockerReachable tells "no Docker on this machine" (skip) apart from "Docker is
// here and the container failed" (a real failure worth reporting). It is a cheap
// probe on purpose: a full health check would need its own client and would fail
// for its own reasons.
func dockerReachable() bool {
	if os.Getenv("DOCKER_HOST") != "" {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	for _, socket := range []string{
		"/var/run/docker.sock",
		filepath.Join(home, ".docker", "run", "docker.sock"),
		filepath.Join(home, ".colima", "default", "docker.sock"),
		filepath.Join(home, ".rd", "docker.sock"),
	} {
		if _, statErr := os.Stat(socket); statErr == nil {
			return true
		}
	}
	return false
}

func job(kind outbox.Kind, marker string) outbox.Job {
	return outbox.Job{
		Kind:           kind,
		SubjectID:      models.NewID(),
		SubjectVersion: "1.0.0",
		Payload:        json.RawMessage(fmt.Sprintf(`{"marker":%q}`, marker)),
	}
}

func newRelay(t *testing.T, cfg outbox.RelayConfig) *outbox.Relay {
	t.Helper()

	client, err := outbox.NewInsertClient(queuePool, nil)
	require.NoError(t, err)

	relay, err := outbox.NewRelay(handle.DB(), outbox.RiverInserter(client), cfg, zerolog.Nop())
	require.NoError(t, err)

	return relay
}

func startRelay(t *testing.T, cfg outbox.RelayConfig) *outbox.Relay {
	t.Helper()

	relay := newRelay(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		require.NoError(t, relay.Run(ctx))
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})
	return relay
}

// waitForSweep blocks until the relay has completed at least one sweep, so a test
// that compares stats before and after is comparing against a running relay.
func waitForSweep(t *testing.T, relay *outbox.Relay) {
	t.Helper()
	requireEventually(t, "the relay completes its first sweep", func() bool {
		return relay.Stats().Sweeps > 0
	})
}

func requireEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 15*time.Second, 20*time.Millisecond, what)
}

// insertPendingRowWithoutNotifying is the missed notification, reproduced exactly:
// a committed pending row that no NOTIFY ever announced.
func insertPendingRowWithoutNotifying(t *testing.T, ctx context.Context, kind outbox.Kind, marker string) uuid.UUID {
	t.Helper()

	id := models.NewID()
	_, err := appPool.Exec(ctx, `insert into outbox (id, job_kind, payload, idempotency_key, state)
		values ($1, $2, $3::jsonb, $4, 'pending')`,
		id, string(kind), fmt.Sprintf(`{"marker":%q}`, marker), "sweep:"+marker)
	require.NoError(t, err)

	return id
}

func seedOutboxRow(t *testing.T, ctx context.Context, state, deliveredAgo string) uuid.UUID {
	t.Helper()

	id := models.NewID()
	_, err := appPool.Exec(ctx, `insert into outbox (id, job_kind, payload, idempotency_key, state, delivered_at)
		values ($1, 'scan', '{}', $2, $3::outbox_state,
		        case when $4 = '' then null else now() - $4::interval end)`,
		id, "prune:"+id.String(), state, deliveredAgo)
	require.NoError(t, err)

	return id
}

func seedVersion(t *testing.T, ctx context.Context, semver string, digest []byte) uuid.UUID {
	t.Helper()

	pubID, pkgID, verID := models.NewID(), models.NewID(), models.NewID()

	// A publisher slug is <namespace>/<team>, and publisher.namespace is generated
	// from its first segment. package.namespace is not: it is denormalised and held
	// to its publisher's by a composite foreign key, so it has to be written and it
	// has to agree.
	namespace := "ns" + strings.ReplaceAll(pubID.String(), "-", "")

	_, err := appPool.Exec(ctx,
		`insert into publisher (id, slug, display_name) values ($1, $2, 'Example')`,
		pubID, namespace+"/relay")
	require.NoError(t, err)

	_, err = appPool.Exec(ctx,
		`insert into package (id, publisher_id, namespace, name, kind, visibility)
		 values ($1, $2, $3, $4, 'skill', 'organisation')`,
		pkgID, pubID, namespace, "p-"+pkgID.String())
	require.NoError(t, err)

	sortKey, err := models.SemverSort(semver)
	require.NoError(t, err)

	// A version with no digest is one whose bytes have not been committed: that is
	// the pre-fetch state the API creates before it enqueues the fetch job.
	verdict, objectKey := "scanning", ""
	if digest != nil {
		verdict, objectKey = "clean", "skills/example/p/"+semver+"/bundle.tar.zst"
	}

	_, err = appPool.Exec(ctx, `insert into version
		(id, package_id, semver, semver_sort, object_key, digest, size_bytes, manifest, dist_tag, verdict, visible)
		values ($1, $2, $3, $4, $5, $6, 2048, '{"name":"p"}', 'latest', $7::verdict, true)`,
		verID, pkgID, semver, sortKey, objectKey, digest, verdict)
	require.NoError(t, err)

	return verID
}

func pendingOutboxCount(t *testing.T, ctx context.Context) int64 {
	t.Helper()

	var n int64
	require.NoError(t, appPool.QueryRow(ctx,
		"select count(*) from outbox where state = 'pending'").Scan(&n))

	return n
}

func outboxRowCount(t *testing.T, ctx context.Context, id uuid.UUID) int {
	t.Helper()

	var n int
	require.NoError(t, appPool.QueryRow(ctx, "select count(*) from outbox where id = $1", id).Scan(&n))

	return n
}

func outboxState(t *testing.T, ctx context.Context, marker string) (string, *time.Time, bool) {
	t.Helper()

	var (
		state       *string
		deliveredAt *time.Time
	)
	// Scalar subqueries, so a missing row comes back as "not there" rather than as
	// no rows to scan.
	require.NoError(t, appPool.QueryRow(ctx,
		`select (select state::text from outbox where payload->>'marker' = $1),
		        (select delivered_at from outbox where payload->>'marker' = $1)`, marker,
	).Scan(&state, &deliveredAt))

	if state == nil {
		return "", nil, false
	}
	return *state, deliveredAt, true
}

func riverJobCount(t *testing.T, ctx context.Context, marker string) int {
	t.Helper()

	var n int
	require.NoError(t, queuePool.QueryRow(ctx,
		`select count(*) from river_job where args->>'marker' = $1`, marker).Scan(&n))

	return n
}
