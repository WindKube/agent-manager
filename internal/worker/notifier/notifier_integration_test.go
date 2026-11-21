//go:build integration

package notifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"agent-manager/internal/fetch"
	"agent-manager/internal/notify"
	"agent-manager/internal/outbox"
	"agent-manager/internal/store/models"
	"agent-manager/internal/store/storetest"
)

var (
	pool     *pgxpool.Pool
	db       *bun.DB // superuser, for fixtures and assertions
	workerDB *bun.DB // am_notifier, for everything under test
)

func TestMain(m *testing.M) {
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "notifier integration suite:", err)
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

	if pool, err = pg.Pool(ctx, "agent_manager"); err != nil {
		return 0, fmt.Errorf("open pool: %w", err)
	}
	defer pool.Close()
	if applyErr := storetest.ApplyMigrations(ctx, pool); applyErr != nil {
		return 0, applyErr
	}
	db = storetest.BunDB(pool)

	var closeWorker func()
	if workerDB, closeWorker, err = storetest.RoleDB(ctx, pg.DSN("agent_manager"), "am_notifier"); err != nil {
		return 0, fmt.Errorf("open am_notifier pool: %w", err)
	}
	defer closeWorker()
	return m.Run(), nil
}

// receiver is a TLS endpoint that answers with whatever status the test sets
// and keeps every request it got.
type receiver struct {
	mu       sync.Mutex
	status   int
	requests []received
	server   *httptest.Server
}

type received struct {
	header http.Header
	body   []byte
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{status: http.StatusOK}
	r.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.requests = append(r.requests, received{header: req.Header.Clone(), body: body})
		w.WriteHeader(r.status)
		_, _ = w.Write([]byte(`{"ok":` + strconv.FormatBool(r.status < 300) + `}`))
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *receiver) answer(status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
}

func (r *receiver) got() []received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]received(nil), r.requests...)
}

// client is the production outbound client with the two test hooks: the
// loopback receiver allowlisted, and its self-signed certificate trusted.
func (r *receiver) client(t *testing.T) fetch.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(r.server.Certificate())
	client, err := fetch.New(fetch.Options{Allowlist: []string{"127.0.0.1"}, RootCAs: roots})
	require.NoError(t, err)
	return client
}

func seedIdentity(t *testing.T) uuid.UUID {
	t.Helper()
	id := models.NewID()
	_, err := db.NewInsert().Model(&models.Identity{ID: id, Subject: "sub-" + id.String(), Email: id.String() + "@example.com"}).Exec(context.Background())
	require.NoError(t, err)
	return id
}

func seedSubscription(t *testing.T, url string, eventTypes, namespaces []string) (id uuid.UUID, key []byte) {
	t.Helper()
	key, err := notify.NewSecret()
	require.NoError(t, err)
	sub := &models.WebhookSubscription{
		ID: models.NewID(), Name: "test", URL: url, EventTypes: eventTypes, Namespaces: append([]string{}, namespaces...),
		Secret: key, Enabled: true, CreatedByIdentityID: seedIdentity(t),
	}
	_, err = db.NewInsert().Model(sub).Exec(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.NewDelete().Model((*models.WebhookDelivery)(nil)).Where("subscription_id = ?", sub.ID).Exec(context.Background())
		_, _ = db.NewDelete().Model((*models.WebhookSubscription)(nil)).Where("id = ?", sub.ID).Exec(context.Background())
	})
	return sub.ID, key
}

func seedAudit(t *testing.T, kind models.AuditKind, action, subjectKind, subjectID, namespace string, data map[string]any) uuid.UUID {
	t.Helper()
	if data == nil {
		data = map[string]any{}
	}
	data["action"] = action
	row := &models.AuditEvent{
		ID: models.NewID(), Actor: "scanner", ActorKind: models.ActorKindSystem, Kind: kind, Text: "x",
		SubjectKind: models.AuditSubjectKind(subjectKind), SubjectID: subjectID, Namespace: namespace, Data: data,
	}
	_, err := db.NewInsert().Model(row).Exec(context.Background())
	require.NoError(t, err)
	return row.ID
}

func notifyJobs(t *testing.T, eventID uuid.UUID) []Delivery {
	t.Helper()
	var payloads []json.RawMessage
	require.NoError(t, db.NewSelect().Model((*models.Outbox)(nil)).Column("payload").
		Where("job_kind = ? and payload ->> 'eventId' = ?", outbox.KindNotify, eventID.String()).
		Scan(context.Background(), &payloads))
	out := make([]Delivery, 0, len(payloads))
	for _, p := range payloads {
		var d Delivery
		require.NoError(t, json.Unmarshal(p, &d))
		out = append(out, d)
	}
	return out
}

func TestEachMatchingAuditRowIsEnqueuedOncePerSubscription(t *testing.T) {
	ctx := context.Background()
	all, _ := seedSubscription(t, "https://hooks.example.com/all", []string{"*"}, nil)
	scansInPlatform, _ := seedSubscription(t, "https://hooks.example.com/scans", []string{"scan.completed"}, []string{"platform"})
	waivers, _ := seedSubscription(t, "https://hooks.example.com/waivers", []string{"waiver.expired"}, nil)
	off, _ := seedSubscription(t, "https://hooks.example.com/off", []string{"*"}, nil)
	_, err := db.NewUpdate().Model((*models.WebhookSubscription)(nil)).Set("enabled = false").Where("id = ?", off).Exec(ctx)
	require.NoError(t, err)

	scanned := seedAudit(t, models.AuditKindScan, "scanned", "version", "platform/tool@1.0.0", "platform",
		map[string]any{"verdict": "flagged"})
	elsewhere := seedAudit(t, models.AuditKindScan, "scanned", "version", "other/tool@1.0.0", "other", nil)
	login := seedAudit(t, models.AuditKindLogin, "signed-in", "identity", models.NewID().String(), "", nil)
	before := seedAudit(t, models.AuditKindPolicy, "updated", "policy", "1", "", nil)
	_, err = db.NewUpdate().Model((*models.AuditEvent)(nil)).Set("occurred_at = now() - interval '1 hour'").
		Where("id = ?", before).Exec(ctx)
	require.NoError(t, err, "audit rows are append-only for the roles, not for the fixture's superuser")

	_, err = DispatchEvents(ctx, workerDB, outbox.NewWriter())
	require.NoError(t, err)

	subsOf := func(jobs []Delivery) []uuid.UUID {
		out := []uuid.UUID{}
		for _, j := range jobs {
			out = append(out, j.SubscriptionID)
		}
		return out
	}
	require.ElementsMatch(t, []uuid.UUID{all, scansInPlatform}, subsOf(notifyJobs(t, scanned)))
	require.ElementsMatch(t, []uuid.UUID{all}, subsOf(notifyJobs(t, elsewhere)))
	require.Empty(t, notifyJobs(t, login), "a login raises no event")
	require.Empty(t, notifyJobs(t, before), "an event older than the subscription is not delivered to it")
	require.NotContains(t, subsOf(notifyJobs(t, scanned)), waivers)

	again, err := DispatchEvents(ctx, workerDB, outbox.NewWriter())
	require.NoError(t, err)
	require.Zero(t, again, "a dispatched row is never enqueued twice")
	require.Len(t, notifyJobs(t, scanned), 2)
}

func deliveriesOf(t *testing.T, sub uuid.UUID) []models.WebhookDelivery {
	t.Helper()
	var rows []models.WebhookDelivery
	require.NoError(t, db.NewSelect().Model(&rows).Where("subscription_id = ?", sub).
		OrderExpr("occurred_at, attempt").Scan(context.Background()))
	return rows
}

func TestADeliveryIsSignedRecordedAndRetriedUntilTheReceiverAccepts(t *testing.T) {
	ctx := context.Background()
	recv := newReceiver(t)
	sub, key := seedSubscription(t, recv.server.URL+"/hook/secret-path", []string{"*"}, nil)
	event := seedAudit(t, models.AuditKindScan, "scanned", "version", "platform/tool@1.2.0", "platform",
		map[string]any{"verdict": "flagged", "ruleIds": []string{"SH-FS-007"}})
	d := NewDeliverer(workerDB, recv.client(t), 5*time.Second)
	job := Delivery{SubscriptionID: sub, EventID: event}

	recv.answer(http.StatusInternalServerError)
	require.Error(t, d.Deliver(ctx, job, 1), "a 500 is retried")

	recv.answer(http.StatusNoContent)
	require.NoError(t, d.Deliver(ctx, job, 2))
	require.NoError(t, d.Deliver(ctx, job, 3), "a redelivery after success sends nothing")

	got := recv.got()
	require.Len(t, got, 2)
	last := got[1]
	require.Equal(t, event.String(), last.header.Get("Webhook-Id"))
	ts, err := strconv.ParseInt(last.header.Get("Webhook-Timestamp"), 10, 64)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), time.Unix(ts, 0), time.Minute)
	require.True(t, notify.Verify(key, event.String(), ts, last.body, last.header.Get("Webhook-Signature")))
	require.False(t, notify.Verify(key, event.String(), ts+1, last.body, last.header.Get("Webhook-Signature")))

	var payload map[string]any
	require.NoError(t, json.Unmarshal(last.body, &payload))
	require.Equal(t, event.String(), payload["id"])
	require.Equal(t, "scan.completed", payload["type"])
	require.Equal(t, "platform", payload["namespace"])
	require.Equal(t, map[string]any{"kind": "version", "id": "platform/tool@1.2.0"}, payload["subject"])
	require.Equal(t, map[string]any{"kind": "system", "name": "scanner"}, payload["actor"])
	require.Equal(t, "flagged", payload["data"].(map[string]any)["verdict"])
	require.NotContains(t, payload["data"], "action")

	log := deliveriesOf(t, sub)
	require.Len(t, log, 2)
	require.EqualValues(t, 500, *log[0].StatusCode)
	require.EqualValues(t, 1, log[0].Attempt)
	require.Contains(t, log[0].ResponseBody, `"ok":false`)
	require.EqualValues(t, 204, *log[1].StatusCode)

	var stored models.WebhookSubscription
	require.NoError(t, db.NewSelect().Model(&stored).Where("id = ?", sub).Scan(ctx))
	require.EqualValues(t, 204, *stored.LastDeliveryStatus)
	require.True(t, stored.Enabled)
}

func TestA410DisablesTheSubscriptionAndSaysSoInTheAuditLog(t *testing.T) {
	ctx := context.Background()
	recv := newReceiver(t)
	recv.answer(http.StatusGone)
	sub, _ := seedSubscription(t, recv.server.URL+"/gone", []string{"*"}, nil)
	event := seedAudit(t, models.AuditKindPolicy, "updated", "policy", "1", "", nil)
	d := NewDeliverer(workerDB, recv.client(t), 5*time.Second)

	require.NoError(t, d.Deliver(ctx, Delivery{SubscriptionID: sub, EventID: event}, 1), "a 410 is not retried")

	var stored models.WebhookSubscription
	require.NoError(t, db.NewSelect().Model(&stored).Where("id = ?", sub).Scan(ctx))
	require.False(t, stored.Enabled)
	require.Contains(t, stored.DisabledReason, "410")

	n, err := db.NewSelect().Model((*models.AuditEvent)(nil)).
		Where("subject_kind = 'webhook' and subject_id = ? and data ->> 'action' = 'disabled' and actor_kind = 'system'", sub.String()).
		Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	require.NoError(t, d.Deliver(ctx, Delivery{SubscriptionID: sub, EventID: event}, 2))
	require.Len(t, recv.got(), 1, "a disabled subscription receives nothing more")
}

func TestTheOutboundPolicyRefusesALoopbackReceiverThatIsNotAllowlisted(t *testing.T) {
	ctx := context.Background()
	recv := newReceiver(t)
	sub, _ := seedSubscription(t, recv.server.URL+"/hook/secret-path", []string{"*"}, nil)
	event := seedAudit(t, models.AuditKindPolicy, "updated", "policy", "1", "", nil)

	guarded, err := fetch.New(fetch.Options{})
	require.NoError(t, err)
	err = NewDeliverer(workerDB, guarded, 5*time.Second).Deliver(ctx, Delivery{SubscriptionID: sub, EventID: event}, 1)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret-path")
	require.Empty(t, recv.got())

	log := deliveriesOf(t, sub)
	require.Len(t, log, 1)
	require.Nil(t, log[0].StatusCode)
	require.Contains(t, log[0].Error, "refused")
	require.NotContains(t, log[0].Error, "secret-path", "a chat webhook's path is its credential")
}

func TestPruneDropsOldDeliveriesAndDispatchMarks(t *testing.T) {
	ctx := context.Background()
	sub, _ := seedSubscription(t, "https://hooks.example.com/p", []string{"*"}, nil)
	old, fresh := models.NewID(), models.NewID()
	for id, age := range map[uuid.UUID]string{old: "31 days", fresh: "1 day"} {
		_, err := db.ExecContext(ctx, `insert into webhook_delivery (id, subscription_id, event_id, event_type, attempt, duration_ms, occurred_at)
			values (?, ?, ?, 'policy.changed', 1, 1, now() - ?::interval)`, id, sub, id, age)
		require.NoError(t, err)
	}
	stale := models.NewID()
	_, err := db.ExecContext(ctx, `insert into webhook_dispatch (audit_event_id, dispatched_at) values (?, now() - interval '3 days')`, stale)
	require.NoError(t, err)

	require.NoError(t, (&Pruner{db: workerDB, retention: 30 * 24 * time.Hour}).Work(ctx, nil))

	ids := []uuid.UUID{}
	for _, d := range deliveriesOf(t, sub) {
		ids = append(ids, d.ID)
	}
	require.Equal(t, []uuid.UUID{fresh}, ids)
	n, err := db.NewSelect().Table("webhook_dispatch").Where("audit_event_id = ?", stale).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
}
