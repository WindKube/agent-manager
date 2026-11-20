package notifier

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/uptrace/bun"

	"agent-manager/internal/fetch"
	"agent-manager/internal/metrics"
	"agent-manager/internal/notify"
	"agent-manager/internal/outbox"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// maxLogged bounds the response body and the error kept per attempt.
const maxLogged = 1024

// Delivery is the `notify` job: one event to one subscription.
type Delivery struct {
	SubscriptionID uuid.UUID `json:"subscriptionId"`
	EventID        uuid.UUID `json:"eventId"`
}

// Kind is the River job kind, the same string as the outbox job kind.
func (Delivery) Kind() string { return string(outbox.KindNotify) }

// NewDeliveryJob is the outbox job for one delivery.
func NewDeliveryJob(subscriptionID, eventID uuid.UUID) outbox.Job {
	return outbox.Job{
		Kind: outbox.KindNotify, SubjectID: subscriptionID, SubjectVersion: eventID.String(),
		Payload: Delivery{SubscriptionID: subscriptionID, EventID: eventID},
	}
}

// Deliverer works `notify` jobs.
type Deliverer struct {
	river.WorkerDefaults[Delivery]

	db      bun.IDB
	client  fetch.Client
	timeout time.Duration
	now     func() time.Time
}

// NewDeliverer builds the worker; timeout bounds one attempt.
func NewDeliverer(db bun.IDB, client fetch.Client, timeout time.Duration) *Deliverer {
	return &Deliverer{db: db, client: client, timeout: timeout, now: time.Now}
}

// Timeout leaves room past the request's own bound to record the attempt.
func (d *Deliverer) Timeout(*river.Job[Delivery]) time.Duration { return d.timeout + 15*time.Second }

// NextRetry backs off exponentially: 2, 4, 8 ... 512 minutes, so the ten
// attempts outbox.MaxAttempts allows span about 17 hours.
func (d *Deliverer) NextRetry(job *river.Job[Delivery]) time.Time {
	attempt := min(job.Attempt, 9)
	return d.now().Add(time.Duration(1<<attempt) * time.Minute)
}

func (d *Deliverer) Work(ctx context.Context, job *river.Job[Delivery]) error {
	return d.Deliver(ctx, job.Args, job.Attempt)
}

type subscription struct {
	ID      uuid.UUID `bun:"id"`
	Name    string    `bun:"name"`
	URL     string    `bun:"url"`
	Secret  []byte    `bun:"secret"`
	Enabled bool      `bun:"enabled"`
}

// Deliver sends one event to one subscription and records the attempt. It
// returns an error only when the attempt should be retried.
func (d *Deliverer) Deliver(ctx context.Context, job Delivery, attempt int) error {
	var sub subscription
	err := d.db.NewSelect().Model((*models.WebhookSubscription)(nil)).
		Column("id", "name", "url", "secret", "enabled").
		Where("id = ?", job.SubscriptionID).Scan(ctx, &sub)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil // deleted since the event was dispatched
	case err != nil:
		return fmt.Errorf("read webhook %s: %w", job.SubscriptionID, err)
	case !sub.Enabled:
		return nil
	}

	done, err := outbox.Delivered(ctx, d.db, NewDeliveryJob(job.SubscriptionID, job.EventID))
	if err != nil || done {
		return err
	}

	event, err := d.event(ctx, job.EventID)
	if err != nil {
		return err
	}
	body, err := event.Body()
	if err != nil {
		return fmt.Errorf("encode event %s: %w", job.EventID, err)
	}

	result := d.post(ctx, sub, event.ID, body)
	metrics.WebhookDeliveries.WithLabelValues(metrics.StatusClass(result.status)).Inc()
	if err := d.record(ctx, sub, event, attempt, result); err != nil {
		return err
	}

	switch {
	case result.status >= 200 && result.status < 300:
		return nil
	case result.status == http.StatusGone:
		return d.disable(ctx, sub)
	case result.status != 0:
		return fmt.Errorf("webhook %s answered %d", sub.ID, result.status)
	default:
		return fmt.Errorf("webhook %s: %s", sub.ID, result.err)
	}
}

func (d *Deliverer) event(ctx context.Context, id uuid.UUID) (notify.Event, error) {
	var row models.AuditEvent
	if err := d.db.NewSelect().Model(&row).Where("id = ?", id).Scan(ctx); err != nil {
		return notify.Event{}, fmt.Errorf("read audit event %s: %w", id, err)
	}
	action, _ := row.Data["action"].(string)
	t, ok := notify.FromAudit(string(row.Kind), action, string(row.SubjectKind))
	if !ok {
		return notify.Event{}, fmt.Errorf("audit event %s raises no webhook event", id)
	}
	return notify.NewEvent(row.ID.String(), t, row.OccurredAt, row.Namespace, string(row.SubjectKind),
		row.SubjectID, string(row.ActorKind), row.Actor, row.Data), nil
}

type attemptResult struct {
	status   int
	body     string
	err      string
	duration time.Duration
}

func (d *Deliverer) post(ctx context.Context, sub subscription, id string, body []byte) attemptResult {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	u, err := url.Parse(sub.URL)
	if err != nil || u.Scheme != "https" {
		return attemptResult{err: "the stored url is not https"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.URL, bytes.NewReader(body))
	if err != nil {
		return attemptResult{err: "build the request: " + scrub(err.Error(), sub.URL)}
	}
	timestamp := d.now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "agent-manager-webhooks")
	req.Header.Set("Webhook-Id", id)
	req.Header.Set("Webhook-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("Webhook-Signature", notify.Sign(sub.Secret, id, timestamp, body))

	started := time.Now()
	resp, err := d.client.Do(ctx, req)
	if err != nil {
		return attemptResult{err: scrub(err.Error(), sub.URL), duration: time.Since(started)}
	}
	defer func() { _ = resp.Body.Close() }()
	head, _ := io.ReadAll(io.LimitReader(resp.Body, maxLogged))
	return attemptResult{status: resp.StatusCode, body: truncate(string(head)), duration: time.Since(started)}
}

func (d *Deliverer) record(ctx context.Context, sub subscription, event notify.Event, attempt int, r attemptResult) error {
	var status *int32
	if r.status != 0 {
		s := clamp32(int64(r.status))
		status = &s
	}
	eventID, err := uuid.Parse(event.ID)
	if err != nil {
		return err
	}
	return d.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewInsert().Model(&models.WebhookDelivery{
			ID: models.NewID(), SubscriptionID: sub.ID, EventID: eventID, EventType: string(event.Type),
			Attempt: clamp32(int64(max(attempt, 1))), StatusCode: status, Error: truncate(r.err), ResponseBody: r.body,
			DurationMs: clamp32(r.duration.Milliseconds()),
		}).Returning("NULL").Exec(ctx); err != nil {
			return fmt.Errorf("record the delivery to webhook %s: %w", sub.ID, err)
		}
		if _, err := tx.NewUpdate().Model((*models.WebhookSubscription)(nil)).
			Set("last_delivery_at = now()").
			Set("last_delivery_status = ?", status).
			Set("last_delivery_error = ?", nullable(truncate(r.err))).
			Where("id = ?", sub.ID).Exec(ctx); err != nil {
			return fmt.Errorf("record the last delivery of webhook %s: %w", sub.ID, err)
		}
		return nil
	})
}

// disable turns a subscription off after its receiver answered 410 Gone,
// which the Standard Webhooks spec reserves for "stop sending".
func (d *Deliverer) disable(ctx context.Context, sub subscription) error {
	return d.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewUpdate().Model((*models.WebhookSubscription)(nil)).
			Set("enabled = false").
			Set("disabled_reason = ?", "the receiver answered 410 Gone").
			Set("updated_at = now()").
			Where("id = ? and enabled", sub.ID).Exec(ctx)
		if err != nil {
			return fmt.Errorf("disable webhook %s: %w", sub.ID, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		event, err := audit.New(audit.Entry{
			Kind: models.AuditKindWebhook, Action: "disabled", Actor: RoleName, ActorKind: models.ActorKindSystem,
			Text:    "disabled webhook " + sub.Name + ": the receiver answered 410 Gone",
			Source:  "system",
			Subject: audit.Webhook(sub.ID, sub.Name),
			Data:    map[string]any{"status": http.StatusGone},
		})
		if err != nil {
			return err
		}
		if _, err := tx.NewInsert().Model(event).Returning("NULL").Exec(ctx); err != nil {
			return fmt.Errorf("write the webhook disabled audit row: %w", err)
		}
		return nil
	})
}

// scrub keeps a chat webhook's path, which is its credential, out of an
// error that reaches the delivery log or a log line.
func scrub(msg, rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return strings.ReplaceAll(msg, rawURL, u.Scheme+"://"+u.Host+"/…")
	}
	return msg
}

func truncate(s string) string {
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "")
	if len(s) <= maxLogged {
		return s
	}
	s = s[:maxLogged]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func clamp32(n int64) int32 {
	return int32(min(max(n, 0), math.MaxInt32)) //nolint:gosec // clamped on the line itself
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
