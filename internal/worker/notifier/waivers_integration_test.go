//go:build integration

package notifier

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/outbox"
	"agent-manager/internal/store/models"
)

// seedWaiver is an accepted finding whose override expires at expiresAt.
func seedWaiver(t *testing.T, state string, expiresIn time.Duration) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	pub, pkg, ver, scan, finding := models.NewID(), models.NewID(), models.NewID(), models.NewID(), models.NewID()
	sortKey, err := models.SemverSort("1.0.0")
	require.NoError(t, err)
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`insert into publisher (id, slug, display_name) values ($1, $2, 'Example')`, []any{pub, "example/" + pub.String()}},
		{`insert into package (id, publisher_id, namespace, name, kind, visibility)
			select $1, p.id, p.namespace, $3, 'skill', 'organisation' from publisher p where p.id = $2`, []any{pkg, pub, "tool-" + pkg.String()}},
		{`insert into version (id, package_id, semver, semver_sort, object_key, digest, size_bytes, manifest, dist_tag, verdict, visible)
			values ($1, $2, '1.0.0', $3, 'k', $4, 1, '{}', 'latest', 'flagged', true)`, []any{ver, pkg, sortKey, bytes.Repeat([]byte{1}, 32)}},
		{`insert into scan (id, version_id, pack_version, verdict) values ($1, $2, 'p', 'flagged')`, []any{scan, ver}},
		{`insert into finding (id, scan_id, version_id, rule_id, severity, title, state)
			values ($1, $2, $3, 'SH-FS-007', 'high', 't', $4)`, []any{finding, scan, ver, state}},
		{`insert into override (finding_id, reviewer_identity_id, note, expires_at)
			values ($1, $2, 'accepted', now() + make_interval(secs => $3))`, []any{finding, seedIdentity(t), expiresIn.Seconds()}},
	} {
		_, err := pool.Exec(ctx, stmt.sql, stmt.args...)
		require.NoError(t, err)
	}
	return finding
}

func waiverNotices(t *testing.T, finding uuid.UUID) []string {
	t.Helper()
	var actions []string
	require.NoError(t, db.NewSelect().Model((*models.AuditEvent)(nil)).ColumnExpr("data ->> 'action'").
		Where("subject_kind = 'finding' and subject_id = ? and kind = 'approve'", finding.String()).
		OrderExpr("occurred_at, id").Scan(context.Background(), &actions))
	return actions
}

func TestEachWaiverGetsOneExpiringAndOneExpiredNotice(t *testing.T) {
	ctx := context.Background()
	week := 7 * 24 * time.Hour
	soon := seedWaiver(t, "approved", 3*24*time.Hour)
	later := seedWaiver(t, "approved", 20*24*time.Hour)
	lapsed := seedWaiver(t, "approved", -time.Hour)
	rejected := seedWaiver(t, "rejected", -time.Hour)

	_, err := CheckWaivers(ctx, workerDB, week)
	require.NoError(t, err)
	_, err = CheckWaivers(ctx, workerDB, week)
	require.NoError(t, err)

	require.Equal(t, []string{"waiver-expiring"}, waiverNotices(t, soon))
	require.Empty(t, waiverNotices(t, later))
	require.Equal(t, []string{"waiver-expired"}, waiverNotices(t, lapsed))
	require.Empty(t, waiverNotices(t, rejected), "a rejected finding's override no longer counts and raises nothing")

	// The expiry passes: the expired notice follows the expiring one, once.
	_, err = pool.Exec(ctx, `update override set expires_at = now() - interval '1 minute' where finding_id = $1`, soon)
	require.NoError(t, err)
	_, err = CheckWaivers(ctx, workerDB, week)
	require.NoError(t, err)
	_, err = CheckWaivers(ctx, workerDB, week)
	require.NoError(t, err)
	require.Equal(t, []string{"waiver-expiring", "waiver-expired"}, waiverNotices(t, soon))

	var row models.AuditEvent
	require.NoError(t, db.NewSelect().Model(&row).
		Where("subject_id = ? and data ->> 'action' = 'waiver-expired'", lapsed.String()).Scan(ctx))
	require.Equal(t, models.ActorKindSystem, row.ActorKind)
	require.Equal(t, "SH-FS-007", row.Data["ruleId"])
	require.NotEmpty(t, row.Data["expiresAt"])
	require.NotEmpty(t, row.Namespace)
}

func TestAWaiverNoticeFlowsToWebhooksLikeAnyOtherEvent(t *testing.T) {
	ctx := context.Background()
	sub, _ := seedSubscription(t, "https://hooks.example.com/waivers", []string{"waiver.expiring", "waiver.expired"}, nil)
	finding := seedWaiver(t, "approved", 2*24*time.Hour)

	_, err := CheckWaivers(ctx, workerDB, 7*24*time.Hour)
	require.NoError(t, err)
	_, err = DispatchEvents(ctx, workerDB, outbox.NewWriter())
	require.NoError(t, err)

	var eventID uuid.UUID
	require.NoError(t, db.NewSelect().Model((*models.AuditEvent)(nil)).Column("id").
		Where("subject_id = ? and data ->> 'action' = 'waiver-expiring'", finding.String()).Scan(ctx, &eventID))
	jobs := notifyJobs(t, eventID)
	require.Len(t, jobs, 1)
	require.Equal(t, sub, jobs[0].SubscriptionID)
}
