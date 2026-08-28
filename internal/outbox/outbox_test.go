// The container-free half of this package's tests. Everything that needs a real
// transaction, a real NOTIFY or a real queue is in the integration-tagged files:
// the guarantees this package exists for are transactional, and a fake database
// would only ever confirm that the fake behaves.
package outbox_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/outbox"
)

func TestTheIdempotencyKeyIsJobKindSubjectIdAndSubjectVersion(t *testing.T) {
	subject := uuid.MustParse("018f1f5b-0000-7000-8000-000000000001")
	other := uuid.MustParse("018f1f5b-0000-7000-8000-000000000002")

	for _, tc := range []struct {
		name string
		job  outbox.Job
		want string
	}{
		{
			name: "a scan names the version and the rule-pack version",
			job:  outbox.Job{Kind: outbox.KindScan, SubjectID: subject, SubjectVersion: "2026.08.1"},
			want: "scan:018f1f5b-0000-7000-8000-000000000001:2026.08.1",
		},
		{
			name: "a fetch names the version",
			job:  outbox.Job{Kind: outbox.KindFetch, SubjectID: subject, SubjectVersion: "1.4.2"},
			want: "fetch:018f1f5b-0000-7000-8000-000000000001:1.4.2",
		},
		{
			name: "a sweep has no subject",
			job:  outbox.Job{Kind: outbox.KindRescanSweep},
			want: "rescan-sweep::",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.job.IdempotencyKey())
		})
	}

	// The three axes each have to move the key, or two different jobs would share
	// one and a handler could not tell a redelivery from a new instruction.
	base := outbox.Job{Kind: outbox.KindScan, SubjectID: subject, SubjectVersion: "2026.08.1"}
	require.NotEqual(t, base.IdempotencyKey(), outbox.Job{Kind: outbox.KindFetch, SubjectID: subject, SubjectVersion: "2026.08.1"}.IdempotencyKey())
	require.NotEqual(t, base.IdempotencyKey(), outbox.Job{Kind: outbox.KindScan, SubjectID: other, SubjectVersion: "2026.08.1"}.IdempotencyKey())
	require.NotEqual(t, base.IdempotencyKey(), outbox.Job{Kind: outbox.KindScan, SubjectID: subject, SubjectVersion: "2026.09.1"}.IdempotencyKey())
}

func TestJobValidateRejectsWhatTheRelayCouldNotDeliver(t *testing.T) {
	for _, tc := range []struct {
		name    string
		job     outbox.Job
		wantErr string
	}{
		{
			name: "a known kind with a struct payload",
			job:  outbox.Job{Kind: outbox.KindFetch, Payload: struct{ URL string }{URL: "https://example.com"}},
		},
		{
			name: "a known kind with a raw payload",
			job:  outbox.Job{Kind: outbox.KindScan, Payload: json.RawMessage(`{"versionId":"x"}`)},
		},
		{
			name: "a known kind with no payload",
			job:  outbox.Job{Kind: outbox.KindRescanSweep},
		},
		{
			name:    "an unknown kind",
			job:     outbox.Job{Kind: outbox.Kind("publish")},
			wantErr: `unknown job kind "publish"`,
		},
		{
			name:    "an empty kind",
			job:     outbox.Job{},
			wantErr: "unknown job kind",
		},
		{
			name:    "a raw payload that is not json",
			job:     outbox.Job{Kind: outbox.KindScan, Payload: json.RawMessage(`{not json`)},
			wantErr: "not valid json",
		},
		{
			name:    "a payload that will not marshal",
			job:     outbox.Job{Kind: outbox.KindScan, Payload: func() {}},
			wantErr: "encode payload",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.job.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// The Writer holds no database handle at all, so "enqueue outside a transaction"
// is not expressible — this asserts the degenerate case where a caller passes
// nothing rather than its own transaction (principle IX).
func TestEnqueueWithoutACallerTransactionIsRefused(t *testing.T) {
	_, err := outbox.NewWriter().Enqueue(context.Background(), nil,
		outbox.Job{Kind: outbox.KindScan, SubjectID: uuid.New()})

	require.ErrorContains(t, err, "no transaction")
}

func TestEveryKindRidesTheDefaultQueueUntilOneAsksForItsOwn(t *testing.T) {
	for _, kind := range []outbox.Kind{outbox.KindFetch, outbox.KindScan, outbox.KindRescanSweep} {
		t.Run(string(kind), func(t *testing.T) {
			require.True(t, kind.Valid())
			require.Equal(t, river.QueueDefault, outbox.Queue(kind))
		})
	}
}
