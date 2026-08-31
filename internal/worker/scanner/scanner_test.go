package scanner_test

import (
	"encoding/json"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/blob"
	"agent-manager/internal/outbox"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/scanner"
)

// Needs IS the enforcement of principle II for this role, so it is asserted
// rather than assumed: worker.Build hands out a blob.Writer for AccessReadWrite
// and for no other value, and it constructs the outbound client only for
// Outbound: true.
func TestTheScannerDeclaresTheNarrowestNeedsThatWork(t *testing.T) {
	def := scanner.Definition()

	require.Equal(t, "scanner", def.Name)
	require.Equal(t, worker.AccessReadWrite, def.Needs.DB)
	require.Equal(t, worker.AccessRead, def.Needs.Blob,
		"read-write here would hand this role a blob.Writer, and the scanner never writes bundle bytes")
	require.False(t, def.Needs.Outbound,
		"a scan is static analysis; an outbound client is a network reach a static analyser cannot need")
	require.NotEmpty(t, def.Queues)
	require.NotNil(t, def.Register)
}

// The Go boundary, tested from the inside: if the bootstrap ever hands this role a
// writer, the role refuses to run rather than quietly holding one.
func TestTheScannerRefusesDependenciesItDidNotDeclare(t *testing.T) {
	bucket, err := blob.Open(t.Context(), "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })

	base := worker.Deps{
		DB:       bun.NewDB(nil, pgdialect.New()),
		BlobRead: bucket.Reader(),
		Log:      zerolog.New(io.Discard),
	}

	t.Run("an object-store writer", func(t *testing.T) {
		deps := base
		deps.BlobWrite = bucket.Writer()
		_, err := scanner.New(deps, scanner.Options{})
		require.ErrorContains(t, err, "never writes bundle bytes")
	})

	t.Run("no object-store reader", func(t *testing.T) {
		deps := base
		deps.BlobRead = nil
		_, err := scanner.New(deps, scanner.Options{})
		require.ErrorContains(t, err, "no object-store reader")
	})

	t.Run("no database handle", func(t *testing.T) {
		deps := base
		deps.DB = nil
		_, err := scanner.New(deps, scanner.Options{})
		require.ErrorContains(t, err, "no database handle")
	})

	t.Run("the declared set builds", func(t *testing.T) {
		w, err := scanner.New(base, scanner.Options{})
		require.NoError(t, err)
		require.NotEmpty(t, w.PackVersion(), "every scan records the pack version it ran")
	})
}

// The payload is the wire contract between the fetcher's publish transaction and
// this worker: it travels as jsonb through the outbox and back out of River, so
// the field names are as load-bearing as any column name.
func TestTheScanPayloadKeepsItsWireNames(t *testing.T) {
	job := scanner.Job{
		VersionID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		PackageID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		Namespace: "example",
		Name:      "cost-report",
		Semver:    "1.2.3",
		ObjectKey: "skills/example/cost-report/1.2.3/bundle.tar.zst",
	}

	encoded, err := json.Marshal(job)
	require.NoError(t, err)

	var wire map[string]any
	require.NoError(t, json.Unmarshal(encoded, &wire))
	require.Equal(t, []string{"name", "namespace", "objectKey", "packageId", "semver", "versionId"}, keys(wire))

	var decoded scanner.Job
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, job, decoded)
	require.Equal(t, string(outbox.KindScan), job.Kind())
}

// SubjectVersion is empty on purpose and it matters: the scan idempotency key is
// (scan, version id, RULE-PACK version), and the pack version is the scanner's
// own. A producer that filled it in would either suppress the first real scan or
// fail to suppress a redelivery.
func TestTheProducerLeavesTheRulePackVersionOutOfTheIdempotencyKey(t *testing.T) {
	job := scanner.Job{
		VersionID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		PackageID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		Namespace: "example", Name: "cost-report", Semver: "1.2.3",
	}

	enqueued, err := job.OutboxJob()
	require.NoError(t, err)
	require.Equal(t, outbox.KindScan, enqueued.Kind)
	require.Equal(t, job.VersionID, enqueued.SubjectID)
	require.Empty(t, enqueued.SubjectVersion)
	require.NoError(t, enqueued.Validate())
}

func TestTheSweepPayloadNamesThePackageAndTheVersionThatCausedIt(t *testing.T) {
	sweep := scanner.SweepJob{
		PackageID:        uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		TriggerVersionID: uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		Namespace:        "example",
		Name:             "cost-report",
	}

	enqueued, err := sweep.OutboxJob()
	require.NoError(t, err)
	require.Equal(t, outbox.KindRescanSweep, enqueued.Kind)
	require.Equal(t, sweep.PackageID, enqueued.SubjectID)
	require.NoError(t, enqueued.Validate())
	require.Equal(t, string(outbox.KindRescanSweep), sweep.Kind())

	_, err = scanner.SweepJob{}.OutboxJob()
	require.Error(t, err)
}

func TestAPayloadNamingNothingIsRefusedBeforeItIsQueued(t *testing.T) {
	for name, job := range map[string]scanner.Job{
		"no version": {PackageID: uuid.New(), Namespace: "a", Name: "b", Semver: "1.0.0"},
		"no package": {VersionID: uuid.New(), Namespace: "a", Name: "b", Semver: "1.0.0"},
		"no subject": {VersionID: uuid.New(), PackageID: uuid.New()},
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			require.Error(t, job.Validate())
			_, err := job.OutboxJob()
			require.Error(t, err)
		})
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sortStrings(out)
	return out
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
