package scanner_test

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// TestAMountedPackThatFailsItsOwnFixturesCannotStartTheRole is the guard on the
// operator path this design is built around.
//
// Rules are data so an operator can tune one without a rebuild, and compose makes
// that real: it mounts internal/worker/scanner/rulepack at
// AGENT_MANAGER_RULEPACK_DIR, so the pack that RUNS is a directory on the host,
// not the one this binary embeds. The unit tests over rules.Builtin() therefore
// constrain what ships and say nothing at all about what runs — which is a gap
// that reads as covered, and was: a mounted rule with the pattern `.` started
// cleanly and flagged every package in the catalog.
//
// The negative fixture is the only artefact separating "this rule detects
// something" from "this rule detects anything", so the pack is refused unless
// every rule still trips one and spares the other.
func TestAMountedPackThatFailsItsOwnFixturesCannotStartTheRole(t *testing.T) {
	bucket, err := blob.Open(t.Context(), "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })

	deps := worker.Deps{
		DB:       bun.NewDB(nil, pgdialect.New()),
		BlobRead: bucket.Reader(),
		Log:      zerolog.New(io.Discard),
	}

	t.Run("the pack as it ships mounts and starts", func(t *testing.T) {
		// The control. Without it the three cases below could pass because the
		// mounted-pack path is broken for every pack, which would be a different bug
		// wearing this test's clothes.
		w, err := scanner.New(deps, scanner.Options{RulepackDir: mountedPack(t, nil)})
		require.NoError(t, err)
		require.NotEmpty(t, w.PackVersion())
	})

	t.Run("a rule widened until it matches everything", func(t *testing.T) {
		dir := mountedPack(t, func(t *testing.T, dir string) {
			t.Helper()
			widenRule(t, filepath.Join(dir, "rules", "SH-SEC-003.yaml"))
		})

		_, err := scanner.New(deps, scanner.Options{RulepackDir: dir})
		require.Error(t, err, "a rule matching everything started the scanner")
		require.ErrorContains(t, err, "fails its own fixtures")
		require.ErrorContains(t, err, "SH-SEC-003")
		require.ErrorContains(t, err, "matches more than it describes")
	})

	t.Run("a rule whose fixtures do not exist", func(t *testing.T) {
		// Load reads pack.yaml and rules/ and never resolves a fixture path, so this
		// one is invisible until something tries to run them.
		dir := mountedPack(t, func(t *testing.T, dir string) {
			t.Helper()
			path := filepath.Join(dir, "rules", "SH-SEC-003.yaml")
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			edited := strings.ReplaceAll(string(raw), "fixtures/SH-SEC-003/", "fixtures/nowhere/")
			require.NotEqual(t, string(raw), edited, "the fixture paths were not where this test expects")
			require.NoError(t, os.WriteFile(path, []byte(edited), 0o600))
		})

		_, err := scanner.New(deps, scanner.Options{RulepackDir: dir})
		require.Error(t, err, "a rule with no fixtures at all started the scanner")
		require.ErrorContains(t, err, "SH-SEC-003")
	})

	t.Run("a rule that detects nothing", func(t *testing.T) {
		dir := mountedPack(t, func(t *testing.T, dir string) {
			t.Helper()
			narrowRule(t, filepath.Join(dir, "rules", "SH-SEC-003.yaml"))
		})

		_, err := scanner.New(deps, scanner.Options{RulepackDir: dir})
		require.Error(t, err, "a rule that fires on nothing started the scanner")
		require.ErrorContains(t, err, "raised no finding")
	})
}

// mountedPack copies the shipped pack into a temp directory and applies one edit,
// so each case starts from the real thing rather than from a miniature pack that
// would prove nothing about the one in production.
func mountedPack(t *testing.T, edit func(t *testing.T, dir string)) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.CopyFS(dir, os.DirFS("rulepack")))
	if edit != nil {
		edit(t, dir)
	}
	return dir
}

func widenRule(t *testing.T, path string) {
	t.Helper()
	replacePattern(t, path, "'.'")
}

func narrowRule(t *testing.T, path string) {
	t.Helper()
	replacePattern(t, path, "'this string appears in no fixture anywhere'")
}

// replacePattern rewrites the rule's `pattern:` value, which sits alone on the
// line after its key.
func replacePattern(t *testing.T, path, pattern string) {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	lines := strings.Split(string(raw), "\n")
	found := false
	for i, line := range lines {
		if strings.TrimSpace(line) != "pattern:" {
			continue
		}
		require.Less(t, i+1, len(lines), "`pattern:` is the last line of %s", path)
		lines[i+1] = "    " + pattern
		found = true
		break
	}
	require.Truef(t, found, "%s has no `pattern:` on a line of its own; this test's edit no longer applies", path)

	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600))
}
