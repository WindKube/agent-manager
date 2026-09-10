package fetcher

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
	"agent-manager/internal/outbox"
	"agent-manager/internal/worker"
)

// The stubs below exist only so New can be reached with one dependency missing.
// None of them is called: New fails before it constructs anything.
type stubDB struct{ bun.IDB }

type stubBlob struct{ blob.Reader }

type stubFetch struct{ fetch.Client }

// ---------------------------------------------------------------------------
// T045 — the error taxonomy, and the separation it exists to hold
// ---------------------------------------------------------------------------

// The requirement is not "classify errors tidily". It is that a fetch failure is
// reported as a fetch failure and NEVER as a scan finding (US1 scenario 5), and
// this test is where the SSRF refusal, the missing ref, the absent subdirectory
// and the repo needing credentials are each nailed to a fetch reason.
func TestEveryFetchFailureIsAFetchErrorAndNeverAFinding(t *testing.T) {
	subject := "example/platform-toolkit@1.3.0"

	for _, tc := range []struct {
		name      string
		err       error
		want      Reason
		retryable bool
	}{
		{
			name: "an ssrf refusal is a fetch error, not a finding",
			err:  fmt.Errorf("resolve host: %w", fetch.ErrBlocked),
			want: ReasonRefused,
		},
		{
			name: "a ref the remote does not have",
			err:  fmt.Errorf("tarball for v9.9.9: %w", fetch.ErrRefNotFound),
			want: ReasonRefNotFound,
		},
		{
			name: "a subdirectory that is not in the tree is the same refusal",
			err:  fmt.Errorf("subdirectory plugins/absent: %w", fetch.ErrRefNotFound),
			want: ReasonRefNotFound,
		},
		{
			name: "a repository that needs a credential the hub does not hold",
			err:  fmt.Errorf("github answered 401: %w", fetch.ErrCredentialsRequired),
			want: ReasonCredentials,
		},
		{
			name: "a forge this build cannot fetch from",
			err:  fmt.Errorf("codeberg.org: %w", fetch.ErrUnsupportedHost),
			want: ReasonUnsupported,
		},
		{
			name: "a source kind with no registered source",
			err:  fmt.Errorf("kind oci: %w", fetch.ErrNoSource),
			want: ReasonUnsupported,
		},
		{
			name:      "any other refusal by the remote, which is worth retrying",
			err:       fmt.Errorf("github answered 502: %w", fetch.ErrRemote),
			want:      ReasonRemote,
			retryable: true,
		},
		{
			name: "an archive over one of the R3 caps",
			err:  fmt.Errorf("entry 4001: %w", bundle.ErrTooLarge),
			want: ReasonArchiveTooLarge,
		},
		{
			name: "an archive member refused outright",
			err:  fmt.Errorf("../../etc/passwd: %w", bundle.ErrRejectedMember),
			want: ReasonArchiveMemberRejected,
		},
		{
			name:      "the extraction wall clock, which a retry can still beat",
			err:       fmt.Errorf("after 60s: %w", bundle.ErrTimeout),
			want:      ReasonArchiveTimeout,
			retryable: true,
		},
		{
			name: "an archive that will not read at all",
			err:  fmt.Errorf("zip central directory: %w", bundle.ErrMalformed),
			want: ReasonArchiveMalformed,
		},
		{
			name: "a manifest that fails its published schema",
			err:  fmt.Errorf("plugin.json: %w", pkgspec.ErrManifestInvalid),
			want: ReasonManifestInvalid,
		},
		{
			name: "a tree with no manifest at its root",
			err:  fmt.Errorf("tree: %w", pkgspec.ErrNoManifest),
			want: ReasonManifestInvalid,
		},
		{
			name: "a manifest naming a component that is not on disk",
			err:  fmt.Errorf("components: %w", pkgspec.ErrTreeInvalid),
			want: ReasonManifestInvalid,
		},
		{
			name: "a manifest whose own version contradicts the registration",
			err:  fmt.Errorf("%w: manifest says 1.4.0", errVersionMismatch),
			want: ReasonVersionMismatch,
		},
		{
			name:      "the hub's own storage failing, which is the fall-through",
			err:       errors.New("write bundle.tar.zst: connection reset"),
			want:      ReasonStore,
			retryable: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := classify(subject, tc.err)
			require.Error(t, err)

			// Every one of them is a fetch error. This is the assertion that stands
			// between an unreadable source and a `finding` row about a package the
			// hub never read.
			require.ErrorIs(t, err, ErrFetch)
			require.ErrorIs(t, err, tc.err, "the cause must stay reachable for the operator")
			require.Equal(t, tc.want, ReasonOf(err))
			require.Contains(t, err.Error(), subject)

			var fetchErr *Error
			require.ErrorAs(t, err, &fetchErr)
			require.Equal(t, tc.retryable, fetchErr.Retryable())
		})
	}
}

// The negative control for the table above: not everything that reaches classify
// is the source's fault. A cancelled caller is a shutdown, and dressing it up as
// a fetch failure would blame a package for the operator restarting the role.
func TestACancelledCallerIsNotAFetchFailure(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		out := classify("example/x@1.0.0", err)
		require.Equal(t, err, out)
		require.NotErrorIs(t, out, ErrFetch)
		require.Empty(t, ReasonOf(out))
	}

	require.NoError(t, classify("example/x@1.0.0", nil))
	require.Empty(t, ReasonOf(nil))
	require.Empty(t, ReasonOf(errors.New("not a fetch error")))
}

// ---------------------------------------------------------------------------
// The publish transaction's inputs, which have to be right before the
// transaction is worth testing
// ---------------------------------------------------------------------------

func TestTheManifestKeywordsBecomeTheVersionsTagsExactlyOnce(t *testing.T) {
	// version_tag is keyed on (version_id, tag) and version.tags is the same set
	// denormalised, so a duplicate keyword would abort the publish transaction on
	// a primary-key violation.
	require.Equal(t, []string{"iac", "terraform"},
		versionTags([]string{"terraform", "iac", "terraform", ""}))
	require.Empty(t, versionTags(nil))
}

func TestTheTagsColumnIsRenderedAsAPostgresTextArray(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given []string
		want  string
	}{
		{"empty", nil, "{}"},
		{"one", []string{"terraform"}, `{"terraform"}`},
		{"several", []string{"a", "b"}, `{"a","b"}`},
		{"a quote and a backslash are escaped, not dropped", []string{`a"b\c`}, `{"a\"b\\c"}`},
		{"a comma inside a value stays inside its quotes", []string{"a,b"}, `{"a,b"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, pgTextArray(tc.given))
		})
	}
}

// ---------------------------------------------------------------------------
// The audit row (US1 scenario 6)
// ---------------------------------------------------------------------------

func TestTheAuditRowNamesTheStoredVersionAndNeverACredential(t *testing.T) {
	job := Job{
		VersionID: uuid.New(),
		PackageID: uuid.New(),
		Namespace: "example",
		Name:      "platform-toolkit",
		Semver:    "1.3.0",
		Source: JobSource{
			Kind: fetch.SourceGit,
			URL:  "https://deploy-key:s3cr3t@github.com/org/plugin",
			Ref:  "v1.3.0",
		},
	}
	pkg := &pkgspec.Package{
		Kind:       pkgspec.KindPlugin,
		Components: []pkgspec.Component{{Kind: pkgspec.ComponentSkill, Name: "a"}},
		Layout:     pkgspec.LayoutReport{Dropped: []string{".github/workflows/ci.yml", "README.md"}},
	}
	commit := blob.Commit{Bundle: blob.Object{Size: 4096}}

	text := storedText(job, pkg, commit)
	require.Contains(t, text, "stored example/platform-toolkit@1.3.0 (plugin)")
	require.Contains(t, text, "git https://redacted@github.com/org/plugin@v1.3.0")
	require.Contains(t, text, "digest sha256:"+
		"0000000000000000000000000000000000000000000000000000000000000000")
	require.Contains(t, text, "4096 bytes")
	require.Contains(t, text, "1 component")
	require.Contains(t, text, "2 paths dropped as outside the spec layout")
	require.NotContains(t, text, "s3cr3t", "an audit row is the copy that is kept forever")

	// The failure row is the same rule: the reason is named, the credential is not.
	require.NotContains(t, describeSource(job.Source), "s3cr3t")
	require.Equal(t, "upload platform-toolkit-1.3.0.zip",
		describeSource(JobSource{Kind: fetch.SourceUpload, ArchiveName: "platform-toolkit-1.3.0.zip"}))
}

func TestCredentialRedactionSurvivesAURLThatWillNotParse(t *testing.T) {
	// The failure mode of a parse-then-redact implementation is a secret in the
	// audit log forever, so this is a string operation and this is the test that
	// says why.
	for _, tc := range []struct{ given, want string }{
		{"https://user:pw@example.com/x", "https://redacted@example.com/x"},
		{"https://token@example.com", "https://redacted@example.com"},
		{"https://example.com/a@b", "https://example.com/a@b"},
		{"h ttp://user:pw@ex ample.com/%zz", "h ttp://redacted@ex ample.com/%zz"},
		{"://user:pw@example.com/x", "://redacted@example.com/x"},
	} {
		require.Equal(t, tc.want, redactCredentials(tc.given), tc.given)
	}
}

// ---------------------------------------------------------------------------
// The job payload, which is the contract between the api and this role
// ---------------------------------------------------------------------------

func TestAFetchJobIsRefusedBeforeItReachesTheQueue(t *testing.T) {
	valid := Job{
		VersionID: uuid.New(),
		PackageID: uuid.New(),
		Namespace: "example",
		Name:      "platform-toolkit",
		Semver:    "1.3.0",
		Source:    JobSource{Kind: fetch.SourceGit, URL: "https://github.com/org/plugin"},
	}
	require.NoError(t, valid.Validate())

	for _, tc := range []struct {
		name  string
		alter func(*Job)
		want  string
	}{
		{"no version row to fill in", func(j *Job) { j.VersionID = uuid.Nil }, "names no version"},
		{"no package", func(j *Job) { j.PackageID = uuid.Nil }, "names no package"},
		{"no identity", func(j *Job) { j.Semver = "" }, "names no publisher, name or semver"},
		{"an object key that would not be a key", func(j *Job) { j.Name = "../etc" }, "fetch job:"},
		{"an upload with no archive", func(j *Job) {
			j.Source = JobSource{Kind: fetch.SourceUpload}
		}, "carries no archive"},
		{"a remote source with no url", func(j *Job) {
			j.Source = JobSource{Kind: fetch.SourceArchiveURL}
		}, "carries no url"},
		{"a kind nothing can fetch", func(j *Job) {
			j.Source = JobSource{Kind: "oci", URL: "oci://ghcr.io/org/plugin"}
		}, `unknown source kind "oci"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := valid
			tc.alter(&job)
			err := job.Validate()
			require.ErrorContains(t, err, tc.want)

			// A payload that cannot be worked cannot be enqueued either: the same
			// check runs at enqueue time so a bad registration fails the REQUEST
			// rather than a job nobody is watching.
			_, err = job.OutboxJob()
			require.Error(t, err)
		})
	}
}

func TestTheFetchJobsIdempotencyKeyIsTheVersionsOwnIdentity(t *testing.T) {
	versionID := uuid.New()
	job := Job{
		VersionID: versionID,
		PackageID: uuid.New(),
		Namespace: "example",
		Name:      "platform-toolkit",
		Semver:    "1.3.0",
		Source:    JobSource{Kind: fetch.SourceGit, URL: "https://github.com/org/plugin"},
	}

	out, err := job.OutboxJob()
	require.NoError(t, err)
	require.Equal(t, outbox.KindFetch, out.Kind)
	require.Equal(t, versionID, out.SubjectID)
	require.Equal(t, "1.3.0", out.SubjectVersion)
	require.Equal(t, "fetch:"+versionID.String()+":1.3.0", out.IdempotencyKey())

	// The River job kind and the outbox job_kind are one string, so a worker
	// registers against a single value and the relay needs no mapping.
	require.Equal(t, string(outbox.KindFetch), job.Kind())

	require.Equal(t, blob.VersionRef{Namespace: "example", Name: "platform-toolkit", Semver: "1.3.0"},
		job.VersionRef())
	require.Equal(t, "skills/example/platform-toolkit/1.3.0/bundle.tar.zst", job.VersionRef().BundleKey())
}

func TestTheWorkerRefusesToStartWithoutTheHalfThatWritesBytes(t *testing.T) {
	// The Definition declares Blob: AccessReadWrite and the bootstrap hands out a
	// blob.Writer for that value alone. A nil BlobWrite here therefore means the
	// declaration and the bootstrap disagree, and defaulting past it would produce
	// a fetcher that fetches and stores nothing — silently.
	_, err := New(worker.Deps{
		DB:        stubDB{},
		BlobRead:  stubBlob{},
		BlobWrite: nil,
		Fetch:     stubFetch{},
	})
	require.ErrorContains(t, err, "no object-store writer")
}

// The fetch kind is enqueued onto outbox.QueueFetch; a Definition that registered
// river.QueueDefault instead would never see it delivered.
func TestTheDefinitionRegistersTheFetchQueue(t *testing.T) {
	def := Definition()

	require.Contains(t, def.Queues, outbox.QueueFetch)
}
