package fetcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
	"agent-manager/internal/outbox"
	"agent-manager/internal/signing"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker"
)

// Stubs so New can be reached with one dependency missing; none is called.
type stubDB struct{ bun.IDB }

type stubBlob struct{ blob.Reader }

type stubFetch struct{ fetch.Client }

// A fetch failure must be reported as a fetch failure, never as a scan finding.
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
			name: "a tag that names a different commit from the one already recorded",
			err: &TagMovedError{Repo: "https://github.com/acme/skills", Tag: "v1.2.0", Version: "acme/pdf@1.2.0",
				From: strings.Repeat("a", 40), To: strings.Repeat("b", 40)},
			want: ReasonTagMoved,
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

func TestAMovedTagNamesBothCommitsShort(t *testing.T) {
	err := &TagMovedError{Repo: "https://github.com/acme/skills", Tag: "v1.2.0", Version: "acme/pdf@1.2.0",
		From: "abc1234" + strings.Repeat("0", 33), To: "def5678" + strings.Repeat("0", 33)}
	require.Equal(t, "tag v1.2.0 of https://github.com/acme/skills moved from abc1234… to def5678…: "+
		"acme/pdf@1.2.0 was stored from the first, and versions are immutable", err.Error())
	outcome, ok := outcomeOf(ReasonTagMoved)
	require.True(t, ok)
	require.Equal(t, models.FetchOutcomeInvalidRef, outcome)
}

// A cancelled caller is a shutdown, not the package's fault.
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

func TestTheManifestKeywordsBecomeTheVersionsTagsExactlyOnce(t *testing.T) {
	// A duplicate would abort the publish on version_tag's primary key.
	require.Equal(t, []string{"iac", "terraform"},
		VersionTags([]string{"terraform", "iac", "terraform", ""}))
	require.Empty(t, VersionTags(nil))

	require.Equal(t, []string{"aws"}, VersionTags([]string{"AWS", "aws", "Aws"}))
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

	text := storedText(job, pkg, commit, signing.Result{Status: signing.StatusUnsigned})
	require.Contains(t, text, "stored example/platform-toolkit@1.3.0 (plugin)")
	require.Contains(t, text, ", unsigned")
	require.Contains(t, text, "git https://redacted@github.com/org/plugin@v1.3.0")
	require.Contains(t, text, "digest sha256:"+
		"0000000000000000000000000000000000000000000000000000000000000000")
	require.Contains(t, text, "4096 bytes")
	require.Contains(t, text, "1 component")
	require.Contains(t, text, "2 paths dropped as outside the spec layout")
	require.NotContains(t, text, "s3cr3t", "an audit row is the copy that is kept forever")

	require.NotContains(t, describeSource(job.Source), "s3cr3t")

	require.Contains(t, storedText(job, pkg, commit, signing.Result{
		Status: signing.StatusVerified, Issuer: "https://issuer.example", Identity: "release@example.com",
	}), "signature verified: release@example.com via https://issuer.example")
	require.Contains(t, storedText(job, pkg, commit, signing.Result{
		Status: signing.StatusInvalid, Reason: "digest mismatch\nmore",
	}), "signature invalid: digest mismatch")
	require.Equal(t, "upload platform-toolkit-1.3.0.zip",
		describeSource(JobSource{Kind: fetch.SourceUpload, ArchiveName: "platform-toolkit-1.3.0.zip"}))
}

func TestCredentialRedactionSurvivesAURLThatWillNotParse(t *testing.T) {
	// Unparseable URLs must still be redacted, or a secret lands in the audit log.
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

			// The same check runs at enqueue time, so a bad registration fails the request.
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

	require.Equal(t, string(outbox.KindFetch), job.Kind())

	require.Equal(t, blob.VersionRef{Namespace: "example", Name: "platform-toolkit", Semver: "1.3.0"},
		job.VersionRef())
	require.Equal(t, "skills/example/platform-toolkit/1.3.0/bundle.tar.zst", job.VersionRef().BundleKey())
}

func TestTheWorkerRefusesToStartWithoutTheHalfThatWritesBytes(t *testing.T) {
	// A nil BlobWrite means the Definition and bootstrap disagree; defaulting past
	// it would silently store nothing.
	_, err := New(worker.Deps{
		DB:        stubDB{},
		BlobRead:  stubBlob{},
		BlobWrite: nil,
		Fetch:     stubFetch{},
	})
	require.ErrorContains(t, err, "no object-store writer")

	_, err = New(worker.Deps{
		DB:        stubDB{},
		BlobRead:  stubBlob{},
		BlobWrite: stubWriter{},
		Fetch:     stubFetch{},
	})
	require.ErrorContains(t, err, "no signature verifier")
}

type stubWriter struct{ blob.Writer }

// A Definition registering river.QueueDefault would never receive fetch jobs.
func TestTheDefinitionRegistersTheFetchQueue(t *testing.T) {
	def := Definition()

	require.Contains(t, def.Queues, outbox.QueueFetch)
}
