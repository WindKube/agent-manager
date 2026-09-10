//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// The registration endpoint over the real database. What is asserted here is what
// the container-free tests cannot reach: that the transaction commits, that the
// unique index behind FR-007 is what refuses the second attempt, and that the
// refusal arrives as a 409 rather than as a 500 with a constraint name in it.

func TestRegisteringAnUploadReturns202AndThenRefusesTheSameVersionWith409(t *testing.T) {
	handler := liveHandler(t)

	// The vocabulary a catalog admin curated (FR-049). It is seeded here rather
	// than in the suite's fixtures because only this file needs one.
	_, err := pool.Exec(t.Context(),
		`insert into category (id, name, slug) values (gen_random_uuid(), 'Infrastructure', 'infrastructure')
		  on conflict (slug) do nothing`)
	require.NoError(t, err)

	// `uploads`, not `example`: the catalog fixtures this branch adds already
	// publish example/platform-toolkit@1.3.0, and `unique (namespace, name)`
	// scopes the rendered id to the namespace rather than to a publisher row, so
	// the two cannot both own that id any more. That is the constraint working —
	// this file takes its own namespace instead of the constraint being relaxed.
	// The object key and the rendered id are still built from the first segment
	// alone, which is what the assertions below spell out.
	contentType, body := upload(t, zipOf(t, scenario2Files()), map[string]string{
		"source":     "upload",
		"publisher":  "uploads/platform",
		"category":   "Infrastructure",
		"visibility": "organisation",
	})

	rec := postForm(t, handler, "/v1/packages", kw.token, contentType, body)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var registered contract.PackageRegistered
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &registered))
	require.Equal(t, "platform-toolkit", registered.Name, "the manifest is the authority on the name")
	require.Equal(t, "1.3.0", registered.Version, "and on the version, when it carries one")
	require.Equal(t, "plugin", registered.Kind, "and on the kind, which is which manifest sits at the root")
	require.Equal(t, "skills/uploads/platform-toolkit/1.3.0/bundle.tar.zst", registered.ObjectKey)
	require.Equal(t, "scanning", registered.Verdict)
	require.False(t, registered.Visible, "FR-008: nothing is readable until the fetcher has committed")
	require.NotEmpty(t, registered.VersionID)

	// The preview rides the response, so the modal can show what was accepted
	// without a second call.
	require.NotNil(t, registered.Preview)
	require.True(t, registered.Preview.Valid)
	require.Contains(t, registered.Preview.Dropped, "README.md")

	// The row, the job and the audit row are all there — one transaction.
	// The category resolved to the curated row rather than being created.
	var categoryID *string
	require.NoError(t, pool.QueryRow(t.Context(),
		`select p.category_id::text from package p
		   join publisher pub on pub.id = p.publisher_id
		  where pub.slug = 'uploads/platform' and p.name = 'platform-toolkit'`).Scan(&categoryID))
	require.NotNil(t, categoryID)

	var versions, jobs, audits int
	require.NoError(t, pool.QueryRow(t.Context(),
		`select
		   (select count(*) from version where id = $1),
		   (select count(*) from outbox where job_kind = 'fetch' and idempotency_key = 'fetch:' || $1 || ':1.3.0'),
		   (select count(*) from audit_event where kind = 'fetch' and actor_kind = 'identity'
		      and text like 'registered uploads/platform-toolkit@1.3.0 from upload%')`,
		registered.VersionID).Scan(&versions, &jobs, &audits))
	require.Equal(t, 1, versions)
	require.Equal(t, 1, jobs)
	require.Equal(t, 1, audits)

	// The same publisher/name@version again, with no fetcher running in this
	// suite to complete the first attempt: FR-007 still refuses it, and the
	// refusal says the version is unresolved rather than falsely claiming it
	// already published — nothing here ran `worker fetcher`, so it has not.
	contentType, body = upload(t, zipOf(t, scenario2Files()), map[string]string{
		"source": "upload", "publisher": "uploads/platform",
	})
	rec = postForm(t, handler, "/v1/packages", kw.token, contentType, body)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	var problem contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problem))
	require.Contains(t, problem.Detail, "uploads/platform-toolkit@1.3.0")
	require.Contains(t, problem.Detail, "fetch has not finished")
	require.NotContains(t, problem.Detail, "already published",
		"nothing has published yet — the fetcher never ran in this suite")
	require.NotContains(t, problem.Detail, "version_package_semver",
		"the constraint name is an implementation detail, not a message for a publisher")

	// And nothing was added by the refused attempt.
	require.NoError(t, pool.QueryRow(t.Context(),
		`select count(*) from outbox where job_kind = 'fetch' and idempotency_key = 'fetch:' || $1 || ':1.3.0'`,
		registered.VersionID).Scan(&jobs))
	require.Equal(t, 1, jobs)
}

// seedPublishedVersion writes a package and a committed version directly,
// bypassing RegisterPackage and worker fetcher both, so a re-registration
// attempt exercises FR-007's refusal against a version already sitting in
// the state named rather than one this test pushed through the real
// pipeline to reach. It returns the publisher slug a colliding registration
// must submit.
func seedPublishedVersion(t *testing.T, namespace, name, semver string, verdict models.Verdict) string {
	t.Helper()
	ctx := t.Context()

	slug := namespace + "/team"
	publisher := &models.Publisher{ID: models.NewID(), Slug: slug, DisplayName: slug}
	_, err := db.NewInsert().Model(publisher).Exec(ctx)
	require.NoError(t, err)

	pkg := &models.Package{
		ID: models.NewID(), PublisherID: publisher.ID, Namespace: namespace, Name: name,
		Kind: models.PackageKindSkill, Visibility: models.PackageVisibilityOrganisation,
	}
	_, err = db.NewInsert().Model(pkg).Exec(ctx)
	require.NoError(t, err)

	version := &models.Version{
		ID: models.NewID(), PackageID: pkg.ID, Semver: semver, SemverSort: semver,
		ObjectKey: "skills/" + namespace + "/" + name + "/" + semver + "/bundle.tar.zst",
		Digest:    bundleSHA, Manifest: json.RawMessage(`{}`), Tags: []string{},
		DistTag: models.DistTagLatest, Verdict: verdict, Visible: true,
	}
	_, err = db.NewInsert().Model(version).Exec(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		for _, statement := range []string{
			`update package set latest_version_id = null where publisher_id = ?`,
			`delete from version where package_id in (select id from package where publisher_id = ?)`,
			`delete from package where publisher_id = ?`,
			`delete from publisher where id = ?`,
		} {
			_, cleanupErr := db.ExecContext(context.Background(), statement, publisher.ID)
			require.NoError(t, cleanupErr)
		}
	})
	return slug
}

// reRegister submits a git-source registration naming an existing publisher,
// package and version directly, so the test controls exactly which row it
// collides with without building an archive.
func reRegister(t *testing.T, handler http.Handler, publisher, name, version string) *contract.Error {
	t.Helper()

	contentType, body := upload(t, nil, map[string]string{
		"source": "git", "url": "https://github.com/example/" + name,
		"publisher": publisher, "name": name, "version": version,
	})
	rec := postForm(t, handler, "/v1/packages", kw.token, contentType, body)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	var problem contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problem))
	return &problem
}

func TestReRegisteringAPublishedVersionReturns409NamingItPublished(t *testing.T) {
	handler := liveHandler(t)
	slug := seedPublishedVersion(t, "conflict-clean", "widget", "1.0.0", models.VerdictClean)

	problem := reRegister(t, handler, slug, "widget", "1.0.0")
	require.Contains(t, problem.Detail, "conflict-clean/widget@1.0.0")
	require.Contains(t, problem.Detail, "already published")
	require.Contains(t, problem.Detail, "immutable")
}

func TestReRegisteringAFlaggedVersionReturns409NamingTheVerdict(t *testing.T) {
	handler := liveHandler(t)
	slug := seedPublishedVersion(t, "conflict-flagged", "widget", "1.0.0", models.VerdictFlagged)

	problem := reRegister(t, handler, slug, "widget", "1.0.0")
	require.Contains(t, problem.Detail, "conflict-flagged/widget@1.0.0")
	require.Contains(t, problem.Detail, "flagged")
	require.Contains(t, problem.Detail, "immutable")
}

func TestReRegisteringARejectedVersionReturns409NamingTheVerdict(t *testing.T) {
	handler := liveHandler(t)
	slug := seedPublishedVersion(t, "conflict-rejected", "widget", "1.0.0", models.VerdictRejected)

	problem := reRegister(t, handler, slug, "widget", "1.0.0")
	require.Contains(t, problem.Detail, "conflict-rejected/widget@1.0.0")
	require.Contains(t, problem.Detail, "rejected")
	require.Contains(t, problem.Detail, "immutable")
}

// A concurrent pair of identical registrations still has to lose the race to
// the unique index rather than to a SELECT, so this drives the collision
// through the insert-time catch instead of the pre-flight one above, and
// asserts what actually matters: never a 500, and never the constraint name.
func TestConcurrentDuplicateRegistrationsNeverLeakARawConstraintViolation(t *testing.T) {
	handler := liveHandler(t)

	const attempts = 12
	codes := make([]int, attempts)
	bodies := make([]string, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := range attempts {
		go func(i int) {
			defer wg.Done()
			contentType, body := upload(t, zipOf(t, scenario2Files()), map[string]string{
				"source": "upload", "publisher": "conflict-race/team",
			})
			rec := postForm(t, handler, "/v1/packages", kw.token, contentType, body)
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}(i)
	}
	wg.Wait()

	var accepted, conflicted int
	for i, code := range codes {
		switch code {
		case http.StatusAccepted:
			accepted++
		case http.StatusConflict:
			conflicted++
			require.NotContains(t, bodies[i], "version_package_semver")
		default:
			t.Fatalf("attempt %d returned %d, want 202 or 409: %s", i, code, bodies[i])
		}
	}
	require.Equal(t, 1, accepted, "exactly one of the identical concurrent registrations wins")
	require.Equal(t, attempts-1, conflicted, "every loser is refused with FR-007's 409, not a raw error")
}

// FR-049: the vocabulary is curated by a catalog admin, so a registration that
// names a category nobody created is refused rather than creating one.
func TestRegisteringAgainstAnUncuratedCategoryIsRefused(t *testing.T) {
	handler := liveHandler(t)

	contentType, body := upload(t, zipOf(t, scenario2Files()), map[string]string{
		"source": "upload", "publisher": "uncurated/team", "category": "Made Up On The Spot",
	})
	rec := postForm(t, handler, "/v1/packages", kw.token, contentType, body)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "curated by a catalog admin")

	var categories int
	require.NoError(t, pool.QueryRow(t.Context(),
		`select count(*) from category where name = 'Made Up On The Spot'`).Scan(&categories))
	require.Zero(t, categories)
}
