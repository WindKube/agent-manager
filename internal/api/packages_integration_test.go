//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
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

	contentType, body := upload(t, zipOf(t, scenario2Files()), map[string]string{
		"source":     "upload",
		"publisher":  "example",
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
	require.Equal(t, "skills/example/platform-toolkit/1.3.0/bundle.tar.zst", registered.ObjectKey)
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
		  where pub.slug = 'example' and p.name = 'platform-toolkit'`).Scan(&categoryID))
	require.NotNil(t, categoryID)

	var versions, jobs, audits int
	require.NoError(t, pool.QueryRow(t.Context(),
		`select
		   (select count(*) from version where id = $1),
		   (select count(*) from outbox where job_kind = 'fetch' and idempotency_key = 'fetch:' || $1 || ':1.3.0'),
		   (select count(*) from audit_event where kind = 'fetch' and actor_kind = 'identity'
		      and text like 'registered example/platform-toolkit@1.3.0 from upload%')`,
		registered.VersionID).Scan(&versions, &jobs, &audits))
	require.Equal(t, 1, versions)
	require.Equal(t, 1, jobs)
	require.Equal(t, 1, audits)

	// The same publisher/name@version again. FR-007: refused, and the refusal is
	// the requirement rather than a duplicate-key leak.
	contentType, body = upload(t, zipOf(t, scenario2Files()), map[string]string{
		"source": "upload", "publisher": "example",
	})
	rec = postForm(t, handler, "/v1/packages", kw.token, contentType, body)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	var problem contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problem))
	require.Contains(t, problem.Detail, "example/platform-toolkit@1.3.0")
	require.Contains(t, problem.Detail, "immutable")
	require.NotContains(t, problem.Detail, "version_package_semver",
		"the constraint name is an implementation detail, not a message for a publisher")

	// And nothing was added by the refused attempt.
	require.NoError(t, pool.QueryRow(t.Context(),
		`select count(*) from outbox where job_kind = 'fetch' and idempotency_key = 'fetch:' || $1 || ':1.3.0'`,
		registered.VersionID).Scan(&jobs))
	require.Equal(t, 1, jobs)
}

// FR-049: the vocabulary is curated by a catalog admin, so a registration that
// names a category nobody created is refused rather than creating one.
func TestRegisteringAgainstAnUncuratedCategoryIsRefused(t *testing.T) {
	handler := liveHandler(t)

	contentType, body := upload(t, zipOf(t, scenario2Files()), map[string]string{
		"source": "upload", "publisher": "curated", "category": "Made Up On The Spot",
	})
	rec := postForm(t, handler, "/v1/packages", kw.token, contentType, body)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "curated by a catalog admin")

	var categories int
	require.NoError(t, pool.QueryRow(t.Context(),
		`select count(*) from category where name = 'Made Up On The Spot'`).Scan(&categories))
	require.Zero(t, categories)
}
