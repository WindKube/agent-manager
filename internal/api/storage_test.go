package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// The storage surface's role gate, with no database.
//
// Same construction as profiles_test.go and governance_test.go: the handler is
// handed Deps with a nil database and a nil bucket, so anything that reached the
// query would panic on one of those and answer 500. A 403 from these cases is
// therefore proof the refusal came first, and needs no container to demonstrate.
func storageHandler(t *testing.T, principal auth.Principal) http.Handler {
	t.Helper()
	return handler(t, api.Deps{Sessions: resolver{principal: principal}})
}

// The Storage screen is administration (US7): only catalog-admin, the role the
// hub's other administration screens use, unlike the profile and scanner
// surfaces which several roles share.
func TestReadingTheStorageReportIsRefusedToEveryRoleButCatalogAdmin(t *testing.T) {
	for _, tc := range []struct {
		name string
		role models.OrgRole
		want int
	}{
		{
			name: "a catalog admin reads the storage report",
			// Past the role check and into the query, which has no database or bucket.
			// The status is not the assertion here; getting past 403 is.
			role: models.OrgRoleCatalogAdmin,
			want: http.StatusInternalServerError,
		},
		{
			name: "a scanner reviewer may not: this is administration, not scanning",
			role: models.OrgRoleScannerReviewer,
			want: http.StatusForbidden,
		},
		{
			name: "a profile consumer may not",
			role: models.OrgRoleProfileConsumer,
			want: http.StatusForbidden,
		},
		{
			name: "a read-only identity may not",
			role: models.OrgRoleReadOnly,
			want: http.StatusForbidden,
		},
		{
			name: "an identity whose groups map to no role at all is refused, and not defaulted into one",
			role: "",
			want: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := storageHandler(t, auth.Principal{Subject: "sub-x", Role: tc.role})

			rec := request(t, h, http.MethodGet, "/v1/storage", "token", "")
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}
}

// FR-126/FR-117: the refusal names what would have worked, so a person with no
// mapped group can tell that from holding the wrong one.
func TestTheStorageRefusalNamesTheRoleThatWouldHaveWorked(t *testing.T) {
	h := storageHandler(t, auth.Principal{Subject: "sub-x", Role: models.OrgRoleReadOnly})

	rec := request(t, h, http.MethodGet, "/v1/storage", "token", "")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "catalog-admin")
}
