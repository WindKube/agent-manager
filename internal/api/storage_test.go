package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// storageHandler is handed Deps with a nil database and a nil bucket, so
// anything that reached the query would panic and answer 500 — a 403 is proof
// the role check ran first.
func storageHandler(t *testing.T, principal auth.Principal) http.Handler {
	t.Helper()
	return handler(t, api.Deps{Sessions: resolver{principal: principal}})
}

func TestReadingTheStorageReportIsRefusedToEveryRoleButCatalogAdmin(t *testing.T) {
	for _, tc := range []struct {
		name string
		role models.OrgRole
		want int
	}{
		{
			// Past the role check and into the query, which has no database or
			// bucket; getting past 403 is the assertion, not the 500.
			name: "a catalog admin reads the storage report",
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

// The refusal names what would have worked, so a person with no mapped group
// can tell that from holding the wrong one.
func TestTheStorageRefusalNamesTheRoleThatWouldHaveWorked(t *testing.T) {
	h := storageHandler(t, auth.Principal{Subject: "sub-x", Role: models.OrgRoleReadOnly})

	rec := request(t, h, http.MethodGet, "/v1/storage", "token", "")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "catalog-admin")
}
