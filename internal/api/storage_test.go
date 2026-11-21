package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// storageHandler has no database or bucket, so a 403 proves the role check ran before the query.
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
			// Getting past 403 is the assertion; the 500 comes from the missing database.
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

func TestTheStorageRefusalNamesTheRoleThatWouldHaveWorked(t *testing.T) {
	h := storageHandler(t, auth.Principal{Subject: "sub-x", Role: models.OrgRoleReadOnly})

	rec := request(t, h, http.MethodGet, "/v1/storage", "token", "")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "catalog-admin")
}
