package hub_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrgDeletesTreatNoContentAsSuccess(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	require.NoError(t, client.DeleteMapping(t.Context(), "eng-platform"))
	require.NoError(t, client.DeleteCategory(t.Context(), "0193a000-0000-7000-8000-000000000001"))
}
