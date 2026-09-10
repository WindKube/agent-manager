package web_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
)

// TestCrossSitePostsAreRefused is the second line of defence behind
// SameSite=Lax: a state-changing request whose Sec-Fetch-Site or Origin names
// another site is refused before it reaches a handler.
func TestCrossSitePostsAreRefused(t *testing.T) {
	h := web.New(web.Deps{Catalog: fixture.New(), Log: zerolog.Nop()}, web.Options{}).Handler()

	for _, tc := range []struct {
		name   string
		header http.Header
		want   int
	}{
		{"cross-site by Sec-Fetch-Site", http.Header{"Sec-Fetch-Site": {"cross-site"}}, http.StatusForbidden},
		{"cross-site by Origin", http.Header{"Origin": {"https://evil.example"}}, http.StatusForbidden},
		{"same-origin by Sec-Fetch-Site", http.Header{"Sec-Fetch-Site": {"same-origin"}}, http.StatusSeeOther},
		{"same-origin by Origin", http.Header{"Origin": {"http://example.com"}}, http.StatusSeeOther},
		{"neither header at all", http.Header{}, http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", http.NoBody)
			req.Host = "example.com"
			req.Header = tc.header
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, tc.want, rec.Code)
		})
	}
}
