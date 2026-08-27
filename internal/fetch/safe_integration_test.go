//go:build integration

package fetch

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// R10 case 6 against the real internet. The hermetic variant in safe_test.go
// proves the control is not vacuous by allowlisting a loopback address; this one
// proves the default configuration — no allowlist, real DNS, real routing — lets
// an ordinary public host through.
//
// task test:integration runs it. go test ./... does not.
func TestLegitimatePublicHostIsAllowed(t *testing.T) {
	c, err := New(Options{Timeout: 20 * time.Second})
	require.NoError(t, err)

	for _, u := range []string{
		"https://example.com/",
		"https://raw.githubusercontent.com/anthropics/anthropic-sdk-go/main/README.md",
	} {
		t.Run(u, func(t *testing.T) {
			resp, err := c.Get(context.Background(), u)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Less(t, resp.StatusCode, http.StatusBadRequest)
		})
	}
}

// The other half of the real-internet check: a public name that answers with a
// private address must still be refused when nothing is stubbed.
func TestRealLinkLocalMetadataIsRefused(t *testing.T) {
	c, err := New(Options{Timeout: 5 * time.Second})
	require.NoError(t, err)

	resp, err := c.Get(context.Background(), "http://169.254.169.254/latest/meta-data/")
	if resp != nil {
		resp.Body.Close()
	}
	require.ErrorIs(t, err, ErrBlocked)
}
