//go:build integration

package fetch

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The default configuration (no allowlist, real DNS and routing) lets an
// ordinary public host through. Run by task test:integration only.
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

// A public name answering with a private address is refused with nothing stubbed.
func TestRealLinkLocalMetadataIsRefused(t *testing.T) {
	c, err := New(Options{Timeout: 5 * time.Second})
	require.NoError(t, err)

	resp, err := c.Get(context.Background(), "http://169.254.169.254/latest/meta-data/")
	if resp != nil {
		resp.Body.Close()
	}
	require.ErrorIs(t, err, ErrBlocked)
}
