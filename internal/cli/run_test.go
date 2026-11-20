package cli

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWebCookieKey(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)

	got, err := webCookieKey("")
	require.NoError(t, err)
	require.Nil(t, got, "unset must fall back to a per-process key")

	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		got, err = webCookieKey(" " + enc.EncodeToString(key) + "\n")
		require.NoError(t, err)
		require.Equal(t, key, got)
	}

	_, err = webCookieKey(base64.StdEncoding.EncodeToString(key[:31]))
	require.ErrorContains(t, err, "at least 32")

	_, err = webCookieKey("not base64 at all!")
	require.ErrorContains(t, err, "not base64")
}
