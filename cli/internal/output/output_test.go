package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFormat(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  Format
		valid bool
	}{
		{"human is accepted", "human", FormatHuman, true},
		{"json is accepted", "json", FormatJSON, true},
		{"an unknown value is rejected", "yaml", "", false},
		{"the empty value is rejected", "", "", false},
		{"the check is case sensitive", "JSON", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFormat(tc.in)
			if !tc.valid {
				require.Error(t, err)
				// Assert the specific failure: the message must name what was
				// accepted, or it does not help the person who typed it.
				require.ErrorContains(t, err, "human")
				require.ErrorContains(t, err, "json")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// results is every Result type in this package. A verb whose result type is
// missing here loses its round-trip coverage silently, so the count is asserted.
func results() []Result {
	return []Result{
		LoginResult{Hub: "https://hub.example", Identity: "alice@example.com", Store: "keychain"},
		LogoutResult{Hub: "https://hub.example", Store: "keychain", Removed: true},
		SyncResult{Hub: "https://hub.example", Profiles: []string{"laptop"}},
		StatusResult{Hub: "https://hub.example", Identity: "alice@example.com"},
		VersionResult{Version: "1.2.3", Commit: "abc", Date: "2026-08-28"},
	}
}

func TestEveryResultRendersInBothFormats(t *testing.T) {
	require.Len(t, results(), 5, "one result type per verb, plus version")

	seenKinds := map[string]bool{}
	for _, r := range results() {
		t.Run(r.Kind()+" human is non-empty", func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, RendererFor(FormatHuman).Render(&buf, r))
			require.NotEmpty(t, buf.String())
		})

		t.Run(r.Kind()+" json is one document tagged with the verb", func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, RendererFor(FormatJSON).Render(&buf, r))

			var doc struct {
				Kind   string          `json:"kind"`
				Result json.RawMessage `json:"result"`
			}
			dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
			require.NoError(t, dec.Decode(&doc))
			require.False(t, dec.More(), "exactly one document per run")
			require.Equal(t, r.Kind(), doc.Kind)
			require.NotEmpty(t, doc.Result)
		})

		require.False(t, seenKinds[r.Kind()], "two result types claim kind %q", r.Kind())
		seenKinds[r.Kind()] = true
	}
}

func TestLoginResultHasNowhereToPutAToken(t *testing.T) {
	// FR-007: no token reaches any output stream. The structural version of
	// that assertion — the rendered document must not gain a token-shaped
	// field — is cheaper to hold than a grep over every message.
	var buf bytes.Buffer
	secret := "am_tok_this-must-never-appear"
	require.NoError(t, RendererFor(FormatJSON).Render(&buf, LoginResult{
		Hub:      "https://hub.example",
		Identity: secret[:5] + "@example.com",
		Store:    "keychain",
	}))

	var fields map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &fields))
	result, ok := fields["result"].(map[string]any)
	require.True(t, ok)
	for _, forbidden := range []string{"token", "access_token", "secret", "credential"} {
		require.NotContains(t, result, forbidden)
	}
}

func TestSyncResultChangedSelectsTheExitCode(t *testing.T) {
	one := []Change{{Package: "acme/lint", To: "1.0.0", Target: "claude-code"}}

	cases := []struct {
		name string
		in   SyncResult
		want bool
	}{
		{"an empty plan changed nothing", SyncResult{}, false},
		{"an add is a change", SyncResult{Added: one}, true},
		{"an upgrade is a change", SyncResult{Upgraded: one}, true},
		{"a downgrade is a change", SyncResult{Downgrade: one}, true},
		{"a removal is a change", SyncResult{Removed: one}, true},
		{"a dry run never changes anything", SyncResult{DryRun: true, Added: one}, false},
		{"a skip alone is not a change", SyncResult{Skipped: []Skip{{Package: "acme/x", Reason: "yanked"}}}, false},
		{"a conflict alone is not a change", SyncResult{Conflicts: one}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.in.Changed())
		})
	}
}

func TestStreamsKeepResultsAndDiagnosticsApart(t *testing.T) {
	t.Run("json stays parseable after warnings", func(t *testing.T) {
		var result, diag bytes.Buffer
		s := NewStreams(FormatJSON, &result, &diag)

		s.Warnf("credential store fell back to a file: %s", "no keychain")
		require.NoError(t, s.Emit(SyncResult{Hub: "https://hub.example"}))
		s.Errorf("sync report refused by the hub: %d", 503)

		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(result.Bytes()))
		require.NoError(t, dec.Decode(&doc), "warnings must not be in the result stream")
		require.False(t, dec.More())
		require.Equal(t, "sync", doc["kind"])

		require.Contains(t, diag.String(), "warning: credential store fell back")
		require.Contains(t, diag.String(), "error: sync report refused by the hub: 503")
	})

	t.Run("verbose output is dropped rather than buffered", func(t *testing.T) {
		var result, diag bytes.Buffer
		s := NewStreams(FormatHuman, &result, &diag)
		s.Debugf("resolving %s", "head")
		require.Empty(t, diag.String())

		s.SetVerbose(true)
		s.Debugf("resolving %s", "head")
		require.Contains(t, diag.String(), "resolving head")
		require.Empty(t, result.String())
	})

	t.Run("a nil diagnostic stream is not a crash", func(t *testing.T) {
		s := NewStreams(FormatHuman, io.Discard, nil)
		s.Warnf("no stderr here")
		s.SetVerbose(true)
		s.Debugf("nor here")
	})

	t.Run("the format is reported back", func(t *testing.T) {
		require.Equal(t, FormatJSON, NewStreams(FormatJSON, io.Discard, io.Discard).Format())
	})
}

func TestRenderersRefuseNothingGracefully(t *testing.T) {
	for _, f := range Formats() {
		var buf bytes.Buffer
		require.NoError(t, RendererFor(f).Render(&buf, nil))
		require.Empty(t, buf.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("stream closed") }

func TestRenderersPropagateAWriteFailure(t *testing.T) {
	// A renderer that swallows a write error reports success for output that
	// never arrived, which is the failure mode a script cannot detect.
	for _, f := range Formats() {
		err := RendererFor(f).Render(failingWriter{}, StatusResult{Hub: "https://hub.example"})
		require.ErrorContains(t, err, "stream closed")
	}
}
