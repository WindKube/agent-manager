package repourl

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestParseAcceptsTheShapesPeoplePaste(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Repository
	}{
		{
			name: "bare owner/repo assumes the default host",
			in:   "owner/repo",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "bare host/owner/repo keeps the host it names",
			in:   "gitlab.com/group/project",
			want: Repository{Host: "gitlab.com", Owner: "group", Repo: "project"},
		},
		{
			name: "https url",
			in:   "https://github.com/owner/repo",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "http url",
			in:   "http://git.internal.example/owner/repo",
			want: Repository{Host: "git.internal.example", Owner: "owner", Repo: "repo"},
		},
		{
			name: "git suffix is dropped",
			in:   "https://github.com/owner/repo.git",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "scp-style with user",
			in:   "git@github.com:owner/repo.git",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "scp-style without user",
			in:   "github.com:owner/repo",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "ssh url",
			in:   "ssh://git@github.com/owner/repo",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "ssh url on a non-default port keeps the port in the host",
			in:   "ssh://git@git.example.com:2222/owner/repo.git",
			want: Repository{Host: "git.example.com:2222", Owner: "owner", Repo: "repo"},
		},
		{
			name: "git scheme",
			in:   "git://github.com/owner/repo.git",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "www host collapses to the bare host",
			in:   "https://www.github.com/owner/repo",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "ref in the query",
			in:   "https://github.com/owner/repo?ref=v1.2.3",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo", Ref: "v1.2.3"},
		},
		{
			name: "unrelated query parameters are ignored",
			in:   "https://github.com/owner/repo?tab=readme-ov-file&utm_source=slack",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "fragment is dropped",
			in:   "https://github.com/owner/repo#readme",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "tree path carries ref and subdirectory",
			in:   "https://github.com/owner/repo/tree/v1.3.0/plugins/platform-toolkit",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "v1.3.0", Subdir: "plugins/platform-toolkit",
			},
		},
		{
			name: "tree path with a ref and no subdirectory",
			in:   "https://github.com/owner/repo/tree/main",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo", Ref: "main"},
		},
		{
			name: "blob path is read like a tree path",
			in:   "https://github.com/owner/repo/blob/abc123/skills/deploy",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "abc123", Subdir: "skills/deploy",
			},
		},
		{
			name: "gitlab dash separator",
			in:   "https://gitlab.com/group/project/-/tree/v2/plugins/toolkit",
			want: Repository{
				Host: "gitlab.com", Owner: "group", Repo: "project",
				Ref: "v2", Subdir: "plugins/toolkit",
			},
		},
		{
			name: "a slashed ref takes only its first segment, the rest is the subdirectory",
			in:   "https://github.com/owner/repo/tree/release/1.2",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "release", Subdir: "1.2",
			},
		},
		{
			name: "trailing and doubled slashes are separators, not segments",
			in:   "https://github.com//owner/repo///",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "surrounding whitespace is trimmed",
			in:   "  https://github.com/owner/repo  ",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "mixed case host is lowercased",
			in:   "https://GitHub.COM/owner/repo",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "uppercase owner and repo are lowercased so identity cannot fork",
			in:   "https://github.com/Owner/Repo.GIT",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "uppercase owner and repo keep subdirectory and ref case",
			in:   "https://github.com/AirHelp/Agent-Manager/tree/Release-1.0/Plugins/Toolkit",
			want: Repository{
				Host: "github.com", Owner: "airhelp", Repo: "agent-manager",
				Ref: "Release-1.0", Subdir: "Plugins/Toolkit",
			},
		},
		{
			name: "a dot-leading repository name is a real repository",
			in:   "https://github.com/owner/.github",
			want: Repository{Host: "github.com", Owner: "owner", Repo: ".github"},
		},
		{
			name: "self-hosted host with a port",
			in:   "https://git.example.com:8443/owner/repo.git",
			want: Repository{Host: "git.example.com:8443", Owner: "owner", Repo: "repo"},
		},
		{
			name: "a username without a password is fine",
			in:   "https://git@github.com/owner/repo",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo"},
		},
		{
			name: "repeated but identical ref parameters are not a contradiction",
			in:   "https://github.com/owner/repo?ref=v1.2.3&ref=v1.2.3",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo", Ref: "v1.2.3"},
		},
		{
			name: "a ref in the path agreeing with the query is not a contradiction",
			in:   "https://github.com/owner/repo/tree/v1.2.3?ref=v1.2.3",
			want: Repository{Host: "github.com", Owner: "owner", Repo: "repo", Ref: "v1.2.3"},
		},
		{
			name: "percent-encoded bytes that are not control characters still decode",
			in:   "https://github.com/owner/repo/tree/main/plug%69ns/tool%6Bit",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "main", Subdir: "plugins/toolkit",
			},
		},
		{
			// An address literal is a legal authority, and this package makes no
			// address-level decision: whether 127.0.0.1 is reachable, private or a
			// rebinding trick is internal/fetch's call (FR-002). Pinned so nobody
			// mistakes the bracketed-IPv6 rejection below for SSRF defence.
			name: "an ipv4 literal host parses; the address decision belongs to fetch",
			in:   "https://127.0.0.1:8443/owner/repo",
			want: Repository{Host: "127.0.0.1:8443", Owner: "owner", Repo: "repo"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantMsg string
	}{
		{name: "empty input", in: "", wantMsg: "reference is empty"},
		{name: "whitespace only", in: "   \t ", wantMsg: "reference is empty"},
		{name: "one path segment", in: "owner", wantMsg: "names no owner and repository"},
		{name: "url with one path segment", in: "https://github.com/owner", wantMsg: "names no owner and repository"},
		{name: "no path at all", in: "https://github.com", wantMsg: "names no owner and repository"},
		{name: "file scheme", in: "file:///etc/passwd", wantMsg: `scheme "file" is not one of`},
		{name: "file scheme without slashes", in: "file:etc/passwd", wantMsg: `scheme "file" is not one of`},
		{name: "javascript scheme", in: "javascript:alert(1)", wantMsg: `scheme "javascript" is not one of`},
		{name: "ftp scheme", in: "ftp://github.com/owner/repo", wantMsg: `scheme "ftp" is not one of`},
		{name: "data scheme", in: "data:text/plain,owner/repo", wantMsg: `scheme "data" is not one of`},
		{
			name:    "owner is a traversal component",
			in:      "https://github.com/../repo",
			wantMsg: `owner ".." contains a path traversal component`,
		},
		{
			name:    "repository is a traversal component",
			in:      "https://github.com/owner/..",
			wantMsg: `repository ".." contains a path traversal component`,
		},
		{
			name:    "percent-encoded traversal is decoded before it is judged",
			in:      "https://github.com/owner/..%2Fetc/repo",
			wantMsg: `repository ".." contains a path traversal component`,
		},
		{
			name:    "owner carrying a shell metacharacter",
			in:      "https://github.com/ow;ner/repo",
			wantMsg: "outside [A-Za-z0-9._-]",
		},
		{
			name:    "subdirectory escapes the repository",
			in:      "https://github.com/owner/repo/tree/v1.0/../../etc",
			wantMsg: `subdirectory "../../etc" escapes the repository`,
		},
		{
			name:    "ref is a traversal component",
			in:      "https://github.com/owner/repo/tree/../secrets",
			wantMsg: `ref ".." contains ".."`,
		},
		{
			name:    "ref starting with a dash could be read as a flag",
			in:      "https://github.com/owner/repo?ref=--upload-pack=sh",
			wantMsg: `ref "--upload-pack=sh" starts with "-"`,
		},
		{
			name:    "ref carrying a space",
			in:      "https://github.com/owner/repo?ref=my%20branch",
			wantMsg: "contains a character git forbids",
		},
		{
			name:    "ref carrying a revision metacharacter",
			in:      "https://github.com/owner/repo?ref=v1%5E1",
			wantMsg: "contains a character git forbids",
		},
		{
			name:    "two contradicting refs",
			in:      "https://github.com/owner/repo/tree/main?ref=v1.2.3",
			wantMsg: `path names ref "main" but the query names "v1.2.3"`,
		},
		{
			name:    "unrecognised web path",
			in:      "https://github.com/owner/repo/issues/4",
			wantMsg: `unexpected path "issues/4" after owner/repo`,
		},
		{
			name:    "gitlab subgroups are not owner/repo",
			in:      "https://gitlab.com/group/subgroup/project",
			wantMsg: `unexpected path "project" after owner/repo`,
		},
		{
			name:    "tree path naming no ref",
			in:      "https://github.com/owner/repo/tree",
			wantMsg: `"tree" names no ref`,
		},
		{
			name:    "embedded credential",
			in:      "https://user:token@github.com/owner/repo",
			wantMsg: "reference embeds a credential",
		},
		{
			// Refused for its shape, not its address: a bracketed literal is not a
			// hostname. The dotted-quad form is accepted (see the accept table).
			name:    "bracketed ipv6 literal is not a hostname",
			in:      "https://[::1]/owner/repo",
			wantMsg: `"::1" is not a hostname`,
		},
		{
			// The raw-input control-character guard runs before percent-decoding, so
			// this is the encoding that used to walk a newline into a provenance line.
			name:    "percent-encoded newline in the query ref",
			in:      "https://github.com/owner/repo?ref=v1%0Aevil",
			wantMsg: `ref "v1\nevil" contains a control character at byte 2`,
		},
		{
			name:    "percent-encoded nul in the path ref",
			in:      "https://github.com/owner/repo/tree/ma%00in",
			wantMsg: "ref \"ma\\x00in\" contains a control character at byte 2",
		},
		{
			name:    "percent-encoded newline in the subdirectory",
			in:      "https://github.com/owner/repo/tree/main/plug%0Ains",
			wantMsg: `subdirectory "plug\nins" contains a control character at byte 4`,
		},
		{
			name:    "percent-encoded del in the subdirectory",
			in:      "https://github.com/owner/repo/tree/main/plug%7Fins",
			wantMsg: "contains a control character",
		},
		{
			// A half-read query drops the ref and would resolve the default branch
			// instead, which publishes a version the user never named.
			name:    "query with an unreadable escape",
			in:      "https://github.com/owner/repo?ref=%zzv1",
			wantMsg: `query "ref=%zzv1" cannot be read`,
		},
		{
			name:    "query separated by semicolons cannot be read",
			in:      "https://github.com/owner/repo?ref=main;utm_source=slack",
			wantMsg: `query "ref=main;utm_source=slack" cannot be read`,
		},
		{
			name:    "two contradicting refs in the query alone",
			in:      "https://github.com/owner/repo?ref=main&ref=v1.2.3",
			wantMsg: `query names both ref "main" and "v1.2.3"`,
		},
		{
			name:    "control character",
			in:      "https://github.com/owner/re\npo",
			wantMsg: "control character",
		},
		{
			name:    "invalid utf-8",
			in:      "https://github.com/owner/re\xffpo",
			wantMsg: "not valid utf-8",
		},
		{
			name:    "over the length limit",
			in:      "https://github.com/owner/" + strings.Repeat("a", maxRawLen),
			wantMsg: "over the 2048 byte limit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorContains(t, err, tc.wantMsg)
			// The rejection must not hand back a repaired value: a cleaned reference
			// fetches bytes the user never named.
			require.Equal(t, Repository{}, got)
		})
	}
}

func TestExplicitRefAndSubdirWin(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		ref, subdir string
		want        Repository
	}{
		{
			name: "explicit ref overrides the one in the url",
			raw:  "https://github.com/owner/repo/tree/main/plugins/toolkit",
			ref:  "v1.2.3",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "v1.2.3", Subdir: "plugins/toolkit",
			},
		},
		{
			name:   "explicit subdirectory overrides the one in the url",
			raw:    "https://github.com/owner/repo/tree/main/plugins/toolkit",
			subdir: "skills/deploy",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "main", Subdir: "skills/deploy",
			},
		},
		{
			name:   "both explicit values override both url values",
			raw:    "https://github.com/owner/repo/tree/main/plugins/toolkit?",
			ref:    "abc123",
			subdir: "plugins/other",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "abc123", Subdir: "plugins/other",
			},
		},
		{
			name: "empty explicit values mean not supplied and leave the url alone",
			raw:  "https://github.com/owner/repo/tree/main/plugins/toolkit",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "main", Subdir: "plugins/toolkit",
			},
		},
		{
			name:   "explicit values supply what the url omitted",
			raw:    "owner/repo",
			ref:    "v0.1.0",
			subdir: "plugins/toolkit",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Ref: "v0.1.0", Subdir: "plugins/toolkit",
			},
		},
		{
			name:   "an explicit subdirectory is normalised, not left as typed",
			raw:    "owner/repo",
			subdir: "plugins//toolkit/",
			want: Repository{
				Host: "github.com", Owner: "owner", Repo: "repo",
				Subdir: "plugins/toolkit",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viaParseWith, err := ParseWith(tc.raw, tc.ref, tc.subdir)
			require.NoError(t, err)
			require.Equal(t, tc.want, viaParseWith)

			parsed, err := Parse(tc.raw)
			require.NoError(t, err)
			viaWith, err := parsed.With(tc.ref, tc.subdir)
			require.NoError(t, err)
			require.Equal(t, tc.want, viaWith)
		})
	}
}

func TestExplicitValuesAreValidatedToo(t *testing.T) {
	tests := []struct {
		name        string
		ref, subdir string
		wantMsg     string
	}{
		{
			name:    "explicit subdirectory escaping the repository",
			subdir:  "../../etc",
			wantMsg: "escapes the repository",
		},
		{
			name:    "explicit absolute subdirectory",
			subdir:  "/etc/passwd",
			wantMsg: "is absolute",
		},
		{
			name:    "explicit subdirectory of only dots",
			subdir:  "plugins/./toolkit",
			wantMsg: `relative component "."`,
		},
		{
			name:    "explicit ref that could be read as a flag",
			ref:     "-oProxyCommand=sh",
			wantMsg: `starts with "-"`,
		},
		{
			name:    "explicit ref containing a traversal",
			ref:     "refs/../heads/main",
			wantMsg: `contains ".."`,
		},
		{
			// Parse guards the pasted string; these arrive from a form field beside it
			// and reach the same provenance strings, audit rows and log lines.
			name:    "explicit ref carrying a newline",
			ref:     "v1\nevil",
			wantMsg: `ref "v1\nevil" contains a control character at byte 2`,
		},
		{
			name:    "explicit subdirectory carrying a nul",
			subdir:  "plug\x00ins",
			wantMsg: "contains a control character",
		},
		{
			name:    "explicit ref that is not valid utf-8",
			ref:     "v1\xff",
			wantMsg: "ref is not valid utf-8",
		},
		{
			name:    "explicit subdirectory that is not valid utf-8",
			subdir:  "plugins/\xff",
			wantMsg: "subdirectory is not valid utf-8",
		},
		{
			name:    "explicit ref over the byte limit",
			ref:     strings.Repeat("a", maxRefLen+1),
			wantMsg: "over the 256 byte limit",
		},
		{
			name:    "explicit subdirectory over the byte limit",
			subdir:  strings.Repeat("a/", maxSubdirLen),
			wantMsg: "over the 1024 byte limit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseWith("https://github.com/owner/repo", tc.ref, tc.subdir)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorContains(t, err, tc.wantMsg)
			require.Equal(t, Repository{}, got)
		})
	}
}

func TestCloneURLAndString(t *testing.T) {
	r, err := ParseWith("git@github.com:Owner/Repo.git", "v1.3.0", "plugins/platform-toolkit")
	require.NoError(t, err)
	require.Equal(t, "https://github.com/owner/repo.git", r.CloneURL())
	require.Equal(t, "github.com/owner/repo@v1.3.0 (plugins/platform-toolkit)", r.String())

	plain, err := Parse("owner/repo")
	require.NoError(t, err)
	require.Equal(t, "github.com/owner/repo", plain.String())
}

// FuzzParse holds the invariants a caller relies on: a parse either fails or
// returns parts that cannot climb out of the repository. This is untrusted input
// (constitution principle III), so "it never panics" is also a requirement.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"owner/repo",
		"https://github.com/owner/repo.git",
		"git@github.com:owner/repo.git",
		"https://github.com/owner/repo/tree/v1.3.0/plugins/platform-toolkit",
		"https://www.github.com/owner/repo?ref=v1#readme",
		"file:///etc/passwd",
		"https://github.com/owner/repo/tree/v1/../../etc",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		r, err := Parse(raw)
		if err != nil {
			require.ErrorIs(t, err, ErrInvalid)
			require.Equal(t, Repository{}, r)
			return
		}
		require.NotEmpty(t, r.Host)
		require.NotEmpty(t, r.Owner)
		require.NotEmpty(t, r.Repo)
		for _, part := range []string{r.Owner, r.Repo} {
			require.NotContains(t, part, "/")
			require.NotContains(t, part, "..")
		}
		require.NotContains(t, r.Ref, "..")
		require.NotContains(t, r.Subdir, "..")
		require.False(t, strings.HasPrefix(r.Subdir, "/"))
		requireLoggableParts(t, r)
	})
}

// FuzzWith covers the second untrusted entry point: a ref and a subdirectory
// typed beside the URL never pass through Parse's guards on the raw string, so
// their own validation is all that stands between a form field and a stored row.
func FuzzWith(f *testing.F) {
	for _, seed := range [][3]string{
		{"owner/repo", "v1.2.3", "plugins/toolkit"},
		{"owner/repo", "", ""},
		{"https://github.com/owner/repo/tree/main/plugins", "abc123", "skills/deploy"},
		{"owner/repo", "-oProxyCommand=sh", "../../etc"},
		{"owner/repo", "v1\n", "a\x00b"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}

	f.Fuzz(func(t *testing.T, raw, ref, subdir string) {
		r, err := ParseWith(raw, ref, subdir)
		if err != nil {
			require.ErrorIs(t, err, ErrInvalid)
			require.Equal(t, Repository{}, r)
			return
		}
		require.NotContains(t, r.Subdir, "..")
		require.NotContains(t, r.Ref, "..")
		require.False(t, strings.HasPrefix(r.Subdir, "/"))
		require.LessOrEqual(t, len(r.Ref), maxRefLen)
		require.LessOrEqual(t, len(r.Subdir), maxSubdirLen)
		requireLoggableParts(t, r)
	})
}

// requireLoggableParts holds the claim the package makes about every field it
// returns: it is safe to put in a log line, a provenance string and a text
// column. Valid utf-8, no control characters, no smuggled line break.
func requireLoggableParts(t *testing.T, r Repository) {
	t.Helper()
	for _, part := range []string{r.Host, r.Owner, r.Repo, r.Ref, r.Subdir} {
		require.True(t, utf8.ValidString(part), "invalid utf-8 in %q", part)
		require.False(t, strings.ContainsFunc(part, isControl), "control character in %q", part)
	}
	require.Equal(t, r.String(), strings.TrimSpace(r.String()))
}
