package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// tempHome points the platform's home variable at a fresh directory. Filesystem
// behaviour is never tested against the developer's own home (plan.md).
func tempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(homeEnvVar(), dir)
	// os.UserHomeDir on darwin and linux reads HOME; on Windows it reads
	// USERPROFILE. Setting only the current platform's variable is the point —
	// setting both would hide a bug in homeEnvVar.
	return dir
}

func TestResolveHomeCreatesTheStateRootAndReportsIt(t *testing.T) {
	dir := tempHome(t)

	home, err := ResolveHome()
	require.NoError(t, err)
	require.Equal(t, dir, home.UserHome)
	require.Equal(t, homeEnvVar(), home.Var)
	require.Equal(t, filepath.Join(dir, DirName), home.Root)

	info, err := os.Stat(home.Root)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
			"the state root holds the list of paths amctl may delete and the cache it later trusts")
	}
}

func TestResolveHomeLeavesNoWriteProbeBehind(t *testing.T) {
	tempHome(t)
	home, err := ResolveHome()
	require.NoError(t, err)

	entries, err := os.ReadDir(home.Root)
	require.NoError(t, err)
	require.Empty(t, entries, "the probe file must be removed; a leftover is state amctl did not intend")
}

func TestResolveHomeIsIdempotent(t *testing.T) {
	tempHome(t)
	first, err := ResolveHome()
	require.NoError(t, err)
	second, err := ResolveHome()
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestResolveHomeRefusesAnUnsetHomeNamingTheVariable(t *testing.T) {
	t.Setenv(homeEnvVar(), "")

	_, err := ResolveHome()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHomeUnset)
	require.True(t, IsRefusal(err), "an unset home is the user's to fix (FR-039), so it must reach CodeRefused")
	require.Equal(t, CodeRefused, ExitCode(CodeNoChanges, err))
	require.Contains(t, err.Error(), homeEnvVar(),
		"FR-039 requires the refusal to NAME the variable; a message naming HOME on Windows is unactionable")
}

func TestResolveHomeRefusesARelativeHome(t *testing.T) {
	t.Setenv(homeEnvVar(), "relative/home")

	_, err := ResolveHome()
	require.ErrorIs(t, err, ErrHomeUnset)
	require.Contains(t, err.Error(), "relative/home")
	require.Contains(t, err.Error(), homeEnvVar())
}

func TestResolveHomeRefusesAMissingHome(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	t.Setenv(homeEnvVar(), missing)

	_, err := ResolveHome()
	require.ErrorIs(t, err, ErrHomeUnset)
	require.Contains(t, err.Error(), missing)
	require.Contains(t, err.Error(), "does not exist")
}

func TestResolveHomeRefusesAHomeThatIsAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "notadir")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	t.Setenv(homeEnvVar(), f)

	_, err := ResolveHome()
	require.ErrorIs(t, err, ErrHomeUnset)
	require.Contains(t, err.Error(), "not a directory")
}

func TestResolveHomeRefusesAnUnwritableHome(t *testing.T) {
	requireUnprivileged(t)
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	t.Setenv(homeEnvVar(), dir)

	_, err := ResolveHome()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHomeUnwritable)
	require.True(t, IsRefusal(err))
	require.Equal(t, CodeRefused, ExitCode(CodeNoChanges, err))
	require.Contains(t, err.Error(), homeEnvVar())
	require.Contains(t, err.Error(), dir)
}

// The mode bits on the home say 0700 and the write still fails, which is the
// whole reason ResolveHome probes with a real write instead of reading a mode.
func TestResolveHomeRefusesAWritableHomeWithAnUnwritableStateRoot(t *testing.T) {
	requireUnprivileged(t)
	dir := tempHome(t)
	root := filepath.Join(dir, DirName)
	require.NoError(t, os.Mkdir(root, 0o700))
	require.NoError(t, os.Chmod(root, 0o500))
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	_, err := ResolveHome()
	require.ErrorIs(t, err, ErrHomeUnwritable)
	require.Contains(t, err.Error(), root)
	require.Contains(t, err.Error(), "cannot write inside")
}

// A relative symlink that stays inside the home is fine. Measured on go1.26:
// os.Root's openat resolution follows it.
func TestResolveHomeAcceptsARelativeSymlinkedStateRootInsideTheHome(t *testing.T) {
	requireSymlinks(t)
	dir := tempHome(t)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "dotfiles"), 0o700))
	require.NoError(t, os.Symlink("dotfiles", filepath.Join(dir, DirName)))

	home, err := ResolveHome()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, DirName), home.Root)
}

// An ABSOLUTE symlink is refused even when it points back inside the home,
// because os.Root refuses every absolute link. This is a deliberate, documented
// usability cost, so the refusal has to say what to do about it.
func TestResolveHomeRefusesAnAbsolutelySymlinkedStateRootAndSaysWhy(t *testing.T) {
	requireSymlinks(t)
	dir := tempHome(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, DirName)))

	_, err := ResolveHome()
	require.ErrorIs(t, err, ErrHomeUnwritable)
	require.Contains(t, err.Error(), "absolute symlink")
	require.Contains(t, err.Error(), "make the link relative")
	require.NoFileExists(t, filepath.Join(target, ".amctl-write-probe"),
		"FR-020: nothing may be written through a link that leaves the home")
}

func TestHomeEnvVarNamesThePlatformVariable(t *testing.T) {
	// Hand-derived from $GOROOT/src/os/file.go's UserHomeDir, not from a run.
	for goos, want := range map[string]string{
		"linux":   "HOME",
		"darwin":  "HOME",
		"freebsd": "HOME",
		"windows": "USERPROFILE",
		"plan9":   "home",
	} {
		t.Run(goos+" uses "+want, func(t *testing.T) {
			require.Equal(t, want, homeEnvVarFor(goos))
		})
	}
}

func TestHubDirAndLockPathSitDirectlyUnderTheStateRoot(t *testing.T) {
	tempHome(t)
	home, err := ResolveHome()
	require.NoError(t, err)

	hub, err := ParseHub("https://hub.example.com")
	require.NoError(t, err)

	require.Equal(t, home.Root, filepath.Dir(home.HubDir(hub)))
	require.Equal(t, filepath.Join(home.Root, LockFileName), home.LockPath())
	require.Equal(t, home.Root, filepath.Dir(home.LockPath()))
}

// FR-039's "before making any network request" is an ORDERING, and a run that
// dialled the hub, got a token and only then discovered the home was unwritable
// has already done the irreversible half. Prepare is the seam that makes the
// ordering structural; this proves it, with a positive control so the test
// cannot pass by never running work at all.
func TestPrepareValidatesTheHomeBeforeAnyNetworkCall(t *testing.T) {
	requireUnprivileged(t)

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dial := func(_ Home, hub Hub) error {
		resp, err := http.Get(hub.URL + "/v1/health") //nolint:noctx // the point is that this must never run
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	t.Run("an unwritable home refuses without dialling", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o500))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		t.Setenv(homeEnvVar(), dir)

		err := Prepare(srv.URL, dial)
		require.ErrorIs(t, err, ErrHomeUnwritable)
		require.Equal(t, CodeRefused, ExitCode(CodeNoChanges, err))
		require.Zero(t, hits.Load(), "FR-039: the hub must not be reached before the home is validated")
	})

	t.Run("an unset home refuses without dialling", func(t *testing.T) {
		t.Setenv(homeEnvVar(), "")

		err := Prepare(srv.URL, dial)
		require.ErrorIs(t, err, ErrHomeUnset)
		require.Zero(t, hits.Load())
	})

	t.Run("a bad hub URL refuses without dialling", func(t *testing.T) {
		tempHome(t)

		err := Prepare("ftp://hub.example.com", dial)
		require.ErrorIs(t, err, ErrHubURL)
		require.Zero(t, hits.Load())
	})

	// The negative control for the three above: with a good home and a good
	// hub, work DOES run and DOES reach the network. Without this, all three
	// assertions above would also pass against a Prepare that never called
	// work.
	t.Run("a valid home and hub reach the network", func(t *testing.T) {
		tempHome(t)

		require.NoError(t, Prepare(srv.URL, dial))
		require.Equal(t, int64(1), hits.Load())
	})
}

func TestPrepareHandsWorkTheValidatedHomeAndHub(t *testing.T) {
	dir := tempHome(t)

	var gotHome Home
	var gotHub Hub
	require.NoError(t, Prepare("HUB.Example.COM.", func(h Home, hub Hub) error {
		gotHome, gotHub = h, hub
		return nil
	}))
	require.Equal(t, filepath.Join(dir, DirName), gotHome.Root)
	require.Equal(t, "https://hub.example.com", gotHub.URL)
	require.NotEmpty(t, gotHub.Dir)
}

func TestPrepareReturnsWorksError(t *testing.T) {
	tempHome(t)
	sentinel := fmt.Errorf("from work")
	err := Prepare("https://hub.example.com", func(Home, Hub) error { return sentinel })
	require.ErrorIs(t, err, sentinel)
}

// The three URLs the brief asks about, plus the rest of the canonicalisation
// decisions, stated as a table so the answer is testable rather than prose.
func TestParseHubCanonicalForm(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"a bare host means https", "hub.example.com", "https://hub.example.com"},
		{"the host is case-folded", "HUB.example.com", "https://hub.example.com"},
		{"a single trailing dot on the host is the same name", "HUB.example.com.", "https://hub.example.com"},
		{"a trailing slash is dropped", "https://hub.example.com/", "https://hub.example.com"},
		{"the https default port is dropped", "https://hub.example.com:443", "https://hub.example.com"},
		{"the http default port is dropped", "http://hub.example.com:80", "http://hub.example.com"},
		{"a non-default port is kept", "https://hub.example.com:8443/", "https://hub.example.com:8443"},
		{"a leading zero in a port is normalised", "https://hub.example.com:08443", "https://hub.example.com:8443"},
		{"a path prefix is kept", "https://example.com/agent-manager", "https://example.com/agent-manager"},
		{"a path's trailing slash is dropped", "https://example.com/agent-manager/", "https://example.com/agent-manager"},
		{"a path is cleaned", "https://example.com/a/./b//c", "https://example.com/a/b/c"},
		{"an interior dot-dot is cleaned away", "https://example.com/a/b/../c", "https://example.com/a/c"},
		{"the scheme is case-folded", "HTTPS://hub.example.com", "https://hub.example.com"},
		{"surrounding whitespace is trimmed", "  https://hub.example.com  ", "https://hub.example.com"},
		{"an IPv6 literal keeps its brackets", "https://[2001:DB8::1]:8443", "https://[2001:db8::1]:8443"},
		{"localhost over http is left alone", "http://localhost:8080", "http://localhost:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hub, err := ParseHub(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, hub.URL)
		})
	}
}

// The decision, restated as behaviour: which of these are the SAME hub.
func TestParseHubIdentityDecision(t *testing.T) {
	same := func(t *testing.T, a, b string) {
		t.Helper()
		ha, err := ParseHub(a)
		require.NoError(t, err)
		hb, err := ParseHub(b)
		require.NoError(t, err)
		require.Equal(t, ha, hb)
	}
	differ := func(t *testing.T, a, b string) {
		t.Helper()
		ha, err := ParseHub(a)
		require.NoError(t, err)
		hb, err := ParseHub(b)
		require.NoError(t, err)
		require.NotEqual(t, ha.URL, hb.URL)
		require.NotEqual(t, ha.Dir, hb.Dir)
	}

	t.Run("hub.example.com and HUB.example.com. are the same hub", func(t *testing.T) {
		same(t, "hub.example.com", "HUB.example.com.")
	})
	t.Run("a port of 8443 is a different hub from no port", func(t *testing.T) {
		differ(t, "https://hub.example.com:8443/", "hub.example.com")
	})
	t.Run("http and https are different hubs", func(t *testing.T) {
		differ(t, "http://hub.example.com", "https://hub.example.com")
	})
	t.Run("two path prefixes on one host are two hubs", func(t *testing.T) {
		differ(t, "https://example.com/a", "https://example.com/b")
	})
	t.Run("a host and its subdomain are two hubs", func(t *testing.T) {
		differ(t, "https://example.com", "https://hub.example.com")
	})
}

// Injectivity is the property FR-006 and internal/record's "hub A refused
// against hub B" rest on: two hubs sharing a directory means one machine's
// record silently applies to the other. Asserted over near-misses rather than
// claimed in a comment.
func TestHubDirNamesAreInjectiveOverNearMissURLs(t *testing.T) {
	urls := []string{
		"https://hub.example.com",
		"http://hub.example.com",
		"https://hub.example.com:8443",
		"https://hub.example.com:8444",
		"https://hub.example.com/a",
		"https://hub.example.com/b",
		"https://hub.example.com/a/b",
		"https://hub.example.com/ab",
		"https://hub-example.com",
		"https://hubexample.com",
		"https://hub.example.co",
		"https://sub.hub.example.com",
		"https://example.com",
		"https://example.com:8443",
		"https://example.com/hub",
		"https://192.0.2.1",
		"https://192.0.2.1:8443",
		"https://[2001:db8::1]",
		"https://[2001:db8::2]",
		"http://localhost",
		"http://localhost:8080",
		"http://localhost:8081",
		"https://a-------------------------------b.example.com/x",
		"https://a-------------------------------b.example.com/y",
		"https://xn--bcher-kva.example.com",
	}
	byDir := map[string]string{}
	byURL := map[string]string{}
	for _, raw := range urls {
		hub, err := ParseHub(raw)
		require.NoError(t, err, raw)
		if prev, dup := byDir[hub.Dir]; dup {
			t.Fatalf("directory %q derived from both %q and %q", hub.Dir, prev, hub.URL)
		}
		byDir[hub.Dir] = hub.URL
		require.NotContains(t, byURL, hub.URL, "two inputs canonicalised to one URL: %q", hub.URL)
		byURL[hub.URL] = raw
	}
	require.Len(t, byDir, len(urls))
}

// Two hubs whose readable prefixes are identical must still get two
// directories. This is the case a prefix-only scheme silently gets wrong.
func TestHubDirNamesDifferWhenOnlyTheReadablePrefixCollides(t *testing.T) {
	a, err := ParseHub("https://hub.example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	b, err := ParseHub("https://hub.example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab")
	require.NoError(t, err)

	require.Equal(t, readablePrefix(a.URL), readablePrefix(b.URL),
		"the prefixes must collide, or this test proves nothing")
	require.NotEqual(t, a.Dir, b.Dir)
}

func TestParseHubRefusesHostileURLs(t *testing.T) {
	cases := []struct {
		name, in, wantMsg string
	}{
		{"empty", "", "--hub is empty"},
		{"whitespace only", "   ", "--hub is empty"},
		{"a NUL byte", "https://hub.example.com/a\x00b", "control character"},
		{"an interior newline", "https://hub.example.com/a\nb", "control character"},
		{"a tab inside the host", "https://hub.exa\tmple.com", "control character"},
		{"a non-http scheme", "ftp://hub.example.com", "amctl speaks http and https"},
		{"a file URL", "file:///etc/passwd", "amctl speaks http and https"},
		{"an opaque URL", "https:hub.example.com", "not a hierarchical URL"},
		{"userinfo", "https://user:pass@hub.example.com", "credentials in the URL"},
		{"a query string", "https://hub.example.com/?a=b", "query string"},
		{"a bare question mark", "https://hub.example.com/?", "query string"},
		{"a fragment", "https://hub.example.com/#x", "fragment"},
		{"no host", "https:///a/b", "has no host"},
		{"a percent-encoded dot-dot escaping the base", "https://hub.example.com/%2e%2e/%2e%2e", "escapes its own base path"},
		{"a literal dot-dot escaping the base", "https://hub.example.com/../../etc", "escapes its own base path"},
		{"a backslash in the path", "https://hub.example.com/a\\b", "backslash in its path"},
		{"a percent-encoded backslash in the path", "https://hub.example.com/a%5cb", "backslash in its path"},
		{"a percent-encoded slash in the host", "https://hub.example.com%2fetc/", "invalid URL escape"},
		{"a colon in the host", "https://hub:example.com", "invalid port"},
		{"an empty host label", "https://hub..example.com", "empty label"},
		{"two trailing dots", "https://hub.example.com..", "unusable host"},
		{"a port of zero", "https://hub.example.com:0", "not a port number"},
		{"a port past 65535", "https://hub.example.com:99999", "not a port number"},
		{"a non-numeric port", "https://hub.example.com:https", "invalid port"},
		{"a non-ASCII host", "https://h\u00fcb.example.com", "in its host"},
		{"a space in the host", "https://hub example.com", "invalid character"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			hub, err := ParseHub(tc.in)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrHubURL)
			require.True(t, IsRefusal(err), "a bad --hub value is the user's to fix")
			require.Equal(t, CodeRefused, ExitCode(CodeNoChanges, err))
			// Assert the SPECIFIC rejection: a case that fails for the wrong
			// reason has silently stopped testing what it names.
			require.Contains(t, err.Error(), tc.wantMsg)
			require.Empty(t, hub.Dir)
		})
	}
}

// Every accepted hub, hostile or not, must yield one boring path component that
// cannot traverse, cannot be absolute and cannot collide on any platform.
func TestHubDirNameIsAlwaysASafeSingleComponent(t *testing.T) {
	root := t.TempDir()
	urls := []string{
		"https://hub.example.com",
		"https://hub.example.com:8443/a/b/c",
		"https://example.com/....",
		"https://example.com/-----",
		"https://con.example.com",
		"https://nul.example.com",
		"https://com1.example.com",
		"https://example.com/con",
		"https://example.com/..%2f..%2fetc",
		"https://example.com/a%20b",
		"https://example.com/" + strings.Repeat("z", 300),
		"https://" + strings.Repeat("a", 60) + ".example.com",
		"https://[2001:db8::1]:8443/x",
		"https://192.0.2.1/a.b.c",
		"https://example.com/%2e",
	}
	for _, raw := range urls {
		t.Run(raw, func(t *testing.T) {
			hub, err := ParseHub(raw)
			if err != nil {
				require.ErrorIs(t, err, ErrHubURL)
				return
			}
			require.NoError(t, validatePathComponent(hub.Dir))
			require.Equal(t, hub.Dir, filepath.Base(hub.Dir), "must be one component")
			require.False(t, filepath.IsAbs(hub.Dir))
			require.NotContains(t, hub.Dir, "/")
			require.NotContains(t, hub.Dir, `\`)
			require.NotEqual(t, "..", hub.Dir)

			// The containment backstop, on the real filesystem: the derived
			// name must land directly under the state root and nowhere else.
			joined := filepath.Join(root, hub.Dir)
			require.Equal(t, root, filepath.Dir(joined))

			r, err := os.OpenRoot(root)
			require.NoError(t, err)
			defer func() { _ = r.Close() }()
			require.NoError(t, r.Mkdir(hub.Dir, 0o700),
				"os.OpenRoot refuses a name that escapes; this is the FR-020 backstop")
		})
	}
}

func TestHubDirNameShapeIsReadableAndBounded(t *testing.T) {
	hub, err := ParseHub("https://hub.example.com:8443/agent-manager")
	require.NoError(t, err)

	require.True(t, strings.HasPrefix(hub.Dir, "hub-example-com-8443-agent-mana"),
		"a hash-only name is a real usability cost, so a readable prefix is kept: %q", hub.Dir)
	require.LessOrEqual(t, len(hub.Dir), maxDirNameLen)
	suffix := hub.Dir[len(hub.Dir)-hubDigestLen:]
	require.Len(t, suffix, hubDigestLen)
	require.Regexp(t, `^[0-9a-f]+$`, suffix)
}

func TestReadablePrefixIsLossyBoundedAndCarriesNoIdentity(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"punctuation collapses to single dashes", "https://hub.example.com:8443/a/b", "hub-example-com-8443-a-b"},
		{"the scheme is stripped", "http://hub.example.com", "hub-example-com"},
		{"runs of punctuation do not double up", "https://example.com/...///a", "example-com-a"},
		{"leading and trailing dashes are trimmed", "https://[2001:db8::1]", "2001-db8-1"},
		{"a prefix of only punctuation is empty", "https://[::]", ""},
		{"it is truncated", "https://" + strings.Repeat("a", 50) + ".com", strings.Repeat("a", readablePrefixLen)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, readablePrefix(tc.in))
			require.LessOrEqual(t, len(readablePrefix(tc.in)), readablePrefixLen)
		})
	}

	t.Run("an empty prefix still yields a usable name", func(t *testing.T) {
		name := hubDirName("https://[::]")
		require.NoError(t, validatePathComponent(name))
		require.True(t, strings.HasPrefix(name, "hub-"))
	})
}

func TestValidatePathComponentRefusals(t *testing.T) {
	cases := []struct {
		name, in, wantMsg string
	}{
		{"empty", "", "empty"},
		{"a single dot", ".", "relative directory reference"},
		{"a double dot", "..", "relative directory reference"},
		{"a forward slash", "a/b", "not portable"},
		{"a backslash", `a\b`, "not portable"},
		{"a colon, legal on darwin and illegal on Windows", "a:b", "not portable"},
		{"an asterisk", "a*b", "not portable"},
		{"a question mark", "a?b", "not portable"},
		{"a pipe", "a|b", "not portable"},
		{"angle brackets", "a<b>c", "not portable"},
		{"a NUL", "a\x00b", "NUL"},
		{"a control character", "a\x01b", "control character"},
		{"non-ASCII", "café", "non-ASCII"},
		{"a trailing dot, which Windows strips", "hub-a.", "Windows strips"},
		{"a trailing space, which Windows strips", "hub-a ", "Windows strips"},
		{"the CON device", "CON", "Windows device name"},
		{"the con device in lower case", "con", "Windows device name"},
		{"CON with an extension", "con.txt", "Windows device name"},
		{"the NUL device", "nul", "Windows device name"},
		{"the PRN device", "prn", "Windows device name"},
		{"the AUX device", "aux", "Windows device name"},
		{"COM1", "com1", "Windows device name"},
		{"COM9", "com9", "Windows device name"},
		{"LPT1", "lpt1", "Windows device name"},
		{"LPT9", "lpt9", "Windows device name"},
		{"CONOUT$", "conout$", "Windows device name"},
		{"over the length budget", strings.Repeat("a", maxDirNameLen+1), "over the"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			err := validatePathComponent(tc.in)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantMsg)
		})
	}

	// Negative control: the shape hubDirName actually produces must pass, or
	// the table above is only proving that everything fails.
	t.Run("a derived hub directory name is accepted", func(t *testing.T) {
		require.NoError(t, validatePathComponent(hubDirName("https://hub.example.com")))
		require.NoError(t, validatePathComponent("hub-example-com-0123456789abcdef"))
	})
}

// A device name is a real bug on a real platform, so the guard is checked on
// every platform: a state root written on Linux gets read on Windows through a
// mounted home or a synced dotfiles repo.
func TestNoHubURLCanProduceAWindowsDeviceName(t *testing.T) {
	for _, host := range []string{"con", "nul", "prn", "aux", "com1", "lpt9", "CON", "Nul"} {
		t.Run(host, func(t *testing.T) {
			hub, err := ParseHub("https://" + host)
			require.NoError(t, err)
			require.NoError(t, validatePathComponent(hub.Dir))
			base, _, _ := strings.Cut(hub.Dir, ".")
			require.False(t, windowsReservedNames[strings.ToLower(base)])
		})
	}
}

func requireUnprivileged(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not deny writes on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the mode bits this case depends on")
	}
}

func requireSymlinks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unprivileged os.Symlink needs Developer Mode on Windows")
	}
}
