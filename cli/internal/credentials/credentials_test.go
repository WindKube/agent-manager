package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/require"
)

// sentinelToken is the value every test that stores anything uses. It is
// deliberately loud so that SC-010's sweep over captured output (T032) has one
// string to look for, and so that a failure of FR-007 is unmistakable rather
// than a plausible-looking blob.
const sentinelToken = "amctl-test-token-DO-NOT-LOG-4f1c9a"

const hubA = "https://hub-a.example.com"
const hubB = "https://hub-b.example.com:8443/am"

// newStore opens a store restricted to one backend over a fresh state root,
// and returns it with the warnings it emitted.
func newStore(t *testing.T, backend keyring.BackendType) (store *Store, warnings *[]string, stateRoot string) {
	t.Helper()
	root := t.TempDir()
	warnings = &[]string{}
	s, err := Open(Options{
		StateRoot: root,
		Backends:  []keyring.BackendType{backend},
		Warnf:     func(format string, args ...any) { *warnings = append(*warnings, fmt.Sprintf(format, args...)) },
	})
	require.NoError(t, err)
	return s, warnings, root
}

// systemKeyringEnv opts the round-trip tests into the platform's own credential
// store. Unset — which is what CI and a colleague running `go test ./...` have
// — they use the file backend only.
const systemKeyringEnv = "AMCTL_TEST_SYSTEM_KEYRING"

// systemBackends are the ones whose store is SHARED OS STATE: the login
// keychain, the session's Secret Service or KWallet, a GPG password store. The
// file backend is not one of them, because Options.StateRoot puts it inside the
// test's own t.TempDir.
//
// WHY THEY ARE OFF BY DEFAULT, measured rather than assumed. On the macOS CI
// runner this suite HUNG for six and a half minutes in
// TestTwoHubsCoexistWithoutTouchingEachOther/keychain, blocked in
// SecItemCopyMatching — the login keychain asking a human for permission that
// no human was there to give. That is not a CI quirk to be waited out: the same
// code on a developer's Mac pops a dialog during `go test ./...` and, if the
// dialog is answered, leaves amctl's test items in their real keychain. A unit
// suite that mutates state outside its temp directory is wrong even when it
// passes.
//
// What is given up is real and is smaller than it looks: Store adds no
// per-backend logic — every backend goes through the same keyring.Item calls —
// so what these subtests cover beyond the file backend is keyring's own
// behaviour and the OS's. Set AMCTL_TEST_SYSTEM_KEYRING=1 to run them
// deliberately, on a machine where a prompt has somewhere to appear.
var systemBackends = map[keyring.BackendType]bool{
	keyring.KeychainBackend:      true,
	keyring.SecretServiceBackend: true,
	keyring.KWalletBackend:       true,
	keyring.PassBackend:          true,
	keyring.KeyCtlBackend:        true,
}

// openableBackends is the policy order intersected with what actually opens on
// this machine AND what this suite may write to. keyctl never appears:
// AllowedBackends excludes it, and amctl configures no KeyCtlScope, so its
// opener would fail anyway — see
// TestAllowedBackendsExcludesTheVolatileKernelKeyring for the reason and the
// negative control.
//
// Opening a backend and being able to USE it are different facts, which is the
// distinction that cost a CI leg: keyring.Open on the macOS keychain succeeds
// without touching the keychain, and the first Get blocks on an authorisation
// prompt. So the gate is on the backend's KIND, not on whether it opened.
func openableBackends(t *testing.T) []keyring.BackendType {
	t.Helper()
	useSystem := os.Getenv(systemKeyringEnv) != ""
	var out []keyring.BackendType
	for _, b := range AllowedBackends() {
		if systemBackends[b] && !useSystem {
			t.Logf("skipping backend %q: it is the machine's own credential store; set %s=1 to include it",
				b, systemKeyringEnv)
			continue
		}
		root := t.TempDir()
		if _, err := Open(Options{StateRoot: root, Backends: []keyring.BackendType{b}}); err != nil {
			t.Logf("skipping backend %q on %s: %v", b, runtime.GOOS, err)
			continue
		}
		out = append(out, b)
	}
	return out
}

func TestACredentialRoundTripsThroughEveryBackendTheSuiteMayUse(t *testing.T) {
	backends := openableBackends(t)
	// The file backend opens everywhere and is never gated, so an empty list
	// means the loop below is testing nothing and the whole suite would pass
	// vacuously.
	require.NotEmpty(t, backends, "no credential backend opened at all on %s", runtime.GOOS)

	issued := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	for _, backend := range backends {
		t.Run(string(backend), func(t *testing.T) {
			s, _, _ := newStore(t, backend)
			require.Equal(t, backend, s.Backend())

			_, found, err := s.Load(hubA)
			require.NoError(t, err)
			require.False(t, found, "a fresh store must report no credential rather than an error")

			want := Issued(hubA, sentinelToken, 3600, issued)
			want.Identity = "someone@example.com"
			require.NoError(t, s.Save(want))

			got, found, err := s.Load(hubA)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, want.Hub, got.Hub)
			require.Equal(t, want.Token, got.Token)
			require.Equal(t, want.Identity, got.Identity)
			// The expiry must survive the round trip: the hub's tokens are
			// opaque, so a store that lost expires_in could never tell an
			// expired credential from a valid one.
			require.True(t, want.ExpiresAt.Equal(got.ExpiresAt), "want %s got %s", want.ExpiresAt, got.ExpiresAt)
			require.True(t, want.IssuedAt.Equal(got.IssuedAt))

			// Overwriting is a replace, not a second item.
			second := Issued(hubA, sentinelToken+"-rotated", 60, issued)
			require.NoError(t, s.Save(second))
			got, found, err = s.Load(hubA)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, second.Token, got.Token)

			removed, err := s.Delete(hubA)
			require.NoError(t, err)
			require.True(t, removed)

			_, found, err = s.Load(hubA)
			require.NoError(t, err)
			require.False(t, found)
		})
	}
}

func TestDeletingACredentialThatIsNotThereIsSuccess(t *testing.T) {
	for _, backend := range openableBackends(t) {
		t.Run(string(backend), func(t *testing.T) {
			s, _, _ := newStore(t, backend)

			// FR-008: `amctl logout` on a machine that never logged in, and
			// `amctl logout` run twice, must both succeed. The file backend's
			// Remove returns a raw ENOENT rather than keyring.ErrKeyNotFound,
			// which is why isMissing checks both and why this runs per backend.
			removed, err := s.Delete(hubA)
			require.NoError(t, err)
			require.False(t, removed)

			require.NoError(t, s.Save(Issued(hubA, sentinelToken, 3600, time.Now())))
			removed, err = s.Delete(hubA)
			require.NoError(t, err)
			require.True(t, removed)

			removed, err = s.Delete(hubA)
			require.NoError(t, err)
			require.False(t, removed)
		})
	}
}

func TestTwoHubsCoexistWithoutTouchingEachOther(t *testing.T) {
	for _, backend := range openableBackends(t) {
		t.Run(string(backend), func(t *testing.T) {
			s, _, _ := newStore(t, backend)
			now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

			require.NoError(t, s.Save(Issued(hubA, sentinelToken+"-a", 3600, now)))
			require.NoError(t, s.Save(Issued(hubB, sentinelToken+"-b", 7200, now)))

			a, found, err := s.Load(hubA)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, sentinelToken+"-a", a.Token)

			b, found, err := s.Load(hubB)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, sentinelToken+"-b", b.Token)
			require.False(t, a.ExpiresAt.Equal(b.ExpiresAt), "the two hubs must keep their own lifetimes")

			// FR-006: logging out of one hub must not touch the other.
			removed, err := s.Delete(hubA)
			require.NoError(t, err)
			require.True(t, removed)

			_, found, err = s.Load(hubA)
			require.NoError(t, err)
			require.False(t, found)

			b, found, err = s.Load(hubB)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, sentinelToken+"-b", b.Token)
		})
	}
}

func TestItemKeysAreDistinctAndFilenameSafe(t *testing.T) {
	hubs := []string{
		hubA, hubB,
		"http://hub-a.example.com",           // a different scheme is a different hub
		"https://hub-a.example.com:8443",     // a non-default port is a different hub
		"https://hub-a.example.com/am",       // a path prefix is a different hub
		"https://HUB-A.example.com",          // canonicalisation is ParseHub's job, not ours
		"https://hub-b.example.com:8443/am/", // and so is the trailing slash
	}
	seen := map[string]string{}
	for _, h := range hubs {
		key := itemKey(h)
		require.NotContains(t, key, "/", "an item key becomes a filename in the file backend")
		require.NotContains(t, key, ":")
		require.NotContains(t, key, "%", "a percent would be re-escaped by keyring")
		require.Regexp(t, `^amctl-hub-[a-z0-9-]*-[0-9a-f]{16}$`, key)
		if prev, dup := seen[key]; dup {
			t.Fatalf("hubs %q and %q share item key %q", prev, h, key)
		}
		seen[key] = h
	}
	require.Len(t, seen, len(hubs))
}

// --- FR-004: the fallback file's permissions, both ways -----------------------

func fileStore(t *testing.T) (store *Store, stateRoot string) {
	t.Helper()
	s, _, root := newStore(t, keyring.FileBackend)
	require.Equal(t, keyring.FileBackend, s.Backend())
	return s, root
}

func TestTheFileFallbackWritesThePathWePredict(t *testing.T) {
	// Two-sided on purpose. filePath is a PREDICTION about keyring's internal
	// filename escaping; if it is wrong, checkFileMode stats a file that does
	// not exist, returns nil, and FR-004 is silently switched off with nothing
	// looking wrong. So the test asks keyring where the item actually landed.
	s, root := fileStore(t)
	require.NoError(t, s.Save(Issued(hubA, sentinelToken, 3600, time.Now())))

	dir := filepath.Join(root, DirName)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, filepath.Join(dir, entries[0].Name()), s.filePath(itemKey(hubA)))
}

func TestTheFileFallbackCreatesAnOwnerOnlyFile(t *testing.T) {
	s, _ := fileStore(t)
	require.NoError(t, s.Save(Issued(hubA, sentinelToken, 3600, time.Now())))

	// The RESULTING mode, not the requested one. keyring creates the file with
	// os.WriteFile(..., 0600); open(2) masks the perm argument with the umask,
	// so the result is always a subset of 0600 and there is no
	// create-then-chmod window in which it is wider. A restrictive umask can
	// make it narrower (0400), which is why the assertion is the FR-004 mask
	// rather than equality with 0600.
	info, err := os.Stat(s.filePath(itemKey(hubA)))
	require.NoError(t, err)
	require.Zero(t, info.Mode().Perm()&ownerOnlyFileMask,
		"the fallback credential file is mode %#o, which someone other than its owner can reach", info.Mode().Perm())

	dirInfo, err := os.Stat(filepath.Dir(s.filePath(itemKey(hubA))))
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o700), dirInfo.Mode().Perm())
}

func TestTheFileFallbackRefusesAFileWiderThanOwnerOnly(t *testing.T) {
	tests := []struct {
		name    string
		mode    fs.FileMode
		refused bool
		// writable is false for a mode amctl accepts but the OS will not let
		// it write to. 0400 is owner-only, so FR-004 has no objection; the
		// EACCES that follows comes from the kernel and is not this gate's
		// refusal, and conflating the two would let a broken check hide behind
		// a real error.
		writable bool
	}{
		{name: "owner read and write is accepted", mode: 0o600, writable: true},
		{name: "owner read only is accepted for reading", mode: 0o400},
		{name: "group readable is refused", mode: 0o640, refused: true},
		{name: "world readable is refused", mode: 0o644, refused: true},
		{name: "group writable is refused", mode: 0o660, refused: true},
		{name: "world writable is refused", mode: 0o606, refused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := fileStore(t)
			require.NoError(t, s.Save(Issued(hubA, sentinelToken, 3600, time.Now())))
			path := s.filePath(itemKey(hubA))
			require.NoError(t, os.Chmod(path, tt.mode))

			_, _, loadErr := s.Load(hubA)
			saveErr := s.Save(Issued(hubA, sentinelToken, 3600, time.Now()))

			if !tt.refused {
				require.NoError(t, loadErr)
				if tt.writable {
					require.NoError(t, saveErr)
				} else {
					require.ErrorIs(t, saveErr, fs.ErrPermission)
					require.NotErrorIs(t, saveErr, ErrFileMode)
				}
				return
			}
			// The specific failure, not err != nil: a refusal for the wrong
			// reason would mean this gate had stopped testing anything.
			require.ErrorIs(t, loadErr, ErrFileMode)
			require.ErrorContains(t, loadErr, fmt.Sprintf("is mode %#o", tt.mode))
			require.ErrorContains(t, loadErr, "chmod 600 "+path)
			require.ErrorIs(t, saveErr, ErrFileMode)

			// And the refusal must not be a lock-in: logout has to be able to
			// remove exactly this file.
			removed, err := s.Delete(hubA)
			require.NoError(t, err)
			require.True(t, removed)
		})
	}
}

func TestTheFileFallbackRefusesADirectoryOthersCanWrite(t *testing.T) {
	s, root := fileStore(t)
	require.NoError(t, s.Save(Issued(hubA, sentinelToken, 3600, time.Now())))
	dir := filepath.Join(root, DirName)
	require.NoError(t, os.Chmod(dir, 0o777))

	_, _, err := s.Load(hubA)
	require.ErrorIs(t, err, ErrFileMode)
	require.ErrorContains(t, err, "lets another user replace the credential in it")
	require.ErrorContains(t, err, "chmod 700 "+dir)

	require.ErrorIs(t, s.Save(Issued(hubA, sentinelToken, 3600, time.Now())), ErrFileMode)

	// 0755 is not a hole: others cannot write, and the file itself is
	// owner-only. Refusing it would refuse the default on many systems.
	require.NoError(t, os.Chmod(dir, 0o755))
	_, found, err := s.Load(hubA)
	require.NoError(t, err)
	require.True(t, found)
}

// TestCheckIsTheSameGateBeforeAnythingIsTouched is FR-004 as a PRE-FLIGHT.
//
// The mode gate used to run first inside Save, which for `amctl login` meant it
// ran after the code had been displayed, after the ten-minute window had been
// spent and after a human had approved a grant that could then not be stored.
// Check is the same arithmetic, callable before any of that. Every row is
// asserted against Save as well, because a Check that disagreed with the check
// Save performs would be worse than no pre-flight: login would pass and then
// fail anyway.
func TestCheckIsTheSameGateBeforeAnythingIsTouched(t *testing.T) {
	for _, tt := range []struct {
		name    string
		setUp   func(t *testing.T, s *Store, root string)
		refused bool
		detail  string
	}{
		{
			name:  "nothing stored yet, which is the ordinary first login",
			setUp: func(*testing.T, *Store, string) {},
		},
		{
			name: "the file keyring itself wrote",
			setUp: func(t *testing.T, s *Store, _ string) {
				require.NoError(t, s.Save(Issued(hubA, sentinelToken, 3600, time.Now())))
			},
		},
		{
			name: "a world-readable file, the restore-from-backup case",
			setUp: func(t *testing.T, s *Store, _ string) {
				require.NoError(t, s.Save(Issued(hubA, sentinelToken, 3600, time.Now())))
				require.NoError(t, os.Chmod(s.filePath(itemKey(hubA)), 0o644))
			},
			refused: true,
			detail:  "is mode 0644",
		},
		{
			name: "a directory anybody may write",
			setUp: func(t *testing.T, s *Store, root string) {
				require.NoError(t, os.Chmod(filepath.Join(root, DirName), 0o777))
			},
			refused: true,
			detail:  "lets another user replace the credential in it",
		},
		{
			name: "another hub's wide file, which is none of this hub's business",
			setUp: func(t *testing.T, s *Store, _ string) {
				require.NoError(t, s.Save(Issued(hubB, sentinelToken, 3600, time.Now())))
				require.NoError(t, os.Chmod(s.filePath(itemKey(hubB)), 0o644))
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, root := fileStore(t)
			tt.setUp(t, s, root)

			err := s.Check(hubA)
			saveErr := s.Save(Issued(hubA, sentinelToken, 3600, time.Now()))
			if !tt.refused {
				require.NoError(t, err)
				require.NoError(t, saveErr, "Check passed and Save then refused, which is the disagreement this test exists to catch")
				return
			}
			require.ErrorIs(t, err, ErrFileMode)
			require.ErrorContains(t, err, tt.detail)
			require.ErrorIs(t, saveErr, ErrFileMode, "Save must keep its own post-condition; Check does not replace it")
		})
	}

	t.Run("a backend that is not the file one has no permissions to answer for", func(t *testing.T) {
		// R1: on a static darwin build the fallback is `pass`, not a file, and
		// inferring "we must be using a file" from the fact that a fallback
		// happened is exactly what would make this gate vacuous. Asserted
		// through the file store's own dir turned 0777 with the backend label
		// changed, because there is no `pass` on a test machine.
		s, root := fileStore(t)
		require.NoError(t, os.Chmod(filepath.Join(root, DirName), 0o777))
		require.ErrorIs(t, s.Check(hubA), ErrFileMode)
		s.backend = keyring.PassBackend
		require.NoError(t, s.Check(hubA))
	})

	t.Run("no hub is a caller bug, not a permission problem", func(t *testing.T) {
		s, _ := fileStore(t)
		err := s.Check("")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrFileMode)
	})
}

func TestTheFileFallbackRefusesToFollowASymlinkToACredential(t *testing.T) {
	s, _ := fileStore(t)
	path := s.filePath(itemKey(hubA))
	target := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.WriteFile(target, []byte("not a credential"), 0o600))
	require.NoError(t, os.Symlink(target, path))

	_, _, err := s.Load(hubA)
	require.ErrorIs(t, err, ErrFileMode)
	require.ErrorContains(t, err, "is a symlink")
}

// --- FR-003: the warning names the backend that actually opened ---------------

func TestTheFallbackWarningNamesTheBackendActuallyChosen(t *testing.T) {
	const dir = "/home/u/.agent-manager/credentials"

	darwinStatic := []keyring.BackendType{keyring.PassBackend, keyring.FileBackend}
	darwinCGO := []keyring.BackendType{keyring.KeychainBackend, keyring.PassBackend, keyring.FileBackend}
	linuxAll := []keyring.BackendType{
		keyring.SecretServiceBackend, keyring.KWalletBackend, keyring.KeyCtlBackend,
		keyring.PassBackend, keyring.FileBackend,
	}

	tests := []struct {
		name      string
		goos      string
		available []keyring.BackendType
		notOpened []keyring.BackendType
		chosen    keyring.BackendType
		want      string
	}{
		{
			// R1's measured case, and the one a hand-written message gets
			// wrong: a CGO_ENABLED=0 darwin build lands on `pass`, not on a
			// file, because pass.go precedes FileBackend in keyring's own
			// order.
			name:      "a static darwin build that lands on pass says pass",
			goos:      "darwin",
			available: darwinStatic,
			chosen:    keyring.PassBackend,
			want: `credential store: using "pass" instead of "keychain", which a darwin build of amctl expects. ` +
				`keyring backend "keychain" is not compiled into this darwin build (available: [pass file]): ` +
				`the platform credential store is missing, most likely built with CGO_ENABLED=0. ` +
				"The token is going into your GPG password store through `pass`.",
		},
		{
			name:      "a static darwin build without pass says file and names the path",
			goos:      "darwin",
			available: darwinStatic,
			notOpened: []keyring.BackendType{keyring.PassBackend},
			chosen:    keyring.FileBackend,
			want: `credential store: using "file" instead of "keychain", which a darwin build of amctl expects. ` +
				`keyring backend "keychain" is not compiled into this darwin build (available: [pass file]): ` +
				`the platform credential store is missing, most likely built with CGO_ENABLED=0. ` +
				`The token is going into ` + dir + `, a file amctl keeps readable and writable only by you.`,
		},
		{
			name:      "a headless linux box says the store is compiled in but did not open",
			goos:      "linux",
			available: linuxAll,
			notOpened: []keyring.BackendType{keyring.SecretServiceBackend, keyring.KWalletBackend, keyring.PassBackend},
			chosen:    keyring.FileBackend,
			want: `credential store: using "file" instead of "secret-service", which a linux build of amctl expects. ` +
				`"secret-service" is compiled into this build but did not open; keyring does not report why, ` +
				`and the usual cause is that no Secret Service is running on the session bus (a headless or SSH session), ` +
				`or the login keyring is locked. ` +
				`The token is going into ` + dir + `, a file amctl keeps readable and writable only by you.`,
		},
		{
			name:      "a narrowed backend order says so rather than blaming the machine",
			goos:      "linux",
			available: linuxAll,
			chosen:    keyring.FileBackend,
			want: `credential store: using "file" instead of "secret-service", which a linux build of amctl expects. ` +
				`"secret-service" was not among the backends this run was allowed to try. ` +
				`The token is going into ` + dir + `, a file amctl keeps readable and writable only by you.`,
		},
		{
			name:      "an unrecorded platform reports the missing R1 entry",
			goos:      "freebsd",
			available: linuxAll,
			chosen:    keyring.FileBackend,
			want: `credential store: using "file" instead of the platform credential store, which a freebsd build of amctl expects. ` +
				`no required credential backend recorded for GOOS "freebsd": add it to the R1 table before shipping the platform. ` +
				`The token is going into ` + dir + `, a file amctl keeps readable and writable only by you.`,
		},
		{
			name:      "no warning when the platform store is the one in use",
			goos:      "darwin",
			available: darwinCGO,
			chosen:    keyring.KeychainBackend,
			want:      "",
		},
		{
			name:      "no warning on linux when secret-service opened",
			goos:      "linux",
			available: linuxAll,
			chosen:    keyring.SecretServiceBackend,
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fallbackWarning(tt.goos, tt.available, tt.notOpened, tt.chosen, dir)
			require.Equal(t, tt.want, got)
			if tt.want == "" {
				return
			}
			// Whatever the wording, these three facts must be in it, because
			// they are what FR-003 exists to deliver.
			require.Contains(t, got, string(tt.chosen), "the warning must name the backend actually chosen")
			require.NotContains(t, got, "falling back to a file",
				"a message that hard-codes a file is a lie on a static darwin build")
		})
	}
}

func TestOpenReportsTheFallbackOnTheDiagnosticStream(t *testing.T) {
	// Forcing the file backend makes this deterministic on every platform:
	// the file backend always opens, and it is never the store any platform's
	// R1 entry expects, so the warning must fire exactly once.
	s, warnings, root := newStore(t, keyring.FileBackend)
	require.Len(t, *warnings, 1, "FR-003: the fallback must be reported, never silent")

	msg := (*warnings)[0]
	require.Contains(t, msg, `using "file"`)
	require.Contains(t, msg, filepath.Join(root, DirName))
	if want, ok := required[runtime.GOOS]; ok {
		require.Contains(t, msg, string(want[0]), "the warning must name what this platform expected instead")
	}
	require.Equal(t, keyring.FileBackend, s.Backend())
	require.Contains(t, s.Location(), filepath.Join(root, DirName))
}

func TestOpenWithTheRealBackendOrderWarnsExactlyWhenItFallsBack(t *testing.T) {
	root := t.TempDir()
	var warnings []string
	s, err := Open(Options{
		StateRoot: root,
		Warnf:     func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) },
	})
	require.NoError(t, err)
	require.Contains(t, AllowedBackends(), s.Backend())

	want, recorded := required[runtime.GOOS]
	if recorded && s.Backend() == want[0] {
		require.Empty(t, warnings, "the platform store opened; there is nothing to report")
		return
	}
	require.Len(t, warnings, 1)
	require.Contains(t, warnings[0], string(s.Backend()))
}

func TestOpenWithADarwinPlatformThatLostItsKeychain(t *testing.T) {
	// End-to-end on the R1 case, on whatever machine the suite runs on: the
	// goos and available hooks are the only way this message is ever exercised,
	// because no macOS runner was available when it was written.
	root := t.TempDir()
	var warnings []string
	s, err := Open(Options{
		StateRoot: root,
		Backends:  []keyring.BackendType{keyring.FileBackend},
		Warnf:     func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) },
		goos:      "darwin",
		available: []keyring.BackendType{keyring.PassBackend, keyring.FileBackend},
	})
	require.NoError(t, err)
	require.Equal(t, keyring.FileBackend, s.Backend())
	require.Len(t, warnings, 1)
	require.Contains(t, warnings[0], "CGO_ENABLED=0")
	require.Contains(t, warnings[0], `using "file" instead of "keychain"`)
}

func TestOpenWithoutAWarnfDoesNotPanic(t *testing.T) {
	_, err := Open(Options{StateRoot: t.TempDir(), Backends: []keyring.BackendType{keyring.FileBackend}})
	require.NoError(t, err)
}

func TestOpenRefusesWithoutAStateRoot(t *testing.T) {
	_, err := Open(Options{})
	require.ErrorContains(t, err, "no state root given")
}

func TestOpenRefusesWhenNoBackendWouldOpen(t *testing.T) {
	// The negative control for the loop in Open: an order containing only a
	// backend that cannot open must be a named failure, not a nil Keyring.
	_, err := Open(Options{StateRoot: t.TempDir(), Backends: []keyring.BackendType{keyring.KeyCtlBackend}})
	require.ErrorIs(t, err, ErrNoStore)
	require.ErrorContains(t, err, "keyctl")
}

func TestAllowedBackendsExcludesTheVolatileKernelKeyring(t *testing.T) {
	allowed := AllowedBackends()
	require.NotContains(t, allowed, keyring.KeyCtlBackend,
		"keyctl is memory-only: a token stored there disappears at reboot with no event, and it sits ahead of pass and file in keyring's order")

	// Negative control: the exclusion must be the ONLY difference, and it must
	// preserve keyring's own preference order. Derived from keyring v1.2.2's
	// backendOrder, not from a run.
	var wantOrder []keyring.BackendType
	for _, b := range Available() {
		if b != keyring.KeyCtlBackend {
			wantOrder = append(wantOrder, b)
		}
	}
	require.Equal(t, wantOrder, allowed)
	require.Contains(t, allowed, keyring.FileBackend, "the sanctioned fallback must always be reachable")
	require.Contains(t, allowed, keyring.PassBackend, "R1: pass is what a static darwin build lands on")
}

// --- FR-007: no token in any message ----------------------------------------

func TestNoErrorOrRenderingEverContainsTheToken(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	c := Issued(hubA, sentinelToken, 3600, now)
	c.Identity = "someone@example.com"

	// Through an interface, because the point is what fmt does with a
	// Credential at run time — the verbs a hurried debug print reaches for —
	// and not what a compile-time-visible String call does.
	var boxed any = c
	rendered := []string{
		c.String(),
		c.GoString(),
		fmt.Sprintf("%v", boxed),
		fmt.Sprintf("%s", boxed),
		fmt.Sprintf("%+v", boxed),
		fmt.Sprintf("%#v", boxed),
		fmt.Sprintf("%q", boxed),
		fmt.Sprint(boxed),
		fmt.Errorf("wrapped: %w", fmt.Errorf("%v", boxed)).Error(),
	}

	s, _ := fileStore(t)
	require.NoError(t, s.Save(c))
	path := s.filePath(itemKey(hubA))
	require.NoError(t, os.Chmod(path, 0o644))
	_, _, err := s.Load(hubA)
	require.Error(t, err)
	rendered = append(rendered, err.Error())
	require.NoError(t, os.Chmod(path, 0o600))

	blob, err := encodeCredential(c)
	require.NoError(t, err)
	if _, err := decodeCredential(blob, hubB); err != nil {
		rendered = append(rendered, err.Error())
	} else {
		t.Fatal("decoding hub A's credential as hub B's must fail")
	}
	if _, err := decodeCredential([]byte("not json"), hubA); err != nil {
		rendered = append(rendered, err.Error())
	}
	if err := s.Save(Credential{Hub: hubA, Token: sentinelToken, fromEnv: true}); err != nil {
		rendered = append(rendered, err.Error())
	} else {
		t.Fatal("saving an environment credential must fail")
	}

	for _, got := range rendered {
		require.NotContains(t, got, sentinelToken, "FR-007: %q leaked the token", got)
	}
	// Negative control: the sweep above is only worth something if it can see
	// the token when the token is there.
	require.Contains(t, string(blob), sentinelToken, "the stored blob is where the token IS supposed to be")
}

func TestSaveRefusesACredentialThatCameFromTheEnvironment(t *testing.T) {
	// FR-005: never persisted. The guard is the unexported fromEnv field, so a
	// caller cannot resolve a credential and then store it by accident.
	s, root := fileStore(t)
	err := s.Save(Credential{Hub: hubA, Token: sentinelToken, fromEnv: true})
	require.ErrorContains(t, err, TokenEnvVar)
	require.ErrorContains(t, err, "never stored")

	entries, readErr := os.ReadDir(filepath.Join(root, DirName))
	require.NoError(t, readErr)
	require.Empty(t, entries, "nothing may reach disk for an environment token")
}

func TestSaveRefusesAnIncompleteCredential(t *testing.T) {
	s, _ := fileStore(t)
	require.ErrorContains(t, s.Save(Credential{Token: sentinelToken}), "no hub")
	require.ErrorContains(t, s.Save(Credential{Hub: hubA}), "empty token")

	_, _, err := s.Load("")
	require.ErrorContains(t, err, "without a hub")
	_, err = s.Delete("")
	require.ErrorContains(t, err, "without a hub")
}

// --- the Credential value ----------------------------------------------------

func TestIssuedTurnsExpiresInIntoAnExpiry(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		expiresIn int64
		want      time.Time
	}{
		{name: "an hour becomes an hour from now", expiresIn: 3600, want: now.Add(time.Hour)},
		{name: "one second becomes one second from now", expiresIn: 1, want: now.Add(time.Second)},
		// A hub that states no lifetime must not be read as a lifetime that
		// has already elapsed: that would throw away a token that works.
		{name: "zero means no stated lifetime, not already expired", expiresIn: 0, want: time.Time{}},
		{name: "a negative lifetime means no stated lifetime", expiresIn: -5, want: time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Issued(hubA, sentinelToken, tt.expiresIn, now)
			require.True(t, tt.want.Equal(c.ExpiresAt), "want %s got %s", tt.want, c.ExpiresAt)
			require.True(t, now.Equal(c.IssuedAt))
			require.False(t, c.FromEnvironment())
		})
	}
}

func TestExpiredIsFalseWhenNoLifetimeWasStated(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		c    Credential
		at   time.Time
		want bool
	}{
		{name: "no stated expiry is never expired", c: Credential{}, at: now, want: false},
		{name: "before the expiry it is valid", c: Issued(hubA, "t", 3600, now), at: now.Add(59 * time.Minute), want: false},
		{name: "at the expiry it is expired", c: Issued(hubA, "t", 3600, now), at: now.Add(time.Hour), want: true},
		{name: "after the expiry it is expired", c: Issued(hubA, "t", 3600, now), at: now.Add(2 * time.Hour), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.c.Expired(tt.at))
		})
	}
}

func TestDecodeRefusesRatherThanGuessing(t *testing.T) {
	valid := storedCredential{SchemaVersion: schemaVersion, Hub: hubA, Token: sentinelToken}

	tests := []struct {
		name    string
		mutate  func(*storedCredential)
		raw     []byte
		hub     string
		wantErr string
	}{
		{
			name:    "a credential naming another hub is refused",
			hub:     hubB,
			wantErr: `names hub "https://hub-a.example.com"; refusing to use it for "https://hub-b.example.com:8443/am"`,
		},
		{
			name:    "a newer schema version is refused by number",
			mutate:  func(s *storedCredential) { s.SchemaVersion = schemaVersion + 1 },
			wantErr: fmt.Sprintf("is schema version %d, and this amctl understands %d", schemaVersion+1, schemaVersion),
		},
		{
			name:    "a missing schema version is refused rather than assumed",
			mutate:  func(s *storedCredential) { s.SchemaVersion = 0 },
			wantErr: "is schema version 0",
		},
		{
			name:    "an empty token is refused",
			mutate:  func(s *storedCredential) { s.Token = "" },
			wantErr: "has no token",
		},
		{
			name:    "an unparseable expiry is refused, not defaulted to no expiry",
			mutate:  func(s *storedCredential) { s.ExpiresAt = "next tuesday" },
			wantErr: "unparseable expires_at",
		},
		{
			name:    "an unparseable issue time is refused",
			mutate:  func(s *storedCredential) { s.IssuedAt = "yesterday" },
			wantErr: "unparseable issued_at",
		},
		{
			name:    "a blob that is not JSON is refused",
			raw:     []byte("{not json"),
			wantErr: "cannot decode the credential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hub := tt.hub
			if hub == "" {
				hub = hubA
			}
			raw := tt.raw
			if raw == nil {
				s := valid
				if tt.mutate != nil {
					tt.mutate(&s)
				}
				var err error
				raw, err = json.Marshal(s)
				require.NoError(t, err)
			}
			_, err := decodeCredential(raw, hub)
			require.ErrorIs(t, err, ErrCredential)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestEncodeOmitsTimestampsThatWereNeverSet(t *testing.T) {
	blob, err := encodeCredential(Credential{Hub: hubA, Token: sentinelToken})
	require.NoError(t, err)
	// The absence must survive as absence. "0001-01-01T00:00:00Z" in a
	// hand-inspected file reads as a real timestamp and would come back as an
	// expiry in the year 1.
	require.NotContains(t, string(blob), "0001-01-01")
	require.NotContains(t, string(blob), "expires_at")
	require.NotContains(t, string(blob), "issued_at")

	c, err := decodeCredential(blob, hubA)
	require.NoError(t, err)
	require.True(t, c.ExpiresAt.IsZero())
	require.False(t, c.Expired(time.Now()))
}

func TestIsMissingCoversBothWaysABackendSaysNothingIsThere(t *testing.T) {
	// Measured against keyring v1.2.2, not assumed: most backends return
	// ErrKeyNotFound, and the file backend's Remove passes os.Remove's ENOENT
	// straight through. Treating only the first as absence breaks `logout` on
	// exactly the platform where the fallback is in use.
	require.True(t, isMissing(keyring.ErrKeyNotFound))
	require.True(t, isMissing(fmt.Errorf("wrapped: %w", keyring.ErrKeyNotFound)))
	require.True(t, isMissing(&os.PathError{Op: "remove", Path: "x", Err: fs.ErrNotExist}))
	require.False(t, isMissing(errors.New("permission denied")))
	require.False(t, isMissing(nil))
}

func TestReadablePrefixCollapsesEverythingUnsafe(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "https://hub.example.com", want: "hub-example-com"},
		{in: "http://hub.example.com", want: "hub-example-com"},
		{in: "https://hub.example.com:8443/am", want: "hub-example-com-8443-am"},
		{in: "https://" + strings.Repeat("a", 40), want: strings.Repeat("a", readablePrefixLen)},
		{in: "https://héllo.example.com", want: "h-llo-example-com"},
		{in: "https://...", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			require.Equal(t, tt.want, readablePrefix(tt.in))
		})
	}
}
