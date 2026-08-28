package credentials

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/99designs/keyring"
)

// DirName is the file fallback's directory, relative to amctl's state root:
// `~/.agent-manager/credentials`. It is NOT under the per-hub directory —
// keyring's file backend takes one directory and distinguishes items by key,
// and the key already carries the hub (FR-006), so a second layer of
// directories would buy nothing and give `logout` two places to look.
const DirName = "credentials"

// ServiceName is the grouping amctl uses in every backend that has the concept
// (keychain service, secret-service collection item, wincred prefix, pass
// subdirectory). It is what a human sees in Keychain Access or seahorse.
const ServiceName = "amctl"

// libSecretCollection is the Secret Service collection amctl stores into.
//
// It is the collection GNOME Keyring unlocks at login, deliberately and not a
// private one named after amctl: keyring's Set CREATES a collection when it
// cannot find the configured one, and creating a collection is an interactive
// password dialog on every desktop that implements the spec — which FR-037
// forbids without a flag. What this does NOT handle: a Secret Service
// implementation that names its default collection something other than
// `login` (KeePassXC and the KWallet bridge are the likely ones). There, amctl
// would create a `login` collection on first Set and may prompt. Unverified —
// R1 measured which backends are compiled in, not what each implementation
// calls its default collection.
const libSecretCollection = "login"

// keyPrefix labels amctl's items so a shared store (a `pass` tree, a keychain)
// shows what wrote them.
const keyPrefix = "amctl-hub-"

// readablePrefixLen bounds the human-readable half of an item key.
const readablePrefixLen = 24

// hubDigestLen is how many hex characters of SHA-256 carry hub identity in an
// item key. 16 hex is 64 bits, which is what makes the key injective; the
// readable prefix is lossy by construction and carries no identity at all.
const hubDigestLen = 16

// ownerOnlyFileMask is every permission bit outside the owner's. FR-004 refuses
// a fallback credential file with any of them set: those bits are a token
// somebody else can read.
const ownerOnlyFileMask fs.FileMode = 0o077

// othersWritableDirMask is the group and other WRITE bits. A directory anybody
// else can write is a directory in which the credential file can be replaced,
// which is a way to hand amctl a token of someone else's choosing. Read bits on
// the directory are not checked: the file itself is owner-only, and refusing an
// 0755 directory would refuse the default on many systems for no gain.
const othersWritableDirMask fs.FileMode = 0o022

// ErrNoStore marks a machine where no credential backend would open at all.
var ErrNoStore = errors.New("no credential store is available")

// ErrFileMode marks a fallback credential file or directory amctl refuses to
// use because someone other than its owner can reach it (FR-004).
var ErrFileMode = errors.New("credential file permissions are too wide")

// Warnf reports something the user must know about a run that still succeeds.
// internal/cmd passes output.Streams.Warnf, which prefixes "warning: " and
// writes to the diagnostic stream — FR-003's "on stderr, never silently".
type Warnf func(format string, args ...any)

// Options configures Open.
type Options struct {
	// StateRoot is amctl's state root, `~/.agent-manager` (cmd.Home.Root).
	// Required: the file fallback lives in <StateRoot>/credentials.
	StateRoot string

	// Warnf receives the FR-003 fallback report. A nil Warnf DROPS the
	// warning, which is right for a test asserting something else and wrong
	// everywhere else; production must pass one.
	Warnf Warnf

	// Backends overrides the order Open tries. Nil means AllowedBackends().
	Backends []keyring.BackendType

	// goos and available exist so the fallback message for a platform can be
	// exercised from a test running on another one. R1's whole point is that
	// the darwin message is the one most likely to be wrong, and no darwin
	// machine was available to write it on.
	goos      string
	available []keyring.BackendType
}

// Store is amctl's per-hub credential store: one keyring backend, chosen and
// named at Open.
type Store struct {
	ring    keyring.Keyring
	backend keyring.BackendType
	fileDir string
}

// AllowedBackends is the backend order amctl permits, in keyring's own
// preference order.
//
// It is Available() minus one: **keyctl is excluded**. The kernel keyring is
// not durable storage — the user keyring is memory-only, gone at reboot and
// gone when the last process of the uid exits — and it sits AHEAD of `pass` and
// the file in keyring's order, so leaving it in would mean that on any Linux
// box without a running Secret Service `amctl login` succeeds, reports a store,
// and then loses the token with no event of any kind. A file the user can see
// is a better answer than a store that silently empties. Note that leaving
// Options.KeyCtlScope unset would have excluded keyctl too, by making its
// opener fail with `unknown scope ""` — which is precisely why the exclusion is
// written down instead of left to a zero value nobody would recognise as a
// decision.
//
// `pass` is NOT excluded: it is durable, GPG-encrypted, and a Mac or Linux
// developer who has it installed chose it. It is, per R1, what a CGO_ENABLED=0
// darwin build actually lands on, so the FR-003 warning has to be able to name
// it rather than pretend the fallback is always a file.
func AllowedBackends() []keyring.BackendType {
	return allowedFrom(Available())
}

func allowedFrom(available []keyring.BackendType) []keyring.BackendType {
	out := make([]keyring.BackendType, 0, len(available))
	for _, b := range available {
		if b == keyring.KeyCtlBackend {
			continue
		}
		out = append(out, b)
	}
	return out
}

// Open selects a credential store and reports a fallback on the way (FR-003).
//
// keyring.Open cannot be asked which backend it picked — the concrete types are
// unexported and it returns the bare Keyring interface — so this walks the
// order one backend at a time and keeps the name of the one that opened. That
// is the whole reason this function is not a single keyring.Open call, and
// without it FR-003's "never silently" is unimplementable: there would be
// nothing to name.
//
// What Open deliberately does NOT do: it does not refuse a build whose platform
// store is missing. VerifyCurrent (backends.go) is the gate for that and it is
// a build-time gate; refusing at run time would leave a user of a static darwin
// binary with no way to log in at all, which is worse than a loud warning and a
// `pass` or file store. It also never infers the backend from runtime.GOOS —
// the choice comes from what actually opened.
func Open(opts Options) (*Store, error) {
	if opts.StateRoot == "" {
		return nil, errors.New("credentials: no state root given; pass cmd.Home.Root")
	}
	goos := opts.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	available := opts.available
	if available == nil {
		available = Available()
	}
	order := opts.Backends
	if order == nil {
		order = allowedFrom(available)
	}

	fileDir := filepath.Join(opts.StateRoot, DirName)
	// 0700 up front rather than letting keyring's file backend MkdirAll it:
	// keyring only creates the directory when it is absent, so an existing
	// directory keeps whatever mode it has, and checkDirMode below is what
	// notices. Creating it here also means the FR-003 warning can name a path
	// that exists.
	if err := os.MkdirAll(fileDir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the credential directory %s: %w", fileDir, err)
	}

	cfg := keyring.Config{
		ServiceName: ServiceName,

		// The default login keychain, not a keychain of our own: creating one
		// needs a passphrase, and a passphrase needs a prompt (FR-037).
		KeychainName: "",
		// Trust the calling binary on the item it creates, so a later read
		// does not raise the macOS "allow access" dialog on a machine with no
		// human at it. This is the FR-037 trade-off stated: amctl asks for
		// broad access once, at store time, rather than being unusable
		// non-interactively.
		KeychainTrustApplication: true,
		// Never sync a machine-bound device token to iCloud. Explicit because
		// it is a security decision, not because false is not the default.
		KeychainSynchronizable: false,
		// The token is unreadable while the machine is locked. Stricter than
		// the alternative and costs a CLI nothing.
		KeychainAccessibleWhenUnlocked: true,
		KeychainPasswordFunc:           refuseToPrompt,

		LibSecretCollectionName: libSecretCollection,

		// FilePasswordFunc is REQUIRED by keyring's file backend and it is a
		// prompt. amctl returns the empty passphrase, deliberately:
		//
		//   - FR-037 forbids an interactive prompt without a flag, and there is
		//     no flag for this, so prompting is not an option.
		//   - A hardcoded non-empty constant would be worse than empty. It
		//     would look like encryption while being a key published in this
		//     source file, and it would make the file undecryptable by any
		//     other tool for no security gain.
		//   - The confidentiality boundary for the fallback is therefore the
		//     FILE MODE, which is exactly what FR-003 and FR-004 describe:
		//     "readable and writable only by its owner", enforced here by
		//     checkFileMode both on read and on write.
		//
		// What is deliberately NOT offered: a passphrase environment variable.
		// An unspecified knob that changes how an existing file decrypts turns
		// a stored credential unreadable the moment it is unset, and the
		// failure looks like a corrupt store. Add it behind an explicit flag if
		// it is ever wanted.
		FilePasswordFunc: emptyPassphrase,
		FileDir:          fileDir,

		PassPrefix: ServiceName,
		// PassDir is left empty on purpose: keyring then honours
		// PASSWORD_STORE_DIR or ~/.password-store, which is the user's own
		// store and not ours to relocate.

		WinCredPrefix: keyPrefix,
	}

	var (
		chosen keyring.BackendType
		ring   keyring.Keyring
		tried  []keyring.BackendType
	)
	for _, b := range order {
		one := cfg
		one.AllowedBackends = []keyring.BackendType{b}
		opened, err := keyring.Open(one)
		if err != nil {
			// keyring.Open DISCARDS the opener's error and returns
			// ErrNoAvailImpl, so there is no reason to record here — only the
			// fact that this backend did not open. fallbackWarning says so
			// rather than inventing a cause.
			tried = append(tried, b)
			continue
		}
		ring, chosen = opened, b
		break
	}
	if ring == nil {
		return nil, fmt.Errorf("%w: none of %v would open on this %s machine", ErrNoStore, order, goos)
	}

	s := &Store{ring: ring, backend: chosen, fileDir: fileDir}
	if opts.Warnf != nil {
		if msg := fallbackWarning(goos, available, tried, chosen, fileDir); msg != "" {
			opts.Warnf("%s", msg)
		}
	}
	return s, nil
}

// emptyPassphrase is the file backend's non-prompt. See Open's FilePasswordFunc
// comment for why it is empty and why that is a decision rather than a default.
func emptyPassphrase(string) (string, error) { return "", nil }

// refuseToPrompt is wired where keyring would otherwise ask a human something
// amctl has no flag for (FR-037). It is unreachable with the config above —
// KeychainName is empty, so keychain never creates a keychain — and it is set
// anyway so that a future config change fails with a sentence instead of a nil
// dereference.
func refuseToPrompt(prompt string) (string, error) {
	return "", fmt.Errorf("the credential store asked for a passphrase (%q) and amctl has no flag to supply one; unlock it first", prompt)
}

// Backend is the backend that actually opened.
func (s *Store) Backend() keyring.BackendType { return s.backend }

// Location is the phrase a result renders in its `store` field.
func (s *Store) Location() string {
	if s.backend == keyring.FileBackend {
		return fmt.Sprintf("file (%s)", s.fileDir)
	}
	return string(s.backend)
}

// Save writes the credential for c.Hub, replacing any existing one.
func (s *Store) Save(c Credential) error {
	if c.fromEnv {
		// FR-005: a token from the environment is never persisted. The check is
		// here, on the field only this package can set, so that no caller can
		// resolve a credential and then store it by accident.
		return fmt.Errorf("refusing to persist the token from %s: an environment token is used, never stored", TokenEnvVar)
	}
	if c.Hub == "" {
		return errors.New("cannot store a credential with no hub")
	}
	if c.Token == "" {
		return fmt.Errorf("cannot store an empty token for %s", c.Hub)
	}

	key := itemKey(c.Hub)
	if err := s.checkFileMode(key); err != nil {
		return err
	}

	blob, err := encodeCredential(c)
	if err != nil {
		return fmt.Errorf("cannot encode the credential for %s: %w", c.Hub, err)
	}
	item := keyring.Item{
		Key: key,
		// Label and Description are what a human sees in Keychain Access or
		// seahorse. The hub URL is in there so two hubs are distinguishable;
		// the token is not, and must never be (FR-007).
		Label:       ServiceName + " token for " + c.Hub,
		Description: "agent-manager hub bearer token",
		Data:        blob,
	}
	if err := s.ring.Set(item); err != nil {
		return fmt.Errorf("cannot store the credential for %s in the %s credential store: %w", c.Hub, s.backend, err)
	}

	// A post-condition, not a formality. keyring's file backend creates the
	// file with os.WriteFile(..., 0600) — and because open(2) MASKS the mode
	// argument with the umask, the result is always a subset of 0600 and never
	// wider, so there is no create-then-chmod window to lose a race in. What
	// there IS is a library that could change; if it ever does, the token has
	// already been written by the time we find out, so the file is removed
	// rather than left readable.
	if err := s.checkFileMode(key); err != nil {
		if s.backend == keyring.FileBackend {
			_ = s.ring.Remove(key)
		}
		return fmt.Errorf("stored the credential for %s and then refused it: %w", c.Hub, err)
	}
	return nil
}

// Check reports whether this store can hold the credential for hubURL, without
// reading or writing one. It is the FR-004 mode gate on its own, for a caller
// that is about to do something expensive and irreversible.
//
// Open deliberately does not run it — opening a store is not the same as
// touching one hub's item, and hub B's over-permissive fallback file is no
// reason to fail a verb that only ever writes hub A — so before this existed the
// first check a login performed was the one inside Save. Measured: with a 0644
// file already present for the hub (a restore from backup, an `rsync` without
// -p, a container COPY — keyring itself always creates 0600), `amctl login`
// printed the user code, waited, the human approved, the device grant was
// consumed, and only THEN did it refuse. The approval was spent on a token that
// was never stored and the wide file was still there holding the old one.
//
// It answers for the file backend only, like checkFileMode, and for the same
// reason: on a static darwin build the fallback is `pass` (R1), whose
// permissions are the GPG store's business.
func (s *Store) Check(hubURL string) error {
	if hubURL == "" {
		return errors.New("cannot check a credential store without a hub")
	}
	return s.checkFileMode(itemKey(hubURL))
}

// Load reads the credential for hubURL. The bool is false when there is none,
// which is not an error: a machine that has never logged in is a normal state.
func (s *Store) Load(hubURL string) (Credential, bool, error) {
	if hubURL == "" {
		return Credential{}, false, errors.New("cannot load a credential without a hub")
	}
	key := itemKey(hubURL)
	if err := s.checkFileMode(key); err != nil {
		return Credential{}, false, err
	}

	item, err := s.ring.Get(key)
	if err != nil {
		if isMissing(err) {
			return Credential{}, false, nil
		}
		return Credential{}, false, fmt.Errorf("cannot read the credential for %s from the %s credential store: %w", hubURL, s.backend, err)
	}
	c, err := decodeCredential(item.Data, hubURL)
	if err != nil {
		return Credential{}, false, err
	}
	return c, true, nil
}

// Delete removes the credential for hubURL (FR-008). The bool reports whether
// there was one; removing a credential that is not there is SUCCESS, because
// `amctl logout` run twice, or run on a machine that never logged in, is a
// reasonable thing to do and must not fail.
//
// It deliberately does NOT check the file mode first. An over-permissive
// fallback file is precisely the thing a user should be able to delete, and
// refusing to remove it would leave the only remedy outside amctl.
func (s *Store) Delete(hubURL string) (bool, error) {
	if hubURL == "" {
		return false, errors.New("cannot delete a credential without a hub")
	}
	if err := s.ring.Remove(itemKey(hubURL)); err != nil {
		if isMissing(err) {
			return false, nil
		}
		return false, fmt.Errorf("cannot remove the credential for %s from the %s credential store: %w", hubURL, s.backend, err)
	}
	return true, nil
}

// isMissing reports whether err means "there was nothing there".
//
// Two cases, because the backends disagree and only one of them is documented:
// most return keyring.ErrKeyNotFound, but the FILE backend's Remove passes
// os.Remove's ENOENT straight through. Treating only the first as absence makes
// `logout` fail on exactly the platform where the fallback is in use — measured
// against keyring v1.2.2, not assumed.
func isMissing(err error) bool {
	return errors.Is(err, keyring.ErrKeyNotFound) || errors.Is(err, fs.ErrNotExist)
}

// itemKey is the per-hub item key (FR-006): a readable prefix plus 16 hex
// characters of SHA-256 over the canonical hub URL.
//
// The digest is what makes it injective and what keeps a hub URL's punctuation
// out of a filename; the prefix is what makes `~/.agent-manager/credentials`
// and a keychain listing readable. The prefix carries NO identity — it is lossy
// on purpose, two hubs may share one, and nothing may parse or compare it.
//
// This is deliberately NOT cmd.Hub.Dir, and not a shared helper with it. The
// two names live in different namespaces (a directory under the state root
// versus an item key inside a store), nothing ever compares one to the other,
// and internal/cmd imports this package — so sharing the derivation would close
// an import cycle. Both are injective functions of the same canonical URL,
// which is the only property either needs.
func itemKey(hubURL string) string {
	sum := sha256.Sum256([]byte(hubURL))
	return keyPrefix + readablePrefix(hubURL) + "-" + hex.EncodeToString(sum[:])[:hubDigestLen]
}

// readablePrefix maps a hub URL to at most readablePrefixLen characters of
// [a-z0-9-]. Everything else collapses to a single dash, which is what keeps
// the key usable as a filename on every platform and as a `pass` entry name:
// no slash, no colon, no percent for keyring's own escaping to act on.
func readablePrefix(hubURL string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(hubURL, "https://"), "http://")
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			dash = b.Len() > 0
			continue
		}
		if dash {
			b.WriteByte('-')
			dash = false
		}
		if b.Len() >= readablePrefixLen {
			break
		}
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

// filePath is the path keyring's file backend uses for key.
//
// keyring escapes only "/" in a key (github.com/mtibben/percent, via
// filenameEscape), and itemKey never emits one, so this is the identity
// mapping. That is an assumption about another module's internals, so it is
// ASSERTED rather than trusted: TestTheFileFallbackWritesThePathWePredict
// proves keyring puts the item exactly here. A wrong prediction would not throw
// an error — it would make checkFileMode stat a file that does not exist and
// pass, silently disabling FR-004.
func (s *Store) filePath(key string) string { return filepath.Join(s.fileDir, key) }

// checkFileMode enforces FR-004 on the fallback file and on the directory
// holding it, before a read and before a write.
//
// It REFUSES rather than repairing. A silent chmod would narrow a file the user
// may have widened on purpose, would hide the fact that the token has been
// exposed since whenever the mode changed, and cannot be right for a file that
// turns out to be a symlink to something else. The refusal names the path and
// the two commands that fix it.
//
// One thing it is NOT responsible for: the fallback file's WRITE and UNLINK go
// through keyring's own plain-`os` calls (os.WriteFile, os.Remove), so the
// Windows sharing semantics that make `os.Root` mandatory elsewhere in this
// module do not apply here and could not be fixed from this package anyway.
// Windows reaches the file backend only if `wincred` fails to open, which it
// does not, so the exposure is a Linux and macOS path in practice.
//
// It applies ONLY when the file backend is the one in use. On a static darwin
// build the chosen fallback is `pass` (R1), whose permissions are the GPG
// store's business, and inferring "we must be using a file" from
// runtime.GOOS — or from the fact that a fallback happened at all — is exactly
// the mistake that would make this check silently vacuous.
func (s *Store) checkFileMode(key string) error {
	if s.backend != keyring.FileBackend {
		return nil
	}

	if info, err := os.Stat(s.fileDir); err == nil {
		if perm := info.Mode().Perm(); perm&othersWritableDirMask != 0 {
			return fmt.Errorf("%w: %s is mode %#o, which lets another user replace the credential in it; run `chmod 700 %s`",
				ErrFileMode, s.fileDir, perm, s.fileDir)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cannot check the permissions of %s: %w", s.fileDir, err)
	}

	path := s.filePath(key)
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Nothing stored yet. keyring creates it 0600 and open(2) masks that
		// with the umask, so the result can only be narrower.
		return nil
	case err != nil:
		return fmt.Errorf("cannot check the permissions of %s: %w", path, err)
	}

	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink, which amctl will not follow to a credential; remove it and run `amctl login` again",
			ErrFileMode, path)
	}
	if perm := info.Mode().Perm(); perm&ownerOnlyFileMask != 0 {
		return fmt.Errorf("%w: %s is mode %#o and must be readable and writable only by you; run `chmod 600 %s`, or `amctl logout` and log in again",
			ErrFileMode, path, perm, path)
	}
	return nil
}
