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

const DirName = "credentials" // file fallback dir under state root, not per-hub

const ServiceName = "amctl" // what a human sees in Keychain Access or seahorse

// libSecretCollection is the login keyring GNOME unlocks at boot, not a
// private one: creating a missing collection is an interactive dialog.
const libSecretCollection = "login"

const keyPrefix = "amctl-hub-" // labels items so a shared store shows what wrote them

const readablePrefixLen = 24 // bounds the human-readable half of an item key

const hubDigestLen = 16 // hex chars of SHA-256 carrying hub identity; 64 bits, injective

const ownerOnlyFileMask fs.FileMode = 0o077 // any of these bits set means someone else can read the token

// othersWritableDirMask: a directory anyone else can write lets the file be
// replaced. Read bits aren't checked; refusing default 0755 buys nothing.
const othersWritableDirMask fs.FileMode = 0o022

var ErrNoStore = errors.New("no credential store is available")
var ErrFileMode = errors.New("credential file permissions are too wide")

type Warnf func(format string, args ...any) // internal/cmd passes output.Streams.Warnf

type Options struct {
	StateRoot string // required: the file fallback lives in <StateRoot>/credentials

	Warnf Warnf // nil drops the fallback report; production must pass one

	Backends []keyring.BackendType // nil means AllowedBackends()

	// goos and available let a test exercise another platform's fallback
	// message; no darwin machine was available to write that message on.
	goos      string
	available []keyring.BackendType
}

type Store struct { // one keyring backend, chosen and named at Open
	ring    keyring.Keyring
	backend keyring.BackendType
	fileDir string
}

// AllowedBackends is Available() minus keyctl: the kernel keyring is
// memory-only (gone at reboot, gone when the uid's last process exits) and
// ranks ahead of `pass`/file, so a headless Linux box would silently lose
// the token with no event at all. `pass` stays in: it's durable and what a
// CGO_ENABLED=0 darwin build actually lands on.
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

// Open walks the backend order one at a time, since keyring.Open cannot be
// asked which backend it picked (unexported concrete types, bare interface
// returned). It does not refuse a build whose platform store is missing —
// that's VerifyCurrent's job at build time — since refusing here would
// leave a static darwin binary user with no way to log in at all.
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
	// 0700 up front: keyring only MkdirAlls when the dir is absent, so an
	// existing dir keeps its mode and checkFileMode below is what notices.
	if err := os.MkdirAll(fileDir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the credential directory %s: %w", fileDir, err)
	}

	cfg := keyring.Config{
		ServiceName: ServiceName,

		KeychainName:                   "",    // default login keychain; a private one needs a passphrase prompt
		KeychainTrustApplication:       true,  // trust this binary so a later read skips the "allow access" dialog
		KeychainSynchronizable:         false, // never sync a machine-bound token to iCloud
		KeychainAccessibleWhenUnlocked: true,
		KeychainPasswordFunc:           refuseToPrompt,

		LibSecretCollectionName: libSecretCollection,

		// FilePasswordFunc must return something; amctl has no interactive
		// prompt, and a hardcoded non-empty constant would look like
		// encryption while being a key published in this file. checkFileMode
		// is the real confidentiality boundary for the fallback, not this.
		FilePasswordFunc: emptyPassphrase,
		FileDir:          fileDir,

		PassPrefix: ServiceName,
		// PassDir stays empty: keyring then honours PASSWORD_STORE_DIR or
		// ~/.password-store, the user's own store, not ours to relocate.
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
			tried = append(tried, b) // keyring discards the real error; only the fact of failure survives
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

func emptyPassphrase(string) (string, error) { return "", nil }

// refuseToPrompt is unreachable today (KeychainName is empty, so keychain
// never creates one) but set anyway so a future config change fails loudly
// instead of nil-dereferencing.
func refuseToPrompt(prompt string) (string, error) {
	return "", fmt.Errorf("the credential store asked for a passphrase (%q) and amctl has no flag to supply one; unlock it first", prompt)
}

func (s *Store) Backend() keyring.BackendType { return s.backend }

func (s *Store) Location() string {
	if s.backend == keyring.FileBackend {
		return fmt.Sprintf("file (%s)", s.fileDir)
	}
	return string(s.backend)
}

func (s *Store) Save(c Credential) error {
	if c.fromEnv { // set only by this package, so no caller can store an env-sourced token by accident
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
		Key:         key,
		Label:       ServiceName + " token for " + c.Hub, // shown in Keychain Access/seahorse; never the token
		Description: "agent-manager hub bearer token",
		Data:        blob,
	}
	if err := s.ring.Set(item); err != nil {
		return fmt.Errorf("cannot store the credential for %s in the %s credential store: %w", c.Hub, s.backend, err)
	}

	// Post-condition, not formality: if the library's file mode ever
	// changes, the token is already written by the time this notices, so
	// remove it rather than leave it readable.
	if err := s.checkFileMode(key); err != nil {
		if s.backend == keyring.FileBackend {
			_ = s.ring.Remove(key)
		}
		return fmt.Errorf("stored the credential for %s and then refused it: %w", c.Hub, err)
	}
	return nil
}

// Check exists so `amctl login` can refuse before spending a device-grant
// approval on a token that would fail to save; Open itself doesn't run this,
// since hub B's bad file mode is no reason to fail a verb writing hub A.
func (s *Store) Check(hubURL string) error {
	if hubURL == "" {
		return errors.New("cannot check a credential store without a hub")
	}
	return s.checkFileMode(itemKey(hubURL))
}

// Load's bool is false for "none", not an error: never logged in is normal.
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

// Delete never checks the file mode first: an over-permissive fallback file
// is precisely what a user should be able to delete regardless.
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

// isMissing: most backends return keyring.ErrKeyNotFound, but the file
// backend's Remove passes os.Remove's ENOENT straight through.
func isMissing(err error) bool {
	return errors.Is(err, keyring.ErrKeyNotFound) || errors.Is(err, fs.ErrNotExist)
}

// itemKey is a readable prefix plus a SHA-256 digest of the hub URL: the
// digest is what makes it injective, the prefix is lossy on purpose and
// carries no identity. Deliberately not shared with cmd.Hub.Dir — sharing
// would close an import cycle, since internal/cmd imports this package.
func itemKey(hubURL string) string {
	sum := sha256.Sum256([]byte(hubURL))
	return keyPrefix + readablePrefix(hubURL) + "-" + hex.EncodeToString(sum[:])[:hubDigestLen]
}

// readablePrefix keeps the key usable as a filename and a `pass` entry name:
// [a-z0-9-] only, everything else collapsed to a single dash.
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

// filePath assumes keyring's identity mapping (it escapes only "/", which
// itemKey never emits) — asserted, not trusted: see
// TestTheFileFallbackWritesThePathWePredict. A wrong prediction wouldn't
// error, it would make checkFileMode stat a missing file and silently pass.
func (s *Store) filePath(key string) string { return filepath.Join(s.fileDir, key) }

// checkFileMode refuses rather than repairing: a silent chmod would hide
// that the token has been exposed, and is wrong outright for a symlink.
// Applies only to the file backend, never inferred from runtime.GOOS alone.
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
