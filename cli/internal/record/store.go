package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	fileMode = 0o600
	dirMode  = 0o700

	// tempPrefix marks a partial write of ours. It starts with a dot so it is
	// hidden, and it can never be a prefix of FileName, so a leftover temp is
	// not mistakable for the record and the record is never swept up as a
	// leftover.
	tempPrefix = "." + FileName + ".amctl-tmp-"
)

// ErrCorrupt marks a record file that could not be read as a record: truncated
// JSON, a wrong shape, an unreadable field.
//
// It is deliberately NOT the same outcome as an absent file. An absent record
// means "prune nothing, install everything", which is the right reading of a
// machine that has never synced. Reading a CORRUPT record that way would tell
// prune it has nothing to remove while a whole installed tree sits on disk —
// which FR-028 then makes permanently unremovable, since the directory listing
// that would find it again is exactly what FR-028 forbids. So corruption
// refuses, with the path in the message, and the user fixes or deletes the
// file.
var ErrCorrupt = errors.New("unreadable installation record")

// ErrSchemaVersion marks a record stamped with a schema version this build
// does not understand. Refused with a message and never a panic, and never
// migrated in place: a newer record read by an older CLI is a downgrade, and
// silently rewriting it at the older version would drop whatever the newer one
// knew — including, in the worst case, a destination path that then becomes
// unremovable.
var ErrSchemaVersion = errors.New("installation record schema version is not supported")

// ErrHubMismatch marks a record that belongs to a different hub. Two hubs get
// two directories, so this normally means the directory was moved, copied
// between machines, or a hub's URL changed. Refusing is not pedantry: the
// record is the authority for what may be removed, so applying hub A's record
// to hub B's tree is a deletion with no evidence behind it.
var ErrHubMismatch = errors.New("installation record belongs to a different hub")

// Path is the record's path inside an already-resolved per-hub directory:
// `~/.agent-manager/<hub>/state.json`.
//
// This is the seam with internal/cmd, which owns the hub-URL-to-directory-name
// function and the canonical URL form (T023). Both halves of hub identity live
// there, in one place: the directory a record is read from, and the string it
// is checked against. This package takes the directory as an argument and
// compares the URL by exact equality, so there is no second opinion here to
// drift from that one.
func Path(hubDir string) string { return filepath.Join(hubDir, FileName) }

// Load reads the record at path and refuses it unless it belongs to hub.
//
// An absent file is an EMPTY RECORD AND NOT AN ERROR — a machine that has
// never synced this hub is a normal state, and the empty record is exactly the
// right description of it. Every other failure is an error naming path: a
// truncated or otherwise unreadable file (ErrCorrupt), an unrecognised schema
// version (ErrSchemaVersion), a record for another hub (ErrHubMismatch), or a
// record whose contents amctl could not have written (ErrInvalid).
//
// All four are refusals a user can fix, so the calling verb wraps them with
// internal/cmd.Refuse to reach FR-036's refusal exit code. That wrapping is
// the caller's because internal/cmd imports this package and cannot be
// imported back.
func Load(path, hub string) (*Record, error) {
	if hub == "" {
		return nil, errors.New("refusing to load an installation record without an expected hub URL")
	}
	b, err := readRecordFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return New(hub), nil
		}
		return nil, fmt.Errorf("reading installation record %s: %w", path, err)
	}

	// The schema version is read on its own first, so that a record from a
	// future format gets "schema version 7, this amctl understands 1" instead
	// of a field-by-field decode failure that reads like corruption. A pointer
	// distinguishes absent from zero: a file with no schemaVersion at all was
	// not written by any version of this CLI.
	var probe struct {
		SchemaVersion *int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrCorrupt, path, err)
	}
	if probe.SchemaVersion == nil {
		return nil, fmt.Errorf("%w %s: no schemaVersion field", ErrCorrupt, path)
	}
	if *probe.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: %s is version %d, this build reads version %d",
			ErrSchemaVersion, path, *probe.SchemaVersion, SchemaVersion)
	}

	// DisallowUnknownFields, at a version we claim to understand, because
	// amctl wrote every byte of this file: a field this build does not know,
	// under a version it does say it knows, means the file was edited or
	// corrupted. Dropping it silently would be worse than refusing — the next
	// Save rewrites the file without it, so the unknown information is
	// destroyed by the act of reading.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrCorrupt, path, err)
	}
	// Trailing content is corruption, not slack. A concatenated second
	// document is exactly what a partially overwritten file looks like.
	if dec.More() {
		return nil, fmt.Errorf("%w %s: trailing content after the record", ErrCorrupt, path)
	}

	if r.Hub != hub {
		return nil, fmt.Errorf("%w: %s records hub %q, this run is against %q",
			ErrHubMismatch, path, r.Hub, hub)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r.normalize()
	return &r, nil
}

// Save writes r to path atomically, and reports whether it actually wrote.
//
// It writes NOTHING when the encoded bytes are already what is on disk. That
// is what makes FR-025 — "a second run against an unchanged hub MUST make no
// filesystem modification" — true of the record as well as of the tree; without
// it, every idempotent sync would rewrite state.json and the claim would be
// false in the one place nobody looks. It is also why the record is normalised
// into a canonical order and why Profile.InstalledAt must not be refreshed on
// an unchanged sync.
//
// Ordering, which is the thing most likely to be "tidied": this is called
// AFTER the swap, never before. See the package comment.
//
// The write is temp-file, fsync, rename, fsync-directory, and each step is
// load bearing. Writing the final name in place is how a killed process leaves
// a truncated state.json — and a truncated record is the worst single file on
// the machine to lose, because it is the only authority for what may be
// removed. The temp name means an interrupted write is invisible to Load and
// the previous record is still there. The fsync of the temp is not decoration:
// on a delayed-allocation filesystem a crash just after the rename would
// otherwise leave the final name present and zero length, which is precisely
// the whole-looking truncated record the temp file exists to prevent.
func Save(path string, r *Record) (bool, error) {
	r.normalize()
	if err := r.Validate(); err != nil {
		return false, fmt.Errorf("refusing to write %s: %w", path, err)
	}

	// Indented and newline-terminated: this file is read by humans debugging a
	// prune, and a one-line 45 KB document is not.
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encoding installation record for %s: %w", path, err)
	}
	b = append(b, '\n')

	if existing, readErr := readRecordFile(path); readErr == nil && bytes.Equal(existing, b) {
		return false, nil
	}

	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, dirMode); mkErr != nil {
		return false, fmt.Errorf("creating hub directory %s: %w", dir, mkErr)
	}
	// Through an *os.Root, for the same measured reason as internal/cache: on
	// Windows os.Rename is MoveFileEx, which fails ERROR_ACCESS_DENIED when the
	// destination has an open handle, and os.Open does not pass
	// FILE_SHARE_DELETE so a concurrent reader creates one. Root.Rename is
	// NtSetInformationFile with FILE_RENAME_POSIX_SEMANTICS and Root.Open does
	// pass it, which is what makes the atomic swap below atomic rather than
	// occasionally failing. The Windows CI leg measured both halves:
	// TestNoReaderEverObservesATornRecord saw readers refused and the install
	// rename denied.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false, fmt.Errorf("opening hub directory %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return false, fmt.Errorf("creating installation record temp file in %s: %w", dir, err)
	}
	name := tmp.Name()
	base := filepath.Base(name)
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = root.Remove(base)
		}
	}()

	if err := tmp.Chmod(fileMode); err != nil {
		return false, fmt.Errorf("setting mode on %s: %w", name, err)
	}
	if _, err := tmp.Write(b); err != nil {
		return false, fmt.Errorf("writing %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		return false, fmt.Errorf("syncing %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("closing %s: %w", name, err)
	}
	if err := root.Rename(base, filepath.Base(path)); err != nil {
		return false, fmt.Errorf("installing installation record %s: %w", path, err)
	}
	committed = true

	syncDir(dir)
	collectTemps(dir)
	return true, nil
}

// readRecordFile reads the record through an *os.Root on its directory.
//
// Not os.ReadFile: os.Open on Windows omits FILE_SHARE_DELETE, so a reader
// holding the record open blocks the rename Save uses to install a new one —
// the reader and the writer break each other rather than the reader simply
// seeing the old bytes or the new ones. Root.Open passes FILE_SHARE_DELETE, so
// both sides behave the way the POSIX implementation always did.
//
// A missing directory reports fs.ErrNotExist, which both callers already treat
// the same as a missing file: a hub that has never been synced.
func readRecordFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(filepath.Base(path))
}

// syncDir makes the new directory entry durable. Non-fatal, matching gate R3's
// treatment of the same step in the swap: the record is already installed and
// correct, and a filesystem that refuses the fsync — some network mounts — must
// not fail an otherwise complete write.
func syncDir(dir string) {
	f, err := os.Open(dir) //nolint:gosec // the directory Save just wrote into
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_ = f.Sync()
}

// collectTemps removes leftover partial writes, best effort.
//
// The criterion is the name prefix and nothing else — no age heuristic, no PID
// liveness check. It needs neither, because a sync holds the per-home lock
// (FR-038, internal/cmd/lock.go) for its whole duration, so at the moment Save
// completes there is no other amctl process writing here and any temp file
// present belongs to a process that is gone. If that lock discipline is ever
// violated the cost is bounded: the other writer's rename fails with ENOENT
// and its Save returns an error, so a record is never left half-written or
// lost — one save is retried.
//
// A prefix match over a directory listing is acceptable HERE and forbidden in
// prune (FR-028) for a reason worth stating: amctl creates and owns
// `~/.agent-manager/<hub>/` entirely, so every name in it is one amctl wrote.
// An agent's skills directory is shared with the user's own hand-written
// files, which is why removal there walks this record instead. `state.json`
// itself can never match tempPrefix, so the record cannot collect itself.
func collectTemps(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		// Through the root: a temp belonging to a concurrent Save is still open,
		// and on Windows plain os.Remove would fail on it rather than defer the
		// unlink. Best effort either way — a leaked temp is collected next time.
		_ = root.Remove(e.Name())
	}
}
