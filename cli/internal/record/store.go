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

	// tempPrefix leads with a dot so it can never prefix-match FileName.
	tempPrefix = "." + FileName + ".amctl-tmp-"
)

// ErrCorrupt marks a record file that could not be read as a record —
// deliberately not the same outcome as an absent file, which means "prune
// nothing, install everything" and must not apply to a corrupt one.
var ErrCorrupt = errors.New("unreadable installation record")

// ErrSchemaVersion marks a schema version this build does not understand.
// Never migrated in place: rewriting a newer record at an older version
// would drop whatever the newer one knew.
var ErrSchemaVersion = errors.New("installation record schema version is not supported")

// ErrHubMismatch marks a record belonging to a different hub. Refused since
// the record is the removal authority: applying hub A's record to hub B's
// tree is a deletion with no evidence behind it.
var ErrHubMismatch = errors.New("installation record belongs to a different hub")

// Path is the record's path inside an already-resolved per-hub directory:
// `~/.agent-manager/<hub>/state.json`.
func Path(hubDir string) string { return filepath.Join(hubDir, FileName) }

// Load reads the record at path and refuses it unless it belongs to hub. An
// absent file is an empty record, not an error. Every other failure names
// path: ErrCorrupt, ErrSchemaVersion, ErrHubMismatch, or ErrInvalid.
func Load(path, hub string) (*Record, error) {
	if hub == "" {
		return nil, errors.New("refusing to load an installation record without an expected hub URL")
	}
	b, err := os.ReadFile(path) //nolint:gosec // path is record.Path of a validated hub directory
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return New(hub), nil
		}
		return nil, fmt.Errorf("reading installation record %s: %w", path, err)
	}

	// Read the schema version alone first, for a clear version mismatch
	// instead of a decode failure that reads like corruption.
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

	// DisallowUnknownFields: amctl wrote every byte, so an unknown field at a
	// version we claim to understand means the file was edited or corrupted.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrCorrupt, path, err)
	}
	// Trailing content is exactly what a partially overwritten file looks like.
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

// Save writes r to path atomically and reports whether it actually wrote —
// nothing, when the encoded bytes already match what's on disk, which is why
// the record is normalised first. Must be called after the swap, never
// before. Writes temp-file, fsync, rename, fsync-directory: the temp name
// keeps an interrupted write invisible to Load, and the fsync before rename
// stops a crash leaving the final name present but zero length.
func Save(path string, r *Record) (bool, error) {
	r.normalize()
	if err := r.Validate(); err != nil {
		return false, fmt.Errorf("refusing to write %s: %w", path, err)
	}

	b, err := json.MarshalIndent(r, "", "  ") // indented: humans debug a prune by reading this file
	if err != nil {
		return false, fmt.Errorf("encoding installation record for %s: %w", path, err)
	}
	b = append(b, '\n')

	if existing, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(existing, b) { //nolint:gosec // as above
		return false, nil
	}

	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, dirMode); mkErr != nil {
		return false, fmt.Errorf("creating hub directory %s: %w", dir, mkErr)
	}
	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return false, fmt.Errorf("creating installation record temp file in %s: %w", dir, err)
	}
	name := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(name)
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
	if err := os.Rename(name, path); err != nil {
		return false, fmt.Errorf("installing installation record %s: %w", path, err)
	}
	committed = true

	syncDir(dir)
	collectTemps(dir)
	return true, nil
}

// syncDir makes the new directory entry durable. Non-fatal: a filesystem
// that refuses the fsync (some network mounts) must not fail an otherwise
// complete write.
func syncDir(dir string) {
	f, err := os.Open(dir) //nolint:gosec // the directory Save just wrote into
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_ = f.Sync()
}

// collectTemps removes leftover partial writes, best effort, matching on the
// name prefix alone: a sync holds the per-home lock throughout, so any temp
// file present when Save completes belongs to a process that is gone.
func collectTemps(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		// Best effort — a leaked temp is collected next time.
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}
