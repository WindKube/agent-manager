package deliver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/WindKube/agent-manager/cli/internal/apply"
)

// canonical fingerprints a decoded JSON or TOML value: object keys sorted, no
// whitespace, so reformatting an entry is not an edit and changing it is.
func canonical(v any) (string, error) {
	b, err := marshalJSON(v)
	if err != nil {
		return "", err
	}
	return sum(b), nil
}

func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func marshalIndentJSON(v any, prefix, indent string) ([]byte, error) {
	b, err := marshalJSON(v)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, prefix, indent); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// readConfig returns a config file's bytes; nil, nil when it does not exist.
func (d *Deliverer) readConfig(path string) ([]byte, error) {
	if _, err := d.contained(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) //nolint:gosec // contained in the home just above
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// writeConfig replaces a config file atomically, through a symlink that stays
// inside the home, keeping the file's mode (0600 for a new one).
func (d *Deliverer) writeConfig(path string, data []byte) error {
	c, err := d.containedPath(path)
	if err != nil {
		return err
	}
	return atomicWrite(c.Resolved, data, 0o600)
}

// writeFile replaces a file atomically, replacing a symlink rather than
// writing through it.
func (d *Deliverer) writeFile(path string, data []byte, newMode fs.FileMode) error {
	c, err := d.containedPath(path)
	if err != nil {
		return err
	}
	return atomicWrite(c.Dest, data, newMode)
}

func (d *Deliverer) containedPath(path string) (apply.Contained, error) {
	if d.Home == nil {
		return apply.Contained{}, errors.New("internal: no home to contain writes in")
	}
	return d.Home.Contains(path)
}

func atomicWrite(dest string, data []byte, mode fs.FileMode) error {
	if info, err := os.Lstat(dest); err == nil && info.Mode().IsRegular() {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".amctl-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return fmt.Errorf("replace %s: %w", dest, err)
	}
	return nil
}
