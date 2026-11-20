package deliver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	if d.Home == nil {
		return errors.New("internal: no home to contain writes in")
	}
	c, err := d.Home.Contains(path)
	if err != nil {
		return err
	}
	dest := c.Resolved
	mode := fs.FileMode(0o600)
	if info, serr := os.Stat(dest); serr == nil {
		mode = info.Mode().Perm()
	}
	if mkErr := os.MkdirAll(filepath.Dir(dest), 0o750); mkErr != nil {
		return mkErr
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
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
