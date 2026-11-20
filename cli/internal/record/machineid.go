package record

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// MachineIDFileName sits next to FileName. The id is random, generated
// once per hub, so it says nothing about the hardware or the user.
const MachineIDFileName = "machine-id"

// LoadMachineID returns the id kept in hubDir, generating and keeping one
// when there is none or it is unreadable as a uuid. Callers hold the lock.
func LoadMachineID(hubDir string) (uuid.UUID, error) {
	path := filepath.Join(hubDir, MachineIDFileName)
	b, err := os.ReadFile(path) //nolint:gosec // path is inside the validated hub directory
	switch {
	case err == nil:
		if id, perr := uuid.Parse(strings.TrimSpace(string(b))); perr == nil && id != uuid.Nil {
			return id, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return uuid.Nil, fmt.Errorf("reading %s: %w", path, err)
	}

	id := uuid.New()
	if err = os.MkdirAll(hubDir, dirMode); err != nil {
		return uuid.Nil, fmt.Errorf("creating %s: %w", hubDir, err)
	}
	tmp, err := os.CreateTemp(hubDir, ".machine-id-*")
	if err != nil {
		return uuid.Nil, fmt.Errorf("writing %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.WriteString(id.String() + "\n"); err != nil {
		_ = tmp.Close()
		return uuid.Nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return uuid.Nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return uuid.Nil, fmt.Errorf("writing %s: %w", path, err)
	}
	return id, nil
}
