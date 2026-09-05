// Package credentials selects and guards the store amctl keeps a hub token in.
package credentials

import (
	"fmt"
	"runtime"

	"github.com/99designs/keyring"
)

// Available reads keyring's own registry rather than a build-constraint
// mirror kept here, which could drift after a library upgrade. Compiled-in
// is not the same as reachable (e.g. secret-service on a headless box).
func Available() []keyring.BackendType {
	return keyring.AvailableBackends()
}

// required is the backend set a shippable build must have, per GOOS; CGO
// isn't a separate axis since darwin's toolchain is the only one that can
// silently drop it (keychain.go is behind `darwin && cgo`).
var required = map[string][]keyring.BackendType{
	"darwin": {keyring.KeychainBackend},
	"linux":  {keyring.SecretServiceBackend},
}

// Verify refuses a build whose platform credential store was dropped at
// compile time (on darwin, CGO_ENABLED=0 silently falls back to `pass` or a
// file); file/pass backends are the sanctioned fallback, so not required.
func Verify(goos string, available []keyring.BackendType) error {
	want, ok := required[goos]
	if !ok {
		return fmt.Errorf("no required credential backend recorded for GOOS %q: add it to the R1 table before shipping the platform", goos)
	}

	have := make(map[keyring.BackendType]bool, len(available))
	for _, b := range available {
		have[b] = true
	}

	for _, b := range want {
		if !have[b] {
			return fmt.Errorf("keyring backend %q is not compiled into this %s build (available: %v): the platform credential store is missing, most likely built with CGO_ENABLED=0", b, goos, available)
		}
	}
	return nil
}

func VerifyCurrent() error {
	return Verify(runtime.GOOS, Available())
}
