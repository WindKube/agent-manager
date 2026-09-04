// Package credentials selects and guards the store amctl keeps a hub token
// in. This file is only the guard: it reports which keyring backends the
// running binary actually has and refuses a build that lost a secure one.
// It stores nothing.
package credentials

import (
	"fmt"
	"runtime"

	"github.com/99designs/keyring"
)

// Available reports the keyring backends compiled into this binary, in the
// order keyring itself would try them. It reads keyring's own registry
// rather than a mirror of its build constraints kept here, since a mirror
// can disagree with the library after an upgrade. It does not report
// whether a backend will actually open at run time (e.g. secret-service
// compiled in but unreachable on a headless box).
func Available() []keyring.BackendType {
	return keyring.AvailableBackends()
}

// required is the backend set a shippable amctl build must have, per GOOS.
// CGO does not appear here since the required set is the same either way by
// policy; darwin is the only platform where the toolchain can fail to
// deliver it, since keychain.go alone is behind `darwin && cgo`.
var required = map[string][]keyring.BackendType{
	"darwin": {keyring.KeychainBackend},
	"linux":  {keyring.SecretServiceBackend},
}

// Verify refuses a build whose platform credential store was dropped at
// compile time. On darwin that means CGO_ENABLED=0, whose only symptom at
// run time is that keyring silently falls back to `pass` or a file. It does
// not require the file or pass backends, since those are the sanctioned
// fallback present in every build. An unknown GOOS is an error, not a pass.
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

// VerifyCurrent applies Verify to the running binary.
func VerifyCurrent() error {
	return Verify(runtime.GOOS, Available())
}
