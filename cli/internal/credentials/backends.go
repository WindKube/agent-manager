// Package credentials selects and guards the store amctl keeps a hub token in.
//
// This file is only the guard: it reports which keyring backends the running
// binary actually has and refuses a build that lost a secure one. It stores
// nothing. FR-003's "never silently" is a property of the build as much as of
// the code — see the R1 gate.
package credentials

import (
	"fmt"
	"runtime"

	"github.com/99designs/keyring"
)

// Available reports the keyring backends compiled into THIS binary, in the
// order keyring itself would try them.
//
// It reads keyring's own registry — the same input keyring.Open consults — and
// not a mirror of keyring's build constraints kept here. A mirror can disagree
// with the library after an upgrade, and a guard that guards a copy guards
// nothing. What this does NOT report is whether a backend will *open*: on a
// headless Linux box secret-service is compiled in and still unreachable, and
// pass is compiled in on every build whether or not the `pass` binary exists. Compiled-in is a build fact; reachable is a run-time one, and
// only the first is this file's business.
func Available() []keyring.BackendType {
	return keyring.AvailableBackends()
}

// required is the backend set a shippable amctl build must have, per GOOS,
// hand-derived from keyring v1.2.2's build constraints (R1). Note that CGO does
// not appear: on both target platforms the required set is the same either way
// *by policy*, and darwin is the only one where the toolchain can fail to
// deliver it, because keychain.go alone is behind `darwin && cgo`.
var required = map[string][]keyring.BackendType{
	"darwin": {keyring.KeychainBackend},
	"linux":  {keyring.SecretServiceBackend},
}

// Verify refuses a build whose platform credential store was dropped at compile
// time. On darwin that means CGO_ENABLED=0, whose only symptom at run time is
// that keyring quietly writes the token to `pass` or to a file instead — the
// silent fallback FR-003 forbids.
//
// It deliberately does not require the file or pass backends: those are the
// sanctioned fallback and are present in every build. An unknown GOOS is an
// error, not a pass, so adding a platform to the release matrix without
// deciding what its store is fails here rather than shipping.
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
