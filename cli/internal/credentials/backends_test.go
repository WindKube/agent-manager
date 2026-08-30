package credentials

import (
	"runtime"
	"testing"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/require"
)

// compiledIn is the exact backend set, in keyring's own try-order, that a
// release build must expose per GOOS. Hand-derived from keyring v1.2.2 —
// `keyring.backendOrder` intersected with the files the toolchain compiles for
// each platform — and NOT from observing a run, which would encode a
// CGO_ENABLED regression as the expectation:
//
//	keychain.go       darwin && cgo
//	secretservice.go  linux
//	kwallet.go        linux
//	keyctl.go         linux
//	pass.go           !windows
//	file.go           (none)
//
// darwin therefore requires cgo to reach this set; linux does not.
var compiledIn = map[string][]keyring.BackendType{
	"darwin": {
		keyring.KeychainBackend,
		keyring.PassBackend,
		keyring.FileBackend,
	},
	"linux": {
		keyring.SecretServiceBackend,
		keyring.KWalletBackend,
		keyring.KeyCtlBackend,
		keyring.PassBackend,
		keyring.FileBackend,
	},
}

// A static darwin build loses keychain.go and keyring silently promotes pass,
// then file. This is the measured set from the R1 gate (`go list -json` GoFiles
// and the itabs in a cross-built darwin/arm64 binary), and it is the input the
// guard exists to reject.
var darwinWithoutCGO = []keyring.BackendType{
	keyring.PassBackend,
	keyring.FileBackend,
}

func TestCompiledInBackendSetIsTheOneThisPlatformShouldHave(t *testing.T) {
	want, ok := compiledIn[runtime.GOOS]
	require.True(t, ok, "no expected backend set recorded for GOOS %q", runtime.GOOS)

	require.Equal(t, want, Available(),
		"the compiled-in keyring backends are not the expected set for %s; "+
			"on darwin this means the build lost the keychain (CGO_ENABLED=0) and "+
			"every token would go to pass or a file instead",
		runtime.GOOS)
}

func TestVerifyCurrentAcceptsThisBuild(t *testing.T) {
	require.NoError(t, VerifyCurrent())
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name      string
		goos      string
		available []keyring.BackendType
		wantErr   string
	}{
		{
			name:      "a cgo darwin build keeps the keychain",
			goos:      "darwin",
			available: compiledIn["darwin"],
		},
		{
			name:      "a static darwin build is refused by name",
			goos:      "darwin",
			available: darwinWithoutCGO,
			wantErr:   `keyring backend "keychain" is not compiled into this darwin build`,
		},
		{
			name:      "the refusal names CGO_ENABLED as the likely cause",
			goos:      "darwin",
			available: darwinWithoutCGO,
			wantErr:   "most likely built with CGO_ENABLED=0",
		},
		{
			name:      "a linux build keeps secret-service either way",
			goos:      "linux",
			available: compiledIn["linux"],
		},
		{
			name:      "a build with only the file fallback is refused",
			goos:      "linux",
			available: []keyring.BackendType{keyring.FileBackend},
			wantErr:   `keyring backend "secret-service" is not compiled into this linux build`,
		},
		{
			// windows is here rather than in `required` on purpose: amctl does
			// not ship it, and the guard's job is to fail the build rather than
			// let an unsupported platform through on a default.
			name:      "windows is not a supported platform and is refused",
			goos:      "windows",
			available: []keyring.BackendType{keyring.WinCredBackend, keyring.FileBackend},
			wantErr:   `no required credential backend recorded for GOOS "windows"`,
		},
		{
			name:      "an unrecorded platform is refused rather than passed",
			goos:      "freebsd",
			available: compiledIn["linux"],
			wantErr:   `no required credential backend recorded for GOOS "freebsd"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(tt.goos, tt.available)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
