package credentials

import (
	"runtime"
	"testing"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/require"
)

// compiledIn is hand-derived from keyring's build constraints, not observed from a run, which would
// encode a CGO_ENABLED regression as the expectation.
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

// A static darwin build silently promotes pass, then file; the guard exists to reject this.
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
