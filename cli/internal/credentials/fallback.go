package credentials

import (
	"fmt"

	"github.com/99designs/keyring"
)

// fallbackHints say what usually stops a platform's own credential store
// from opening. They are hints, labelled as such in the message, since
// keyring.Open discards the opener's own error and amctl can only name
// which backend did not open, not why.
var fallbackHints = map[keyring.BackendType]string{
	keyring.SecretServiceBackend: "no Secret Service is running on the session bus (a headless or SSH session), or the login keyring is locked",
	keyring.KeychainBackend:      "the login keychain is locked, or access was denied",
}

// fallbackWarning reports a fallback, or "" when there is nothing to
// report. It names the backend that actually opened (a CGO_ENABLED=0 darwin
// build lands on `pass`, not a file, since pass.go precedes FileBackend in
// keyring's own order), what was expected instead (from the same `required`
// table backends.go's build-time guard uses), and where the token is going.
func fallbackWarning(goos string, available, notOpened []keyring.BackendType, chosen keyring.BackendType, fileDir string) string {
	want, recorded := required[goos]
	if recorded {
		for _, b := range want {
			if b == chosen {
				return ""
			}
		}
	}

	expected := "the platform credential store"
	if len(want) > 0 {
		expected = fmt.Sprintf("%q", want[0])
	}

	return fmt.Sprintf("credential store: using %q instead of %s, which a %s build of amctl expects. %s %s",
		chosen, expected, goos,
		fallbackReason(goos, want, available, notOpened),
		fallbackDestination(chosen, fileDir))
}

// fallbackReason explains why the expected store was not the one used. There
// are exactly two shapes, and they are different facts: the backend is not in
// this binary at all (a build problem, e.g. a static darwin binary), or it is
// in the binary and would not open (a machine problem).
func fallbackReason(goos string, want, available, notOpened []keyring.BackendType) string {
	if err := Verify(goos, available); err != nil {
		return err.Error() + "."
	}
	if len(want) == 0 {
		return "amctl has no recorded expectation for this platform."
	}
	target := want[0]
	if !contains(notOpened, target) {
		// Neither missing from the build nor tried: the caller narrowed the
		// backend order, which is a test or a future --credential-store flag.
		return fmt.Sprintf("%q was not among the backends this run was allowed to try.", target)
	}
	reason := fmt.Sprintf("%q is compiled into this build but did not open; keyring does not report why", target)
	if hint, ok := fallbackHints[target]; ok {
		reason += ", and the usual cause is that " + hint
	}
	return reason + "."
}

func fallbackDestination(chosen keyring.BackendType, fileDir string) string {
	switch chosen {
	case keyring.FileBackend:
		return fmt.Sprintf("The token is going into %s, a file amctl keeps readable and writable only by you.", fileDir)
	case keyring.PassBackend:
		return "The token is going into your GPG password store through `pass`."
	default:
		return fmt.Sprintf("The token is going into the %q backend.", chosen)
	}
}

func contains(set []keyring.BackendType, b keyring.BackendType) bool {
	for _, v := range set {
		if v == b {
			return true
		}
	}
	return false
}
