package credentials

import (
	"fmt"

	"github.com/99designs/keyring"
)

// fallbackHints say what usually stops a platform's own credential store from
// opening. They are hints and are labelled as such in the message, because
// keyring.Open DISCARDS the opener's error — it returns its own ErrNoAvailImpl
// however the backend failed — so amctl can name which backend did not open but
// genuinely cannot say why. Guessing in the message without saying it is a
// guess is how a user spends an afternoon on the wrong cause.
var fallbackHints = map[keyring.BackendType]string{
	keyring.SecretServiceBackend: "no Secret Service is running on the session bus (a headless or SSH session), or the login keyring is locked",
	keyring.KeychainBackend:      "the login keychain is locked, or access was denied",
	keyring.WinCredBackend:       "the credential manager refused the request",
}

// fallbackWarning is FR-003's report, or "" when there is nothing to report.
//
// Three things it must get right, and each has a wrong version that reads
// perfectly well:
//
//  1. It names the backend that ACTUALLY OPENED. R1 measured that a
//     CGO_ENABLED=0 darwin build lands on `pass`, not on a file, because
//     pass.go is `!windows` and precedes FileBackend in keyring's own order. A
//     message that says "falling back to a file" is therefore a lie on the one
//     platform this warning exists for, and no test catches it unless the test
//     asserts the words.
//  2. It names what was EXPECTED instead, from the same `required` table
//     backends.go's build-time guard uses — not from runtime.GOOS reasoning
//     duplicated here.
//  3. It says where the token is going, because "we fell back" without a
//     destination is not actionable. Only the file case is a path; `pass` is a
//     GPG store somewhere else entirely.
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
// this binary at all (a build problem — R1's static darwin), or it is in the
// binary and would not open (a machine problem).
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
