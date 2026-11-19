// Package signer decides whether a version's recorded Sigstore signature is
// one its package trusts. The fetcher records any Fulcio identity that
// verifies; this is where that identity is bound to the package, at read
// time, so changing a package's expected signer re-decides every version.
package signer

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Status is a signature as a reader should understand it. Only
// StatusMatching is trustworthy.
type Status string

const (
	StatusUnsigned Status = "unsigned"
	StatusInvalid  Status = "invalid"
	// StatusNoExpectedSigner verified, but the package names no signer to
	// compare it with, so it proves nothing about who should have signed.
	StatusNoExpectedSigner Status = "verified-no-expected-signer"
	StatusUnexpectedSigner Status = "verified-unexpected-signer"
	StatusMatching         Status = "verified-matching"
)

func Statuses() []Status {
	return []Status{StatusUnsigned, StatusInvalid, StatusNoExpectedSigner, StatusUnexpectedSigner, StatusMatching}
}

const (
	MaxIssuerLength   = 512
	MaxIdentityLength = 512
)

// Expected is a package's expected signer: an exact OIDC issuer and an RE2
// pattern the certificate identity must match whole.
type Expected struct {
	Issuer   string
	Identity string
}

func (e Expected) Configured() bool { return e.Issuer != "" && e.Identity != "" }

var ErrInvalid = errors.New("invalid expected signer")

// Normalise trims both fields and refuses a half-set, oversized or
// uncompilable signer. Both empty is a valid "no expected signer".
func Normalise(e Expected) (Expected, error) {
	e.Issuer, e.Identity = strings.TrimSpace(e.Issuer), strings.TrimSpace(e.Identity)
	switch {
	case e.Issuer == "" && e.Identity == "":
		return e, nil
	case e.Issuer == "" || e.Identity == "":
		return e, fmt.Errorf("%w: an issuer and an identity pattern are set together or not at all", ErrInvalid)
	case len(e.Issuer) > MaxIssuerLength:
		return e, fmt.Errorf("%w: the issuer is longer than %d characters", ErrInvalid, MaxIssuerLength)
	case len(e.Identity) > MaxIdentityLength:
		return e, fmt.Errorf("%w: the identity pattern is longer than %d characters", ErrInvalid, MaxIdentityLength)
	}
	if _, err := compile(e.Identity); err != nil {
		return e, fmt.Errorf("%w: the identity pattern is not an RE2 regular expression: %w", ErrInvalid, err)
	}
	return e, nil
}

// compile anchors the pattern, so `.*@example.com` cannot match a longer
// identity that merely contains it.
func compile(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(`^(?:` + pattern + `)$`)
}

// Matches reports whether a verified signer is the expected one. A pattern
// that does not compile matches nothing.
func (e Expected) Matches(issuer, identity string) bool {
	if !e.Configured() || issuer != e.Issuer {
		return false
	}
	re, err := compile(e.Identity)
	return err == nil && re.MatchString(identity)
}

// Observed is the fetcher's record: Result is "verified", "invalid" or empty
// for no bundle.
type Observed struct {
	Result   string
	Issuer   string
	Identity string
}

// Evaluate binds what the fetcher verified to what the package expects.
func Evaluate(o Observed, e Expected) Status {
	switch {
	case o.Result == "invalid":
		return StatusInvalid
	case o.Result != "verified":
		return StatusUnsigned
	case !e.Configured():
		return StatusNoExpectedSigner
	case e.Matches(o.Issuer, o.Identity):
		return StatusMatching
	default:
		return StatusUnexpectedSigner
	}
}
