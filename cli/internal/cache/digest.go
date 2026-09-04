package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Digest is a sha256 value stored as raw bytes so the lockfile's
// `sha256:<hex>` spelling and the header's `sha-256=<base64>` spelling can
// never be compared as unequal strings for the same value. Digest is
// comparable, so `==` is the digest check; do NOT compare formatted strings.
type Digest struct {
	raw [sha256.Size]byte
}

const (
	lockfileScheme = "sha256:"
	headerScheme   = "sha-256="

	// fileScheme: a colon is special to some darwin tooling, so the on-disk
	// key is spelled `sha256-<hex>` instead.
	fileScheme = "sha256-"
)

// ErrDigest is returned by both parsers for input that is not their exact
// accepted encoding; callers must not fall back to a looser parse.
var ErrDigest = errors.New("malformed sha256 digest")

// Compute measures b. This is the only place a digest is produced from bytes.
func Compute(b []byte) Digest {
	return Digest{raw: sha256.Sum256(b)}
}

// digestFromSlice wraps exactly sha256.Size bytes, e.g. a hash.Hash's Sum.
func digestFromSlice(b []byte) (Digest, error) {
	var d Digest
	if len(b) != sha256.Size {
		return Digest{}, fmt.Errorf("%w: %d bytes, want %d", ErrDigest, len(b), sha256.Size)
	}
	copy(d.raw[:], b)
	return d, nil
}

// ParseLockfileDigest reads the lockfile encoding, `sha256:<64 lowercase hex>`.
// Uppercase hex is refused rather than folded, since accepting it would hide
// a hub bug that violates the schema behind a working sync.
func ParseLockfileDigest(s string) (Digest, error) {
	rest, ok := strings.CutPrefix(s, lockfileScheme)
	if !ok {
		return Digest{}, fmt.Errorf("%w: %q does not start with %q", ErrDigest, s, lockfileScheme)
	}
	if len(rest) != hex.EncodedLen(sha256.Size) {
		return Digest{}, fmt.Errorf("%w: %q has %d hex characters, want %d",
			ErrDigest, s, len(rest), hex.EncodedLen(sha256.Size))
	}
	if strings.ToLower(rest) != rest {
		return Digest{}, fmt.Errorf("%w: %q is not lowercase hex", ErrDigest, s)
	}
	b, err := hex.DecodeString(rest)
	if err != nil {
		return Digest{}, fmt.Errorf("%w: %q: %w", ErrDigest, s, err)
	}
	return digestFromSlice(b)
}

// ParseHeaderDigest reads the RFC 3230 `Digest` response header value,
// `sha-256=<base64>`. The algorithm token is matched case-insensitively
// (RFC 3230 spells it uppercase); the base64 payload is not, since base64url
// decodes the same characters to different bytes. Both padded and unpadded
// standard base64 are accepted.
func ParseHeaderDigest(s string) (Digest, error) {
	eq := strings.IndexByte(s, '=')
	if eq < 0 || !strings.EqualFold(s[:eq+1], headerScheme) {
		return Digest{}, fmt.Errorf("%w: %q does not start with %q", ErrDigest, s, headerScheme)
	}
	payload := s[eq+1:]
	if payload == "" {
		return Digest{}, fmt.Errorf("%w: %q carries no value", ErrDigest, s)
	}
	if strings.ContainsAny(payload, "-_") {
		return Digest{}, fmt.Errorf("%w: %q is base64url; the contract specifies standard base64", ErrDigest, s)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		if raw, rawErr := base64.RawStdEncoding.Strict().DecodeString(payload); rawErr == nil {
			b = raw
		} else {
			return Digest{}, fmt.Errorf("%w: %q: %w", ErrDigest, s, err)
		}
	}
	return digestFromSlice(b)
}

// IsZero reports whether d is the uninitialised zero value, which Get/Put
// must refuse since two zero digests would otherwise compare equal.
func (d Digest) IsZero() bool { return d == Digest{} }

// Hex is the 64 lowercase hex characters, without a scheme.
func (d Digest) Hex() string { return hex.EncodeToString(d.raw[:]) }

// Lockfile is the lockfile / state-record encoding, `sha256:<64 hex>`.
func (d Digest) Lockfile() string { return lockfileScheme + d.Hex() }

// Header is the RFC 3230 header encoding, `sha-256=<padded base64>`. Emitted
// lowercase and padded to match the contract's regex exactly.
func (d Digest) Header() string {
	return headerScheme + base64.StdEncoding.EncodeToString(d.raw[:])
}

// FileName is the cache's on-disk key, `sha256-<64 hex>`.
func (d Digest) FileName() string { return fileScheme + d.Hex() }

// String is the lockfile encoding, because that is the form a user has seen:
// it is what the lockfile and the installation record show.
func (d Digest) String() string { return d.Lockfile() }
