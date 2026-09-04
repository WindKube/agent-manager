package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Digest is a sha256 value stored as raw bytes, not as one of its string
// encodings, so `==` is always the correct equality check.
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

// ParseLockfileDigest reads `sha256:<64 lowercase hex>`. Uppercase is refused
// rather than folded, so a schema-violating hub bug is not hidden.
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

// ParseHeaderDigest reads RFC 3230's `sha-256=<base64>` header value. The
// base64 payload is matched case-sensitively, since base64url decodes the
// same characters to different bytes.
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

// IsZero reports whether d is the uninitialised zero value.
func (d Digest) IsZero() bool { return d == Digest{} }

// Hex is the 64 lowercase hex characters, without a scheme.
func (d Digest) Hex() string { return hex.EncodeToString(d.raw[:]) }

// Lockfile is `sha256:<64 hex>`, the lockfile / state-record encoding.
func (d Digest) Lockfile() string { return lockfileScheme + d.Hex() }

// Header is `sha-256=<padded base64>`, the RFC 3230 header encoding.
func (d Digest) Header() string {
	return headerScheme + base64.StdEncoding.EncodeToString(d.raw[:])
}

// FileName is `sha256-<64 hex>`, the cache's on-disk key.
func (d Digest) FileName() string { return fileScheme + d.Hex() }

func (d Digest) String() string { return d.Lockfile() }
