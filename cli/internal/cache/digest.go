package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Digest is a sha256 value in the ONE canonical internal form: the 32 raw
// bytes. It is a struct around a private array so that the raw bytes cannot be
// set, mutated or converted into from outside this package — a Digest can only
// come out of Compute, ParseLockfileDigest or ParseHeaderDigest, and therefore
// always holds a value that was either measured here or parsed from a known
// encoding.
//
// This exists because the same digest reaches the CLI in two encodings and they
// meet in the same comparison. The lockfile carries `sha256:<64 lowercase hex>`
// (lockfile.schema.json) and the `Digest` response header carries
// `sha-256=<base64>` (RFC 3230, and CLI-CONTRACT.md). A `type Digest string`
// holding "either of those" compares unequal for two spellings of one value,
// and FR-014's whole point is that the comparison is the last line of defence:
// a check that silently never matches is indistinguishable from a check that
// silently always matches. So the encodings live only at the edges — the two
// parsers in and the three formatters out — and nothing in between can hold
// one.
//
// Digest is comparable, so `==` is the digest check and it is also usable as a
// map key. Do NOT compare formatted strings.
type Digest struct {
	raw [sha256.Size]byte
}

const (
	// lockfileScheme is lockfile.schema.json's `^sha256:[0-9a-f]{64}$`.
	lockfileScheme = "sha256:"

	// headerScheme is RFC 3230's instance-digest algorithm token. Note the
	// hyphen: `sha-256=`, not `sha256:`. Two characters different from the
	// lockfile's spelling of the same algorithm, which is why neither prefix is
	// ever written at a call site.
	headerScheme = "sha-256="

	// fileScheme prefixes the cache filename. A colon is not a legal filename
	// character on Windows and is special to some darwin tooling, so the
	// on-disk key is `sha256-<hex>` as plan.md specifies — a THIRD spelling,
	// produced only by Digest.FileName so no call site does string surgery on
	// one of the other two.
	fileScheme = "sha256-"
)

// ErrDigest is returned by both parsers for anything that is not the exact
// encoding they accept. Callers report it; they must never fall back to a
// looser parse, because a digest this CLI cannot read is not a digest it may
// guess at.
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
//
// Uppercase hex is REFUSED rather than folded. The schema is frozen and says
// lowercase; accepting a form it forbids would make this client the lenient one
// and hide a hub bug behind a working sync, and the cost of refusing is a clear
// error rather than a wrong install.
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
// `sha-256=<base64>`.
//
// Two deliberate asymmetries with the contract's `^sha-256=[A-Za-z0-9+/=]+$`:
//
//   - The algorithm token is matched case-insensitively. RFC 3230 registers it
//     as `SHA-256` in uppercase while the contract's regex writes it lowercase,
//     and refusing a real server for spelling it the way the RFC does would be
//     a bug in us, not in it.
//   - The base64 payload is never case-folded and the `-_` alphabet is never
//     accepted. base64 is case-significant, and base64url decodes the same
//     characters to different bytes; a tolerant decoder here turns a mismatch
//     into a silently wrong digest.
//
// Padded and unpadded standard base64 are both accepted; the length of the
// decoded value is what is actually checked.
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

// IsZero reports whether d is the zero value — a Digest that was never parsed
// or computed. The zero value is not the digest of anything (sha256 of the
// empty input is e3b0c442…), so it can only arrive from an uninitialised
// struct field, and Get/Put refuse it: two uninitialised digests compare EQUAL,
// which is the one way this type could still let a verification pass by
// accident.
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
