// Package signing verifies Sigstore bundles against the archive the fetcher
// downloaded and reports who signed it. It checks the certificate chain,
// transparency log and timestamps only; whether that signer is acceptable for
// a package is the resolver's question, not this package's.
package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// Status is what a version's signature amounts to.
type Status string

const (
	StatusUnsigned Status = "unsigned"
	StatusVerified Status = "verified"
	StatusInvalid  Status = "invalid"
)

// MaxBundleBytes bounds a bundle read off a remote; real ones are a few KiB.
const MaxBundleBytes = 1 << 20

// Result is one verification's outcome. Issuer and Identity are set only
// when Status is verified, Reason only when it is invalid.
type Result struct {
	Status   Status
	Issuer   string
	Identity string
	SignedAt *time.Time
	LogIndex *int64
	Reason   string
}

// ErrTrustUnavailable is the trusted root not being loadable right now: a
// transient condition, never a verdict on the bundle.
var ErrTrustUnavailable = errors.New("sigstore trusted root unavailable")

// refreshEvery is how long a TUF-fetched trusted root is used before it is
// fetched again.
const refreshEvery = 24 * time.Hour

// Verifier checks bundles against one trust root.
type Verifier struct {
	mu       sync.Mutex
	material root.TrustedMaterial
	loadedAt time.Time
	load     func() (root.TrustedMaterial, error)
	options  []verify.VerifierOption
}

// Options picks the trust root. TrustedRootPath wins when set; otherwise the
// public-good root is fetched over TUF, from the embedded TUF root, through
// Fetcher.
type Options struct {
	TrustedRootPath string
	Fetcher         fetcher.Fetcher
}

// publicGood is what cosign requires of a public-good signature.
var publicGood = []verify.VerifierOption{
	verify.WithSignedCertificateTimestamps(1),
	verify.WithTransparencyLog(1),
	verify.WithObserverTimestamps(1),
}

// New loads a trusted root file now, so a bad path fails at startup, and
// defers a TUF fetch until the first bundle needs it.
func New(opts Options) (*Verifier, error) {
	if opts.TrustedRootPath != "" {
		material, err := root.NewTrustedRootFromPath(opts.TrustedRootPath)
		if err != nil {
			return nil, fmt.Errorf("load the sigstore trusted root %s: %w", opts.TrustedRootPath, err)
		}
		return NewWithMaterial(material, publicGood...), nil
	}
	if opts.Fetcher == nil {
		return nil, errors.New("signing: no trusted root path and no fetcher for TUF")
	}
	return &Verifier{
		options: publicGood,
		load: func() (root.TrustedMaterial, error) {
			tufOpts := tuf.DefaultOptions().WithDisableLocalCache().WithFetcher(opts.Fetcher)
			return root.FetchTrustedRootWithOptions(tufOpts)
		},
	}, nil
}

// NewWithMaterial verifies against fixed trusted material.
func NewWithMaterial(material root.TrustedMaterial, options ...verify.VerifierOption) *Verifier {
	return &Verifier{material: material, options: options}
}

func (v *Verifier) trusted() (root.TrustedMaterial, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.load == nil || (v.material != nil && time.Since(v.loadedAt) < refreshEvery) {
		return v.material, nil
	}
	material, err := v.load()
	if err != nil {
		if v.material != nil {
			// A stale root beats refusing every signed fetch while the TUF mirror is down.
			return v.material, nil
		}
		return nil, fmt.Errorf("%w: %w", ErrTrustUnavailable, err)
	}
	v.material, v.loadedAt = material, time.Now()
	return material, nil
}

// Verify checks raw bundle JSON against the sha256 of the signed artefact. An
// empty bundle is unsigned. A bundle that does not verify is a Result, not an
// error; the error is reserved for ErrTrustUnavailable.
func (v *Verifier) Verify(ctx context.Context, raw []byte, digest [32]byte) (Result, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Result{Status: StatusUnsigned}, nil
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if len(raw) > MaxBundleBytes {
		return invalid("the bundle is larger than %d bytes", MaxBundleBytes), nil
	}

	var entity bundle.Bundle
	if err := entity.UnmarshalJSON(raw); err != nil {
		return invalid("the bundle is not a sigstore bundle: %v", err), nil
	}

	material, err := v.trusted()
	if err != nil {
		return Result{}, err
	}
	verifier, err := verify.NewVerifier(material, v.options...)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrTrustUnavailable, err)
	}
	outcome, err := verifier.Verify(&entity, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest[:]),
		// The signer is checked against each package's expected signer at
		// resolution; here any Fulcio identity that verifies is recorded.
		verify.WithoutIdentitiesUnsafe(),
	))
	if err != nil {
		return invalid("%v", err), nil
	}
	if outcome.Signature == nil || outcome.Signature.Certificate == nil {
		return invalid("the bundle is signed by a key, not a Fulcio certificate, so it names no identity"), nil
	}

	out := Result{
		Status:   StatusVerified,
		Issuer:   outcome.Signature.Certificate.Issuer,
		Identity: outcome.Signature.Certificate.SubjectAlternativeName,
	}
	for _, ts := range outcome.VerifiedTimestamps {
		at := ts.Timestamp.UTC()
		if out.SignedAt == nil || at.Before(*out.SignedAt) {
			out.SignedAt = &at
		}
	}
	if entries, entriesErr := entity.TlogEntries(); entriesErr == nil && len(entries) > 0 {
		index := entries[0].LogIndex()
		out.LogIndex = &index
	}
	return out, nil
}

// DigestString renders a digest the way the audit log and the wire show it.
func DigestString(digest [32]byte) string { return "sha256:" + hex.EncodeToString(digest[:]) }

func invalid(format string, args ...any) Result {
	reason := fmt.Sprintf(format, args...)
	if len(reason) > 500 {
		reason = reason[:500]
	}
	return Result{Status: StatusInvalid, Reason: reason}
}
