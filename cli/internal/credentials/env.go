package credentials

import (
	"fmt"
	"os"
)

// TokenEnvVar supplies a bearer token directly, bypassing every store (FR-005).
//
// One variable rather than one per hub: a per-hub name would have to encode a
// URL in an environment variable name, and the case this exists for — CI, a
// container, a machine with no credential store and no TTY (SC-006) — talks to
// one hub. The token applies to whichever hub the command was given.
//
//nolint:gosec // G101: this is the NAME of an environment variable, not a credential.
const TokenEnvVar = "AMCTL_TOKEN"

// Source says where a credential came from. It is what `login` and `status`
// render in their `store` field, so a user can tell "the hub trusts me" from
// "this shell has a variable set".
type Source string

const (
	// SourceEnvironment — TokenEnvVar. Nothing was read from disk.
	SourceEnvironment Source = "environment"
	// SourceStore — a keyring backend.
	SourceStore Source = "store"
)

// Resolved is a credential together with where it came from.
type Resolved struct {
	Credential Credential
	Source     Source
	// Location is the human phrase for a result's `store` field: the
	// environment variable's name, or the backend and, for the fallback, its
	// directory.
	Location string
}

// Resolver reads the credential for a hub: the environment first, a store
// second.
//
// Open is a FUNCTION and not a *Store for one reason, and it is the whole
// point of FR-005. "Takes precedence" is only worth something if the store is
// never opened at all when the environment supplies a token, because opening
// one has side effects that a machine using TokenEnvVar has specifically
// arranged to avoid: it creates ~/.agent-manager/credentials, it can raise a
// keychain access dialog, it can shell out to `pass`, and it can emit the
// FR-003 fallback warning. A resolver that opened the store and then discarded
// the answer would do all four and pass a test that only checked which token
// won. TestAnEnvironmentTokenNeverOpensTheStore is the negative control.
type Resolver struct {
	// Open constructs the store. Called at most once per Resolve, and not at
	// all when TokenEnvVar is set.
	Open func() (*Store, error)
	// LookupEnv defaults to os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

// NewResolver is the production wiring: the environment, then a store opened
// lazily from opts.
func NewResolver(opts Options) Resolver {
	return Resolver{Open: func() (*Store, error) { return Open(opts) }}
}

// Resolve returns the credential for hubURL. The bool is false when there is
// none, which is not an error — `status` on a machine that has never logged in
// is a valid answer, and `sync` turns it into FR-037's refusal naming the flag.
//
// Resolve deliberately does NOT reject an expired credential. Whether an expiry
// in the past is fatal is the verb's decision: `status` must report it, and
// `sync` must be able to say "your token expired at X, run amctl login" rather
// than "no credential". Credential.Expired is how a caller asks.
func (r Resolver) Resolve(hubURL string) (Resolved, bool, error) {
	if hubURL == "" {
		return Resolved{}, false, fmt.Errorf("cannot resolve a credential without a hub")
	}

	lookup := r.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if token, ok := lookup(TokenEnvVar); ok && token != "" {
		return Resolved{
			// ExpiresAt stays zero: the environment states no lifetime and
			// there is nothing in an opaque token to read one out of. Inventing
			// one here would refuse a token that works.
			Credential: Credential{Hub: hubURL, Token: token, fromEnv: true},
			Source:     SourceEnvironment,
			Location:   TokenEnvVar,
		}, true, nil
	}

	if r.Open == nil {
		return Resolved{}, false, fmt.Errorf("credentials: resolver has no store and %s is not set", TokenEnvVar)
	}
	store, err := r.Open()
	if err != nil {
		return Resolved{}, false, err
	}
	c, found, err := store.Load(hubURL)
	if err != nil || !found {
		return Resolved{}, false, err
	}
	return Resolved{Credential: c, Source: SourceStore, Location: store.Location()}, true, nil
}
