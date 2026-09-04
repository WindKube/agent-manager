package credentials

import (
	"fmt"
	"os"
)

// TokenEnvVar supplies a bearer token directly, bypassing every store. One
// variable rather than one per hub, since the case this exists for — CI, a
// container, a machine with no credential store and no TTY — talks to one hub.
//
//nolint:gosec // G101: this is the NAME of an environment variable, not a credential.
const TokenEnvVar = "AMCTL_TOKEN"

// Source says where a credential came from, rendered in `login` and
// `status`'s `store` field.
type Source string

const (
	SourceEnvironment Source = "environment"
	SourceStore       Source = "store"
)

// Resolved is a credential together with where it came from.
type Resolved struct {
	Credential Credential
	Source     Source
	// Location is the human phrase for a result's `store` field.
	Location string
}

// Resolver reads the credential for a hub: the environment first, a store
// second. Open is a function and not a *Store so the store is never opened
// at all when the environment supplies a token, since opening one has side
// effects (creating the credentials directory, a keychain dialog, shelling
// out to `pass`, a fallback warning) that TokenEnvVar exists to avoid.
type Resolver struct {
	// Open constructs the store. Called at most once per Resolve, and not
	// at all when TokenEnvVar is set.
	Open func() (*Store, error)
	// LookupEnv defaults to os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

// NewResolver is the production wiring: the environment, then a store
// opened lazily from opts.
func NewResolver(opts Options) Resolver {
	return Resolver{Open: func() (*Store, error) { return Open(opts) }}
}

// Resolve returns the credential for hubURL. The bool is false when there is
// none, which is not an error. Resolve deliberately does not reject an
// expired credential: whether an expiry in the past is fatal is the verb's
// decision, and Credential.Expired is how a caller asks.
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
			// ExpiresAt stays zero: the environment states no lifetime.
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
