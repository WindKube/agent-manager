package credentials

import (
	"fmt"
	"os"
)

// TokenEnvVar bypasses every store; one variable, since the case it exists
// for (CI, a container, no credential store, no TTY) talks to one hub.
//
//nolint:gosec // G101: this is the NAME of an environment variable, not a credential.
const TokenEnvVar = "AMCTL_TOKEN"

// Source says where a credential came from, for `login`/`status`'s `store` field.
type Source string

const (
	SourceEnvironment Source = "environment"
	SourceStore       Source = "store"
)

// Resolved is a credential together with where it came from.
type Resolved struct {
	Credential Credential
	Source     Source
	Location   string // human phrase for a result's `store` field
}

// Resolver tries the environment, then a store. Open is a func, not a
// *Store, so opening (a keychain dialog, shelling to `pass`, a fallback
// warning) never happens when the environment already supplied a token.
type Resolver struct {
	Open      func() (*Store, error)      // called at most once, never when TokenEnvVar is set
	LookupEnv func(string) (string, bool) // defaults to os.LookupEnv
}

func NewResolver(opts Options) Resolver {
	return Resolver{Open: func() (*Store, error) { return Open(opts) }}
}

// Resolve's bool is false for "none", not an error; an expired credential
// is returned as-is — Credential.Expired is how a caller checks.
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
			Credential: Credential{Hub: hubURL, Token: token, fromEnv: true}, // ExpiresAt zero: env states no lifetime
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
