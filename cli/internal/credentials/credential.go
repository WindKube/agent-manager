package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrCredential marks a stored credential amctl refuses to use: undecodable,
// a newer schema version, or a mismatched hub.
var ErrCredential = errors.New("stored credential is unusable")

const schemaVersion = 1 // a format change is a migration or a named refusal, never a silent half-decode

// Credential is one hub's bearer token; ExpiresAt exists only because the
// tokens are opaque, so `expires_in` at issue time is the sole source of a
// lifetime. String/GoString exist so %v/%s/%#v never print Token, and
// `json:"-"` on Token stops json.Marshal doing the same (it ignores the
// Stringer methods entirely) — the on-disk shape is storedCredential below.
type Credential struct {
	Hub string // stored and compared on load, so a token can never reach the wrong hub

	Token string `json:"-"` // never rendered, logged or marshalled

	ExpiresAt time.Time // zero means "no stated lifetime", not "already expired"
	IssuedAt  time.Time // for `status` to report age
	Identity  string    // empty is normal: the token endpoint doesn't return one

	fromEnv bool // came from TokenEnvVar; Store.Save refuses to persist it
}

// Issued leaves ExpiresAt zero for expiresIn <= 0, since "no stated
// lifetime" and "already elapsed" are different facts.
func Issued(hubURL, token string, expiresIn int64, now time.Time) Credential {
	c := Credential{Hub: hubURL, Token: token, IssuedAt: now}
	if expiresIn > 0 {
		c.ExpiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	}
	return c
}

// Expired: a credential with no recorded expiry is never expired.
func (c Credential) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

func (c Credential) FromEnvironment() bool { return c.fromEnv }

func (c Credential) String() string {
	expiry := "no stated expiry"
	if !c.ExpiresAt.IsZero() {
		expiry = "expires " + c.ExpiresAt.UTC().Format(time.RFC3339)
	}
	identity := c.Identity
	if identity == "" {
		identity = "unknown"
	}
	return fmt.Sprintf("credential for %s as %s, token redacted, %s", c.Hub, identity, expiry)
}

func (c Credential) GoString() string { return "credentials.Credential{" + c.String() + "}" } // %#v ignores String

// storedCredential is the JSON in a keyring item; timestamps are RFC 3339
// strings, omitted when zero, so an absent lifetime round-trips as absent.
type storedCredential struct {
	SchemaVersion int    `json:"schema_version"`
	Hub           string `json:"hub"`
	Token         string `json:"token"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	IssuedAt      string `json:"issued_at,omitempty"`
	Identity      string `json:"identity,omitempty"`
}

func encodeCredential(c Credential) ([]byte, error) {
	s := storedCredential{
		SchemaVersion: schemaVersion,
		Hub:           c.Hub,
		Token:         c.Token,
		Identity:      c.Identity,
	}
	if !c.ExpiresAt.IsZero() {
		s.ExpiresAt = c.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if !c.IssuedAt.IsZero() {
		s.IssuedAt = c.IssuedAt.UTC().Format(time.RFC3339)
	}
	return json.Marshal(s)
}

// decodeCredential refuses a stored hub mismatch: the item key is a digest
// of the URL, so a mismatch means a hand-edited store or a collision, and
// handing one hub's token to another is the worst thing this package could do.
func decodeCredential(blob []byte, hubURL string) (Credential, error) {
	var s storedCredential
	if err := json.Unmarshal(blob, &s); err != nil {
		return Credential{}, fmt.Errorf("%w: cannot decode the credential stored for %s: %w", ErrCredential, hubURL, err)
	}
	if s.SchemaVersion != schemaVersion {
		return Credential{}, fmt.Errorf("%w: the credential stored for %s is schema version %d, and this amctl understands %d; run `amctl login` again",
			ErrCredential, hubURL, s.SchemaVersion, schemaVersion)
	}
	if s.Hub != hubURL {
		return Credential{}, fmt.Errorf("%w: the credential stored under %s names hub %q; refusing to use it for %q",
			ErrCredential, itemKey(hubURL), s.Hub, hubURL)
	}
	if s.Token == "" {
		return Credential{}, fmt.Errorf("%w: the credential stored for %s has no token", ErrCredential, hubURL)
	}

	c := Credential{Hub: s.Hub, Token: s.Token, Identity: s.Identity}
	var err error
	if c.ExpiresAt, err = parseStoredTime(s.ExpiresAt, "expires_at", hubURL); err != nil {
		return Credential{}, err
	}
	if c.IssuedAt, err = parseStoredTime(s.IssuedAt, "issued_at", hubURL); err != nil {
		return Credential{}, err
	}
	return c, nil
}

// parseStoredTime refuses an unparseable timestamp rather than defaulting
// to zero, which would turn a corrupt record into a token that never expires.
func parseStoredTime(value, field, hubURL string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: the credential stored for %s has an unparseable %s: %w", ErrCredential, hubURL, field, err)
	}
	return t, nil
}
