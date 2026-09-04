package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrCredential marks a stored credential amctl refuses to use: a blob it
// cannot decode, a schema version from a newer amctl, or a record that names a
// different hub than the one asked for.
var ErrCredential = errors.New("stored credential is unusable")

// schemaVersion is the on-disk shape of one stored credential; a format
// change should be a migration or a named refusal, never a silent
// half-filled decode.
const schemaVersion = 1

// Credential is one hub's bearer token as amctl holds it. ExpiresAt exists
// because the hub's tokens are opaque with no claims to read, so the only
// source of a lifetime is the `expires_in` returned beside it at issue time.
//
// The type carries String and GoString so a Credential reaching %v, %s or
// %#v cannot print the token, and `json:"-"` on Token guards the other
// serialiser: json.Marshal ignores String and GoString entirely, so a
// Credential handed to the JSON renderer would otherwise emit the raw
// token. The on-disk shape is the separate storedCredential below; this tag
// is the only one on this type, since nothing here is a wire format.
type Credential struct {
	// Hub is the canonical hub URL this token authenticates against. Stored
	// and compared on load, so a credential can never be handed to the
	// wrong hub.
	Hub string
	// Token is the bearer token. Never rendered, logged or marshalled.
	Token string `json:"-"`
	// ExpiresAt is when the token stops working. The zero value means the
	// issuer named no lifetime, not "already expired".
	ExpiresAt time.Time
	// IssuedAt is when amctl obtained it, for `status` to report age.
	IssuedAt time.Time
	// Identity is who the hub says this token belongs to, when learned.
	// Empty is normal: the token endpoint does not return one.
	Identity string

	// fromEnv marks a credential that came from TokenEnvVar; Store.Save
	// refuses to persist one. Unexported so only this package can set it.
	fromEnv bool
}

// Issued builds a Credential from what the device token endpoint returned.
// expiresIn <= 0 leaves ExpiresAt at its zero value rather than computing an
// expiry in the past, since "no stated lifetime" and "already elapsed" are
// different facts.
func Issued(hubURL, token string, expiresIn int64, now time.Time) Credential {
	c := Credential{Hub: hubURL, Token: token, IssuedAt: now}
	if expiresIn > 0 {
		c.ExpiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	}
	return c
}

// Expired reports whether the credential's stated lifetime has passed. A
// credential with no recorded expiry is never expired.
func (c Credential) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

// FromEnvironment reports whether this credential came from TokenEnvVar
// rather than a store, which is what makes it unsavable.
func (c Credential) FromEnvironment() bool { return c.fromEnv }

// String implements fmt.Stringer without the token.
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

// GoString implements fmt.GoStringer, because %#v is what a hurried debug
// print reaches for and it ignores String.
func (c Credential) GoString() string { return "credentials.Credential{" + c.String() + "}" }

// storedCredential is the JSON amctl puts in a keyring item. Timestamps are
// RFC 3339 strings, omitted when zero, so an absent lifetime stays absent
// through a round trip instead of becoming a timestamp in the year 1.
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

// decodeCredential turns a stored blob back into a Credential, refusing
// rather than guessing. A stored credential naming a different hub than
// hubURL is refused: the item key is a digest of the URL, so a mismatch
// means a hand-edited store or a collision, and handing one hub's token to
// another would be the worst thing this package could do.
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

// parseStoredTime refuses an unparseable timestamp rather than defaulting it
// to zero, since zero means "no stated expiry" and silently falling back to
// it would turn a corrupt record into a token that never expires.
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
