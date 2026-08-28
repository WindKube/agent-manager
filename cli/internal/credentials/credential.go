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

// schemaVersion is the on-disk shape of one stored credential. It is here for
// the same reason the installation record has one: a format change should be a
// migration or a named refusal, never a struct that silently decodes into a
// half-filled credential.
const schemaVersion = 1

// Credential is one hub's bearer token as amctl holds it.
//
// ExpiresAt exists because the hub's tokens are OPAQUE — base64url of 32 random
// bytes, one segment, no header and no claims. Nothing can be read out of the
// token itself, so the only source of a lifetime is the `expires_in` returned
// beside it, and a store that kept the token alone could never tell an expired
// credential from a valid one, which is exactly what `amctl status` has to
// report. Never parse a token: there is nothing in it to parse.
//
// The type carries String and GoString so that a Credential reaching a %v, a
// %s or a %#v cannot print the token (FR-007). That guard belongs to the type
// rather than to every call site, because the call site that forgets is the one
// nobody reviews.
//
// `json:"-"` on Token is the same guard for the OTHER serialiser, and it is
// there because the fmt one was measured to be the only one: json.Marshal
// ignores String and GoString, so a Credential — or a Resolved, or any result
// struct holding either — handed to internal/output's JSON renderer wrote
// {"Hub":…,"Token":"<the bearer token>",…} onto the RESULT stream. Nothing in
// the tree marshalled one at the time, which is precisely why it had to be
// fixed at the type: the first caller to reach for the JSON renderer with a
// credential in scope would have leaked it and looked correct doing so.
//
// The tag cannot change the stored format: the on-disk shape is the unexported
// storedCredential below, which carries its own tags and is the only thing ever
// written to a keyring item. It is the ONLY tag on this type, for that reason —
// nothing here is a wire format.
type Credential struct {
	// Hub is the canonical hub URL this token authenticates against, as
	// internal/cmd.ParseHub produced it. Stored and compared on load, so a
	// credential can never be handed to the wrong hub.
	Hub string
	// Token is the bearer token. Never rendered, never logged, never
	// marshalled — see the type comment on the tag.
	Token string `json:"-"`
	// ExpiresAt is when the token stops working. The zero value means the
	// issuer named no lifetime — not "already expired".
	ExpiresAt time.Time
	// IssuedAt is when amctl obtained it, for `status` to report age.
	IssuedAt time.Time
	// Identity is who the hub says this token belongs to, when a caller has
	// learned it. Empty is normal: the token endpoint does not return one.
	Identity string

	// fromEnv marks a credential that came from TokenEnvVar. Store.Save
	// refuses one, because FR-005 says an environment token is never
	// persisted. The field is unexported so that only this package can set it
	// and no caller can clear it, which turns "remember not to save it" into
	// something the type enforces.
	fromEnv bool
}

// Issued builds a Credential from what the device token endpoint returned.
//
// expiresIn is the response's `expires_in`, in seconds. A value of zero or
// less leaves ExpiresAt at its zero value rather than computing an expiry in
// the past: the hub declining to state a lifetime and the hub stating a
// lifetime that has already elapsed are different facts, and treating the
// first as the second would throw away a token that works.
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

// FromEnvironment reports whether this credential came from TokenEnvVar rather
// than from a store, which is what makes it unsavable.
func (c Credential) FromEnvironment() bool { return c.fromEnv }

// String implements fmt.Stringer without the token (FR-007).
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

// storedCredential is the JSON amctl puts in a keyring item.
//
// The timestamps are RFC 3339 strings and omitted when zero, so a
// hand-inspected fallback file reads as a date rather than as
// "0001-01-01T00:00:00Z", and an absent lifetime stays absent through a round
// trip instead of becoming a timestamp in the year 1.
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

// decodeCredential turns a stored blob back into a Credential, refusing rather
// than guessing.
//
// hubURL is what the caller asked for. A stored credential naming a different
// hub is refused instead of returned: the item key is a digest of the URL, so a
// mismatch means either a hand-edited store or a collision, and handing one
// hub's bearer token to another is the single worst thing this package could
// do. The error names both hubs and no token.
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

// parseStoredTime refuses an unparseable timestamp rather than defaulting it to
// zero. Zero means "no stated expiry", which is the permissive reading, so
// silently falling back to it would turn a corrupt record into a token that
// never expires.
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
