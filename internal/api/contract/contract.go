// Package contract holds the request and response shapes that cross the HTTP
// boundary.
//
// Constitution principle V: the OpenAPI document is EMITTED from these types and
// the huma operations that use them. Nothing here is a copy of
// specs/001-agent-manager-hub/contracts/openapi.yaml — that file freezes the
// machine-facing subset, and internal/api's superset test is what proves this
// package still satisfies it. A struct tag changed here changes the published
// contract, so treat it as such.
package contract

import "time"

// Profile is one entry of listProfiles. Visibility says how the profile came to
// be readable by the caller, which is why it is not the profile's own setting
// rendered verbatim.
type Profile struct {
	Slug         string `json:"slug" doc:"URL-safe identifier, unique within the organisation." example:"platform-baseline"`
	Name         string `json:"name" doc:"Human-readable name as shown in the web UI." example:"Platform baseline"`
	Visibility   string `json:"visibility,omitempty" enum:"organisation,shared,private" doc:"How this profile came to be readable by this identity." example:"organisation"`
	PackageCount int    `json:"packageCount" doc:"Packages in the head revision, excluding skipped entries." example:"12"`
	HeadRevision int    `json:"headRevision" doc:"The most recent published revision number." example:"7"`
}

// ProfileList is the listProfiles body. FR-044: it holds exactly the profiles the
// caller may read, so it is the whole list and not a page of a larger one.
type ProfileList struct {
	Profiles []Profile `json:"profiles" doc:"Readable profiles. Order is not part of the contract."`
}

// Lockfile is the resolved revision the CLI syncs from. It is the Go form of
// contracts/lockfile.schema.json; the superset test compares the emitted schema
// against that file property by property.
type Lockfile struct {
	SchemaVersion string          `json:"schemaVersion" const:"1.0.0"`
	Profile       LockfileProfile `json:"profile" doc:"Identifies the profile this revision belongs to."`
	Revision      int             `json:"revision" minimum:"1" doc:"Sequential per profile, no gaps." example:"7"`
	Note          string          `json:"note,omitempty" doc:"The publisher's note on this revision." example:"Quarterly refresh"`
	ResolvedAt    time.Time       `json:"resolvedAt"`
	Gate          string          `json:"gate" enum:"block,approval,warn-with-override" doc:"The org scan gate in force at resolution. Recorded so a lockfile explains itself later." example:"approval"`
	DefaultPolicy string          `json:"defaultPolicy,omitempty" enum:"floating-latest,pinned,range" example:"pinned"`
	Entries       []LockfileEntry `json:"entries" doc:"Packages this revision resolves to an exact version."`
	Skipped       []LockfileSkip  `json:"skipped" doc:"FR-036: an excluded package is reported with its reason, never silently omitted."`
	Targets       []string        `json:"targets" enum:"claude-code,codex" doc:"Which agent directories the CLI should write. Advisory to the client; the server stores nothing per target (FR-039)."`
}

// LockfileProfile identifies the profile a lockfile belongs to.
type LockfileProfile struct {
	Slug       string `json:"slug" example:"platform-baseline"`
	Name       string `json:"name" example:"Platform baseline"`
	Visibility string `json:"visibility,omitempty" enum:"organisation,shared,private" example:"organisation"`
}

// LockfileEntry is one package resolved to an exact version. `verdict` is
// narrower than the catalog's: a rejected version never reaches a lockfile
// (FR-029), so `rejected` is not a value this schema admits.
type LockfileEntry struct {
	ID         string             `json:"id" doc:"publisher/name" example:"acme/code-review"`
	Kind       string             `json:"kind" enum:"plugin,skill" example:"skill"`
	Version    string             `json:"version" example:"2.4.1"`
	Digest     string             `json:"digest" pattern:"^sha256:[0-9a-f]{64}$"`
	ObjectKey  string             `json:"objectKey" example:"bundles/acme/code-review/2.4.1/bundle.tar.zst"`
	Resolution string             `json:"resolution" enum:"latest,pinned,range" example:"pinned"`
	Verdict    string             `json:"verdict" enum:"clean,flagged" example:"clean"`
	Override   *LockfileOverride  `json:"override,omitempty" doc:"Present only when a flagged version resolved under warn-with-override."`
	Signature  *LockfileSignature `json:"signature,omitempty" doc:"Signature provenance, when the source carried one."`
}

// LockfileOverride records the human decision that let a flagged version through.
type LockfileOverride struct {
	Reviewer  string    `json:"reviewer" example:"security-lead@example.dev"`
	Note      string    `json:"note" example:"Network call is to our own registry"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// LockfileSignature carries signature provenance. Verified stays false until
// cryptographic verification ships (FR-048a) and must never be rendered as a pass.
type LockfileSignature struct {
	Ref      string `json:"ref,omitempty" example:"sigstore:acme/code-review@2.4.1"`
	Verified *bool  `json:"verified,omitempty" doc:"False until Sigstore verification ships (FR-048a). Never render a false value as a pass."`
}

// LockfileSkip is an excluded package and the reason it was excluded (FR-036).
type LockfileSkip struct {
	ID                  string `json:"id" example:"acme/legacy-helper"`
	Reason              string `json:"reason" enum:"flagged-blocked-by-gate,flagged-awaiting-approval,version-rejected,no-clean-version-available,pin-target-missing,unsigned-and-signatures-required" example:"flagged-awaiting-approval"`
	Detail              string `json:"detail,omitempty" example:"SH-NET-002 in postinstall.sh"`
	WouldHaveResolvedTo string `json:"wouldHaveResolvedTo,omitempty" example:"1.9.0"`
}

// DeviceAuthorizeRequest opens an RFC 8628 authorisation.
type DeviceAuthorizeRequest struct {
	ClientID string `json:"client_id" doc:"The CLI's registered OAuth client identifier." example:"agent-manager-cli"`
	Host     string `json:"host" doc:"Hostname of the requesting machine. Bound to the authorisation and displayed to the approving human (FR-041), so approval is an informed act." example:"dev-laptop-01"`
	Scope    string `json:"scope,omitempty" doc:"Space-delimited scopes. Omitted means the client's default scope." example:"profiles:read bundles:read"`
}

// DeviceAuthorization is a pending request, not a credential grant.
//
// The name avoids `DeviceAuthorizeResponse`: oapi-codegen names its own client
// wrapper types `<operationId>Response`, and a schema with that name collides
// with the generated code. Schema names are not part of the frozen contract,
// which declares these bodies inline, so the rename costs nothing.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code" doc:"Bearer credential. Stored hashed server-side; never logged."`
	UserCode                string `json:"user_code" pattern:"^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$" doc:"Crockford base32, ambiguous glyphs excluded. Shape \"HKQ2-9FTL\"." example:"HKQ2-9FTL"`
	VerificationURI         string `json:"verification_uri" format:"uri" doc:"The page the human opens to type the user code in."`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty" format:"uri" doc:"The same page with the code pre-filled, for a QR code or a click."`
	ExpiresIn               int    `json:"expires_in" doc:"Seconds until the device code expires and polling must stop." example:"900"`
	Interval                int    `json:"interval" doc:"Minimum seconds between polls of /v1/device/token." example:"5"`
}

// DeviceTokenRequest is the RFC 8628 token request. It arrives form-encoded, as
// the RFC requires, which is why the operation declares the media type by hand:
// huma models an object body as JSON and cannot express this one.
type DeviceTokenRequest struct {
	GrantType  string `json:"grant_type" const:"urn:ietf:params:oauth:grant-type:device_code" doc:"Fixed by RFC 8628 3.4. No other grant type is accepted here."`
	DeviceCode string `json:"device_code" doc:"The device_code handed back by /v1/device/authorize."`
	ClientID   string `json:"client_id" doc:"Must be the same client_id that opened the authorisation." example:"agent-manager-cli"`
}

// DeviceToken carries the short-lived machine token (FR-043).
type DeviceToken struct {
	AccessToken  string `json:"access_token" doc:"Bearer token for every other operation here. Never logged."`
	TokenType    string `json:"token_type" const:"Bearer" doc:"Always Bearer."`
	ExpiresIn    int    `json:"expires_in" doc:"Seconds until the access token expires." example:"3600"`
	RefreshToken string `json:"refresh_token,omitempty" doc:"Present only when the client may refresh without a second human approval."`
}

// DeviceTokenError is the RFC 8628 error envelope, which is deliberately NOT the
// project's error shape: the RFC fixes these field names and a polling client
// parses them. Every other operation returns Error.
type DeviceTokenError struct {
	Error string `json:"error,omitempty" enum:"authorization_pending,slow_down,access_denied,expired_token,invalid_grant" doc:"authorization_pending means keep polling at the advertised interval; slow_down means back off and widen it. The rest are final - stop." example:"authorization_pending"`
}

// SyncReport is one completed sync, not one package (FR-050, R8).
type SyncReport struct {
	Profile  string   `json:"profile" doc:"Slug of the profile that was synced." example:"platform-baseline"`
	Revision int      `json:"revision" doc:"The exact revision the client resolved against." example:"7"`
	Host     string   `json:"host" doc:"Hostname the sync landed on, for the audit row." example:"dev-laptop-01"`
	Targets  []string `json:"targets" enum:"claude-code,codex" doc:"Agent directories the client actually wrote."`
	Skipped  []string `json:"skipped,omitempty" doc:"Entry ids the client skipped locally, if any."`
}

// Health is the FR-058 probe body. The frozen contract declares no body for
// /v1/health, so this is additive: a probe that says only "503" tells an operator
// nothing about which dependency went away.
type Health struct {
	Status string        `json:"status" enum:"ok,unavailable"`
	Checks []HealthCheck `json:"checks" doc:"One entry per dependency this role needs."`
}

// HealthCheck is one dependency's result.
type HealthCheck struct {
	Name  string `json:"name" example:"database"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty" doc:"Fixed text when the dependency is unreachable. The driver's message goes to the log, never to this unauthenticated body, because it can carry a host or a DSN."`
}
