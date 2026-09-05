// Package contract holds the request and response shapes that cross the HTTP
// boundary. The OpenAPI document is emitted from these types; a struct tag
// changed here changes the published contract.
package contract

import "time"

type Profile struct {
	Slug         string `json:"slug" doc:"URL-safe identifier, unique within the organisation." example:"platform-baseline"`
	Name         string `json:"name" doc:"Human-readable name as shown in the web UI." example:"Platform baseline"`
	Visibility   string `json:"visibility,omitempty" enum:"organisation,shared,private" doc:"How this profile came to be readable by this identity." example:"organisation"`
	PackageCount int    `json:"packageCount" doc:"Packages in the head revision, excluding skipped entries." example:"12"`
	HeadRevision int    `json:"headRevision" doc:"The most recent published revision number." example:"7"`
}

type ProfileList struct {
	Profiles []Profile `json:"profiles" doc:"Readable profiles. Order is not part of the contract."`
}

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

type LockfileProfile struct {
	Slug       string `json:"slug" example:"platform-baseline"`
	Name       string `json:"name" example:"Platform baseline"`
	Visibility string `json:"visibility,omitempty" enum:"organisation,shared,private" example:"organisation"`
}

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

type LockfileOverride struct {
	Reviewer  string    `json:"reviewer" example:"security-lead@example.dev"`
	Note      string    `json:"note" example:"Network call is to our own registry"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Verified stays false until cryptographic verification ships and must
// never be rendered as a pass.
type LockfileSignature struct {
	Ref      string `json:"ref,omitempty" example:"sigstore:acme/code-review@2.4.1"`
	Verified *bool  `json:"verified,omitempty" doc:"False until Sigstore verification ships (FR-048a). Never render a false value as a pass."`
}

type LockfileSkip struct {
	ID                  string `json:"id" example:"acme/legacy-helper"`
	Reason              string `json:"reason" enum:"flagged-blocked-by-gate,flagged-awaiting-approval,version-rejected,no-clean-version-available,pin-target-missing,unsigned-and-signatures-required" example:"flagged-awaiting-approval"`
	Detail              string `json:"detail,omitempty" example:"SH-NET-002 in postinstall.sh"`
	WouldHaveResolvedTo string `json:"wouldHaveResolvedTo,omitempty" example:"1.9.0"`
}

type DeviceAuthorizeRequest struct {
	ClientID string `json:"client_id" doc:"The CLI's registered OAuth client identifier." example:"agent-manager-cli"`
	Host     string `json:"host" doc:"Hostname of the requesting machine. Bound to the authorisation and displayed to the approving human (FR-041), so approval is an informed act." example:"dev-laptop-01"`
	Scope    string `json:"scope,omitempty" doc:"Space-delimited scopes. Omitted means the client's default scope." example:"profiles:read bundles:read"`
}

// DeviceAuthorization avoids the name `DeviceAuthorizeResponse`: oapi-codegen
// names its own client wrapper types that way, and a schema with that name
// would collide with the generated code.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code" doc:"Bearer credential. Stored hashed server-side; never logged."`
	UserCode                string `json:"user_code" pattern:"^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$" doc:"Crockford base32, ambiguous glyphs excluded. Shape \"HKQ2-9FTL\"." example:"HKQ2-9FTL"`
	VerificationURI         string `json:"verification_uri" format:"uri" doc:"The page the human opens to type the user code in."`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty" format:"uri" doc:"The same page with the code pre-filled, for a QR code or a click."`
	ExpiresIn               int    `json:"expires_in" doc:"Seconds until the device code expires and polling must stop." example:"900"`
	Interval                int    `json:"interval" doc:"Minimum seconds between polls of /v1/device/token." example:"5"`
}

// DeviceTokenRequest arrives form-encoded, as RFC 8628 requires; the
// operation declares the media type by hand since huma models an object
// body as JSON.
type DeviceTokenRequest struct {
	GrantType  string `json:"grant_type" const:"urn:ietf:params:oauth:grant-type:device_code" doc:"Fixed by RFC 8628 3.4. No other grant type is accepted here."`
	DeviceCode string `json:"device_code" doc:"The device_code handed back by /v1/device/authorize."`
	ClientID   string `json:"client_id" doc:"Must be the same client_id that opened the authorisation." example:"agent-manager-cli"`
}

type DeviceToken struct {
	AccessToken  string `json:"access_token" doc:"Bearer token for every other operation here. Never logged."`
	TokenType    string `json:"token_type" const:"Bearer" doc:"Always Bearer."`
	ExpiresIn    int    `json:"expires_in" doc:"Seconds until the access token expires." example:"3600"`
	RefreshToken string `json:"refresh_token,omitempty" doc:"Present only when the client may refresh without a second human approval."`
}

type PendingDeviceAuthorization struct {
	RequestingHost string `json:"requestingHost" doc:"The host bound to this authorisation at issue. Shown before approval so it is an informed act." example:"dev-laptop-01"`
	ExpiresIn      int    `json:"expiresIn" doc:"Seconds until this code expires." example:"420"`
}

type ApprovedDeviceAuthorization struct {
	RequestingHost string `json:"requestingHost" example:"dev-laptop-01"`
}

// DeviceTokenError is deliberately NOT the project's error shape: RFC 8628
// fixes these field names and a polling client parses them.
type DeviceTokenError struct {
	Error string `json:"error,omitempty" enum:"authorization_pending,slow_down,access_denied,expired_token,invalid_grant" doc:"authorization_pending means keep polling at the advertised interval; slow_down means back off and widen it. The rest are final - stop." example:"authorization_pending"`
}

type SyncReport struct {
	Profile  string   `json:"profile" doc:"Slug of the profile that was synced." example:"platform-baseline"`
	Revision int      `json:"revision" doc:"The exact revision the client resolved against." example:"7"`
	Host     string   `json:"host" doc:"Hostname the sync landed on, for the audit row." example:"dev-laptop-01"`
	Targets  []string `json:"targets" enum:"claude-code,codex" doc:"Agent directories the client actually wrote."`
	Skipped  []string `json:"skipped,omitempty" doc:"Entry ids the client skipped locally, if any."`
}

type Health struct {
	Status string        `json:"status" enum:"ok,unavailable"`
	Checks []HealthCheck `json:"checks" doc:"One entry per dependency this role needs."`
}

type HealthCheck struct {
	Name  string `json:"name" example:"database"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty" doc:"Fixed text when the dependency is unreachable. The driver's message goes to the log, never to this unauthenticated body, because it can carry a host or a DSN."`
}
