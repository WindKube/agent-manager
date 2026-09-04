package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"reflect"
	"strconv"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

// register declares the whole HTTP surface. This is the file the OpenAPI document
// is emitted from (constitution principle V): an operation that is not here does
// not exist, and one that is here cannot be undocumented.
func (s *Server) register() {
	s.registerHealth()
	s.registerDevice()
	s.registerSessions()
	s.registerPackages()
	s.registerProfiles()
	s.registerBundles()
	s.registerSync()
	s.registerScanner()
	s.registerAudit()
	s.registerBadges()
	s.registerDeviceApproval()
	s.registerStorage()
}

// publicSecurity is the empty security requirement that removes the document's
// root requirement for one operation. It must be non-nil and empty: OpenAPI reads
// an absent `security` as "inherit the root" and an empty array as "none".
func publicSecurity() []map[string][]string { return []map[string][]string{} }

func (s *Server) registerHealth() {
	huma.Register(s.api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/v1/health",
		Tags:        []string{"system"},
		Summary:     "Liveness and readiness",
		Description: "Liveness and readiness in one probe: 200 when every dependency this role needs is " +
			"reachable, 503 otherwise. Has no authenticated variant and no client error case (FR-058).",
		Security: publicSecurity(),
		Responses: map[string]*huma.Response{
			"200": {Description: "Serving."},
			"503": {
				Description: "Not ready — a dependency is unreachable.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.Health{}, "Health")},
				},
			},
		},
	}, s.health)
}

func (s *Server) registerDevice() {
	huma.Register(s.api, huma.Operation{
		OperationID: "deviceAuthorize",
		Method:      http.MethodPost,
		Path:        "/v1/device/authorize",
		Tags:        []string{"device"},
		Summary:     "Begin device authorisation",
		Description: "Opens an RFC 8628 device authorisation. Returns a user code for the human to type on " +
			"the hub's verification page and a device code for the client to poll with. Nothing is " +
			"authorised until a human approves that user code, so the response is not a credential " +
			"grant — it is a pending request.",
		Security: publicSecurity(),
		// The issuance cap is an operation middleware rather than a branch in the
		// handler, so the 429 is answered before a statement is issued and the body
		// stays empty, which is what the declared response says (device.go).
		Middlewares: huma.Middlewares{s.limitDeviceAuthorize},
		Responses: map[string]*huma.Response{
			// 400 and 415 are the framework's own, not this handler's: the request
			// body is `required: true` and JSON-only, so an absent body, a body that
			// is not JSON and a body sent under another media type are all refused
			// before deviceAuthorize runs. They are declared because they are what
			// actually goes out — a generated client (internal/apiclient) leaves every
			// typed response field nil for an undeclared status and returns no error,
			// so a caller switching on those fields reads an undeclared 400 as
			// "success, empty body". Same reasoning as deviceToken's 400 below.
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("The request body is not a valid authorisation request."),
			"429": {
				Description: "Too many requests.",
				Headers: map[string]*huma.Param{
					"Retry-After": {
						Description: "Seconds to wait before retrying.",
						Schema:      &huma.Schema{Type: huma.TypeInteger},
					},
				},
			},
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.deviceAuthorize)

	huma.Register(s.api, huma.Operation{
		OperationID: "deviceToken",
		Method:      http.MethodPost,
		Path:        "/v1/device/token",
		Tags:        []string{"device"},
		Summary:     "Poll for the issued token",
		Description: "Standard RFC 8628 polling. A code that has expired, been consumed, or been approved " +
			"by an identity other than the requester is refused and no token is issued (FR-042). " +
			"The issued token is a session for the identity that APPROVED the authorisation, so the " +
			"machine holds exactly that person's access, re-derived from their groups on every " +
			"request (FR-040, FR-044).",
		Security: publicSecurity(),
		Responses: map[string]*huma.Response{
			"400": {
				Description: "RFC 8628 error. A request that is not a token request at all — no body — is " +
					"refused before the flow is entered and carries the project's error shape instead; " +
					"the two are told apart by the response's content type.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.DeviceTokenError{}, "DeviceTokenError")},
					// Declared because it is what actually goes out, not because a
					// second shape is wanted here. The request body is `required: true`
					// in the frozen contract, so an absent body is refused by the
					// framework's own validation before this handler runs, and a
					// response the document does not describe is worse than a second
					// media type that it does.
					"application/problem+json": {Schema: s.schemaOf(contract.Error{}, "Error")},
				},
			},
			// Declared because a fault here must not be reported as one of the RFC's
			// five values: three of them are terminal, so answering a database outage
			// with invalid_grant would tell every polling client to give up.
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.deviceToken)

	// RFC 8628 3.4 fixes this body as form-encoded, and huma models an object body
	// as JSON only, so the media type is declared here instead. The schema still
	// comes from contract.DeviceTokenRequest — it is emitted, not hand-written.
	s.declareRequestBody(http.MethodPost, "/v1/device/token", "application/x-www-form-urlencoded",
		"The RFC 8628 token request, form-encoded as the RFC requires.",
		s.schemaOf(contract.DeviceTokenRequest{}, "DeviceTokenRequest"))
}

func (s *Server) registerSessions() {
	huma.Register(s.api, huma.Operation{
		OperationID: "createSession",
		Method:      http.MethodPost,
		Path:        "/v1/sessions",
		Tags:        []string{"identity"},
		Summary:     "Mint a browser session from a verified ID token",
		Description: "The one operation in this system whose caller is a ROLE rather than a person, and it " +
			"can mint a session for any subject — its rules are contracts/auth.md's and its " +
			"justification is the sole row of the plan's Complexity Tracking table. The web role " +
			"owns the browser's origin and therefore the cookie; this role owns the relational " +
			"schema and therefore the session row (FR-111), and this call is the whole of what " +
			"crosses that gap. " +
			"It takes the RAW ID token and verifies it here, against the configured issuer, " +
			"audience and signing keys: verification lives in the role that owns identity, the " +
			"caller's own parsing is not trusted, and the shared secret is therefore defence in " +
			"depth rather than the only control. " +
			"Refused outright when no shared secret is configured — there is no default and no " +
			"development bypass, because an unauthenticated session mint is an account-takeover " +
			"primitive. Refusals are rate-limited per caller address.",
		Security: sessionMintSecurity(),
		// The cap is an operation middleware rather than a branch in the handler, so
		// a blocked caller is answered before the secret is compared at all.
		Middlewares: huma.Middlewares{s.limitSessionMint},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Minted. The token is in this body and nowhere else on this side: the row holds " +
					"only its sha256.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.Session{}, "Session")},
				},
			},
			// Declared for the same reason the device flow declares its framework
			// failures: a generated client leaves every typed response field nil for
			// an undeclared status and returns no error, so a caller switching on
			// those fields reads an undeclared 400 as "success, empty body".
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"401": s.errorResponse("The shared secret is missing or is not the one this hub holds."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("The body carries no ID token, or the ID token did not verify. The " +
				"second case is deliberately unexplained: which check failed is not something to " +
				"tell whoever presented the token."),
			"429": s.errorResponse("Too many refused mints from this address."),
			"500": s.errorResponse("The request could not be completed."),
			"503": s.errorResponse("This hub cannot mint sessions: no shared secret is configured, or the " +
				"identity provider could not be reached to verify the token."),
		},
	}, s.createSession)

	huma.Register(s.api, huma.Operation{
		OperationID:   "deleteSession",
		Method:        http.MethodDelete,
		Path:          "/v1/sessions/current",
		Tags:          []string{"identity"},
		Summary:       "Sign out",
		DefaultStatus: http.StatusNoContent,
		Description: "Expires the session this request presented, server-side, and writes the sign-out " +
			"audit row in the same transaction (FR-114, FR-115). Clearing the cookie is the " +
			"caller's courtesy to the browser, not the mechanism: a replayed cookie is refused " +
			"here afterwards, indistinguishably from a token that never existed. " +
			"Exactly this session and no other — expiring every session the identity holds would " +
			"be a remote sign-out, which is a real feature and a later one.",
		Responses: map[string]*huma.Response{
			"204": {Description: "Signed out."},
			"401": s.errorResponse("Missing, expired or invalid token. Also what a session that had " +
				"already expired gets, and what a second concurrent sign-out gets — the caller " +
				"clears its cookie either way, so the two need not be told apart."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.deleteSession)

	huma.Register(s.api, huma.Operation{
		OperationID: "getViewer",
		Method:      http.MethodGet,
		Path:        "/v1/viewer",
		Tags:        []string{"identity"},
		Summary:     "Who this request is acting as",
		Description: "The display name, email and role of the identity behind this request, plus whether " +
			"any group it holds maps to a role AT ALL (FR-117) — signed in with no role is a " +
			"screen state a person must be told about, never an empty catalog. " +
			"Resolved on this request and not cached: the session resolver joins group_role_map " +
			"every time, which is what makes an admin's mapping change take effect on the next " +
			"request with nothing to invalidate (FR-118).",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token. There is no anonymous viewer."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getViewer)
}

func (s *Server) registerPackages() {
	huma.Register(s.api, huma.Operation{
		OperationID: "listPackages",
		Method:      http.MethodGet,
		Path:        "/v1/packages",
		Tags:        []string{"catalog"},
		Summary:     "Browse, search and facet the catalog",
		Description: "One page of the catalog with both facet option sets and the live total, from two " +
			"statements issued concurrently (R4). The two facets count differently, and the " +
			"asymmetry is FR-013's: CATEGORIES are disjunctive, so each option is counted with " +
			"the category filter removed; TAGS are conjunctive, so each option is counted " +
			"against the current results — the number selecting it actually yields. " +
			"Browsing requires a session: public anonymous browsing is out of scope (spec.md).",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("No usable session. The caller must sign in; there is no anonymous view."),
			"422": s.errorResponse("A filter value is outside its vocabulary."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.listPackages)

	huma.Register(s.api, huma.Operation{
		OperationID: "getPackage",
		Method:      http.MethodGet,
		Path:        "/v1/packages/{namespace}/{name}",
		Tags:        []string{"catalog"},
		Summary:     "One package's detail",
		Description: "Description, origin, tags, manifest, components, capabilities, version history and " +
			"dependent profiles for one package (FR-016). The path is the package id, whose two " +
			"segments are the namespace and the name. " +
			"Two panels are scoped to the caller: the dependent profiles are exactly the ones this " +
			"identity may read (FR-044), and each version's `pinnedBy` counts only those — an " +
			"unscoped count beside a scoped list would leak the existence of private profiles by " +
			"arithmetic. " +
			"`capabilities.scanned` distinguishes a version that was scanned and reaches nothing " +
			"from one that has never been scanned; the two produce identical empty lists, and only " +
			"that flag tells them apart.",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("No usable session. The caller must sign in; there is no anonymous view."),
			"404": s.errorResponse("No such package, or it has no published version."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getPackage)

	huma.Register(s.api, huma.Operation{
		OperationID: "previewPackage",
		Method:      http.MethodPost,
		Path:        "/v1/packages/preview",
		Tags:        []string{"packages"},
		Summary:     "Validate an archive before registering it",
		Description: "FR-005's pre-submit answer: every entry with a validation mark, the discarded paths " +
			"named, the components the FILE TREE reveals, and — when a manifest fails — the " +
			"schema path that refused it. Writes nothing, and runs the same validation the " +
			"fetcher runs, so the panel a user approves is the tree that gets stored.",
		MaxBodyBytes: maxUploadBytes,
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"413": s.errorResponse("The archive is larger than this hub accepts."),
			"422": s.errorResponse("No archive was attached, or it could not be read."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.previewPackage)

	huma.Register(s.api, huma.Operation{
		OperationID:   "registerPackage",
		Method:        http.MethodPost,
		Path:          "/v1/packages",
		Tags:          []string{"packages"},
		Summary:       "Register a package from a URL or an upload",
		DefaultStatus: http.StatusAccepted,
		Description: "Creates the publisher, the package and an invisible version, enqueues the fetch and " +
			"writes the audit row, in one transaction. The response is an acknowledgement and not " +
			"a published version: the bytes are fetched, validated, packed and committed by " +
			"`worker fetcher`, which is the only role that may write them. A version becomes " +
			"visible only once all of that has landed (FR-008).",
		MaxBodyBytes: maxUploadBytes,
		Responses: map[string]*huma.Response{
			"202": {
				Description: "Registered. The fetch is queued.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.PackageRegistered{}, "PackageRegistered")},
				},
			},
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity may not register a package."),
			"409": s.errorResponse("FR-007: this publisher/name@version is already published and its bytes are immutable."),
			"413": s.errorResponse("The archive is larger than this hub accepts."),
			"422": s.errorResponse("The registration is incomplete, or the uploaded archive was refused."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.registerPackage)
}

func (s *Server) registerProfiles() {
	huma.Register(s.api, huma.Operation{
		OperationID: "listProfiles",
		Method:      http.MethodGet,
		Path:        "/v1/profiles",
		Tags:        []string{"profiles"},
		Summary:     "Profiles readable by this identity",
		Description: "Returns exactly the profiles this identity may read via direct membership or group " +
			"mapping, and no others (FR-044). Not a filtered view of a larger list — unreadable " +
			"profiles are not enumerated at all.",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.listProfiles)

	huma.Register(s.api, huma.Operation{
		OperationID: "getProfile",
		Method:      http.MethodGet,
		Path:        "/v1/profiles/{slug}",
		Tags:        []string{"profiles"},
		Summary:     "One profile, resolved under the org gate",
		Description: "The profile detail screen (001 US5): every package the profile holds, what each one " +
			"resolves to, its scan state, and what the gate did about it — INCLUDING the entries " +
			"the gate excludes, which are reported with their reason and never silently omitted " +
			"(FR-036). " +
			"The gate's effect is COMPUTED by the one resolver internal/domain/resolve holds, the " +
			"same code the published lockfile and the CLI's sync go through. It is not restated " +
			"in this query, because two implementations of the gate is how the screen and the " +
			"machine start disagreeing about what is installed. " +
			"`latestVersion` / `latestVerdict` are what the CATALOG offers and are the row's scan " +
			"badge; `version` / `verdict` are what the entry actually resolves to and are absent " +
			"when it is excluded. The two differ exactly when the gate did something. " +
			"`unpublishedChanges` is 001 US5 scenario 1: a pin toggled here reaches no machine " +
			"until a revision is published, and this says a revision is owed.",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"404": s.errorResponse("No such profile, or not readable by this identity. The two are " +
				"deliberately one answer (FR-044)."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getProfile)

	huma.Register(s.api, huma.Operation{
		OperationID:   "createProfile",
		Method:        http.MethodPost,
		Path:          "/v1/profiles",
		Tags:          []string{"profiles"},
		Summary:       "Create a profile, or fork one",
		DefaultStatus: http.StatusCreated,
		Description: "Creates a profile and records the caller as its OWNER, in one transaction with one " +
			"audit row of kind `profile`. The owner membership is not a courtesy: every other " +
			"profile operation is authorised by membership role, and `am_api` holds no DELETE on " +
			"`membership`, so a profile created without one would be permanently uneditable. " +
			"`forkOf` copies the named profile's entries as they stand at this instant and records " +
			"the lineage. A fork NEVER inherits a revision the upstream publishes afterwards " +
			"(FR-038) — not by configuration but by construction: nothing reads `forked_from_id` " +
			"in the other direction. The upstream must be readable by this identity. " +
			"Visibility defaults to `private`: a profile nobody has chosen to publish is not " +
			"readable by the whole organisation. " +
			"Requires an organisation role above read-only.",
		Responses: map[string]*huma.Response{
			"201": {
				Description: "Created.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.Profile{}, "Profile")},
				},
			},
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity may not create a profile."),
			"404": s.errorResponse("`forkOf` names no profile this identity may read."),
			"409": s.errorResponse("A profile with this slug already exists."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("The slug, the visibility or the default policy is not one this hub accepts."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.createProfile)

	huma.Register(s.api, huma.Operation{
		OperationID: "setProfileEntries",
		Method:      http.MethodPut,
		Path:        "/v1/profiles/{slug}/entries",
		Tags:        []string{"profiles"},
		Summary:     "Set the packages a profile holds and how each one tracks versions",
		Description: "Float or pin per package (FR-032), in one transaction with one audit row of kind " +
			"`profile`. " +
			"NOT DURABLE UNTIL A REVISION IS PUBLISHED (001 US5 scenario 1). This writes the " +
			"draft — `profile_entry` — and nothing a machine syncs changes until " +
			"POST /v1/profiles/{slug}/revisions freezes it. The response is the profile as it now " +
			"resolves, with `unpublished` set on every row that differs from the head revision. " +
			"The body is the WHOLE ordered set, because position is what an ordered set means and " +
			"a patch cannot express a reorder. Naming a package the profile does not hold adds it. " +
			"OMITTING one it does hold is REFUSED and named: `am_api` deliberately holds no DELETE " +
			"on `profile_entry` (removal is unspecified and no screen carries the control), so " +
			"quietly keeping it would answer 200 to a request whose stored result disagrees with " +
			"what was sent. " +
			"Requires owner or maintainer on the profile.",
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Set. The body is the profile as it now resolves.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.ProfileDetail{}, "ProfileDetail")},
				},
			},
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity may not curate this profile."),
			"404": s.errorResponse("No such profile, or not readable by this identity."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("A package is unknown, a pin names a version this hub does not hold, a " +
				"range is not a constraint, or the request leaves out a package the profile holds."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.setProfileEntries)

	huma.Register(s.api, huma.Operation{
		OperationID: "setProfileSharing",
		Method:      http.MethodPut,
		Path:        "/v1/profiles/{slug}/sharing",
		Tags:        []string{"profiles"},
		Summary:     "Set the role each member and identity-provider group holds",
		Description: "Individual members and IdP groups at the four levels FR-037 names — owner, " +
			"maintainer, reviewer, consumer — in one transaction with one audit row of kind " +
			"`share`. " +
			"An UPSERT of roles and not a replacement of the membership set: a subject the body " +
			"does not name keeps the role it has. FR-037 is about roles, a demotion is an update " +
			"of `role`, and `am_api` holds no DELETE on `membership`. " +
			"A body that would leave the profile with NO OWNER is refused, because nothing could " +
			"add one back — only an owner may change sharing. " +
			"A group is matched against the `groups` claim on every request rather than expanded " +
			"into people, so losing a mapped group takes effect at the next token refresh " +
			"(FR-045) and a near-miss on the group's name silently grants nothing. " +
			"Nothing here can make a fork inherit a revision (FR-038); sharing grants access to " +
			"this profile and creates no relationship between two of them. " +
			"Requires owner on the profile.",
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Shared. The body is the profile, with its members.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.ProfileDetail{}, "ProfileDetail")},
				},
			},
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity may not change who can see this profile."),
			"404": s.errorResponse("No such profile, or not readable by this identity."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("A subject or role is outside its vocabulary, a subject is named twice, " +
				"or the change would leave the profile with no owner."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.setProfileSharing)

	huma.Register(s.api, huma.Operation{
		OperationID: "setProfileTargets",
		Method:      http.MethodPut,
		Path:        "/v1/profiles/{slug}/targets",
		Tags:        []string{"profiles"},
		Summary:     "Choose which agent directories a client writes",
		Description: "The enabled set, in full, with one audit row of kind `profile`. An omitted target is " +
			"disabled rather than removed — `sync_target.enabled` is a column, which is how a " +
			"replacement works with no DELETE grant. " +
			"A TARGET AFFECTS ONLY WHAT A CLIENT WRITES LOCALLY, never what the server stores " +
			"(001 US5 scenario 7, FR-039). Nothing the resolver reads changes here and no version " +
			"resolves differently; the list rides in the lockfile so a client knows where to put " +
			"what it already resolved. " +
			"An empty list is legal and means the profile writes nothing until somebody chooses. " +
			"Requires owner or maintainer on the profile.",
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Set. The body is the profile, with every target and whether it is enabled.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.ProfileDetail{}, "ProfileDetail")},
				},
			},
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity may not curate this profile."),
			"404": s.errorResponse("No such profile, or not readable by this identity."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("A named target is not one this hub writes."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.setProfileTargets)

	huma.Register(s.api, huma.Operation{
		OperationID:   "publishRevision",
		Method:        http.MethodPost,
		Path:          "/v1/profiles/{slug}/revisions",
		Tags:          []string{"profiles"},
		Summary:       "Publish the next immutable revision",
		DefaultStatus: http.StatusCreated,
		Description: "Freezes the current resolution as a new sequential revision and writes one audit row " +
			"of kind `profile` (001 US5 scenario 5, FR-033). The body is the lockfile it wrote. " +
			"The lockfile comes from the resolver, through the same code path the detail screen " +
			"reads, so a revision cannot freeze a resolution nobody was shown (003 US5 scenario 3). " +
			"THE NUMBER IS THE SERVER'S. There is no field in which to name one, it is allocated " +
			"under a row lock on the profile so two racing publishes serialise into r15 and r16 " +
			"with no gap, and `unique (profile_id, seq)` refuses a duplicate outright. " +
			"REPUBLISHING A NUMBER IS REFUSED, NOT OVERWRITTEN, and the refusal is a constraint " +
			"rather than a branch (principle IV). " +
			"Every previous revision stays readable for ever: `am_api` holds no DELETE on " +
			"`revision` and no UPDATE path reaches one (FR-034). " +
			"Requires owner or maintainer on the profile — a consumer may not publish.",
		Responses: map[string]*huma.Response{
			"201": {
				Description: "Published. The body conforms to lockfile.schema.json.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.Lockfile{}, "Lockfile")},
				},
			},
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity may not publish a revision of this profile."),
			"404": s.errorResponse("No such profile, or not readable by this identity."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("The profile holds a state the resolver refuses."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.publishRevision)

	huma.Register(s.api, huma.Operation{
		OperationID: "getRevision",
		Method:      http.MethodGet,
		Path:        "/v1/profiles/{slug}/revisions/{revision}",
		Tags:        []string{"profiles"},
		Summary:     "Fetch a resolved revision lockfile",
		Description: "`revision` accepts `head` or an integer. The response body conforms to " +
			"lockfile.schema.json, including the `skipped` array — a gate-excluded package is " +
			"reported with its reason, never silently omitted (FR-036).",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"404": s.errorResponse("No such profile or revision, or not readable by this identity."),
			"422": s.errorResponse("`revision` is neither `head` nor an integer."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getRevision)
}

func (s *Server) registerBundles() {
	huma.Register(s.api, huma.Operation{
		OperationID: "getBundle",
		Method:      http.MethodGet,
		Path:        "/v1/bundles/{publisher}/{name}/{version}",
		Tags:        []string{"bundles"},
		Summary:     "Download an immutable version bundle",
		Description: "Returns the `bundle.tar.zst` bytes, or a 307 to a pre-signed object-store URL. The " +
			"`Digest` header carries the sha256 the client MUST verify before writing anything to " +
			"disk. A rejected version is never served regardless of gate (FR-029).",
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Bundle bytes",
				Content: map[string]*huma.MediaType{
					// Declared rather than inferred: huma types a []byte body as a
					// base64 string, and these bytes are served verbatim.
					"application/zstd": {Schema: &huma.Schema{Type: huma.TypeString, Format: "binary"}},
				},
			},
			"307": {Description: "Redirect to a short-lived pre-signed object-store URL."},
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("Version rejected or not distributable under the current gate."),
			"404": s.errorResponse("No such version."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getBundle)
}

func (s *Server) registerSync() {
	huma.Register(s.api, huma.Operation{
		OperationID: "reportSync",
		Method:      http.MethodPost,
		Path:        "/v1/sync",
		Tags:        []string{"profiles"},
		Summary:     "Report a completed sync",
		Description: "Writes one sync_event and one audit row of kind `sync` (FR-050, R8). One call per " +
			"sync, not per package — install counts are aggregated server-side from the " +
			"revision's contents.",
		DefaultStatus: http.StatusNoContent,
		Responses: map[string]*huma.Response{
			"204": {Description: "Recorded."},
			"401": s.errorResponse("Missing, expired or invalid token."),
			"404": s.errorResponse("No such profile or revision, or not readable by this identity."),
			"422": s.errorResponse("The request body is not a valid sync report."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.reportSync)
}

func (s *Server) registerScanner() {
	huma.Register(s.api, huma.Operation{
		OperationID: "scannerSummary",
		Method:      http.MethodGet,
		Path:        "/v1/scanner/summary",
		Tags:        []string{"scanner"},
		Summary:     "The Scanner screen's headline figures",
		Description: "Versions that reached a verdict in the period, how many packages are quarantined, " +
			"how many acceptances are still in force and when the first of them lapses, and the " +
			"median time from a scan starting to its verdict (001 US4 scenario 1). " +
			"`quarantined` counts packages whose LATEST VISIBLE version is flagged, not flagged " +
			"versions: a superseded flagged version is not quarantining anything, because nothing " +
			"resolves to it. " +
			"`nearestOverrideExpiry` and `medianScanSeconds` are ABSENT rather than zero when " +
			"there is nothing to report — no active override and no finished scan are different " +
			"statements from \"expires now\" and \"instant\".",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("No usable session. There is no anonymous view of the scanner."),
			"422": s.errorResponse("`days` is outside 1..365."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.scannerSummary)

	huma.Register(s.api, huma.Operation{
		OperationID: "listFindings",
		Method:      http.MethodGet,
		Path:        "/v1/findings",
		Tags:        []string{"scanner"},
		Summary:     "Findings, paged and filterable",
		Description: "One page of findings, highest severity first and newest within a severity, " +
			"filterable by state and by severity. " +
			"Each row carries the PRIMARY evidence location only; a finding legitimately has " +
			"several, and the whole of them is on the detail operation. " +
			"`verdict` is the subject VERSION's verdict and not the finding's state: an accepted " +
			"finding leaves its version flagged, because the override is what lets it through and " +
			"the gate still governs whether it does.",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("No usable session."),
			"422": s.errorResponse("A filter value is outside its vocabulary."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.listFindings)

	huma.Register(s.api, huma.Operation{
		OperationID: "getFinding",
		Method:      http.MethodGet,
		Path:        "/v1/findings/{id}",
		Tags:        []string{"scanner"},
		Summary:     "One finding, its evidence and every check that ran",
		Description: "The detail pane of 001 US4 scenario 2: severity, rule, subject, the prose " +
			"explanation, EVERY evidence location, and EVERY check the raising scan ran — passes " +
			"included (FR-025). " +
			"The passes are not padding. A pane showing only failures cannot be told apart from " +
			"one where nothing else ran, so the absence of a finding would be indistinguishable " +
			"from the absence of a check, which is the distinction the whole matrix exists for. " +
			"Evidence and check labels are bundle content and identity-provider content " +
			"respectively: every consumer renders them escaped (FR-055).",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("No usable session."),
			"404": s.errorResponse("No such finding."),
			"422": s.errorResponse("The finding id is not a uuid."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getFinding)

	huma.Register(s.api, huma.Operation{
		OperationID: "acceptFinding",
		Method:      http.MethodPost,
		Path:        "/v1/findings/{id}/accept",
		Tags:        []string{"scanner"},
		Summary:     "Accept a finding with a recorded note and an expiry",
		Description: "Approves the finding, records the override carrying the reviewer's identity, their " +
			"note and an expiry, and writes ONE audit row of kind `approve` — all in one " +
			"transaction (FR-028, FR-050). " +
			"The version's verdict is NOT changed. US4 scenario 3 makes the version distributable " +
			"SUBJECT TO THE GATE, and the override is what the gate reads; rewriting the verdict " +
			"to clean would make an accepted version indistinguishable from one that never had a " +
			"finding, under every gate, for ever. " +
			"Re-accepting an already-accepted finding replaces the decision, which is what a " +
			"reviewer extending an expiring override does. " +
			"A rejected finding cannot be accepted: rejection is terminal (409). " +
			"Requires the scanner-reviewer role. The screen must also hide or disable the action " +
			"for an identity that lacks it (FR-126) — this refusal is the backstop, not the " +
			"mechanism.",
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Accepted. The body carries the finding's new state and the version's verdict.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.FindingDecision{}, "FindingDecision")},
				},
			},
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity may not adjudicate a finding."),
			"404": s.errorResponse("No such finding."),
			"409": s.errorResponse("This finding was rejected, which is terminal."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("The finding id is not a uuid, or the body carries no note."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.acceptFinding)

	huma.Register(s.api, huma.Operation{
		OperationID: "rejectFinding",
		Method:      http.MethodPost,
		Path:        "/v1/findings/{id}/reject",
		Tags:        []string{"scanner"},
		Summary:     "Reject a finding and quarantine its version for good",
		Description: "Rejects the finding, sets the subject version's verdict to `rejected`, and writes ONE " +
			"audit row — in one transaction. " +
			"This is TERMINAL and it is not an accept with a different flag. A rejected version " +
			"cannot be resolved by any profile REGARDLESS OF GATE and is never served at all " +
			"(FR-029), so there is no expiry to set and no field in which to suggest there is one. " +
			"An override already recorded on the finding is left in place: it is the record of a " +
			"decision that really was taken, it stops counting as active, and it can permit " +
			"nothing once the verdict is terminal. " +
			"The audit kind is `approve` because `audit_kind` has no `reject` value and adding one " +
			"is a migration; the row's text is what distinguishes the two. " +
			"Requires the scanner-reviewer role.",
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Rejected. The version is quarantined for good.",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: s.schemaOf(contract.FindingDecision{}, "FindingDecision")},
				},
			},
			"400": s.errorResponse("The request body is missing or is not valid JSON."),
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity may not adjudicate a finding."),
			"404": s.errorResponse("No such finding."),
			"415": s.errorResponse("The request body must be sent as application/json."),
			"422": s.errorResponse("The finding id is not a uuid."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.rejectFinding)
}

func (s *Server) registerAudit() {
	huma.Register(s.api, huma.Operation{
		OperationID: "listAudit",
		Method:      http.MethodGet,
		Path:        "/v1/audit",
		Tags:        []string{"audit"},
		Summary:     "The audit log, paged, most recent first",
		Description: "One page of `audit_event`, ordered by when it happened, newest first, served by the " +
			"index created for exactly that read. " +
			"There is deliberately no filter. The export below must return the full CURRENT SCOPE " +
			"(FR-051), and with no filters the current scope is the whole log — a filter added " +
			"here without being added there would quietly stop that holding. " +
			"Rows are append-only, enforced by revoked grants rather than by anything in this " +
			"process (FR-052). `text` quotes package and profile names, so it is rendered escaped.",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"422": s.errorResponse("`page` or `pageSize` is outside its range."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.listAudit)

	huma.Register(s.api, huma.Operation{
		OperationID: "exportAudit",
		Method:      http.MethodGet,
		Path:        "/v1/audit/export",
		Tags:        []string{"audit"},
		Summary:     "Export the whole audit log",
		Description: "FR-051: the full current scope, not the visible page. Newline-delimited JSON, one " +
			"row per line, streamed — the rows are never materialised, because `audit_event` is " +
			"the one table in this schema designed to grow without bound. " +
			"NDJSON rather than CSV because an audit row's text quotes names a publisher chose, " +
			"and a spreadsheet evaluates a cell that begins with `=`. " +
			"The LAST LINE is a completeness sentinel. A streamed response cannot fail — its " +
			"status was sent before the first row was read — so a stream that ends without that " +
			"line was truncated and the export is incomplete.",
		Responses: map[string]*huma.Response{
			"200": auditExportResponse(),
			"401": s.errorResponse("Missing, expired or invalid token."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.exportAudit)
}

func (s *Server) registerBadges() {
	huma.Register(s.api, huma.Operation{
		OperationID: "getBadges",
		Method:      http.MethodGet,
		Path:        "/v1/badges",
		Tags:        []string{"navigation"},
		Summary:     "The application shell's counts",
		Description: "The three counts the sidebar renders, in one call: packages visible in the catalog, " +
			"profiles THIS IDENTITY may read, and findings awaiting a decision (FR-121). " +
			"One operation because the shell renders on every screen, so three would be three " +
			"round trips per page. Three indexed counts over the base tables and not a " +
			"projection: principle VIII sanctions exactly one and it is not spent here (research " +
			"R5). " +
			"The profile count is the length of the list the Profiles screen shows and cannot be " +
			"more: a count including a profile the reader cannot open would leak its existence by " +
			"arithmetic.",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getBadges)
}

func (s *Server) registerDeviceApproval() {
	huma.Register(s.api, huma.Operation{
		OperationID: "lookupDeviceCode",
		Method:      http.MethodGet,
		Path:        "/v1/device/authorizations/{user_code}",
		Tags:        []string{"device"},
		Summary:     "Look up a pending device authorisation",
		Description: "Shows the requesting host and remaining validity BEFORE the viewer confirms " +
			"(FR-041), so approval is an informed act. Refuses distinguishably when the code is " +
			"unknown, expired or already decided (FR-042). " +
			"The path parameter is a bearer-equivalent secret for the length of its validity and " +
			"is never logged verbatim (see the api role's correlation middleware).",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"404": s.errorResponse("No such device authorisation."),
			"409": s.errorResponse("This code has already been decided."),
			"410": s.errorResponse("This code has expired."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.lookupDeviceCode)

	huma.Register(s.api, huma.Operation{
		OperationID: "approveDeviceCode",
		Method:      http.MethodPost,
		Path:        "/v1/device/authorizations/{user_code}/approve",
		Tags:        []string{"device"},
		Summary:     "Approve a pending device authorisation",
		Description: "The confirm action (US6). Moves the code from pending to approved in one " +
			"transaction and writes the `login` audit row naming the host, source `cli / <host>` " +
			"(FR-050). Single-use: a second approval of the same code refuses the same way any " +
			"already-decided code does.",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"404": s.errorResponse("No such device authorisation."),
			"409": s.errorResponse("This code has already been decided."),
			"410": s.errorResponse("This code has expired."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.approveDeviceCode)
}

func (s *Server) registerStorage() {
	huma.Register(s.api, huma.Operation{
		OperationID: "getStorage",
		Method:      http.MethodGet,
		Path:        "/v1/storage",
		Tags:        []string{"storage"},
		Summary:     "The object store's own state",
		Description: "001 FR-053: object count, compressed size, region, the key layout for skills/ " +
			"and profiles/, the bucket's own versioning, object-lock, encryption, write-access and " +
			"retention settings, and the most recent ingestion attempts with an outcome. " +
			"The screen reports what the bucket reports: this system configures and surfaces object " +
			"lock and retention, it does not enforce them, so a setting the bucket declines to answer " +
			"comes back UNKNOWN rather than a guessed default. " +
			"Restricted to catalog-admin, the role this hub's other administration screens use.",
		Responses: map[string]*huma.Response{
			"401": s.errorResponse("Missing, expired or invalid token."),
			"403": s.errorResponse("This identity's role may not read the storage report."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getStorage)
}

// ---- handlers ----------------------------------------------------------------

type listProfilesOutput struct {
	Body contract.ProfileList
}

func (s *Server) listProfiles(ctx context.Context, _ *struct{}) (*listProfilesOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	profiles, err := queries.ReadableProfiles(ctx, s.deps.DB, principal)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listProfilesOutput{Body: contract.ProfileList{Profiles: profiles}}, nil
}

type getRevisionInput struct {
	Slug     string `path:"slug" doc:"The profile's URL-safe identifier."`
	Revision string `path:"revision" pattern:"^(head|[0-9]+)$" doc:"Either head, for the latest published revision, or an exact revision number."`
}

type getRevisionOutput struct {
	Body contract.Lockfile
}

func (s *Server) getRevision(ctx context.Context, in *getRevisionInput) (*getRevisionOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	var seq *int
	if in.Revision != "head" {
		n, err := strconv.Atoi(in.Revision)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity("revision must be `head` or an integer")
		}
		seq = &n
	}

	lock, err := queries.RevisionLockfile(ctx, s.deps.DB, principal, in.Slug, seq)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &getRevisionOutput{Body: lock}, nil
}

type getBundleInput struct {
	Publisher string `path:"publisher" doc:"The publishing namespace, as it appears in the catalog."`
	Name      string `path:"name" doc:"The package name within that publisher."`
	Version   string `path:"version" doc:"An exact version. Ranges and dist-tags are resolved before this call."`
}

type getBundleOutput struct {
	// Content-Type is set by hand because huma writes a []byte body raw, without
	// negotiating a type. hidden keeps it out of the document, where OpenAPI
	// ignores a Content-Type response header anyway.
	ContentType string `header:"Content-Type" hidden:"true"`
	Digest      string `header:"Digest" pattern:"^sha-256=[A-Za-z0-9+/=]+$" doc:"RFC 3230 digest of the body. Verify before writing to disk."`
	ETag        string `header:"ETag" doc:"The immutable version's entity tag. Safe to cache forever."`
	Body        []byte
}

func (s *Server) getBundle(ctx context.Context, in *getBundleInput) (*getBundleOutput, error) {
	log := logging.From(ctx)

	ref, err := queries.Bundle(ctx, s.deps.DB, in.Publisher, in.Name, in.Version)
	if err != nil {
		return nil, fail(log, err)
	}
	// FR-029, and the reason this check is here rather than in the query: a
	// rejected version is never served, so refusing it is a distribution decision
	// and must not be confused with the org gate, which governs resolution.
	if !ref.Distributable() {
		return nil, huma.Error403Forbidden("this version was rejected and is never served")
	}
	if s.deps.Bundles == nil {
		return nil, fail(log, fmt.Errorf("no bundle reader is configured"))
	}

	body, err := s.deps.Bundles.ReadAll(ctx, ref.ObjectKey)
	if err != nil {
		return nil, fail(log, err)
	}

	out := &getBundleOutput{ContentType: "application/zstd", Body: body}
	if len(ref.Digest) > 0 {
		out.Digest = "sha-256=" + base64.StdEncoding.EncodeToString(ref.Digest)
		out.ETag = `"sha256:` + hex.EncodeToString(ref.Digest) + `"`
	}
	return out, nil
}

type reportSyncInput struct {
	Body contract.SyncReport
}

func (s *Server) reportSync(ctx context.Context, in *reportSyncInput) (*struct{}, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := commands.ReportSync(ctx, s.deps.DB, principal, in.Body); err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &struct{}{}, nil
}

// The device flow's two handlers, its request and response types and its rate
// limit live in device.go.

// ---- document helpers -------------------------------------------------------

// schemaOf registers a type in the document's schema registry and returns a
// reference to it. Used where a response or request body cannot be inferred from
// a handler signature, so the schema still comes from a Go type.
func (s *Server) schemaOf(v any, hint string) *huma.Schema {
	return s.api.OpenAPI().Components.Schemas.Schema(reflect.TypeOf(v), true, hint)
}

// errorResponse documents a failure with the project's single error shape.
func (s *Server) errorResponse(description string) *huma.Response {
	return &huma.Response{
		Description: description,
		Content: map[string]*huma.MediaType{
			"application/problem+json": {Schema: s.schemaOf(contract.Error{}, "Error")},
		},
	}
}

// declareRequestBody replaces an operation's request body with one media type and
// schema. huma writes `{type: string, format: binary}` for a RawBody field, which
// is right for bytes and wrong for a form.
func (s *Server) declareRequestBody(method, path, mediaType, description string, schema *huma.Schema) {
	item := s.api.OpenAPI().Paths[path]
	if item == nil {
		panic("declareRequestBody: no path " + path)
	}
	var op *huma.Operation
	switch method {
	case http.MethodGet:
		op = item.Get
	case http.MethodPost:
		op = item.Post
	case http.MethodPut:
		op = item.Put
	default:
		panic("declareRequestBody: unsupported method " + method)
	}
	if op == nil {
		panic("declareRequestBody: no " + method + " on " + path)
	}
	op.RequestBody = &huma.RequestBody{
		Description: description,
		Required:    true,
		Content:     map[string]*huma.MediaType{mediaType: {Schema: schema}},
	}
}
