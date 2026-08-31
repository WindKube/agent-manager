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
	s.registerPackages()
	s.registerProfiles()
	s.registerBundles()
	s.registerSync()
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
