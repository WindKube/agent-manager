package api

import (
	"github.com/danielgtaylor/huma/v2"
)

// Document metadata. Constants rather than configuration: they are the api's
// identity in every generated client.
const (
	DocumentTitle   = "Agent Manager"
	DocumentVersion = "1.0.0"

	// OpenAPIPath serves /v1/openapi.json (3.1), /v1/openapi.yaml, and a downgraded
	// /v1/openapi-3.0.json for tools that cannot read 3.1.
	OpenAPIPath = "/v1/openapi"

	BearerScheme = "bearerAuth"
)

// humaConfig is deliberately not huma.DefaultConfig, which adds a `$schema`
// property to every response body and mounts a CDN-loaded docs UI.
func humaConfig(opts Options) huma.Config {
	cfg := huma.Config{
		OpenAPI: &huma.OpenAPI{
			OpenAPI: "3.1.0",
			Info: &huma.Info{
				Title:   DocumentTitle,
				Version: DocumentVersion,
				Description: "Self-hosted registry for AI agent plugins and skills. " +
					"This document is emitted from the huma operation definitions in internal/api " +
					"(constitution principle V) and is the source every generated client is built from.",
				Contact: &huma.Contact{
					Name: "Agent Manager maintainers",
					URL:  "https://github.com/WindKube/agent-manager",
				},
				License: &huma.License{Name: "Apache-2.0", Identifier: "Apache-2.0"},
			},
			Components: &huma.Components{
				SecuritySchemes: map[string]*huma.SecurityScheme{
					BearerScheme: {
						Type:   "http",
						Scheme: "bearer",
						// auth.NewToken is random bytes, not a JWT.
						BearerFormat: "opaque",
						Description: "The `access_token` issued by /v1/device/token, or a web session token, " +
							"sent as `Authorization: Bearer <token>`. The token is OPAQUE — one " +
							"base64url segment of random bytes, with no header, payload or claims. Do " +
							"not decode one and do not read `exp` from it: a token's lifetime is the " +
							"`expires_in` returned beside it.",
					},
					// Declared so the document does not describe the most privileged call as unauthenticated.
					SessionMintScheme: {
						Type: "apiKey",
						In:   "header",
						Name: SessionMintHeader,
						Description: "A secret shared between the `serve web` and `serve api` roles, compared " +
							"in constant time. It authorises minting a session for ANY subject, so it is " +
							"the most privileged credential this hub accepts. The mint is refused " +
							"outright when no secret is configured: there is no default and no " +
							"development bypass.",
					},
				},
			},
			// Every operation is authenticated unless it overrides this, so a new operation
			// is never public by accident.
			Security: []map[string][]string{{BearerScheme: {}}},
			Tags: []*huma.Tag{
				{Name: "audit", Description: "What happened, who caused it, and the export of all of it."},
				{Name: "bundles", Description: "Immutable version content."},
				{Name: "catalog", Description: "Browsing what is registered. Readable without a token."},
				{Name: "device", Description: "RFC 8628 device authorisation. Unauthenticated by definition."},
				{Name: "identity", Description: "Who a request is acting as, and the sessions that say so."},
				{Name: "machines", Description: "Which machines reported a sync, and what each one has installed."},
				{Name: "navigation", Description: "Counts the application shell renders."},
				{Name: "profiles", Description: "What this identity may read, and how it resolves."},
				{Name: "scanner", Description: "Findings, their evidence, and the decisions taken on them."},
				{Name: "service-tokens", Description: "Scoped, expiring, non-human credentials for CI and headless machines."},
				{Name: "system", Description: "Probes a supervisor calls. Unauthenticated."},
				{Name: "webhooks", Description: "Signed outbound notifications of catalog, scan and governance events."},
			},
		},
		OpenAPIPath: OpenAPIPath,
		Formats: map[string]huma.Format{
			"application/json": huma.DefaultJSONFormat,
			"json":             huma.DefaultJSONFormat,
		},
		DefaultFormat: "application/json",
		Transformers:  []huma.Transformer{stampCorrelation},
	}

	// The committed document names no server, so `task gen:client` is byte-stable.
	if opts.PublicBaseURL != "" {
		cfg.Servers = []*huma.Server{{URL: opts.PublicBaseURL, Description: "This hub"}}
	}
	return cfg
}

// Document emits the OpenAPI document without opening any connection.
func Document(opts Options) *huma.OpenAPI {
	srv := New(Deps{}, opts)
	return srv.api.OpenAPI()
}
