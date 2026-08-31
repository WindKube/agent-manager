package api

import (
	"github.com/danielgtaylor/huma/v2"
)

// Document metadata. The title and version are the api's identity in every
// generated client, so they are constants here rather than configuration: a
// deployment that renamed its own contract would produce clients that disagree
// about what they are talking to.
const (
	DocumentTitle   = "Agent Manager"
	DocumentVersion = "1.0.0"

	// OpenAPIPath is the prefix huma hangs the document off. It serves
	// /v1/openapi.json (3.1, the emitted document), /v1/openapi.yaml, and the
	// downgraded /v1/openapi-3.0.json for tools that cannot read 3.1.
	OpenAPIPath = "/v1/openapi"

	// BearerScheme is the security scheme name the frozen contract uses.
	BearerScheme = "bearerAuth"
)

// humaConfig builds the configuration the document is emitted from.
//
// It is deliberately not huma.DefaultConfig: that one installs a schema-link
// transformer which adds a `$schema` property to every response body, and the
// machine-facing surface is frozen. It also mounts a docs UI that loads a
// renderer from a CDN, which this project has no business doing.
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
						// `opaque`, and the frozen contract now says the same. It said JWT
						// on both sides until the device flow made the claim reachable:
						// auth.NewToken is 256 crypto/rand bits in base64url — one segment,
						// no header, no claims. The field is a hint to a client author and
						// nothing else, so a wrong hint is worse than an absent one.
						BearerFormat: "opaque",
						Description: "The `access_token` issued by /v1/device/token, or a web session token, " +
							"sent as `Authorization: Bearer <token>`. The token is OPAQUE — one " +
							"base64url segment of random bytes, with no header, payload or claims. Do " +
							"not decode one and do not read `exp` from it: a token's lifetime is the " +
							"`expires_in` returned beside it.",
					},
				},
			},
			// Every operation is authenticated unless it says otherwise with an
			// empty `security: []`, which is the OpenAPI way to remove the root
			// requirement. Defaulting the other way round means a new operation is
			// public until somebody remembers.
			Security: []map[string][]string{{BearerScheme: {}}},
			Tags: []*huma.Tag{
				{Name: "bundles", Description: "Immutable version content."},
				{Name: "catalog", Description: "Browsing what is registered. Readable without a token."},
				{Name: "device", Description: "RFC 8628 device authorisation. Unauthenticated by definition."},
				{Name: "profiles", Description: "What this identity may read, and how it resolves."},
				{Name: "system", Description: "Probes a supervisor calls. Unauthenticated."},
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

	// The served document names the hub it is served from; the committed one names
	// nothing, so `task gen:client` is byte-stable regardless of where it runs.
	if opts.PublicBaseURL != "" {
		cfg.Servers = []*huma.Server{{URL: opts.PublicBaseURL, Description: "This hub"}}
	}
	return cfg
}

// Document emits the OpenAPI document without opening a single connection. It is
// what `task gen:client` generates the typed client from and what the superset
// test compares against the frozen contract.
func Document(opts Options) *huma.OpenAPI {
	srv := New(Deps{}, opts)
	return srv.api.OpenAPI()
}
