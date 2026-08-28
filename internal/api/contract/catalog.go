package contract

import "time"

// The catalog browse surface (US2). It is web-facing: the frozen contract
// inventories `GET /v1/packages` but specifies no schema for it, so these shapes
// are emitted rather than frozen and may still change.

// CatalogPackage is one row of the catalog list (FR-009).
//
// `name` is the manifest name — `platform-toolkit` — because nothing in the
// schema or in Agent Plugins 1.0.0 carries a human title. The design's
// "Platform Toolkit" is derived from it at render time, which is a view decision
// and deliberately not made here: an API that returned a title would make it for
// every client.
//
// `updatedAt` is a timestamp for the same reason. The design shows "2 days ago";
// which words express an age is a rendering choice, and a relative string is
// wrong the moment it is cached.
type CatalogPackage struct {
	ID        string    `json:"id" doc:"namespace/name — the first segment of the publisher slug, not the whole slug." example:"example/platform-toolkit"`
	Name      string    `json:"name" doc:"The manifest name, not a display title — no manifest field and no column carries one." example:"platform-toolkit"`
	Publisher string    `json:"publisher" doc:"The owning publisher's full slug. A different string from the id's namespace: example/security publishes example/pii-redactor." example:"example/platform"`
	Kind      string    `json:"kind" enum:"plugin,skill" example:"plugin"`
	Category  string    `json:"category,omitempty" doc:"The admin-curated category (FR-049). Empty when none was chosen." example:"Infrastructure"`
	Version   string    `json:"version" doc:"The latest visible version's semver." example:"1.3.0"`
	Verdict   string    `json:"verdict" enum:"scanning,clean,flagged,rejected" doc:"The latest version's scan verdict." example:"clean"`
	Uses      int       `json:"uses" doc:"Profiles containing this package, derived at query time and never self-reported (R8)." example:"42"`
	UpdatedAt time.Time `json:"updatedAt" doc:"When the latest visible version was published."`
	Tags      []string  `json:"tags" doc:"The latest version's manifest keywords. Tags belong to the version, not the package."`
}

// CatalogFacetOption is one option of a facet menu with its count (FR-012).
type CatalogFacetOption struct {
	Value string `json:"value" example:"Infrastructure"`
	Count int    `json:"count" doc:"Packages this option yields under the other filters. See the operation's description for what 'the other filters' means for each facet." example:"4"`
}

// CatalogPage is one rendered page of the catalog plus both facets.
type CatalogPage struct {
	Packages []CatalogPackage `json:"packages" doc:"The requested page of results, already sorted."`
	Total    int              `json:"total" doc:"Packages matching every filter, across all pages. This is FR-015's live count." example:"10"`
	Page     int              `json:"page" doc:"The page actually returned, which is clamped into range." example:"1"`
	PageSize int              `json:"pageSize" example:"10"`

	Categories []CatalogFacetOption `json:"categories" doc:"The whole admin-curated vocabulary, in curated order, including options that currently match nothing."`
	Tags       []CatalogFacetOption `json:"tags" doc:"Tags reachable from the current result set, alphabetically."`
}
