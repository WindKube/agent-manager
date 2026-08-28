package api

import (
	"context"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

// The catalog browse operation (US2). The web role reaches it through the
// generated client and holds no other door to this data.

// The filter vocabularies. They are lowercase canonical values, not the design's
// chip labels: "All" / "Plugins" / "Verified" are what a screen says, and an API
// that took them would have made a rendering decision for every client.
const (
	kindPlugin = "plugin"
	kindSkill  = "skill"

	statusVerified  = "verified"
	statusCommunity = "community"
	statusFlagged   = "flagged"

	sortName    = "name"
	sortUpdated = "updated"

	dirAsc = "asc"
)

type listPackagesInput struct {
	Q          string   `query:"q" doc:"Case-insensitive substring, matched against name, id, publisher and tags (FR-010)." example:"terraform"`
	Kind       string   `query:"kind" enum:"all,plugin,skill" default:"all" doc:"Mutually exclusive single selection (FR-011)."`
	Status     string   `query:"status" enum:"all,verified,community,flagged" default:"all" doc:"Mutually exclusive single selection. Verified means a verified publisher AND a clean verdict, both."`
	Categories []string `query:"category,explode" doc:"Repeatable. Selected categories narrow DISJUNCTIVELY (FR-013)."`
	Tags       []string `query:"tag,explode" doc:"Repeatable. Selected tags narrow CONJUNCTIVELY (FR-013)."`
	Sort       string   `query:"sort" enum:"name,uses,updated" default:"uses"`
	Dir        string   `query:"dir" enum:"desc,asc" default:"desc" doc:"Descending first, ascending on a second click (FR-014)."`
	Page       int      `query:"page" minimum:"1" default:"1" doc:"Clamped into range: a page past the end returns the last one."`
	PageSize   int      `query:"pageSize" minimum:"1" maximum:"100" default:"10"`
}

type listPackagesOutput struct {
	Body contract.CatalogPage
}

// listPackages answers the catalog screen. It inherits the document's root
// bearer requirement: there is no anonymous view of the catalog, because public
// anonymous browsing is out of scope (spec.md, Out of Scope). Until the web
// role's login lands the screen renders signed out, which is a sequencing cost
// and not a reason to open the operation.
//
// There is no principal-dependent branch in the filter either. See
// queries.CatalogFilter.baseFilters for why `team` and `private` are hidden from
// everybody rather than scoped to somebody.
func (s *Server) listPackages(ctx context.Context, in *listPackagesInput) (*listPackagesOutput, error) {
	page, err := queries.Catalog(ctx, s.deps.DB, queries.CatalogFilter{
		Text:       in.Q,
		Kind:       packageKind(in.Kind),
		Status:     catalogStatus(in.Status),
		Categories: in.Categories,
		Tags:       in.Tags,
		Sort:       catalogSort(in.Sort),
		Ascending:  in.Dir == dirAsc,
		Page:       in.Page,
		PageSize:   in.PageSize,
	})
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listPackagesOutput{Body: page}, nil
}

func packageKind(kind string) models.PackageKind {
	switch kind {
	case kindPlugin:
		return models.PackageKindPlugin
	case kindSkill:
		return models.PackageKindSkill
	default:
		return ""
	}
}

func catalogStatus(status string) queries.CatalogStatus {
	switch status {
	case statusVerified:
		return queries.CatalogStatusVerified
	case statusCommunity:
		return queries.CatalogStatusCommunity
	case statusFlagged:
		return queries.CatalogStatusFlagged
	default:
		return queries.CatalogStatusAny
	}
}

func catalogSort(sort string) queries.CatalogSort {
	switch sort {
	case sortName:
		return queries.CatalogSortName
	case sortUpdated:
		return queries.CatalogSortUpdated
	default:
		return queries.CatalogSortUses
	}
}
