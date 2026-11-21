package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/starfederation/datastar-go/datastar"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// catalog's first paint is complete, so the screen is usable before any signal round trip.
func (s *Server) catalog(c *gin.Context) {
	page, ok := s.load(c, queryFromURL(c))
	if !ok {
		return
	}
	s.render(c, http.StatusOK, "Catalog", "catalog", components.CatalogScreen(components.Catalog{
		Page: page,
		// Facet options are fetched when a menu opens, so first paint stays small at any size.
		Category: categoryFacet(page, false),
		Tags:     tagFacet(page, false),
		// The import categories ship up front: a short curated select, not a searchable menu.
		Import: components.Import{
			Categories:   categoryNames(page),
			Visibilities: view.ImportVisibilityOptions(viewerGroups(c)),
		},
		Notice: view.CatalogNoticeFrom(c.Query("notice"), c.Query("id")),
	}))
}

// catalogResults re-renders the table, the count and, when a menu is open, its option counts.
func (s *Server) catalogResults(c *gin.Context) {
	signals, ok := readSignals(c)
	if !ok {
		return
	}
	page, loaded := s.load(c, signals.query())
	if !loaded {
		return
	}

	sse := datastar.NewSSE(c.Writer, c.Request)
	if err := sse.PatchElementTempl(components.CatalogTable(page),
		datastar.WithSelectorID("catalog-card"), datastar.WithModeInner()); err != nil {
		logFrom(c).Error().Err(err).Msg("patch catalog table")
		return
	}
	if err := sse.PatchElementTempl(components.CatalogCount(page)); err != nil {
		logFrom(c).Error().Err(err).Msg("patch catalog count")
		return
	}

	switch signals.Menu {
	case "category":
		s.patchFacet(c, sse, categoryFacet(page, true))
	case "tag":
		s.patchFacet(c, sse, tagFacet(page, true))
	}
}

func (s *Server) catalogFacet(c *gin.Context) {
	signals, ok := readSignals(c)
	if !ok {
		return
	}
	page, loaded := s.load(c, signals.query())
	if !loaded {
		return
	}

	var facet components.Facet
	switch c.Param("name") {
	case "category":
		facet = categoryFacet(page, true)
	case "tag":
		facet = tagFacet(page, true)
	default:
		c.Status(http.StatusNotFound)
		return
	}

	s.patchFacet(c, datastar.NewSSE(c.Writer, c.Request), facet)
}

func (s *Server) patchFacet(c *gin.Context, sse *datastar.ServerSentEventGenerator, facet components.Facet) {
	if err := sse.PatchElementTempl(components.FacetOptions(facet),
		datastar.WithSelectorID(facet.OptionsID()), datastar.WithModeInner()); err != nil {
		logFrom(c).Error().Err(err).Str("facet", facet.Name).Msg("patch facet options")
	}
}

// load answers signed-out with a 200 screen and an unreachable api with a 502,
// so an outage never renders as an empty hub.
func (s *Server) load(c *gin.Context, q view.CatalogQuery) (view.CatalogPage, bool) {
	page, err := s.deps.Hub.Catalog(session(c), q)
	switch {
	case errors.Is(err, view.ErrSignedOut):
		logFrom(c).Debug().Msg("catalog requested without a session")
		return view.CatalogPage{Query: q, SignedOut: true}, true
	case err != nil:
		logFrom(c).Error().Err(err).Msg("load catalog")
		c.Status(http.StatusBadGateway)
		return view.CatalogPage{}, false
	}
	return page, true
}

func categoryNames(page view.CatalogPage) []string {
	out := make([]string, 0, len(page.Categories))
	for _, option := range page.Categories {
		out = append(out, option.Label)
	}
	return out
}

func categoryFacet(page view.CatalogPage, withOptions bool) components.Facet {
	facet := components.Facet{
		Name:        "category",
		Label:       "Category",
		Signal:      "cats",
		QuerySignal: "_catQuery",
		Placeholder: "Filter categories",
		Selected:    page.Query.Categories,
	}
	if withOptions {
		facet.Options = page.Categories
	}
	return facet
}

func tagFacet(page view.CatalogPage, withOptions bool) components.Facet {
	facet := components.Facet{
		Name:        "tag",
		Label:       "Tags",
		Signal:      "tags",
		QuerySignal: "_tagQuery",
		Placeholder: "Filter tags",
		Mono:        true,
		Selected:    page.Query.Tags,
	}
	if withOptions {
		facet.Options = page.Tags
	}
	return facet
}

// catalogSignals is what the browser sends. Facet filter boxes bind to
// underscore-prefixed signals, which datastar never sends, so typing there cannot reach the server.
type catalogSignals struct {
	Q      string `json:"q"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	// Cats and Tags are JSON arrays in a string: datastar's proxy wraps array
	// elements, so a live array signal cannot be compared on the client.
	Cats string `json:"cats"`
	Tags string `json:"tags"`
	Sort string `json:"sort"`
	Dir  string `json:"dir"`
	Page int    `json:"page"`
	// Menu is the open facet menu; it is excluded from the round-trip trigger
	// so opening a menu does not re-query the table.
	Menu string `json:"menu"`
}

func (s catalogSignals) query() view.CatalogQuery {
	return view.CatalogQuery{
		Text:       s.Q,
		Kind:       s.Kind,
		Status:     s.Status,
		Categories: decodeList(s.Cats),
		Tags:       decodeList(s.Tags),
		Sort:       view.SortKey(s.Sort),
		Dir:        view.SortDir(s.Dir),
		Page:       s.Page,
	}.Normalise()
}

// maxSelections caps a client-supplied selection so the filter cannot go quadratic.
const maxSelections = 64

func decodeList(raw string) []string {
	if raw == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	if len(values) > maxSelections {
		values = values[:maxSelections]
	}
	return values
}

func readSignals(c *gin.Context) (catalogSignals, bool) {
	var signals catalogSignals
	if err := datastar.ReadSignals(c.Request, &signals); err != nil {
		logFrom(c).Warn().Err(err).Msg("read datastar signals")
		c.Status(http.StatusBadRequest)
		return signals, false
	}
	return signals, true
}

// queryFromURL makes a catalog view a shareable link.
func queryFromURL(c *gin.Context) view.CatalogQuery {
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		page = 1
	}
	return view.CatalogQuery{
		Text:       c.Query("q"),
		Kind:       c.Query("kind"),
		Status:     c.Query("status"),
		Categories: limit(c.QueryArray("category")),
		Tags:       limit(c.QueryArray("tag")),
		Sort:       view.SortKey(c.Query("sort")),
		Dir:        view.SortDir(c.Query("dir")),
		Page:       page,
	}.Normalise()
}

func limit(values []string) []string {
	if len(values) > maxSelections {
		return values[:maxSelections]
	}
	return values
}
