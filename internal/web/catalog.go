package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/starfederation/datastar-go/datastar"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// catalog renders the whole screen. The first paint is complete — rows, count and
// both chip rows — so the catalog is usable before a single signal is touched.
func (s *Server) catalog(c *gin.Context) {
	page, ok := s.load(c, queryFromURL(c))
	if !ok {
		return
	}
	s.render(c, http.StatusOK, "Catalog", "catalog", components.CatalogScreen(components.Catalog{
		Page: page,
		// Options are deliberately absent from the first render: the option list is
		// a payload the menu fetches when it opens. That is what keeps the
		// interaction the same shape at ten options and at ten thousand.
		Category: categoryFacet(page, false),
		Tags:     tagFacet(page, false),
		// The modal's category list IS shipped on the first render, unlike the facet
		// option lists: it is the admin-curated vocabulary (FR-049), a select rather
		// than a searchable menu, and a registration can only choose from it.
		Import: components.Import{Categories: categoryNames(page)},
	}))
}

// catalogResults is the debounced round trip: it re-renders the result table, the
// live count and — when a menu is open — that menu's option counts. Everything
// else about the facet menu stays on the client.
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

// catalogFacet is the payload sent when a menu opens.
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

func (s *Server) load(c *gin.Context, q view.CatalogQuery) (view.CatalogPage, bool) {
	page, err := s.deps.Catalog.Catalog(c.Request.Context(), q)
	if err != nil {
		logFrom(c).Error().Err(err).Msg("load catalog")
		c.Status(http.StatusBadGateway)
		return view.CatalogPage{}, false
	}
	return page, true
}

// categoryNames is the curated vocabulary as the modal's select needs it.
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

// catalogSignals is the datastar signal set the browser sends. The facet filter
// boxes bind to _catQuery and _tagQuery, which datastar excludes from every
// request because of the leading underscore — that exclusion IS the R7 budget:
// typing cannot reach the server even by accident.
type catalogSignals struct {
	Q      string `json:"q"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	// Cats and Tags arrive as JSON arrays inside a string. datastar's signal proxy
	// wraps array elements, so a live array signal cannot be compared to a value
	// on the client; a string is unambiguous on both sides.
	Cats string `json:"cats"`
	Tags string `json:"tags"`
	Sort string `json:"sort"`
	Dir  string `json:"dir"`
	Page int    `json:"page"`
	// Menu is which facet menu is open, so a round trip knows whose counts to
	// re-render. It is excluded from the signal-patch filter that triggers the
	// round trip, so opening a menu does not re-query the table.
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

// maxSelections caps a facet selection. The list arrives from the client, and an
// unbounded one turns a cheap filter into a quadratic one.
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

// queryFromURL reads the same state from the URL, so a catalog view is a
// shareable link and the screenshot harness can ask for one directly.
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
