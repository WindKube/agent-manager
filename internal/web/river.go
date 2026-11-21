package web

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

func (s *Server) riverScreen(c *gin.Context) {
	s.render(c, http.StatusOK, "River Dashboard", "river",
		components.RiverScreen(view.RiverFor(viewerFor(c), s.riverUI != nil)))
}

// riverEmbed proxies reads only: the dashboard's write verbs would change state
// without an audit row.
func (s *Server) riverEmbed(c *gin.Context) {
	if s.riverUI == nil {
		s.notFound(c)
		return
	}
	// The api is not in this path, so this is the only role check; it mirrors GET /v1/runtime.
	if access := view.RiverAccessFor(viewerFor(c)); !access.Allowed {
		logFrom(c).Info().Str("reason", access.Reason).Msg("river dashboard refused")
		c.Status(http.StatusForbidden)
		return
	}
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		c.Status(http.StatusMethodNotAllowed)
		return
	}
	s.riverUI.ServeHTTP(c.Writer, c.Request)
}

// riverProxy strips the session cookie and credentials going out, and Set-Cookie
// coming back, so neither side can touch this origin's session.
func riverProxy(base *url.URL, log zerolog.Logger) *httputil.ReverseProxy {
	if base == nil {
		return nil
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(base)
			r.Out.Header.Del("Cookie")
			r.Out.Header.Del("Authorization")
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Set-Cookie")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Error().Err(err).Msg("proxy to the river dashboard")
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}
