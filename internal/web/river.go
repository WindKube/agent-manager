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

// riverEmbed hands one request to the queue dashboard.
//
// Reads only. The dashboard's own api can cancel, retry and delete jobs and
// pause queues, and none of that writes this hub's audit row — constitution
// principle IV calls a state change with no audit row incomplete, so those
// verbs are refused here rather than proxied and later regretted. A viewer who
// needs to act on a job has the dashboard's own port for it.
func (s *Server) riverEmbed(c *gin.Context) {
	if s.riverUI == nil {
		s.notFound(c)
		return
	}
	// The same role the api demands for GET /v1/runtime. The api is not in this
	// path, so this check is the only one there is — and the dashboard shows
	// strictly more than the runtime report does, job arguments included.
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

// riverProxy builds the passthrough onto the dashboard, or nil when none is
// configured.
//
// The request goes out stripped of everything that identifies this hub's
// viewer: the session cookie is this role's own secret and the dashboard has
// no use for it, so it is deleted rather than forwarded to a third-party
// process. Set-Cookie is dropped on the way back for the same reason in
// reverse — a cookie from upstream would land on this origin, where the
// session lives.
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
