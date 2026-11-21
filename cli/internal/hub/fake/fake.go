package fake

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/hub"
)

// ErrUnsupported is a [Control]'s answer for an operation the hub behind it can't perform; the suite
// must skip, not pass.
var ErrUnsupported = errors.New("this hub cannot be driven that way")

// Control is the human-and-operator half of a hub, so a behavioural test never needs a *fake.Hub.
type Control interface {
	ApproveDevice(userCode string) error
	DenyDevice(userCode string) error // terminal
	// ExpireDevice ages the authorisation now. Likely [ErrUnsupported] on a real hub.
	ExpireDevice(userCode string) error
	// SetHealthy distinguishes unauthorised from broken.
	SetHealthy(bool) error
	// SyncReports lets a suite assert exactly one row was written per sync.
	SyncReports() ([]hub.SyncReport, error)
	// MintServiceToken returns an `amst_` token that may sync only profiles,
	// as a hub service token scoped to sync:profile/<slug> does.
	MintServiceToken(profiles ...string) (string, error)
}

// staleSignature matches no package, so the object-store handler refuses it like an expired one.
const staleSignature = "s1Gn4tur3-thAt-h4s-3xp1r3d"

// Fixtures names seeded content a test may address. Empty means the suite must skip, not improvise a
// slug that 404s for the wrong reason.
type Fixtures struct {
	// Profile's HeadRevision and PriorRevision differ in content, not just number.
	Profile       string
	HeadRevision  int64
	PriorRevision int64

	// SharedNamespaceIDs share one namespace across two publishers.
	SharedNamespaceIDs []string

	DigestMismatch   string // one entry's digest is really some other bundle's
	ForbiddenBundle  string // middle entry answers 403; the others still install
	ForbiddenEntryID string
	// PresignedBundle answers 307 to the same host, where net/http alone would leak the token.
	PresignedBundle string
	// StalePresignedBundle's second entry gets a store 403 behind a hub 307.
	StalePresignedBundle  string
	StalePresignedEntryID string
	// UnknownSkipReason's skipped array carries a reason this build has never seen.
	UnknownSkipReason string
	BothTargets       string
	Plugin            string

	MissingProfile string // 404
}

// Target is everything a behavioural test gets.
type Target struct {
	BaseURL string
	Token   string
	// HTTPClient trusts the fake's self-signed cert.
	HTTPClient *http.Client
	Fixtures   Fixtures
	Control    Control
}

// Options configures the fake. Every zero value is a working default.
type Options struct {
	Now func() time.Time // only the device flow reads it; nil means time.Now
	// PollInterval is both the advertised interval and the slow_down window, so an obedient client is
	// never punished. Default 5s, rounded up, 1s floor.
	PollInterval  time.Duration
	DeviceCodeTTL time.Duration // authorize response's expires_in; default 15m
	TokenTTL      time.Duration // access token's expires_in; default 1h
	// TLS serves a self-signed cert.
	TLS bool
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 5 * time.Second
	}
	o.PollInterval = (o.PollInterval + time.Second - 1).Truncate(time.Second)
	if o.DeviceCodeTTL <= 0 {
		o.DeviceCodeTTL = 15 * time.Minute
	}
	if o.TokenTTL <= 0 {
		o.TokenTTL = time.Hour
	}
	return o
}

type tokenInfo struct {
	expiresAt time.Time
	clientID  string
	host      string
	// profiles is set for a service token: it may sync these and nothing else.
	profiles []string
}

func (t tokenInfo) serviceToken() bool { return t.profiles != nil }

// Hub is the running fake. Tests pass [Hub.Target] around, not the Hub.
type Hub struct {
	opts Options
	srv  *httptest.Server

	mu         sync.Mutex
	tokens     map[string]tokenInfo
	devices    map[string]*deviceAuth
	byUserCode map[string]*deviceAuth
	reports    []hub.SyncReport
	healthy    bool

	pkgs       map[string]*pkg // "id@version"
	signatures map[string]string
	profiles   []profileSpec
	lockfiles  map[string][]byte // "slug/revision"
	heads      map[string]int64
	seedToken  string
}

// New starts the fake. Call [Hub.Close] when done.
func New(opts Options) *Hub {
	h := &Hub{
		opts:       opts.withDefaults(),
		tokens:     map[string]tokenInfo{},
		devices:    map[string]*deviceAuth{},
		byUserCode: map[string]*deviceAuth{},
		healthy:    true,
		pkgs:       map[string]*pkg{},
		signatures: map[string]string{},
		profiles:   profiles(),
		lockfiles:  map[string][]byte{},
		heads:      map[string]int64{},
	}
	for _, p := range catalog() {
		h.pkgs[p.ID+"@"+p.Version] = p
		h.signatures[p.ID+"@"+p.Version] = randomToken()
	}
	h.buildLockfiles()

	// Minted like a device-flow token so no test can depend on a shape only the seed has.
	h.seedToken = randomToken()
	h.tokens[h.seedToken] = tokenInfo{expiresAt: h.opts.Now().Add(h.opts.TokenTTL), clientID: "agent-manager-cli", host: "seed"}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/device/authorize", h.deviceAuthorize)
	mux.HandleFunc("POST /v1/device/token", h.deviceToken)
	mux.HandleFunc("GET /v1/health", h.health)
	mux.HandleFunc("GET /v1/profiles", h.listProfiles)
	mux.HandleFunc("GET /v1/profiles/{slug}/revisions/{revision}", h.getRevision)
	// The contract spells this parameter `publisher` but it holds the namespace.
	mux.HandleFunc("GET /v1/bundles/{namespace}/{name}/{version}", h.getBundle)
	mux.HandleFunc("POST /v1/sync", h.reportSync)
	// Stands in for the object store the 307 points at, on the same host so a redirect leak is visible.
	mux.HandleFunc("GET /objects/{key...}", h.presigned)

	if h.opts.TLS {
		h.srv = httptest.NewTLSServer(mux)
	} else {
		h.srv = httptest.NewServer(mux)
	}
	return h
}

func (h *Hub) Close() { h.srv.Close() }

// URL is the base URL, no trailing slash.
func (h *Hub) URL() string { return h.srv.URL }

func (h *Hub) Target() Target {
	baseline, _ := h.profileSpec(slugBaseline)
	return Target{
		BaseURL:    h.srv.URL,
		Token:      h.seedToken,
		HTTPClient: h.srv.Client(),
		Control:    control{h},
		Fixtures: Fixtures{
			Profile:               slugBaseline,
			HeadRevision:          baseline.revisions[len(baseline.revisions)-1].revision,
			PriorRevision:         baseline.revisions[0].revision,
			SharedNamespaceIDs:    []string{"acme/code-review", "acme/lint-guard"},
			DigestMismatch:        slugDigestMismatch,
			ForbiddenBundle:       slugForbidden,
			ForbiddenEntryID:      "contoso/gated",
			PresignedBundle:       slugPresigned,
			StalePresignedBundle:  slugPresignedStale,
			StalePresignedEntryID: "contoso/offloaded-stale",
			UnknownSkipReason:     slugFutureSkip,
			BothTargets:           slugBothTargets,
			Plugin:                slugPlugin,
			MissingProfile:        slugMissing,
		},
	}
}

func (h *Hub) profileSpec(slug string) (profileSpec, bool) {
	for _, p := range h.profiles {
		if p.slug == slug {
			return p, true
		}
	}
	return profileSpec{}, false
}

func (h *Hub) buildLockfiles() {
	for _, p := range h.profiles {
		for i := range p.revisions {
			rev := p.revisions[i]
			lf := hub.Lockfile{
				SchemaVersion: "1.0.0",
				Profile: hub.LockfileProfile{
					Slug: p.slug, Name: p.name, Visibility: ptr(p.visibility),
				},
				Revision:   rev.revision,
				ResolvedAt: time.Date(2026, 4, 17, 9, 12, 4, 0, time.UTC),
				Gate:       rev.gate,
				Entries:    make([]hub.LockfileEntry, 0, len(rev.entries)),
				Skipped:    rev.skipped,
				Targets:    rev.targets,
			}
			if rev.note != "" {
				lf.Note = ptr(rev.note)
			}
			if rev.policy != "" {
				lf.DefaultPolicy = ptr(rev.policy)
			}
			for _, es := range rev.entries {
				pk := h.pkgs[es.pkgID]
				if pk == nil {
					panic("fake: entry names an unknown package " + es.pkgID)
				}
				digest := pk.blob.LockfileDigest()
				if es.digestOverride != "" {
					other := h.pkgs[es.digestOverride]
					if other == nil {
						panic("fake: digest override names an unknown package " + es.digestOverride)
					}
					digest = other.blob.LockfileDigest()
				}
				lf.Entries = append(lf.Entries, hub.LockfileEntry{
					Id:         pk.ID,
					Kind:       pk.Kind,
					Version:    pk.Version,
					Digest:     digest,
					ObjectKey:  pk.objectKey(),
					Resolution: es.resolution,
					Verdict:    es.verdict,
					Signature:  es.signature,
					Override:   es.override,
				})
			}
			if lf.Skipped == nil {
				lf.Skipped = []hub.LockfileSkip{}
			}
			body, err := json.Marshal(lf)
			if err != nil {
				panic(fmt.Sprintf("fake: marshal lockfile %s r%d: %v", p.slug, rev.revision, err))
			}
			h.lockfiles[lockKey(p.slug, rev.revision)] = body
			if rev.revision > h.heads[p.slug] {
				h.heads[p.slug] = rev.revision
			}
		}
	}
}

func lockKey(slug string, rev int64) string {
	return slug + "/" + strconv.FormatInt(rev, 10)
}

func (h *Hub) health(w http.ResponseWriter, _ *http.Request) {
	h.mu.Lock()
	ok := h.healthy
	h.mu.Unlock()

	body := hub.Health{Status: "ok", Checks: []hub.HealthCheck{
		{Name: "database", Ok: true},
		{Name: "objectstore", Ok: true},
	}}
	status := http.StatusOK
	if !ok {
		body = hub.Health{Status: "unavailable", Checks: []hub.HealthCheck{
			{Name: "database", Ok: false, Error: ptr("dependency unavailable")},
			{Name: "objectstore", Ok: true},
		}}
		status = http.StatusServiceUnavailable
	}
	// No auth by contract: this probe tells "unreachable" from "unauthorised".
	writeJSON(w, status, "application/json", body)
}

func (h *Hub) listProfiles(w http.ResponseWriter, r *http.Request) {
	info, ok := h.authorized(w, r)
	if !ok {
		return
	}
	if info.serviceToken() {
		writeProblem(w, http.StatusForbidden, "Forbidden", "a service token may not call listProfiles with its scopes")
		return
	}
	out := hub.ProfileList{Profiles: make([]hub.Profile, 0, len(h.profiles))}
	for _, p := range h.profiles {
		head := h.heads[p.slug]
		lf := h.decodeLockfile(p.slug, head)
		out.Profiles = append(out.Profiles, hub.Profile{
			Slug: p.slug, Name: p.name,
			HeadRevision: head,
			// Excludes skipped entries, per the contract.
			PackageCount: int64(len(lf.Entries)),
			Visibility:   ptr(hub.ProfileVisibility(p.visibility)),
		})
	}
	writeJSON(w, http.StatusOK, "application/json", out)
}

var revisionPattern = regexp.MustCompile(`^(head|\d+)$`)

func (h *Hub) getRevision(w http.ResponseWriter, r *http.Request) {
	info, ok := h.authorized(w, r)
	if !ok {
		return
	}
	slug := r.PathValue("slug")
	raw := r.PathValue("revision")
	if !revisionPattern.MatchString(raw) {
		writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity",
			"revision must match ^(head|[0-9]+)$")
		return
	}
	if !inScope(w, info, slug) {
		return
	}
	if _, known := h.profileSpec(slug); !known {
		writeProblem(w, http.StatusNotFound, "Not Found", "no such profile")
		return
	}
	rev := h.heads[slug]
	if raw != "head" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity",
				"revision must be a positive integer")
			return
		}
		rev = n
	}
	body, ok := h.lockfiles[lockKey(slug, rev)]
	if !ok {
		writeProblem(w, http.StatusNotFound, "Not Found", "no such revision")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *Hub) getBundle(w http.ResponseWriter, r *http.Request) {
	info, ok := h.authorized(w, r)
	if !ok {
		return
	}
	id := r.PathValue("namespace") + "/" + r.PathValue("name")
	key := id + "@" + r.PathValue("version")
	p, ok := h.pkgs[key]
	if !ok || (info.serviceToken() && !h.locked(info.profiles, key)) {
		writeProblem(w, http.StatusNotFound, "Not Found", "no such package version")
		return
	}
	switch p.serve {
	case serveForbidden:
		writeProblem(w, http.StatusForbidden, "Forbidden",
			"version rejected by the organisation's scan gate")
	case serveRedirectStale:
		// The same 307, with a signature the store will not accept.
		loc := "/objects/" + p.objectKey() + "?X-Amz-Expires=60&X-Amz-Signature=" + url.QueryEscape(staleSignature)
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusTemporaryRedirect)
	case serveRedirect:
		loc := "/objects/" + p.objectKey() + "?X-Amz-Expires=60&X-Amz-Signature=" + url.QueryEscape(h.signatures[key])
		// Same host on purpose: net/http strips Authorization across hosts already.
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusTemporaryRedirect)
	default:
		writeBundle(w, p.blob)
	}
}

// presigned stands in for the object store. Like S3, it answers 400 to a request carrying Authorization,
// so a leaked bearer is visible from outside the fake.
func (h *Hub) presigned(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		writeProblem(w, http.StatusBadRequest, "Bad Request",
			"a pre-signed request must not also carry an Authorization header")
		return
	}
	sig := r.URL.Query().Get("X-Amz-Signature")
	key := r.PathValue("key")
	for pkgKey, p := range h.pkgs {
		if p.objectKey() != key {
			continue
		}
		if sig == "" || sig != h.signatures[pkgKey] {
			writeProblem(w, http.StatusForbidden, "Forbidden", "signature missing or does not match")
			return
		}
		writeBundle(w, p.blob)
		return
	}
	writeProblem(w, http.StatusNotFound, "Not Found", "no such object")
}

func writeBundle(w http.ResponseWriter, b blob) {
	w.Header().Set("Content-Type", "application/zstd")
	// Derived from the bytes served, so header and body cannot disagree by accident.
	w.Header().Set("Digest", b.HeaderDigest())
	w.Header().Set("ETag", b.ETag())
	w.Header().Set("Content-Length", strconv.Itoa(len(b.Bytes)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b.Bytes)
}

func (h *Hub) reportSync(w http.ResponseWriter, r *http.Request) {
	info, ok := h.authorized(w, r)
	if !ok {
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity",
			"body must be application/json")
		return
	}
	var body hub.SyncReport
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity", "malformed body")
		return
	}
	switch {
	case body.Profile == "":
		writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity", "profile is required")
		return
	case body.Host == "":
		writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity", "host is required")
		return
	case body.Revision < 1:
		// The client must report the resolved number, not `head`.
		writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity",
			"revision must be a positive integer")
		return
	case len(body.Targets) == 0:
		writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity", "targets is required")
		return
	}
	for _, t := range body.Targets {
		if !t.Valid() {
			writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity",
				"unknown target "+string(t))
			return
		}
	}
	if !inScope(w, info, body.Profile) {
		return
	}
	if _, ok := h.profileSpec(body.Profile); !ok {
		writeProblem(w, http.StatusNotFound, "Not Found", "no such profile")
		return
	}

	h.mu.Lock()
	h.reports = append(h.reports, body)
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// authorized enforces the bearer. Every bad token is the same 401, since distinguishing them would be
// a probing oracle.
func (h *Hub) authorized(w http.ResponseWriter, r *http.Request) (tokenInfo, bool) {
	raw := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(raw, "Bearer ")
	if !ok || token == "" {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "a bearer token is required")
		return tokenInfo{}, false
	}
	h.mu.Lock()
	info, known := h.tokens[token]
	h.mu.Unlock()
	if !known || h.opts.Now().After(info.expiresAt) {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "the bearer token is not valid")
		return tokenInfo{}, false
	}
	return info, true
}

// inScope answers a service token outside its profiles with the hub's 403,
// before anything about the profile is looked up.
func inScope(w http.ResponseWriter, info tokenInfo, slug string) bool {
	if !info.serviceToken() || slices.Contains(info.profiles, slug) {
		return true
	}
	writeProblem(w, http.StatusForbidden, "Forbidden",
		"this service token is not scoped to profile "+slug+"; it needs sync:profile/"+slug)
	return false
}

// locked reports whether any revision of profiles locks the bundle key.
func (h *Hub) locked(profiles []string, key string) bool {
	for _, slug := range profiles {
		for k, body := range h.lockfiles {
			if rev, ok := strings.CutPrefix(k, slug+"/"); !ok || strings.Contains(rev, "/") {
				continue
			}
			var lf hub.Lockfile
			if json.Unmarshal(body, &lf) != nil {
				continue
			}
			for i := range lf.Entries {
				if lf.Entries[i].Id+"@"+lf.Entries[i].Version == key {
					return true
				}
			}
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, contentType string, body any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	writeJSON(w, status, "application/problem+json", hub.Error{
		Status: int64(status), Title: title, Detail: ptr(detail),
	})
}

func (h *Hub) decodeLockfile(slug string, rev int64) hub.Lockfile {
	var lf hub.Lockfile
	if err := json.Unmarshal(h.lockfiles[lockKey(slug, rev)], &lf); err != nil {
		panic(fmt.Sprintf("fake: own lockfile %s r%d does not decode: %v", slug, rev, err))
	}
	return lf
}

type control struct{ h *Hub }

func (c control) SetHealthy(ok bool) error {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	c.h.healthy = ok
	return nil
}

func (c control) MintServiceToken(profiles ...string) (string, error) {
	token := "amst_" + randomToken()
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	c.h.tokens[token] = tokenInfo{
		expiresAt: c.h.opts.Now().Add(c.h.opts.TokenTTL), host: "service-token",
		profiles: append([]string{}, profiles...),
	}
	return token, nil
}

func (c control) SyncReports() ([]hub.SyncReport, error) {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	out := make([]hub.SyncReport, len(c.h.reports))
	copy(out, c.h.reports)
	return out, nil
}
