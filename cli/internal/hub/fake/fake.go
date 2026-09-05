package fake

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/hub"
)

// ErrUnsupported is a [Control]'s honest answer for an operation the hub
// behind it can't perform; the suite must skip with a named reason, not
// treat it as a pass.
var ErrUnsupported = errors.New("this hub cannot be driven that way")

// Control is the human-and-operator half of a hub, kept off Target's other
// fields so a behavioural test never needs a *fake.Hub to run against a
// real compose-stack adapter too.
type Control interface {
	ApproveDevice(userCode string) error
	DenyDevice(userCode string) error // terminal
	// ExpireDevice ages the authorisation NOW, producing expired_token or
	// (after approval) the never-collected case. Likely [ErrUnsupported] on
	// a real hub.
	ExpireDevice(userCode string) error
	// SetHealthy distinguishes unauthorised from broken; unreachable needs
	// no control, just close the listener.
	SetHealthy(bool) error
	// SyncReports lets a suite assert exactly one row was written per sync.
	SyncReports() ([]hub.SyncReport, error)
}

// staleSignature matches no package, so the object-store handler refuses it
// like a real store refuses an expired one; fixed, not random, so a failing
// test reads without rerunning.
const staleSignature = "s1Gn4tur3-thAt-h4s-3xp1r3d"

// Fixtures names seeded content a test may address. Empty means the suite
// must skip, not improvise a slug: an invented one 404s against the real
// hub for the wrong reason.
type Fixtures struct {
	// Profile is healthy; HeadRevision/PriorRevision differ in content, not
	// just number.
	Profile       string
	HeadRevision  int64
	PriorRevision int64

	// SharedNamespaceIDs: two ids, one namespace, two publishers — catches
	// an implementation that keyed off publisher instead.
	SharedNamespaceIDs []string

	DigestMismatch   string // one entry's digest is really some other bundle's
	ForbiddenBundle  string // middle entry answers 403; the others still install
	ForbiddenEntryID string
	// PresignedBundle answers 307 same-host, so a cross-host redirect leak
	// defence alone wouldn't catch a same-host leak.
	PresignedBundle string
	// StalePresignedBundle's second entry gets a store 403 behind a hub 307;
	// a hub 403 and a store 403 must not be read as the same failure.
	StalePresignedBundle  string
	StalePresignedEntryID string
	UnknownSkipReason     string // must be reported verbatim
	// UnwritableTarget names codex, which must be refused by name, not
	// silently skipped — see catalog.go's profiles().
	UnwritableTarget string

	MissingProfile string // 404
}

// Target is everything a behavioural test gets: no *fake.Hub.
type Target struct {
	BaseURL string
	Token   string
	// HTTPClient trusts the fake's self-signed cert; a suite must use this,
	// not build its own, or the TLS variant fails for an unrelated reason.
	HTTPClient *http.Client
	Fixtures   Fixtures
	Control    Control
}

// Options configures the fake. Every zero value is a working default.
type Options struct {
	Now func() time.Time // only the device flow reads it; nil means time.Now
	// PollInterval is both the advertised interval and the slow_down
	// window — never two numbers, since a sub-second gap while advertising
	// 0 would punish an obedient client. Default 5s, rounded up, 1s floor.
	PollInterval  time.Duration
	DeviceCodeTTL time.Duration // authorize response's expires_in; default 15m
	TokenTTL      time.Duration // access token's expires_in; default 1h
	// TLS serves a self-signed cert; the CLI refuses plaintext without an
	// explicit flag, so the normal-path test wants this on.
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
}

// Hub is the running fake. Tests construct it; they do NOT pass it around —
// pass [Hub.Target] instead. See doc.go.
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

	// The seed token stands in for "the operator already logged this machine in".
	// It is minted the same way the device flow mints one — opaque, random — so no
	// test can accidentally depend on a shape only the seed has.
	h.seedToken = randomToken()
	h.tokens[h.seedToken] = tokenInfo{expiresAt: h.opts.Now().Add(h.opts.TokenTTL), clientID: "agent-manager-cli", host: "seed"}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/device/authorize", h.deviceAuthorize)
	mux.HandleFunc("POST /v1/device/token", h.deviceToken)
	mux.HandleFunc("GET /v1/health", h.health)
	mux.HandleFunc("GET /v1/profiles", h.listProfiles)
	mux.HandleFunc("GET /v1/profiles/{slug}/revisions/{revision}", h.getRevision)
	// The path parameter is SPELLED `publisher` in the frozen contract and holds
	// the NAMESPACE. Its own description says so and the name does not. Naming the
	// wildcard `namespace` here is deliberate: this is the bug that shipped three
	// times on the hub side, and the fake must not be a fourth place it can hide.
	mux.HandleFunc("GET /v1/bundles/{namespace}/{name}/{version}", h.getBundle)
	mux.HandleFunc("POST /v1/sync", h.reportSync)
	// Not a hub route. It stands in for the object store the 307 points at, on
	// the SAME host, which is the only shape that can catch a redirect leak.
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

// Target is the only value a behavioural test should ever see.
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
			UnwritableTarget:      slugUnwritable,
			MissingProfile:        slugMissing,
		},
	}
}

// ---- lockfile construction

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

// ---- handlers

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
	// No auth on this route, by contract: it is the probe that tells
	// "unreachable" from "unauthorised", so requiring a token would defeat its
	// purpose.
	writeJSON(w, status, "application/json", body)
}

func (h *Hub) listProfiles(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r) {
		return
	}
	out := hub.ProfileList{Profiles: make([]hub.Profile, 0, len(h.profiles))}
	for _, p := range h.profiles {
		head := h.heads[p.slug]
		lf := h.decodeLockfile(p.slug, head)
		out.Profiles = append(out.Profiles, hub.Profile{
			Slug: p.slug, Name: p.name,
			HeadRevision: head,
			// "excluding skipped entries", per the contract: the count is entries,
			// not entries+skipped, and getting that backwards is invisible until
			// somebody compares the number with what installed.
			PackageCount: int64(len(lf.Entries)),
			Visibility:   ptr(hub.ProfileVisibility(p.visibility)),
		})
	}
	writeJSON(w, http.StatusOK, "application/json", out)
}

// The contract writes this as ^(head|[0-9]+)$; \d is Go's ASCII-only digit class
// and therefore the same set.
var revisionPattern = regexp.MustCompile(`^(head|\d+)$`)

func (h *Hub) getRevision(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r) {
		return
	}
	slug := r.PathValue("slug")
	raw := r.PathValue("revision")
	if !revisionPattern.MatchString(raw) {
		writeProblem(w, http.StatusUnprocessableEntity, "Unprocessable Entity",
			"revision must match ^(head|[0-9]+)$")
		return
	}
	if _, ok := h.profileSpec(slug); !ok {
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
	if !h.authorized(w, r) {
		return
	}
	// The namespace, not the publisher slug. A publisher slug is two segments and
	// could not fit in one path element; an id that is not exactly two non-empty
	// segments is an error the CLI must raise rather than paper over.
	id := r.PathValue("namespace") + "/" + r.PathValue("name")
	key := id + "@" + r.PathValue("version")
	p, ok := h.pkgs[key]
	if !ok {
		writeProblem(w, http.StatusNotFound, "Not Found", "no such package version")
		return
	}
	switch p.serve {
	case serveForbidden:
		writeProblem(w, http.StatusForbidden, "Forbidden",
			"version rejected by the organisation's scan gate")
	case serveRedirectStale:
		// The same 307, with a signature the store will not accept. See
		// serveRedirectStale.
		loc := "/objects/" + p.objectKey() + "?X-Amz-Expires=60&X-Amz-Signature=" + url.QueryEscape(staleSignature)
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusTemporaryRedirect)
	case serveRedirect:
		loc := "/objects/" + p.objectKey() + "?X-Amz-Expires=60&X-Amz-Signature=" + url.QueryEscape(h.signatures[key])
		// 307, not 302: the method must survive. The Location is on THIS host on
		// purpose — net/http strips Authorization across hosts already, so a
		// cross-host redirect cannot catch the redirect-leak bug it is meant to
		// catch.
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusTemporaryRedirect)
	default:
		writeBundle(w, p.blob)
	}
}

// presigned stands in for the object store the 307 points at. It refuses a
// request carrying an Authorization header, matching real pre-signed stores
// like S3 — so a client that leaks the bearer to the redirect target gets an
// ordinary 400, testable without reaching inside the fake.
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
	// RFC 3230: `sha-256=<standard base64>`. Derived from the bytes below, never
	// written by hand — a fake whose header and body can disagree is a fake that
	// cannot test the digest check.
	w.Header().Set("Digest", b.HeaderDigest())
	w.Header().Set("ETag", b.ETag())
	w.Header().Set("Content-Length", strconv.Itoa(len(b.Bytes)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b.Bytes)
}

func (h *Hub) reportSync(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(w, r) {
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
		// `head` is not a revision here. The client must have replaced it with the
		// number it resolved against and a fake that accepted a string
		// would let that bug through.
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
	if _, ok := h.profileSpec(body.Profile); !ok {
		writeProblem(w, http.StatusNotFound, "Not Found", "no such profile")
		return
	}

	h.mu.Lock()
	h.reports = append(h.reports, body)
	h.mu.Unlock()
	// 204: no body, by contract. One call per sync, never one per package.
	w.WriteHeader(http.StatusNoContent)
}

// ---- auth

// authorized enforces the bearer on the five authenticated routes. An absent,
// malformed, unknown or expired token is 401 and they are NOT distinguished in the
// body: telling a caller which of those it was is a probing oracle, and the
// four failure classes are decided by status code, not by prose.
func (h *Hub) authorized(w http.ResponseWriter, r *http.Request) bool {
	raw := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(raw, "Bearer ")
	if !ok || token == "" {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "a bearer token is required")
		return false
	}
	h.mu.Lock()
	info, known := h.tokens[token]
	h.mu.Unlock()
	if !known || h.opts.Now().After(info.expiresAt) {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "the bearer token is not valid")
		return false
	}
	return true
}

// ---- responses

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

// ---- Control, implemented over the fake's own state

type control struct{ h *Hub }

func (c control) SetHealthy(ok bool) error {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	c.h.healthy = ok
	return nil
}

func (c control) SyncReports() ([]hub.SyncReport, error) {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	out := make([]hub.SyncReport, len(c.h.reports))
	copy(out, c.h.reports)
	return out, nil
}
