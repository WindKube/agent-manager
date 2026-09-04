package fake

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/hub"
)

// userCodeAlphabet is Crockford base32: no I, L, O or U, so nothing a human reads
// aloud or types is ambiguous. The contract's shape is
// ^[0-9A-HJ-NP-TV-Z]{4}-[0-9A-HJ-NP-TV-Z]{4}$, whose character class happens to
// admit L as well; this alphabet is the stricter of the two on purpose, because a
// fake that emitted a code the real hub would never emit could pass a client whose
// parser is too lax.
const userCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

type deviceState int

const (
	devicePending deviceState = iota
	deviceApproved
	deviceDenied
	deviceConsumed
)

type deviceAuth struct {
	deviceCode string
	userCode   string
	clientID   string
	host       string
	interval   time.Duration
	expiresAt  time.Time

	state    deviceState
	polled   bool
	lastPoll time.Time

	// approvalExpiresAt is when an approval that nobody collected goes stale. It is
	// tracked separately from expiresAt only so ExpireDevice can age an already
	// approved grant; the real hub ages both off the same authorisation record.
	approvalExpiresAt time.Time
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("fake: rand: %v", err))
	}
	// Opaque: base64url of 32 random bytes, one segment, no padding, no dots and no
	// claims. NOT a JWT. The hub's bearerFormat is `opaque` (corrected from `JWT`,
	// which nothing caught for months because the endpoint returned 501), and a
	// token with a decodable payload would let a test read an expiry out of it here
	// and then fail against the real hub. A token's lifetime is expires_in.
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func randomUserCode() string {
	out := make([]byte, 0, 9)
	for i := range 8 {
		if i == 4 {
			out = append(out, '-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			panic(fmt.Sprintf("fake: rand: %v", err))
		}
		out = append(out, userCodeAlphabet[n.Int64()])
	}
	return string(out)
}

func (h *Hub) deviceAuthorize(w http.ResponseWriter, r *http.Request) {
	// 415 for the wrong media type and 400 for a body that does not parse. The
	// document this tree generates from still declares 422 and 501 here because the
	// hub's device endpoints live on PR #14; these are the codes the merged
	// implementation returns, and matching the stale document instead would make
	// the fake pass what the real hub refuses.
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeProblem(w, http.StatusUnsupportedMediaType, "Unsupported Media Type",
			"body must be application/json")
		return
	}
	var req hub.DeviceAuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad Request", "malformed body")
		return
	}
	if req.ClientId == "" || req.Host == "" {
		// host is required and is shown to the approving human, so approval is an
		// informed act. An empty one is not a nicety.
		writeProblem(w, http.StatusBadRequest, "Bad Request", "client_id and host are required")
		return
	}

	now := h.opts.Now()
	auth := &deviceAuth{
		deviceCode: randomToken(),
		userCode:   randomUserCode(),
		clientID:   req.ClientId,
		host:       req.Host,
		interval:   h.opts.PollInterval,
		expiresAt:  now.Add(h.opts.DeviceCodeTTL),
	}
	auth.approvalExpiresAt = auth.expiresAt

	h.mu.Lock()
	h.devices[auth.deviceCode] = auth
	h.byUserCode[auth.userCode] = auth
	h.mu.Unlock()

	verify := h.srv.URL + "/device"
	writeJSON(w, http.StatusOK, "application/json", hub.DeviceAuthorization{
		DeviceCode:              auth.deviceCode,
		UserCode:                auth.userCode,
		VerificationUri:         verify,
		VerificationUriComplete: ptr(verify + "?user_code=" + auth.userCode),
		ExpiresIn:               int64(h.opts.DeviceCodeTTL.Seconds()),
		Interval:                int64(h.opts.PollInterval.Seconds()),
	})
}

// deviceToken implements RFC 8628 §3.4 as the hub implements it.
//
// The ordering below is load-bearing and is the ordering the real hub uses:
// TERMINAL states are decided before slow_down. Telling a client to back off and
// keep polling a grant that is already denied, consumed or expired would keep it
// in a loop that can never succeed, so a hammering client on a dead code gets the
// terminal answer rather than slow_down.
func (h *Hub) deviceToken(w http.ResponseWriter, r *http.Request) {
	// Form-encoded ONLY. RFC 8628 §3.4 fixes it and the real hub enforces it, so
	// accepting JSON here would pass a test the real hub fails. Do not
	// "helpfully" add a JSON branch.
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		writeProblem(w, http.StatusUnsupportedMediaType, "Unsupported Media Type",
			"body must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "Bad Request", "malformed body")
		return
	}
	grant := r.PostForm.Get("grant_type")
	deviceCode := r.PostForm.Get("device_code")
	clientID := r.PostForm.Get("client_id")

	// The five values in the contract's enum are the only errors this endpoint may
	// return, so an unsupported grant type is reported as invalid_grant rather than
	// RFC 6749's unsupported_grant_type: a value outside the enum would be a
	// response the generated client cannot represent.
	if grant != "urn:ietf:params:oauth:grant-type:device_code" {
		writeTokenError(w, hub.InvalidGrant)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	auth, ok := h.devices[deviceCode]
	if !ok || (clientID != "" && clientID != auth.clientID) {
		writeTokenError(w, hub.InvalidGrant)
		return
	}
	now := h.opts.Now()

	switch auth.state {
	case deviceConsumed:
		// A second poll of a consumed code is invalid_grant, NOT
		// authorization_pending. A fake that answered pending here would let a
		// client loop forever against the real hub while its tests stayed green.
		writeTokenError(w, hub.InvalidGrant)
		return
	case deviceDenied:
		writeTokenError(w, hub.AccessDenied)
		return
	}
	if now.After(auth.expiresAt) {
		writeTokenError(w, hub.ExpiredToken)
		return
	}

	// slow_down fires only when the client has polled BEFORE and polled again
	// inside the advertised interval. A first poll is never slow_down — a client
	// that must wait one interval before its first poll would make login slower for
	// everybody and RFC 8628 does not ask for it.
	if auth.polled && now.Sub(auth.lastPoll) < auth.interval {
		// The poll still counts: lastPoll advances, so hammering keeps earning
		// slow_down instead of sliding into a free poll.
		auth.lastPoll = now
		writeTokenError(w, hub.SlowDown)
		return
	}
	auth.polled = true
	auth.lastPoll = now

	if auth.state != deviceApproved {
		writeTokenError(w, hub.AuthorizationPending)
		return
	}
	if now.After(auth.approvalExpiresAt) {
		// Approved, but nobody collected it in time. This yields NO token; the grant
		// is spent either way, so a client cannot poll its way back into it.
		auth.state = deviceConsumed
		writeTokenError(w, hub.ExpiredToken)
		return
	}

	token := randomToken()
	h.tokens[token] = tokenInfo{
		expiresAt: now.Add(h.opts.TokenTTL),
		clientID:  auth.clientID,
		host:      auth.host,
	}
	auth.state = deviceConsumed
	writeJSON(w, http.StatusOK, "application/json", hub.DeviceToken{
		AccessToken: token,
		TokenType:   hub.Bearer,
		ExpiresIn:   int64(h.opts.TokenTTL.Seconds()),
		// No refresh_token: this client may not refresh without a second human
		// approval, and inventing one would let a test exercise a path the hub does
		// not have.
	})
}

// writeTokenError answers 400 with the OAuth error object. Note the media type:
// application/json, not problem+json — /v1/device/token is the one route in the
// contract whose error body is an OAuth structure rather than RFC 7807.
func writeTokenError(w http.ResponseWriter, code hub.DeviceTokenErrorError) {
	writeJSON(w, http.StatusBadRequest, "application/json", hub.DeviceTokenError{Error: &code})
}

// ---- Control's device half

func (c control) ApproveDevice(userCode string) error {
	return c.h.setDeviceState(userCode, deviceApproved)
}
func (c control) DenyDevice(userCode string) error { return c.h.setDeviceState(userCode, deviceDenied) }

func (h *Hub) setDeviceState(userCode string, to deviceState) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	auth, ok := h.byUserCode[strings.ToUpper(userCode)]
	if !ok {
		return fmt.Errorf("no pending authorisation for that user code")
	}
	if auth.state == deviceConsumed {
		return fmt.Errorf("that authorisation has already been consumed")
	}
	auth.state = to
	return nil
}

func (c control) ExpireDevice(userCode string) error {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	auth, ok := c.h.byUserCode[strings.ToUpper(userCode)]
	if !ok {
		return fmt.Errorf("no pending authorisation for that user code")
	}
	past := c.h.opts.Now().Add(-time.Second)
	auth.expiresAt = past
	auth.approvalExpiresAt = past
	return nil
}
