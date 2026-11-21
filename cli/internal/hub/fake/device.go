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

// userCodeAlphabet is Crockford base32, stricter than the contract's regex, matching what the real hub emits.
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

	// approvalExpiresAt is tracked separately from expiresAt only so
	// ExpireDevice can age an already-approved grant on its own.
	approvalExpiresAt time.Time
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("fake: rand: %v", err))
	}
	// Opaque, never a JWT, so no test can read an expiry here that the real hub wouldn't offer.
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
	// 415/400 as the real hub answers, not what the stale generated doc shows.
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
		// host is shown to the approving human; an empty one is not a nicety
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

// deviceToken implements RFC 8628 §3.4. Terminal states are decided before slow_down, as on the real
// hub, so a hammering client on a dead code gets the terminal answer.
func (h *Hub) deviceToken(w http.ResponseWriter, r *http.Request) {
	// Form-encoded ONLY (RFC 8628 §3.4); a JSON branch would pass a test the real hub fails.
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

	// invalid_grant, since the contract's enum has no unsupported_grant_type.
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
		// invalid_grant, not authorization_pending, or a client would loop forever against the real hub
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

	// A first poll is never slow_down.
	if auth.polled && now.Sub(auth.lastPoll) < auth.interval {
		// counts anyway: lastPoll still advances, so hammering keeps earning slow_down
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
		// approved but uncollected in time yields no token; the grant is spent either way
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
		// no refresh_token: a second human approval is required, and inventing one would test a path the hub lacks
	})
}

// writeTokenError answers 400 as application/json, the one OAuth-shaped error body.
func writeTokenError(w http.ResponseWriter, code hub.DeviceTokenErrorError) {
	writeJSON(w, http.StatusBadRequest, "application/json", hub.DeviceTokenError{Error: &code})
}

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
