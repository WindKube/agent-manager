// Tests live in package device, not device_test, so the never-polls-faster
// negative control can zero Flow.slowDown directly. The clock is virtual;
// nothing here actually sleeps.
package device

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testDeviceCode  = "DEVICE-CODE-a1b2c3d4e5f6-MUST-NEVER-BE-LOGGED"
	testUserCode    = "HKQ2-9FTL"
	testAccessToken = "ACCESS-TOKEN-9f8e7d6c5b4a-MUST-NEVER-BE-LOGGED"
	testRefresh     = "REFRESH-TOKEN-0011223344-MUST-NEVER-BE-LOGGED"
	testVerifyURI   = "https://hub.example.com/device"
)

var epoch = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	now   time.Time
	waits []time.Duration
}

func newClock() *fakeClock { return &fakeClock{now: epoch} }

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return ctx.Err()
	}
	c.waits = append(c.waits, d)
	c.now = c.now.Add(d)
	return nil
}

func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

type step struct {
	code    ErrorCode
	issued  *Issued
	err     error
	latency time.Duration // how far the clock moves while this poll is in flight
	do      func()        // runs after the clock moves; how a test cancels mid-flight
}

type pollRecord struct {
	at       time.Time
	interval time.Duration // implementation's own view, recorded only as a cross-check
}

type fakeHub struct {
	t   *testing.T
	clk *fakeClock

	auth    Authorization
	authErr error

	steps []step
	tail  *step // answer given once steps runs out

	flow           *Flow
	polls          []pollRecord
	authorizeCalls int
}

func (h *fakeHub) Authorize(_ context.Context, req AuthorizeRequest) (Authorization, error) {
	h.authorizeCalls++
	require.NotEmpty(h.t, req.ClientID, "client id must reach the transport")
	require.NotEmpty(h.t, req.Host, "host must reach the transport (FR-001)")
	if h.authErr != nil {
		return Authorization{}, h.authErr
	}
	return h.auth, nil
}

func (h *fakeHub) Poll(_ context.Context, req PollRequest) (*Issued, ErrorCode, error) {
	require.Equal(h.t, testDeviceCode, req.DeviceCode, "the device code must reach the transport")
	var interval time.Duration
	if h.flow != nil {
		interval = h.flow.Interval()
	}
	h.polls = append(h.polls, pollRecord{at: h.clk.Now(), interval: interval})

	s := h.tail
	if n := len(h.polls) - 1; n < len(h.steps) {
		s = &h.steps[n]
	}
	require.NotNil(h.t, s, "fake hub ran out of scripted answers after %d polls", len(h.polls))

	if s.latency > 0 {
		h.clk.advance(s.latency)
	}
	if s.do != nil {
		s.do()
	}
	if s.err != nil {
		return nil, "", s.err
	}
	return s.issued, s.code, nil
}

func issuedToken() *Issued {
	return &Issued{
		AccessToken:  testAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    time.Hour,
		RefreshToken: testRefresh,
	}
}

func authorization(expiresIn, interval time.Duration) Authorization {
	return Authorization{
		DeviceCode:              testDeviceCode,
		UserCode:                testUserCode,
		VerificationURI:         testVerifyURI,
		VerificationURIComplete: testVerifyURI + "?code=" + testUserCode,
		ExpiresIn:               expiresIn,
		Interval:                interval,
	}
}

func begin(t *testing.T, h *fakeHub) (*Flow, error) {
	t.Helper()
	f, err := Begin(context.Background(), h, h.clk, AuthorizeRequest{
		ClientID: "agent-manager-cli",
		Host:     "dev-laptop-01",
		Scope:    "profiles:read bundles:read",
	})
	h.flow = f
	return f, err
}

func newHub(t *testing.T, auth Authorization, steps []step, tail *step) *fakeHub {
	t.Helper()
	return &fakeHub{t: t, clk: newClock(), auth: auth, steps: steps, tail: tail}
}

// requiredInterval is RFC 8628 §3.2/§3.5 restated, hand-derived rather than
// read off Flow.interval so a bug in the implementation can't self-validate.
func requiredInterval(advertised time.Duration, slowDownsSeen int) time.Duration {
	if advertised <= 0 {
		advertised = 5 * time.Second
	}
	return advertised + time.Duration(slowDownsSeen)*5*time.Second
}

// violations reports every consecutive pair of polls whose gap was shorter
// than the interval in force at the earlier poll.
func violations(polls []pollRecord, answers []ErrorCode, advertised time.Duration) []string {
	var out []string
	slowDowns := 0
	for i := 1; i < len(polls); i++ {
		if answers[i-1] == CodeSlowDown {
			slowDowns++
		}
		want := requiredInterval(advertised, slowDowns)
		got := polls[i].at.Sub(polls[i-1].at)
		if got < want {
			out = append(out, fmt.Sprintf("poll %d came %v after poll %d, but the interval in force was %v",
				i, got, i-1, want))
		}
	}
	return out
}

func TestNeverPollsFasterThanItWasTold(t *testing.T) {
	answers := []ErrorCode{
		CodeAuthorizationPending, CodeAuthorizationPending, CodeSlowDown,
		CodeAuthorizationPending, CodeAuthorizationPending, CodeSlowDown,
		CodeAuthorizationPending, CodeAuthorizationPending,
	}
	build := func() *fakeHub {
		steps := make([]step, 0, len(answers)+1)
		for i, code := range answers {
			steps = append(steps, step{code: code, latency: time.Duration(i%3) * 250 * time.Millisecond})
		}
		steps = append(steps, step{issued: issuedToken()})
		return newHub(t, authorization(15*time.Minute, 5*time.Second), steps, nil)
	}

	t.Run("every gap is at least the interval in force", func(t *testing.T) {
		h := build()
		f, err := begin(t, h)
		require.NoError(t, err)

		realStart := time.Now()
		tok, err := f.Wait(context.Background())
		require.NoError(t, err)
		require.Equal(t, testAccessToken, tok.AccessToken())

		require.Len(t, h.polls, len(answers)+1)
		require.Empty(t, violations(h.polls, answers, 5*time.Second))

		slowDowns := 0
		for i, p := range h.polls {
			if i > 0 && answers[i-1] == CodeSlowDown {
				slowDowns++
			}
			require.Equal(t, requiredInterval(5*time.Second, slowDowns), p.interval,
				"interval in force at poll %d", i)
		}

		require.Greater(t, h.clk.Now().Sub(epoch), 30*time.Second)
		require.Less(t, time.Since(realStart), 2*time.Second, "the suite must not actually sleep")
	})

	t.Run("negative control: a poller that ignores slow_down is caught", func(t *testing.T) {
		h := build()
		f, err := begin(t, h)
		require.NoError(t, err)
		f.slowDown = 0 // simulate a poller that ignores slow_down

		_, err = f.Wait(context.Background())
		require.NoError(t, err)

		bad := violations(h.polls, answers, 5*time.Second)
		require.NotEmpty(t, bad, "the assertion is vacuous: it passed a poller that ignores slow_down")
		require.Contains(t, bad[0], "the interval in force was 10s")
	})
}

func TestApprovalReturnsTheTokenAndItsLifetime(t *testing.T) {
	h := newHub(t, authorization(15*time.Minute, 7*time.Second), []step{
		{code: CodeAuthorizationPending},
		{code: CodeAuthorizationPending, latency: 400 * time.Millisecond},
		{issued: issuedToken(), latency: time.Second},
	}, nil)
	f, err := begin(t, h)
	require.NoError(t, err)
	require.Equal(t, 1, h.authorizeCalls)
	require.Equal(t, testUserCode, f.UserCode())
	require.Equal(t, testVerifyURI, f.VerificationURI())
	require.Equal(t, testVerifyURI+"?code="+testUserCode, f.VerificationURIComplete())
	require.Equal(t, 7*time.Second, f.Interval())
	require.Equal(t, epoch.Add(15*time.Minute), f.ExpiresAt())

	tok, err := f.Wait(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, h.authorizeCalls, "Wait must not reopen the authorisation")
	require.Equal(t, 3, f.Polls())
	require.Equal(t, testAccessToken, tok.AccessToken())
	require.Equal(t, "Bearer", tok.TokenType)
	require.Equal(t, time.Hour, tok.ExpiresIn)

	refresh, ok := tok.RefreshToken()
	require.True(t, ok)
	require.Equal(t, testRefresh, refresh)

	receipt := epoch.Add(7*time.Second + 400*time.Millisecond + 7*time.Second + time.Second)
	require.Equal(t, receipt, h.clk.Now())
	require.Equal(t, receipt.Add(time.Hour), tok.ExpiresAt)
}

func TestDenialStopsTheLoopAtOnce(t *testing.T) {
	h := newHub(t, authorization(15*time.Minute, 5*time.Second), []step{
		{code: CodeAuthorizationPending},
		{code: CodeAccessDenied},
	}, &step{code: CodeAuthorizationPending})
	f, err := begin(t, h)
	require.NoError(t, err)

	_, err = f.Wait(context.Background())
	require.ErrorIs(t, err, ErrDenied)
	require.NotErrorIs(t, err, ErrExpired)
	require.NotErrorIs(t, err, context.Canceled)
	require.Equal(t, 2, f.Polls(), "a denial must not be polled past")
}

func TestTerminalCodesStopAndContinuingCodesDoNot(t *testing.T) {
	terminal := map[ErrorCode]error{
		CodeAccessDenied: ErrDenied,
		CodeExpiredToken: ErrExpired,
		CodeInvalidGrant: ErrInvalidGrant,
	}
	continuing := map[ErrorCode]bool{
		CodeAuthorizationPending: true,
		CodeSlowDown:             true,
	}
	require.Len(t, Codes(), 5)
	require.Len(t, terminal, 3)

	for _, code := range Codes() {
		t.Run(string(code), func(t *testing.T) {
			want, isTerminal := terminal[code]
			require.Equal(t, isTerminal, code.Terminal())
			require.Equal(t, continuing[code], code.Continues())
			require.NotEqual(t, code.Terminal(), code.Continues(), "every declared code is one or the other")

			h := newHub(t, authorization(15*time.Minute, 5*time.Second),
				[]step{{code: code}, {issued: issuedToken()}}, nil)
			f, err := begin(t, h)
			require.NoError(t, err)

			tok, err := f.Wait(context.Background())
			if isTerminal {
				require.ErrorIs(t, err, want)
				require.Nil(t, tok)
				require.Equal(t, 1, f.Polls())
				return
			}
			require.NoError(t, err)
			require.Equal(t, 2, f.Polls())
		})
	}
	require.False(t, ErrorCode("").Terminal(), "the empty code is the issued-token case, not a refusal")
	require.False(t, ErrorCode("").Continues())
}

func TestUnrecognisedRefusalIsTerminalAndQuotedVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name, code, want string
	}{
		{"a code this build has never heard of", "authorization_declined_by_policy", `"authorization_declined_by_policy"`},
		{"no code at all", "", "named no reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHub(t, authorization(15*time.Minute, 5*time.Second),
				[]step{{code: ErrorCode(tc.code)}}, &step{issued: issuedToken()})
			f, err := begin(t, h)
			require.NoError(t, err)

			_, err = f.Wait(context.Background())
			require.ErrorIs(t, err, ErrUnknownRefusal)
			require.Contains(t, err.Error(), tc.want)
			require.Equal(t, 1, f.Polls(), "an unknown refusal fails closed rather than polling on")
		})
	}
}

func TestExpiry(t *testing.T) {
	t.Run("the hub says expired_token", func(t *testing.T) {
		h := newHub(t, authorization(15*time.Minute, 5*time.Second),
			[]step{{code: CodeAuthorizationPending}, {code: CodeExpiredToken}}, nil)
		f, err := begin(t, h)
		require.NoError(t, err)

		_, err = f.Wait(context.Background())
		require.ErrorIs(t, err, ErrExpired)
		require.Contains(t, err.Error(), "the hub says")
		require.Equal(t, 2, f.Polls())
	})

	t.Run("the clock passes the deadline while polling", func(t *testing.T) {
		h := newHub(t, authorization(30*time.Second, 5*time.Second),
			[]step{{code: CodeAuthorizationPending, latency: 40 * time.Second}}, nil)
		f, err := begin(t, h)
		require.NoError(t, err)

		_, err = f.Wait(context.Background())
		require.ErrorIs(t, err, ErrExpired)
		require.Contains(t, err.Error(), "closed while polling")
		require.Equal(t, 1, f.Polls())
	})

	t.Run("the next poll would fall after the deadline", func(t *testing.T) {
		h := newHub(t, authorization(12*time.Second, 5*time.Second), nil,
			&step{code: CodeAuthorizationPending})
		f, err := begin(t, h)
		require.NoError(t, err)

		_, err = f.Wait(context.Background())
		require.ErrorIs(t, err, ErrExpired)
		require.Contains(t, err.Error(), "not due for 5s")
		require.Equal(t, 3, f.Polls())
		require.Equal(t, epoch.Add(10*time.Second), h.clk.Now(), "it must not sleep past the deadline")
	})

	t.Run("slow_down widening the interval past the window ends the flow", func(t *testing.T) {
		h := newHub(t, authorization(20*time.Second, 5*time.Second),
			[]step{{code: CodeSlowDown}}, &step{code: CodeAuthorizationPending})
		f, err := begin(t, h)
		require.NoError(t, err)

		_, err = f.Wait(context.Background())
		require.ErrorIs(t, err, ErrExpired)
		require.Equal(t, 10*time.Second, f.Interval())
		require.Equal(t, 2, f.Polls(), "polls at 0 and 10; the third would be at 20, the deadline itself")
	})
}

func TestSlowDown(t *testing.T) {
	t.Run("each slow_down adds the RFC's five seconds", func(t *testing.T) {
		h := newHub(t, authorization(15*time.Minute, 5*time.Second), []step{
			{code: CodeSlowDown},
			{code: CodeSlowDown},
			{code: CodeAuthorizationPending},
			{issued: issuedToken()},
		}, nil)
		f, err := begin(t, h)
		require.NoError(t, err)
		_, err = f.Wait(context.Background())
		require.NoError(t, err)

		require.Equal(t, 15*time.Second, f.Interval())
		// RFC 8628 §3.5: the widened interval governs the gap immediately
		// following the slow_down, not the one after that.
		require.Equal(t, []time.Duration{10 * time.Second, 15 * time.Second, 15 * time.Second}, h.clk.waits)
	})

	t.Run("the first poll is immediate and never pre-emptively slowed", func(t *testing.T) {
		h := newHub(t, authorization(15*time.Minute, 5*time.Second),
			[]step{{code: CodeAuthorizationPending}, {issued: issuedToken()}}, nil)
		f, err := begin(t, h)
		require.NoError(t, err)
		require.Equal(t, 5*time.Second, f.Interval(), "no backoff exists before a slow_down arrives")

		_, err = f.Wait(context.Background())
		require.NoError(t, err)
		require.Equal(t, epoch, h.polls[0].at, "the interval is a floor between polls, not a delay before the first")
		require.Equal(t, 5*time.Second, h.polls[1].at.Sub(h.polls[0].at))
		require.Equal(t, 5*time.Second, f.Interval())
	})

	t.Run("slow_down on the very first poll widens and keeps polling", func(t *testing.T) {
		h := newHub(t, authorization(15*time.Minute, 5*time.Second),
			[]step{{code: CodeSlowDown}, {issued: issuedToken()}}, nil)
		f, err := begin(t, h)
		require.NoError(t, err)

		_, err = f.Wait(context.Background())
		require.NoError(t, err)
		require.Equal(t, 10*time.Second, f.Interval())
		require.Equal(t, 10*time.Second, h.polls[1].at.Sub(h.polls[0].at))
	})
}

func TestIntervalNormalisation(t *testing.T) {
	for _, tc := range []struct {
		name string
		give time.Duration
		want time.Duration
	}{
		{"omitted, so the RFC's default", 0, 5 * time.Second},
		{"negative, from a hostile hub", -30 * time.Second, 5 * time.Second},
		{"one nanosecond, from a hostile hub", time.Nanosecond, time.Nanosecond},
		{"the hub's own value is honoured", 11 * time.Second, 11 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHub(t, authorization(15*time.Minute, tc.give),
				[]step{{code: CodeAuthorizationPending}, {issued: issuedToken()}}, nil)
			f, err := begin(t, h)
			require.NoError(t, err)
			require.Equal(t, tc.want, f.Interval())

			_, err = f.Wait(context.Background())
			require.NoError(t, err)
			require.GreaterOrEqual(t, h.polls[1].at.Sub(h.polls[0].at), tc.want)
		})
	}
}

// TestBeginRefusesAnIntervalNoWindowCouldFit proves the failure is reported
// as ErrProtocol naming both numbers, not misdiagnosed as ErrExpired (which
// would send the user into a retry loop that can never succeed).
func TestBeginRefusesAnIntervalNoWindowCouldFit(t *testing.T) {
	for _, tc := range []struct {
		name            string
		expiresIn, give time.Duration
		wantInMessage   []string
	}{
		{
			name: "an interval longer than the code lives", expiresIn: 15 * time.Minute, give: 24 * time.Hour,
			wantInMessage: []string{"24h0m0s", "15m0s"},
		},
		{
			name:      "an interval exactly as long as the window, which allows one poll at t=0 and nothing after",
			expiresIn: 15 * time.Minute, give: 15 * time.Minute,
			wantInMessage: []string{"15m0s"},
		},
		{
			name: "no interval and a window shorter than the RFC's default", expiresIn: 3 * time.Second, give: 0,
			wantInMessage: []string{"5s", "3s"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHub(t, authorization(tc.expiresIn, tc.give), nil, &step{issued: issuedToken()})
			f, err := begin(t, h)
			require.Nil(t, f)
			require.ErrorIs(t, err, ErrProtocol)
			require.NotErrorIs(t, err, ErrExpired,
				"the code has its whole window; calling this an expiry sends the user to retry a flow that cannot work")
			for _, want := range tc.wantInMessage {
				require.Contains(t, err.Error(), want)
			}
			require.Empty(t, h.polls, "nothing is polled, so no user code is ever shown")
		})
	}

	t.Run("an interval one nanosecond inside the window is accepted", func(t *testing.T) {
		h := newHub(t, authorization(time.Minute, time.Minute-time.Nanosecond),
			[]step{{issued: issuedToken()}}, nil)
		f, err := begin(t, h)
		require.NoError(t, err)
		require.Equal(t, time.Minute-time.Nanosecond, f.Interval())
	})
}

// TestSubSecondIntervalIsNotClampedUp proves this package enforces only the
// hub's floor and imposes none of its own.
func TestSubSecondIntervalIsNotClampedUp(t *testing.T) {
	h := newHub(t, authorization(time.Minute, time.Millisecond),
		[]step{{code: CodeAuthorizationPending}, {issued: issuedToken()}}, nil)
	f, err := begin(t, h)
	require.NoError(t, err)
	_, err = f.Wait(context.Background())
	require.NoError(t, err)
	require.Equal(t, []time.Duration{time.Millisecond}, h.clk.waits)
}

func TestContextCancellationIsDistinguishableFromAHubRefusal(t *testing.T) {
	t.Run("cancelled while waiting out the interval", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		h := newHub(t, authorization(15*time.Minute, 5*time.Second),
			[]step{{code: CodeAuthorizationPending, do: cancel}}, &step{issued: issuedToken()})
		f, err := begin(t, h)
		require.NoError(t, err)

		tok, err := f.Wait(ctx)
		require.Nil(t, tok)
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, ErrDenied)
		require.NotErrorIs(t, err, ErrExpired)
		require.NotErrorIs(t, err, ErrUnknownRefusal)
		require.Equal(t, 1, f.Polls())
	})

	t.Run("already cancelled before the first poll", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h := newHub(t, authorization(15*time.Minute, 5*time.Second), nil, &step{issued: issuedToken()})
		f, err := begin(t, h)
		require.NoError(t, err)

		_, err = f.Wait(ctx)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 0, f.Polls(), "a cancelled context must not produce a request")
	})

	t.Run("the deadline case keeps its own identity", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := newHub(t, authorization(15*time.Minute, 5*time.Second), []step{{
			code: CodeAuthorizationPending,
			err:  fmt.Errorf("Post \"https://hub.example.com/v1/device/token\": %w", context.DeadlineExceeded),
			do:   func() {},
		}}, nil)
		f, err := begin(t, h)
		require.NoError(t, err)

		_, err = f.Wait(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.NotErrorIs(t, err, ErrDenied)
	})

	t.Run("a refusal is not a cancellation", func(t *testing.T) {
		h := newHub(t, authorization(15*time.Minute, 5*time.Second),
			[]step{{code: CodeAccessDenied}}, nil)
		f, err := begin(t, h)
		require.NoError(t, err)

		_, err = f.Wait(context.Background())
		require.ErrorIs(t, err, ErrDenied)
		require.NotErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestTransportFailureEndsTheFlowWithItsOwnError(t *testing.T) {
	boom := errors.New("health: hub unreachable at https://hub.example.com/v1/health")
	h := newHub(t, authorization(15*time.Minute, 5*time.Second),
		[]step{{code: CodeAuthorizationPending}, {err: boom}}, &step{issued: issuedToken()})
	f, err := begin(t, h)
	require.NoError(t, err)

	_, err = f.Wait(context.Background())
	require.ErrorIs(t, err, boom, "the transport's diagnosis must survive (FR-040)")
	require.NotErrorIs(t, err, ErrDenied)
	require.Equal(t, 2, f.Polls(), "a transport failure is not retried here")
}

func TestBeginRefusesAnUnusableAuthorisation(t *testing.T) {
	full := authorization(15*time.Minute, 5*time.Second)
	for _, tc := range []struct {
		name   string
		mutate func(*Authorization)
		want   string
	}{
		{"no device code", func(a *Authorization) { a.DeviceCode = "" }, "no device code"},
		{"no user code", func(a *Authorization) { a.UserCode = "" }, "nothing to show the human"},
		{"no verification URI", func(a *Authorization) { a.VerificationURI = "" }, "nowhere to send the human"},
		{"expires_in of zero", func(a *Authorization) { a.ExpiresIn = 0 }, "already dead"},
		{"negative expires_in", func(a *Authorization) { a.ExpiresIn = -time.Minute }, "already dead"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := full
			tc.mutate(&auth)
			h := newHub(t, auth, nil, &step{issued: issuedToken()})
			f, err := begin(t, h)
			require.Nil(t, f)
			require.ErrorIs(t, err, ErrProtocol)
			require.Contains(t, err.Error(), tc.want)
			require.Empty(t, h.polls, "nothing is polled after a refused authorisation")
		})
	}

	t.Run("the authorisation call itself fails", func(t *testing.T) {
		h := newHub(t, full, nil, nil)
		h.authErr = errors.New("deviceAuthorize: hub does not implement this operation (501)")
		f, err := begin(t, h)
		require.Nil(t, f)
		require.ErrorContains(t, err, "opening the device authorisation")
		require.ErrorContains(t, err, "501")
	})
}

func TestBeginRefusesAMiswiredCaller(t *testing.T) {
	h := newHub(t, authorization(15*time.Minute, 5*time.Second), nil, nil)
	req := AuthorizeRequest{ClientID: "agent-manager-cli", Host: "dev-laptop-01"}

	_, err := Begin(context.Background(), nil, h.clk, req)
	require.ErrorIs(t, err, ErrNoTransport)

	_, err = Begin(context.Background(), h, nil, req)
	require.ErrorIs(t, err, ErrNoClock)

	_, err = Begin(context.Background(), h, h.clk, AuthorizeRequest{Host: "dev-laptop-01"})
	require.ErrorIs(t, err, ErrProtocol)
	require.ErrorContains(t, err, "no client id")

	_, err = Begin(context.Background(), h, h.clk, AuthorizeRequest{ClientID: "agent-manager-cli"})
	require.ErrorIs(t, err, ErrProtocol)
	require.ErrorContains(t, err, "no hostname")
	require.Equal(t, 0, h.authorizeCalls)
}

func TestIssuedTokenIsRefusedWhenItCannotBeUsed(t *testing.T) {
	for _, tc := range []struct {
		name string
		give Issued
		want string
	}{
		{"success with no token", Issued{TokenType: "Bearer", ExpiresIn: time.Hour}, "no access token"},
		{"no lifetime", Issued{AccessToken: testAccessToken, TokenType: "Bearer"}, "expires_in 0s"},
		{"negative lifetime", Issued{AccessToken: testAccessToken, ExpiresIn: -time.Hour}, "expires_in -1h0m0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			give := tc.give
			h := newHub(t, authorization(15*time.Minute, 5*time.Second), []step{{issued: &give}}, nil)
			f, err := begin(t, h)
			require.NoError(t, err)

			tok, err := f.Wait(context.Background())
			require.Nil(t, tok)
			require.ErrorIs(t, err, ErrProtocol)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestNoCodeAndNoTokenSurvivesFormatting proves no credential leaks through
// any fmt verb on Flow or Token; the user code is the one deliberate exception,
// since it must be shown to the human.
func TestNoCodeAndNoTokenSurvivesFormatting(t *testing.T) {
	secrets := []string{testDeviceCode, testAccessToken, testRefresh}

	h := newHub(t, authorization(15*time.Minute, 5*time.Second),
		[]step{{code: CodeSlowDown}, {issued: issuedToken()}}, nil)
	f, err := begin(t, h)
	require.NoError(t, err)
	tok, err := f.Wait(context.Background())
	require.NoError(t, err)

	var rendered []string
	for _, v := range []any{f, tok, *tok} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered = append(rendered, fmt.Sprintf(verb, v))
		}
	}
	rendered = append(rendered, f.String(), tok.String())

	for _, code := range append(Codes(), "wildcat") {
		if code.Terminal() {
			rendered = append(rendered, terminalError(code).Error())
		}
	}
	for _, e := range []error{
		terminalError(""),
		fmt.Errorf("%w: x", ErrProtocol),
	} {
		rendered = append(rendered, e.Error())
	}
	for _, steps := range [][]step{
		{{code: CodeAccessDenied}},
		{{code: CodeExpiredToken}},
		{{code: CodeInvalidGrant}},
		{{code: "who_knows"}},
		{{err: errors.New("unreachable")}},
		{{issued: &Issued{AccessToken: testAccessToken}}},
	} {
		hh := newHub(t, authorization(15*time.Minute, 5*time.Second), steps, nil)
		ff, berr := begin(t, hh)
		require.NoError(t, berr)
		if _, werr := ff.Wait(context.Background()); werr != nil {
			rendered = append(rendered, werr.Error(), fmt.Sprintf("%+v", werr))
		}
	}

	for _, s := range rendered {
		for _, secret := range secrets {
			require.NotContains(t, s, secret, "FR-007: a credential reached a rendered string")
		}
	}

	leak := fmt.Sprintf("device_code=%s", testDeviceCode)
	require.Contains(t, leak, testDeviceCode)

	require.Equal(t, testUserCode, f.UserCode())
	require.Contains(t, f.VerificationURIComplete(), testUserCode)
	require.NotContains(t, f.String(), testUserCode, "but not through a formatted Flow")
}

func touchesTheClock(src string) []string {
	var found []string
	for _, bad := range []string{"time.Now(", "time.Sleep(", "time.After(", "time.Tick(", "time.NewTimer(", "time.NewTicker("} {
		if strings.Contains(src, bad) {
			found = append(found, bad)
		}
	}
	return found
}

// TestPackageTouchesTheClockOnlyThroughClock enforces mechanically that only
// clock.go may read the wall clock or block.
func TestPackageTouchesTheClockOnlyThroughClock(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") || name == "clock.go" {
			continue
		}
		src, rerr := os.ReadFile(name)
		require.NoError(t, rerr)
		require.Empty(t, touchesTheClock(string(src)),
			"%s reads the clock directly; go through the Clock interface", name)
		checked++
	}
	require.NotZero(t, checked, "the scan found no source files, so it checked nothing")

	require.Equal(t, []string{"time.Now(", "time.Sleep("},
		touchesTheClock("func f() { _ = time.Now(); time.Sleep(time.Second) }"))
}
