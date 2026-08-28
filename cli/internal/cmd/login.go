package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"

	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/device"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/output"
)

// clientID is the OAuth client this CLI presents at /v1/device/authorize. It is
// the contract's own example value and it is a constant rather than a flag: the
// hub registers clients, so a client id the operator can pass is a client id
// that can only ever be wrong. internal/device deliberately exported no default
// for it, because which client this binary IS is the command layer's fact.
const clientID = "agent-manager-cli"

// loginDeps is everything login reaches outside its own process, gathered in one
// place so login_test.go can drive the real code paths against the fake hub.
//
// A struct rather than a package variable: two logins in one test binary must
// not share a clock, and a package-level hook is the thing that makes a suite
// order-dependent for reasons that look like a race in the code under test.
type loginDeps struct {
	// clock is the device flow's whole access to time. The production value is
	// device.System(); a test injects one whose Wait returns without sleeping,
	// which is what makes FR-002's "never faster than told" provable in
	// microseconds. The INTERVAL still comes off the wire either way — nothing
	// here tells the state machine how long to wait.
	clock device.Clock
	// httpClient is the transport for the hub. nil means net/http's default;
	// the fake hub over TLS hands a test a client that trusts its self-signed
	// certificate, and a test that built its own would fail for a reason that
	// has nothing to do with login.
	httpClient *http.Client
	// hostname supplies the machine name bound to the authorisation (FR-001).
	hostname func() (string, error)
	// backends overrides the credential store order. nil means the policy
	// order, credentials.AllowedBackends().
	backends []keyring.BackendType
	// lookupEnv reads the environment, for the AMCTL_TOKEN precedence warning.
	lookupEnv func(string) (string, bool)
}

func productionLoginDeps() loginDeps {
	return loginDeps{
		clock:     device.System(),
		hostname:  os.Hostname,
		lookupEnv: os.LookupEnv,
	}
}

// newLoginCmd builds `amctl login`.
//
// THE NO-TTY CONTRACT (FR-037), decided here because login is the only verb
// that talks to a human mid-operation and is therefore the one people assume is
// interactive.
//
// login RUNS with no TTY. It is FR-037's first clause and not its second: the
// device authorisation grant exists precisely so that the machine needing a
// credential never has to collect one. Nothing here reads stdin, nothing
// prompts, and nothing branches on whether a stream is a terminal — a verb that
// behaved differently under a pipe would make the CI path the untested one.
// TestLoginNeedsNoTerminal is the assertion, and
// TestNoVerbReachesForATerminalOrStandardInput is the mechanical gate that
// keeps it true for files written later.
//
// The one question login would otherwise have to ask is WHICH HUB, and with no
// TTY there is nobody to ask, so it refuses naming --hub (FR-037's second
// clause, exit CodeRefused). There is no environment variable for the hub and
// no stored default: inventing either here would be inventing contract, and a
// login that silently picked a hub is a credential written for a hub the
// operator did not name.
//
// What login deliberately does NOT do: open a browser. That is the interaction
// FR-037 is about — it needs a session and a display, it is unwanted on a
// server, and a --no-browser flag would only exist to switch off something that
// should not have been the default. amctl prints the URL and the code; opening
// them is the human's move, and the human may not even be at this machine.
func newLoginCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate this machine against a hub",
		Long: "Opens a device authorisation against the hub, prints a short code and the page\n" +
			"to type it into, and waits for a human to approve it. The token is stored in\n" +
			"this platform's credential store, per hub.\n\n" +
			"login never prompts and needs no terminal: the code and the URL are written to\n" +
			"stderr as they are learned, so `amctl --output json login` leaves stdout a\n" +
			"single parseable document. It does not open a browser.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLogin(cmd.Context(), opts, productionLoginDeps())
		},
	}
}

// runLogin is `login` with its outside world as an argument.
//
// The ORDER below is FR-039 and is the whole reason Prepare exists: the home
// directory and the hub URL are validated, and the credential store is opened
// AND CHECKED, before any packet leaves — so a machine that cannot store the
// token never sends a human to a browser to approve one. It costs a 0700
// directory and one Lstat on a login that then fails, and buys the FR-003/FR-004
// refusals arriving before the ten-minute authorisation window rather than after
// it.
//
// Opening the store is NOT enough on its own, which is the mistake this comment
// used to describe as fixed: credentials.Open walks backends and warns, and
// touches no item, so the mode gate only ran inside Save — after the code had
// been shown and the approval spent. store.Check is the pre-flight, and
// Store.Check's own comment carries the measurement.
func runLogin(ctx context.Context, opts *Options, deps loginDeps) error {
	s := opts.Streams()

	host, err := machineHostname(deps.hostname)
	if err != nil {
		return err
	}

	return Prepare(opts.Hub, func(home Home, target Hub) error {
		client, err := hub.New(hub.Config{
			URL: target.URL,
			// No token: /v1/device/authorize and /v1/device/token are the two
			// unauthenticated endpoints in the contract, and login is how a
			// machine with no credential gets one.
			AllowPlaintext: opts.AllowPlaintextHub,
			HTTPClient:     deps.httpClient,
			UserAgent:      userAgent(),
		})
		if err != nil {
			// hub.ErrInsecureHub and hub.ErrHubURL are both the user's to fix,
			// and hub.New's message already names --allow-plaintext-hub
			// (FR-041). Refuse marks it CodeRefused; unmarked it would exit 1
			// alongside the genuine bugs.
			return Refuse(err)
		}
		if client.Insecure() {
			s.Warnf("%s is plaintext: the token will cross the network in the clear, and so will every request that presents it", target.URL)
		}

		store, err := openStore(home, s, deps.backends)
		if err != nil {
			return err
		}
		if err = store.Check(target.URL); err != nil {
			// FR-004 before the device flow, not after it. Save runs the same
			// check as a post-condition and must keep doing so — the file could
			// change underneath a long login — but by then a human has approved
			// a grant that cannot be stored.
			return storeFailure(err)
		}
		if token, ok := lookupEnv(deps.lookupEnv)(credentials.TokenEnvVar); ok && token != "" {
			// Not a refusal: storing a credential is still the right outcome and
			// the token in the environment is still what every other verb will
			// use (FR-005). Saying so is the difference between a user believing
			// this login took effect and knowing it did not.
			s.Warnf("%s is set, so every other command will use that token in preference to the credential this login stores",
				credentials.TokenEnvVar)
		}

		flow, err := device.Begin(ctx, hubTransport{h: client}, deps.clock, device.AuthorizeRequest{
			ClientID: clientID,
			// FR-001: the hub shows this to the approving human, so approval is
			// an informed act rather than a click on an anonymous request.
			Host: host,
			// Scope is deliberately EMPTY. The contract says an omitted scope
			// means the client's default, and the hub is the authority on what
			// this client may do (FR-009). A scope list hardcoded here is a
			// second opinion that starts wrong the day the hub adds a scope.
		})
		if err != nil {
			return err
		}
		showAuthorization(s, flow)

		tok, err := flow.Wait(ctx)
		if err != nil {
			return loginFailure(err)
		}

		// int64(Seconds()) loses nothing: `expires_in` is an integer number of
		// seconds on the wire, so the Duration device built from it is whole.
		// The lifetime has to be carried here at all because hub tokens are
		// OPAQUE — base64url of 32 random bytes, no claims — so `expires_in` is
		// the only statement of it that will ever exist. Nothing may parse the
		// token; there is nothing in it to parse.
		cred := credentials.Issued(target.URL, tok.AccessToken(), int64(tok.ExpiresIn.Seconds()), deps.clock.Now())

		// IDENTITY is the machine, not a person, and that is a limitation
		// rather than a choice. None of the six frozen endpoints returns one:
		// the token response carries access_token, token_type, expires_in and
		// an optional refresh_token, there is no whoami operation, and
		// /v1/profiles describes profiles rather than the caller. So the
		// honest answer to "who am I now" is the thing this login actually
		// established — this host, bound to the grant the human approved.
		// Inventing a person here, or leaving it empty so the renderer says
		// "as ", would both be worse than saying what is true.
		cred.Identity = host
		if err := store.Save(cred); err != nil {
			return storeFailure(err)
		}

		// Emit AFTER the token is durably stored. A result claiming a login
		// that then failed to persist is the one ordering a script cannot
		// recover from.
		result := output.LoginResult{Hub: target.URL, Identity: host, Store: store.Location()}
		if !cred.ExpiresAt.IsZero() {
			expires := cred.ExpiresAt
			result.Expires = &expires
		}
		return opts.Emit(result)
	})
}

// showAuthorization writes the user code and the verification URL for a human
// to act on. It is the one place in amctl where a credential is deliberately
// written to a stream, so the reasoning is here in full.
//
// WHICH STREAM, AND WHY IT IS NOT THE RESULT STREAM.
//
// The diagnostic stream, in BOTH output formats, unconditionally.
//
//   - FR-035 requires `--output json` to leave stdout one parseable document.
//     A code printed into the middle of that document breaks every scripted
//     caller, and there is no way to defer it: the code is only useful BEFORE
//     the result exists, because by the time login has a result the code has
//     already been redeemed. So under json it cannot be on stdout.
//   - It must not be on stdout under `human` either, even though it could be.
//     A destination that depends on --output means a script that switches
//     formats for readability suddenly finds prose on the stream it parses, and
//     it means the two formats have different security properties. One
//     destination, always.
//   - "Invisible to someone piping stdout to a file" is the objection, and it
//     is backwards: stderr is precisely the stream that stays on the terminal
//     when stdout is redirected, which is where the human doing the approving
//     is looking. `2>/dev/null` hides it, and a user who discarded diagnostics
//     asked for that.
//   - FR-007 permits exactly this. The user code may not reach a LOG, a REPORT
//     or an ERROR: this is none of the three. It is one live write to the
//     interactive stream by the verb whose entire job is to show it — the rule
//     internal/leakscan states and enforces. That is also why it does not go
//     through Warnf (it is not a warning and must not be prefixed as one) or
//     Debugf (which is dropped without -v, and a login whose code appears only
//     under -v cannot be completed).
//
// One Write for the whole block, so a concurrent warning cannot interleave into
// the middle of the code a human is reading.
//
// Note for whoever next greps this file: verification_uri_complete embeds the
// user code as a `?user_code=` query parameter, which is the exact shape
// internal/leakscan's credentialAssignment pattern hunts for. That is correct
// and it is why no test may echo this text into its own output — see
// login_test.go's note on asserting without printing the haystack.
func showAuthorization(s *output.Streams, f *device.Flow) {
	w := s.Diag
	if w == nil {
		// Nowhere to show it. Nothing to do but let the flow run: the poll may
		// still succeed if a human learns the code by other means, and there is
		// no second stream to fall back to that would not violate FR-035.
		return
	}
	msg := fmt.Sprintf("\nTo authorise this machine, open\n\n    %s\n\nand enter\n\n    %s\n\n",
		f.VerificationURI(), f.UserCode())
	if complete := f.VerificationURIComplete(); complete != "" {
		// The same page with the code already filled in — what a terminal makes
		// clickable and what a QR code encodes. The code is printed above as
		// well, because a URL a terminal did not linkify is useless on its own.
		msg += fmt.Sprintf("or open this, which has the code filled in:\n\n    %s\n\n", complete)
	}
	msg += fmt.Sprintf("Waiting for approval. This expires at %s.\n",
		f.ExpiresAt().Format(time.RFC3339))
	// A failed write to the diagnostic stream is swallowed for the same reason
	// output.Streams swallows one: there is nowhere left to report it.
	_, _ = io.WriteString(w, msg)
}

// machineHostname reads the name the authorisation is bound to (FR-001).
//
// A failure is refused rather than defaulted. The hostname is what the
// approving human sees, so "unknown" would turn an informed approval into a
// blind one — the one thing FR-001 exists to prevent. There is deliberately no
// --host flag: a flag that lets the caller choose what the approver is told is
// a flag for lying to the approver.
func machineHostname(fn func() (string, error)) (string, error) {
	if fn == nil {
		return "", errors.New("internal: login has no way to read the hostname")
	}
	host, err := fn()
	if err != nil {
		return "", Refusef("cannot read this machine's hostname, which the hub shows to whoever approves this login: %w", err)
	}
	if host = strings.TrimSpace(host); host == "" {
		return "", Refusef("this machine has no hostname, and the hub shows it to whoever approves this login; set the hostname and try again")
	}
	return host, nil
}

// openStore opens the credential store, mapping the one failure a user can act
// on to CodeRefused.
//
// ONE, not two: credentials.Open never returns ErrFileMode. It creates the
// directory, walks the backends and warns, and touches no item, so there is no
// mode to check yet — a `case errors.Is(err, credentials.ErrFileMode)` here is
// dead code that reads like coverage of FR-004 and is not. The mode gate is
// store.Check, called by runLogin before the device flow and by Save after it.
func openStore(home Home, s *output.Streams, backends []keyring.BackendType) (*credentials.Store, error) {
	store, err := credentials.Open(credentials.Options{
		StateRoot: home.Root,
		// FR-003's "reporting the fallback on stderr, never silently". Passing
		// nil here would drop the warning, which is why it is passed at every
		// production call site rather than defaulted inside the package.
		Warnf:    s.Warnf,
		Backends: backends,
	})
	switch {
	case errors.Is(err, credentials.ErrNoStore):
		// "No backend would open" is fixable where the user is standing and the
		// message already says how.
		return nil, Refuse(err)
	case err != nil:
		return nil, err
	}
	return store, nil
}

// storeFailure maps a credential-store failure to an exit code. It serves both
// the pre-flight and the post-token save, so the wording says only that the
// credential could not be stored — a sentence about a token that has just been
// issued would be a lie on the pre-flight path, which runs before there is one.
func storeFailure(err error) error {
	if errors.Is(err, credentials.ErrFileMode) {
		return Refuse(err)
	}
	return fmt.Errorf("the credential could not be stored: %w", err)
}

// loginFailure turns the end of a device flow into the sentence a user reads
// and the exit code a script switches on.
//
// The three device sentinels are refusals the user can fix, so they become
// CodeRefused with an instruction. Everything else — a transport failure, a hub
// that is not a hub — is returned UNCHANGED, deliberately: internal/hub has
// already classified it into FR-040's unreachable / unauthorised / forbidden /
// not-found, and rewriting the message here would flatten exactly the
// distinction FR-040 asks for. Note also what none of these can contain: the
// device code and the user code never appear in a device error (FR-007), so
// there is nothing to redact on the way out.
//
// CANCELLATION IS DECIDED FIRST, AND DROPS THE CHAIN IT ARRIVED IN. That is the
// one place this function deliberately throws information away, so here is why.
// A context cancelled while a poll was in flight comes back through
// internal/hub's classifyTransport, which classifies a cancelled request as
// ClassUnreachable — documented and correct for that package, since nothing
// answered. Wrapping that chain produced "login was interrupted before it was
// approved: … hub unreachable at https://…: context canceled", and any FR-040
// consumer switching on hub.ClassOf got "unreachable" for a hub that was
// answering perfectly. So the sentinel is wrapped rather than the chain:
// errors.Is(err, context.Canceled) still holds, the exit code is still 1 rather
// than 2, and no hub diagnosis rides along. What is lost is which endpoint was
// in flight, which is worth nothing to someone who just pressed Ctrl-C.
//
// Note the latency on this: no verb installs a signal handler — Main calls
// root.Execute(), so cmd.Context() is context.Background() and SIGINT kills the
// process outright — so today this path is reached only by a caller that passes
// its own cancellable context, which in practice means a test. It is kept, and
// kept correct, because it becomes live the day someone wires
// signal.NotifyContext, and a wrong diagnosis is cheaper to fix now than then.
func loginFailure(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("login was interrupted before it was approved: %w", context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("login ran out of time before it was approved: %w", context.DeadlineExceeded)
	case errors.Is(err, device.ErrDenied):
		return Refusef("the login was not approved: %w", err)
	case errors.Is(err, device.ErrExpired):
		return Refusef("%w; run `amctl login` again and approve it inside the window", err)
	case errors.Is(err, device.ErrInvalidGrant):
		return Refusef("%w; run `amctl login` again to open a fresh authorisation", err)
	default:
		return err
	}
}

func userAgent() string { return "amctl/" + Version }

func lookupEnv(fn func(string) (string, bool)) func(string) (string, bool) {
	if fn == nil {
		return os.LookupEnv
	}
	return fn
}

// hubTransport adapts *hub.Hub to device.Transport.
//
// This is the ~25 lines internal/device's package comment promises: that
// package refuses to import internal/hub so its state machine can be tested
// with no HTTP in it, and this is the seam that costs. It translates and judges
// nothing.
type hubTransport struct{ h *hub.Hub }

func (t hubTransport) Authorize(ctx context.Context, req device.AuthorizeRequest) (device.Authorization, error) {
	var scope *string
	if req.Scope != "" {
		scope = &req.Scope
	}
	a, err := t.h.DeviceAuthorize(ctx, hub.DeviceAuthorizeRequest{
		ClientId: req.ClientID, Host: req.Host, Scope: scope,
	})
	if err != nil {
		return device.Authorization{}, err
	}
	complete := ""
	if a.VerificationUriComplete != nil {
		complete = *a.VerificationUriComplete
	}
	expiresIn, err := wireSeconds("expires_in", a.ExpiresIn)
	if err != nil {
		return device.Authorization{}, err
	}
	interval, err := wireSeconds("interval", a.Interval)
	if err != nil {
		return device.Authorization{}, err
	}
	return device.Authorization{
		DeviceCode: a.DeviceCode, UserCode: a.UserCode,
		VerificationURI: a.VerificationUri, VerificationURIComplete: complete,
		ExpiresIn: expiresIn,
		Interval:  interval,
	}, nil
}

// wireSeconds converts an `expires_in` or `interval` field — an unbounded int64
// number of seconds on the wire — into a time.Duration, or refuses it.
//
// The guard is not theoretical and the multiplication is not safe. time.Duration
// is int64 NANOSECONDS, so `seconds * time.Second` wraps silently above about
// 9.22e9 seconds, and a wrapped value can land anywhere — including on a small
// POSITIVE duration that every downstream check accepts. Measured end to end
// against a hub answering interval 18446744074: the adapter produced 290.448ms,
// device.normaliseInterval had nothing to object to (it catches zero and
// negative, which is all a wrap CAN be caught as), and the client made 18 HTTP
// polls inside a 5-second window against a hub that had asked for one poll every
// 584 years. That is FR-002 broken silently, by an unconditional MUST, in the
// adapter — upstream of the state machine whose own never-polls-faster-than-told
// assertion would otherwise have caught it.
//
// It REFUSES rather than clamping, and the bound is representability rather than
// a policy about plausible seconds. Clamping would hand the state machine a
// number the hub never sent, and this layer translates: judging what an interval
// SHOULD be is internal/device's job, which is why an interval at or beyond the
// code's lifetime is refused there and not here. Negative values are bounded
// too, and not left to device's own negative handling, because the wrap is
// symmetric: -9223372037 seconds becomes a POSITIVE 292 years.
//
// The error wraps device.ErrProtocol, so it reads and classifies as what it is —
// a hub sending numbers no client can use — and login reports it unchanged.
func wireSeconds(field string, seconds int64) (time.Duration, error) {
	const maxSeconds = int64(math.MaxInt64 / time.Second)
	if seconds > maxSeconds || seconds < -maxSeconds {
		return 0, fmt.Errorf("%w: the hub's %s is %d seconds, which is beyond anything this client can measure",
			device.ErrProtocol, field, seconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

func (t hubTransport) Poll(ctx context.Context, req device.PollRequest) (*device.Issued, device.ErrorCode, error) {
	tok, err := t.h.DeviceToken(ctx, hub.DeviceTokenRequest{
		ClientId: req.ClientID, DeviceCode: req.DeviceCode,
		GrantType: hub.UrnIetfParamsOauthGrantTypeDeviceCode,
	})
	// RFC 8628's 400 envelope is the protocol, not a failure of it. Which codes
	// are terminal is internal/device's decision — do not classify here.
	var flow *hub.DeviceFlowError
	if errors.As(err, &flow) {
		return nil, device.ErrorCode(flow.Code), nil
	}
	if err != nil {
		return nil, "", err
	}
	refresh := ""
	if tok.RefreshToken != nil {
		refresh = *tok.RefreshToken
	}
	// The token's own lifetime goes through the same guard, for a reason worth
	// naming: an `expires_in` that wrapped to 290ms becomes, after login's
	// int64(Seconds()), a lifetime of ZERO, and credentials.Issued reads zero as
	// "the issuer named no lifetime" — a credential that never expires. Failing
	// closed on the hub's number is better than storing a token amctl will
	// present forever.
	expiresIn, err := wireSeconds("expires_in", tok.ExpiresIn)
	if err != nil {
		return nil, "", err
	}
	return &device.Issued{
		AccessToken: tok.AccessToken, TokenType: string(tok.TokenType),
		ExpiresIn: expiresIn, RefreshToken: refresh,
	}, "", nil
}
