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

// clientID is a constant, not a flag: the hub registers clients, so an
// operator-supplied id could only ever be wrong.
const clientID = "agent-manager-cli"

// loginDeps is everything login reaches outside its own process, as a struct
// (not package vars) so two logins in one test binary don't share a clock.
type loginDeps struct {
	// clock is production device.System(); a test injects a non-sleeping one.
	clock device.Clock
	// httpClient nil means net/http's default; the fake hub hands tests one
	// that trusts its self-signed cert.
	httpClient *http.Client
	hostname   func() (string, error)
	// backends nil means credentials.AllowedBackends()'s policy order.
	backends  []keyring.BackendType
	lookupEnv func(string) (string, bool)
}

func productionLoginDeps() loginDeps {
	return loginDeps{
		clock:     device.System(),
		hostname:  os.Hostname,
		lookupEnv: os.LookupEnv,
	}
}

// newLoginCmd builds `amctl login`. It runs with no TTY — nothing reads
// stdin or prompts — since the device grant exists so a machine never has
// to collect a credential interactively. With no TTY to ask, a missing
// --hub is refused rather than defaulted from env or a stored value, and
// login never opens a browser: it only prints the URL and code.
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

// runLogin validates home, hub and the credential store's writability before
// any packet leaves, so a machine that can't store the token never sends a
// human to approve one — credentials.Open alone doesn't check that; only
// store.Check (called here as pre-flight) does.
func runLogin(ctx context.Context, opts *Options, deps loginDeps) error {
	s := opts.Streams()

	host, err := machineHostname(deps.hostname)
	if err != nil {
		return err
	}

	return Prepare(opts.Hub, func(home Home, target Hub) error {
		client, err := hub.New(hub.Config{
			URL:            target.URL, // no token: the device endpoints are unauthenticated
			AllowPlaintext: opts.AllowPlaintextHub,
			HTTPClient:     deps.httpClient,
			UserAgent:      userAgent(),
		})
		if err != nil {
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
			return storeFailure(err)
		}
		if token, ok := lookupEnv(deps.lookupEnv)(credentials.TokenEnvVar); ok && token != "" {
			// Not a refusal: the credential is still stored correctly, but the
			// env token will still outrank it for every other verb.
			s.Warnf("%s is set, so every other command will use that token in preference to the credential this login stores",
				credentials.TokenEnvVar)
		}

		flow, err := device.Begin(ctx, hubTransport{h: client}, deps.clock, device.AuthorizeRequest{
			ClientID: clientID,
			Host:     host, // shown to the approving human
			// Scope deliberately empty: an omitted scope means the hub's
			// default, and a hardcoded list here would be a second opinion.
		})
		if err != nil {
			return err
		}
		showAuthorization(s, flow)

		tok, err := flow.Wait(ctx)
		if err != nil {
			return loginFailure(err)
		}

		// hub tokens are opaque, so expires_in is the only statement of lifetime.
		cred := credentials.Issued(target.URL, tok.AccessToken(), int64(tok.ExpiresIn.Seconds()), deps.clock.Now())

		cred.Identity = host // the machine, not a person: no endpoint names one
		if err := store.Save(cred); err != nil {
			return storeFailure(err)
		}

		result := output.LoginResult{Hub: target.URL, Identity: host, Store: store.Location()} // after durable storage
		if !cred.ExpiresAt.IsZero() {
			expires := cred.ExpiresAt
			result.Expires = &expires
		}
		return opts.Emit(result)
	})
}

// showAuthorization writes the user code and verification URL to the
// diagnostic stream, unconditionally, in both output formats — never stdout,
// since `--output json` must leave stdout one parseable document and stderr
// is what stays visible when stdout is redirected. This is the one place a
// credential-shaped value is deliberately written to a stream; the URL's
// `?user_code=` is exactly what internal/leakscan's pattern hunts for, so no
// test may echo this text into its own output.
func showAuthorization(s *output.Streams, f *device.Flow) {
	w := s.Diag
	if w == nil {
		return // no second stream to fall back to without breaking the contract above
	}
	msg := fmt.Sprintf("\nTo authorise this machine, open\n\n    %s\n\nand enter\n\n    %s\n\n",
		f.VerificationURI(), f.UserCode())
	if complete := f.VerificationURIComplete(); complete != "" {
		msg += fmt.Sprintf("or open this, which has the code filled in:\n\n    %s\n\n", complete)
	}
	msg += fmt.Sprintf("Waiting for approval. This expires at %s.\n",
		f.ExpiresAt().Format(time.RFC3339))
	_, _ = io.WriteString(w, msg) // a failed write here has nowhere left to report to
}

// machineHostname refuses rather than defaults to "unknown", since the
// approving human sees this name; there's deliberately no --host override.
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

// openStore: credentials.Open never returns ErrFileMode (store.Check is the
// mode gate), so only ErrNoStore maps to CodeRefused here.
func openStore(home Home, s *output.Streams, backends []keyring.BackendType) (*credentials.Store, error) {
	store, err := credentials.Open(credentials.Options{
		StateRoot: home.Root,
		Warnf:     s.Warnf, // reports a backend fallback on stderr, never silently
		Backends:  backends,
	})
	switch {
	case errors.Is(err, credentials.ErrNoStore):
		return nil, Refuse(err)
	case err != nil:
		return nil, err
	}
	return store, nil
}

// storeFailure serves both pre-flight and post-save, so it says only that
// the credential couldn't be stored — pre-flight runs before a token exists.
func storeFailure(err error) error {
	if errors.Is(err, credentials.ErrFileMode) {
		return Refuse(err)
	}
	return fmt.Errorf("the credential could not be stored: %w", err)
}

// loginFailure maps a device-flow end into a message and exit code. The
// three device sentinels become CodeRefused; everything else is returned
// unchanged since internal/hub already classified it (unreachable /
// unauthorised / forbidden / not-found) and rewriting would flatten that.
// Cancellation is checked first and wraps only the sentinel, not the chain:
// a cancelled poll otherwise surfaces as "hub unreachable" for a hub that
// was answering fine — losing which endpoint was in flight, which a Ctrl-C'd
// user doesn't need anyway.
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

// hubTransport adapts *hub.Hub to device.Transport; translates and judges nothing.
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

// wireSeconds converts an unbounded wire `seconds` field to a time.Duration,
// refusing rather than clamping: `seconds * time.Second` wraps silently
// above ~9.22e9s, and a wrapped interval (e.g. 18446744074 -> 290ms) would
// pass device's zero/negative check and silently break "never polls faster
// than told". Judging a plausible interval is internal/device's job, not
// this translation layer's, so this only guards representability.
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
	// RFC 8628's 400 envelope is the protocol, not a failure; classifying
	// which codes are terminal is internal/device's job, not this one's.
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
	// Same guard here: a wrapped expires_in rounds to a lifetime of zero,
	// which credentials.Issued reads as "never expires" — worse than refusing.
	expiresIn, err := wireSeconds("expires_in", tok.ExpiresIn)
	if err != nil {
		return nil, "", err
	}
	return &device.Issued{
		AccessToken: tok.AccessToken, TokenType: string(tok.TokenType),
		ExpiresIn: expiresIn, RefreshToken: refresh,
	}, "", nil
}
