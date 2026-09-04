package cmd

import (
	"errors"
	"os"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"

	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/output"
)

// logoutDeps is logout's outside world. See loginDeps for why it is a struct.
type logoutDeps struct {
	backends  []keyring.BackendType
	lookupEnv func(string) (string, bool)
}

func productionLogoutDeps() logoutDeps {
	return logoutDeps{lookupEnv: os.LookupEnv}
}

// newLogoutCmd builds `amctl logout`.
//
// What logout does not do, which is most of what there is to say about it:
//
//   - It touches nothing installed. It removes one credential and returns.
//     It does not read the installation record, does not walk a target
//     directory and does not remove a package: a credential is how amctl
//     reaches the hub, and forgetting it is not a statement about the bytes
//     already on disk. Somebody logging out to switch hubs would otherwise
//     find their skills deleted. `amctl sync` is what removes packages.
//   - It makes no network request, and constructs no hub client. That is
//     not an optimisation. hub.New refuses an http:// URL without
//     --allow-plaintext-hub, so building one here would mean a credential
//     stored for a plaintext hub could not be deleted without re-typing
//     the flag that permitted it, leaving the token on disk. It also means
//     logout works with the hub unreachable, which is when people reach
//     for it.
//   - It does not remove the ~/.agent-manager/credentials directory, or
//     the per-hub state directory. Another hub's credential lives in the
//     first and the installation record lives in the second.
//   - It is idempotent. Logging out when not logged in is success with a
//     message on the result stream and exit 0, because `logout` in a
//     provisioning script that may or may not have logged in must not
//     fail. The `removed` field is how a script tells the two apart
//     without parsing prose.
func newLogoutCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove this machine's credential for a hub",
		Long: "Removes the stored credential for one hub and nothing else: no installed\n" +
			"package is touched, and no other hub's credential is affected.\n\n" +
			"Logging out when there is nothing stored succeeds and says so.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runLogout(opts, productionLogoutDeps())
		},
	}
}

// runLogout is `logout` with its outside world as an argument.
//
// It goes through Prepare even though it dials nothing: Prepare is what
// validates the home directory before the hub URL, and the credential key
// is Hub.URL — the canonical form. login stores under the same canonical
// string, so `logout --hub HUB.Example.com.` removes the credential
// `login --hub https://hub.example.com/` wrote; a second opinion on
// canonicalisation anywhere in this path would produce a logout that
// silently removes nothing and reports success.
func runLogout(opts *Options, deps logoutDeps) error {
	s := opts.Streams()

	return Prepare(opts.Hub, func(home Home, target Hub) error {
		store, err := openStore(home, s, deps.backends)
		if err != nil {
			return err
		}

		removed, err := store.Delete(target.URL)
		if err != nil {
			if errors.Is(err, credentials.ErrFileMode) {
				return Refuse(err)
			}
			return err
		}

		if token, ok := lookupEnv(deps.lookupEnv)(credentials.TokenEnvVar); ok && token != "" {
			// The environment token outranks the store, so removing the
			// stored credential does not log this shell out. A logout that
			// let someone believe otherwise is worse than no logout.
			s.Warnf("%s is still set, so commands in this environment remain authenticated; unset it to finish logging out",
				credentials.TokenEnvVar)
		}

		return opts.Emit(output.LogoutResult{Hub: target.URL, Store: store.Location(), Removed: removed})
	})
}
