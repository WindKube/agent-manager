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

// newLogoutCmd builds `amctl logout`. It only removes one hub's stored
// credential: no installed package, no other hub's credential, and no
// network request (so it still works with the hub unreachable, and can
// delete a plaintext-hub credential without re-passing --allow-plaintext-hub).
// It is idempotent; `removed` in the result tells a script whether there was
// anything to remove.
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

// runLogout goes through Prepare (though it dials nothing) so its credential
// key matches login's canonicalised Hub.URL exactly.
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
			// The env token outranks the store, so this shell isn't logged out.
			s.Warnf("%s is still set, so commands in this environment remain authenticated; unset it to finish logging out",
				credentials.TokenEnvVar)
		}

		return opts.Emit(output.LogoutResult{Hub: target.URL, Store: store.Location(), Removed: removed})
	})
}
