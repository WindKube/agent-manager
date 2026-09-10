// Package cli is the cobra tree: every deployable unit is a subcommand of
// this one binary, never a separate build.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is stamped at build time with -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func Execute() error {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return err
	}
	return nil
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "agent-manager",
		Short:         "Self-hosted registry for AI agent plugins and skills",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newServeCmd(),
		newWorkerCmd(),
		newMigrateCmd(),
		newSeedCmd(),
		newHealthcheckCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "agent-manager %s (%s, %s)\n", Version, Commit, Date)
			return err
		},
	}
}
