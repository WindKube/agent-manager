package cli

import "github.com/spf13/cobra"

func newWorkerCmd() *cobra.Command {
	worker := &cobra.Command{
		Use:   "worker",
		Short: "Run a background role",
	}
	worker.AddCommand(&cobra.Command{
		Use:   "run <name>",
		Short: "Run the named worker from the registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWorker(cmd.Context(), args[0])
		},
	})
	worker.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List registered workers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return listWorkers(cmd.OutOrStdout())
		},
	})
	return worker
}

func newMigrateCmd() *cobra.Command {
	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Schema migration helpers",
	}
	migrate.AddCommand(&cobra.Command{
		Use:   "queue",
		Short: "Apply River's own migrations to the queue database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrateQueue(cmd.Context())
		},
	})
	return migrate
}

func newSeedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "seed",
		Short: "Load the representative dataset",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSeed(cmd.Context())
		},
	}
}

func newHealthcheckCmd() *cobra.Command {
	var target string
	c := &cobra.Command{
		Use:   "healthcheck",
		Short: "Self-probe a serving role (usable by a shell-less container)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHealthcheck(cmd.Context(), target)
		},
	}
	c.Flags().StringVar(&target, "url", "http://127.0.0.1:8081/v1/health", "health endpoint to probe")
	return c
}
