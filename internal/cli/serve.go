package cli

import "github.com/spf13/cobra"

func newServeCmd() *cobra.Command {
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Run a serving role",
	}
	serve.AddCommand(newServeAPICmd(), newServeWebCmd())
	return serve
}

func newServeAPICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "api",
		Short: "REST API, OIDC, device flow and the outbox relay",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAPI(cmd.Context())
		},
	}
}

func newServeWebCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "web",
		Short: "Web UI (holds no datastore credential)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWeb(cmd.Context())
		},
	}
}
