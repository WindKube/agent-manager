// Command amctl installs and reconciles agent skills and plugins from an Agent Manager hub.
package main

import (
	"os"

	"github.com/WindKube/agent-manager/cli/internal/cmd"
)

func main() {
	// The only os.Exit in the module; cmd.ExitCode owns the outcome-to-status mapping.
	os.Exit(int(cmd.Main(os.Args[1:], os.Stdout, os.Stderr)))
}
