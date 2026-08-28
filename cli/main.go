// Command amctl installs and reconciles agent skills and plugins from an Agent
// Manager hub. Wiring only: everything is in internal/cmd and below.
package main

import (
	"os"

	"github.com/WindKube/agent-manager/cli/internal/cmd"
)

func main() {
	// The only os.Exit in the module, and the only place os.Stdout and
	// os.Stderr are named. cmd.ExitCode owns the mapping from an outcome to a
	// status; see internal/cmd/exit.go.
	os.Exit(int(cmd.Main(os.Args[1:], os.Stdout, os.Stderr)))
}
