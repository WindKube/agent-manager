// Package cmd is amctl's cobra tree: flag parsing and output, nothing else.
// Every verb delegates its work to a package under internal/.
package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/output"
)

// Stamped at build time with -ldflags -X, the same way the hub's
// internal/cli does it. See cli/Taskfile.yaml for the exact flags; CI runs
// `amctl version` against the built binary, so a broken stamp fails there
// rather than in someone's release notes.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Options holds every global flag and the output streams for one invocation.
// Constructed per NewRootCmd call, deliberately not package-level: a package
// variable would make the verbs untestable in parallel.
type Options struct {
	// Hub is --hub, empty meaning "not given"; resolving a stored default is
	// the caller's job, not here, since `amctl version` must work without one.
	Hub     string
	Output  string // raw --output; parsed by PersistentPreRunE
	Offline bool
	Verbose bool
	// AllowPlaintextHub is not registered under a literal: hub.New composes
	// the refusal naming this flag, so the two names must never drift apart.
	AllowPlaintextHub bool

	Outcome Code // consulted only when the verb returned no error; see ExitCode

	streams *output.Streams
	result  io.Writer
	diag    io.Writer
}

// Streams falls back to the human renderer, never nil, so a failure before a
// format is chosen can still be reported.
func (o *Options) Streams() *output.Streams {
	if o.streams == nil {
		o.streams = output.NewStreams(output.FormatHuman, o.result, o.diag)
		o.streams.SetVerbose(o.Verbose)
	}
	return o.streams
}

// Emit renders the verb's one result to the result stream.
func (o *Options) Emit(r output.Result) error {
	return o.Streams().Emit(r)
}

// NewRootCmd builds the command tree over the given result and diagnostic
// writers, and returns the Options its flags are bound to.
func NewRootCmd(result, diag io.Writer) (*cobra.Command, *Options) {
	opts := &Options{result: result, diag: diag}

	root := &cobra.Command{
		Use:   "amctl",
		Short: "Install and reconcile agent skills and plugins from an Agent Manager hub",
		Long: "amctl turns a hub's resolved lockfile into files on this machine, and removes\n" +
			"them again when the hub says so. The hub resolves; amctl applies.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// Version deliberately unset: cobra's --version shorthand -v collides
		// with --verbose; `amctl version` answers this instead.

		// Replaces cobra's legacyArgs so a mistyped verb is CodeRefused, not
		// an unmarked CodeFailure.
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return Refusef("unknown command %q for %q", args[0], cmd.CommandPath())
			}
			return nil
		},
		// Must exist for Args above to run at all: a non-runnable command
		// returns flag.ErrHelp before validating arguments.
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			format, err := output.ParseFormat(opts.Output)
			if err != nil {
				return Refusef("--output: %w", err) // flag name belongs in the message
			}
			opts.streams = output.NewStreams(format, result, diag)
			opts.streams.SetVerbose(opts.Verbose)
			cmd.SetOut(result)
			cmd.SetErr(diag)
			return nil
		},
	}

	root.SetOut(result)
	root.SetErr(diag)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return Refuse(err) })

	flags := root.PersistentFlags()
	flags.StringVar(&opts.Hub, "hub", "", "hub base URL")
	flags.StringVar(&opts.Output, "output", string(output.FormatHuman),
		fmt.Sprintf("output format: %s or %s", output.FormatHuman, output.FormatJSON))
	flags.BoolVar(&opts.Offline, "offline", false, "use only cached bundles; fail rather than reach the network")
	flags.BoolVarP(&opts.Verbose, "verbose", "v", false, "diagnostics on stderr")
	// Not `--insecure`: the flag name should say what it costs. Imported from
	// hub.PlaintextFlagName so its refusal can't name a flag this file doesn't register.
	flags.BoolVar(&opts.AllowPlaintextHub, hub.PlaintextFlagName, false,
		"accept an http:// hub — sends the bearer token over cleartext")

	root.AddCommand(
		newLoginCmd(opts),
		newLogoutCmd(opts),
		newSyncCmd(opts),
		newStatusCmd(opts),
		newVersionCmd(opts),
	)
	return root, opts
}

// Main writes nothing to os.Stdout/Stderr itself — the writers are
// arguments — so the whole CLI is exercisable from a test.
func Main(args []string, result, diag io.Writer) Code {
	root, opts := NewRootCmd(result, diag)
	root.SetArgs(args)

	err := root.Execute()
	if err != nil {
		// The only place an error is printed (SilenceErrors is on), and to the
		// diagnostic stream: on the result stream it would corrupt the JSON a script reads.
		opts.Streams().Errorf("%v", err)
	}
	return ExitCode(opts.Outcome, err)
}

func newVersionCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return opts.Emit(output.VersionResult{Version: Version, Commit: Commit, Date: Date})
		},
	}
}
