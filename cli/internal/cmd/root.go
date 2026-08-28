// Package cmd is amctl's cobra tree: flag parsing and output, nothing else.
// Every verb delegates its work to a package under internal/, so a verb file
// stays readable and the logic stays testable without a command.
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
//
// It is constructed per NewRootCmd call and deliberately not package-level: a
// package variable makes the verbs untestable in parallel, cobra's test
// helpers have no way to reset one between runs, and the first test that runs
// two command trees at once starts failing for reasons that look like a race
// in the code under test.
type Options struct {
	// Hub is --hub. Empty means "not given on the command line"; resolving it
	// from the environment or from a stored default belongs to the code that
	// needs a hub, not here, because `amctl version` must work without one.
	Hub string
	// Output is the raw --output value. Parsed into an output.Format by
	// PersistentPreRunE so an unknown value is refused once, centrally.
	Output string
	// Offline is --offline: complete from the cache or fail naming what is
	// missing (FR-018). Never a silent degradation to a partial install.
	Offline bool
	// Verbose is -v: diagnostics to the diagnostic stream, never to the
	// result stream.
	Verbose bool
	// AllowPlaintextHub is --allow-plaintext-hub, FR-041's explicit opt-in for an
	// http:// hub. It is not registered under a literal here: hub.New composes the
	// refusal message that names the flag, so the two must be one string or the
	// error tells a user to pass a flag that does not exist.
	AllowPlaintextHub bool

	// Outcome is what the verb achieved. It is consulted only when the verb
	// returned no error — see ExitCode. A verb that modified the tree sets
	// CodeChanged; the zero value is the correct default for every other verb.
	Outcome Code

	streams *output.Streams
	result  io.Writer
	diag    io.Writer
}

// Streams returns the output streams for this invocation.
//
// If flag parsing failed before a format was chosen, this falls back to the
// human renderer over the same writers rather than returning nil: the one
// moment we most need to report something is the moment setup failed.
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
		// Root.Version is deliberately unset. Setting it makes cobra add
		// --version with -v as its shorthand, which would collide with
		// --verbose; `amctl version` is the subcommand that answers this, and
		// it renders through the same result seam as every other verb.

		// Replaces cobra's legacyArgs, whose "unknown command" error would
		// arrive unmarked and therefore exit CodeFailure. A mistyped verb is a
		// refusal the user can fix, and every mistyped-input path has to reach
		// the same code or the code stops meaning anything.
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return Refusef("unknown command %q for %q", args[0], cmd.CommandPath())
			}
			return nil
		},
		// RunE has to exist for Args above to run at all: cobra returns
		// flag.ErrHelp from a non-runnable command *before* it validates
		// arguments, which silently turned a mistyped verb into a help screen
		// and exit 0. With a RunE, `amctl` alone still prints help and
		// succeeds, and `amctl instal` reaches the validator.
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			format, err := output.ParseFormat(opts.Output)
			if err != nil {
				// A bad --output value is the user's to fix, and the flag name
				// belongs in the message because the value alone does not say
				// where it came from.
				return Refusef("--output: %w", err)
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
	// A malformed flag is always the user's to fix; without this it would
	// arrive unmarked and exit CodeFailure alongside the genuine bugs.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return Refuse(err) })

	flags := root.PersistentFlags()
	flags.StringVar(&opts.Hub, "hub", "", "hub base URL")
	flags.StringVar(&opts.Output, "output", string(output.FormatHuman),
		fmt.Sprintf("output format: %s or %s", output.FormatHuman, output.FormatJSON))
	flags.BoolVar(&opts.Offline, "offline", false, "use only cached bundles; fail rather than reach the network")
	flags.BoolVarP(&opts.Verbose, "verbose", "v", false, "diagnostics on stderr")
	// Deliberately verbose and deliberately not `--insecure`: this is the only way
	// to send a bearer token over cleartext, and the flag a person has to type
	// should say what it costs. hub.PlaintextFlagName is imported rather than
	// retyped so hub.New's refusal cannot name a flag this file does not register.
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

// Main runs the tree and returns the process exit status. It writes nothing to
// os.Stdout or os.Stderr itself — the writers are arguments — so the whole CLI
// is exercisable from a test.
func Main(args []string, result, diag io.Writer) Code {
	root, opts := NewRootCmd(result, diag)
	root.SetArgs(args)

	err := root.Execute()
	if err != nil {
		// SilenceErrors is on, so this is the only place an error is printed,
		// and it goes to the diagnostic stream: an error text on the result
		// stream would corrupt the JSON document a script is reading (FR-035).
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

// The two stubs below are replaced by internal/cmd/sync.go and status.go as
// each user story lands. Until then they exit 0 and say so on the diagnostic
// stream, so the command tree, the flags and the exit codes can be wired and
// tested ahead of the work they front. `login` and `logout` have landed: they
// are in login.go and logout.go.

func newSyncCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Apply a hub's resolved lockfile to this machine",
		Args:  cobra.NoArgs,
		RunE:  func(_ *cobra.Command, _ []string) error { return notYet(opts, "sync") },
	}
}

func newStatusCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report the hub, identity, profiles and any drift",
		Args:  cobra.NoArgs,
		RunE:  func(_ *cobra.Command, _ []string) error { return notYet(opts, "status") },
	}
}

// notYet keeps a stub's exit status at CodeNoChanges and its message off the
// result stream, so `--output json` still emits nothing rather than something
// unparseable.
func notYet(opts *Options, verb string) error {
	opts.Streams().Warnf("%s is not implemented yet", verb)
	opts.Outcome = CodeNoChanges
	return nil
}
