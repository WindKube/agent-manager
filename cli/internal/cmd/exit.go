package cmd

import (
	"errors"
	"fmt"
)

// Code is a process exit status: four distinguishable outcomes, and there
// are no others. The numbers follow the convention every convergence tool
// in this space already established (terraform's -detailed-exitcode,
// puppet's --detailed-exitcodes): the steady state is 0, and "I changed
// something" is a distinct non-error code above the error codes rather
// than below them.
type Code int

const (
	// CodeNoChanges — the run succeeded and the tree was already correct.
	//
	// Distinguished by: a scheduled or CI invocation under `set -e`, which is
	// the overwhelming majority of runs of a converged machine. This is 0
	// because that caller must not abort on the common case.
	CodeNoChanges Code = 0

	// CodeFailure — an unexpected failure: a bug, an unreachable hub, a disk
	// error, anything this CLI did not anticipate.
	//
	// Distinguished by: everyone, and by nobody in particular — which is
	// exactly why it is 1. Any path that forgets to classify itself, including
	// a cobra parse error and a panic recovered at the top, lands here by
	// default. Failing closed into "unexpected" beats failing open into
	// "success".
	CodeFailure Code = 1

	// CodeChanged — the run succeeded and modified the tree: something was
	// added, upgraded, downgraded or removed.
	//
	// Distinguished by: a CI script that wants to know whether to notify, open
	// a PR or restart an agent. It must not be confused with a failure, hence a
	// dedicated code rather than reusing 1, and it is above the error codes so
	// that a script written as `amctl sync || handle_error` still treats it as
	// worth looking at instead of silently ignoring it.
	CodeChanged Code = 2

	// CodeRefused — the CLI refused, and the user can fix it: an unwritable
	// HOME, a plaintext hub URL without the flag, a conflicting managed
	// file without --force, a concurrent sync, an unknown --output value, a
	// missing token with no TTY.
	//
	// Distinguished by: a human reading the message, and by a wrapper script
	// deciding whether retrying could ever help. Retrying a refusal is
	// pointless until something changes; retrying a CodeFailure may work.
	CodeRefused Code = 3
)

// codeNames is the reverse mapping, and the only place a Code becomes a word.
// The exit-code test walks it, so a fifth code cannot be added without a name.
var codeNames = map[Code]string{
	CodeNoChanges: "no-changes",
	CodeFailure:   "failure",
	CodeChanged:   "changed",
	CodeRefused:   "refused",
}

// String implements fmt.Stringer.
func (c Code) String() string {
	if name, ok := codeNames[c]; ok {
		return name
	}
	return fmt.Sprintf("Code(%d)", int(c))
}

// refusal marks an error as one the user can fix, so ExitCode can map it to
// CodeRefused. It is a wrapper rather than a sentinel because the useful
// message is always the wrapped one.
type refusal struct{ err error }

func (r refusal) Error() string { return r.err.Error() }
func (r refusal) Unwrap() error { return r.err }

// Refuse marks err as a refusal the user can fix (CodeRefused). Anything not
// marked is an unexpected failure (CodeFailure), which is the safe default:
// forgetting to call Refuse over-reports severity, while the reverse would
// quietly tell a caller a bug was their own fault.
func Refuse(err error) error {
	if err == nil {
		return nil
	}
	return refusal{err: err}
}

// Refusef is Refuse over a formatted message.
func Refusef(format string, args ...any) error {
	return refusal{err: fmt.Errorf(format, args...)}
}

// IsRefusal reports whether err, or anything it wraps, was marked by Refuse.
func IsRefusal(err error) bool {
	var r refusal
	return errors.As(err, &r)
}

// ExitCode is the ONE place in this module where an outcome becomes a process
// exit status. Every verb reports through it — `outcome` is what the verb
// achieved, `err` is why it stopped — and main.go's os.Exit is the only os.Exit
// in the module (the forbidigo rule in .golangci.yml enforces that, so a bare
// os.Exit(1) elsewhere is a lint failure rather than a code review question).
//
// An error always wins over an outcome: a sync that installed four of twelve
// entries and then failed is not a success with changes, it is a failure. The
// four installed entries are reported in the result and the next run
// converges; see plan.md on the partially applied sync.
func ExitCode(outcome Code, err error) Code {
	if err != nil {
		if IsRefusal(err) {
			return CodeRefused
		}
		return CodeFailure
	}
	return outcome
}
