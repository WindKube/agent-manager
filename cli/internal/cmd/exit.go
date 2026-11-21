package cmd

import (
	"errors"
	"fmt"
)

// Code is a process exit status, following terraform's -detailed-exitcode
// convention: steady state is 0 and "changed" is a distinct non-error code.
type Code int

const (
	CodeNoChanges Code = 0 // must be 0 so a scheduled `set -e` run doesn't abort
	CodeFailure   Code = 1 // default for anything that forgets to classify itself
	CodeChanged   Code = 2 // distinct from 1 so `sync || handle_error` still fires
	CodeRefused   Code = 3 // the user can fix it; retrying alone cannot
)

// codeNames is walked by the exit-code test, so a new code can't lack a name.
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

type refusal struct{ err error }

func (r refusal) Error() string { return r.err.Error() }
func (r refusal) Unwrap() error { return r.err }

// Refuse marks err as user-fixable (CodeRefused); unmarked defaults to
// CodeFailure, the safer direction to be wrong in.
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

// ExitCode maps a verb's outcome and error to a Code; an error always wins
// over outcome.
func ExitCode(outcome Code, err error) Code {
	if err != nil {
		if IsRefusal(err) {
			return CodeRefused
		}
		return CodeFailure
	}
	return outcome
}
