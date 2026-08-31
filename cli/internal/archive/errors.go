package archive

import (
	"errors"
	"fmt"
)

// The six failure classes a caller must be able to tell apart. They are separate
// sentinels rather than one ErrExtract because they mean different things to the
// person running amctl: a malformed archive or a busted cap is the publisher's
// problem, a refused member is a security refusal worth naming loudly, an unsafe
// destination means something is already wrong on this machine, a timeout may just
// be a slow link, and local I/O is a full disk.
var (
	ErrMalformed         = errors.New("malformed archive")
	ErrTooLarge          = errors.New("archive exceeds extraction limits")
	ErrRejectedMember    = errors.New("archive member rejected")
	ErrUnsafeDestination = errors.New("unsafe extraction destination")
	ErrTimeout           = errors.New("extraction exceeded its time budget")
	ErrIO                = errors.New("cannot write extracted file")
)

type Kind int

const (
	KindMalformed Kind = iota + 1
	KindTooLarge
	KindRejectedMember
	KindUnsafeDestination
	KindTimeout
	KindIO
)

func (k Kind) String() string {
	switch k {
	case KindMalformed:
		return "malformed"
	case KindTooLarge:
		return "too-large"
	case KindRejectedMember:
		return "rejected-member"
	case KindUnsafeDestination:
		return "unsafe-destination"
	case KindTimeout:
		return "timeout"
	case KindIO:
		return "io"
	default:
		return "unknown"
	}
}

func (k Kind) sentinel() error {
	switch k {
	case KindTooLarge:
		return ErrTooLarge
	case KindRejectedMember:
		return ErrRejectedMember
	case KindUnsafeDestination:
		return ErrUnsafeDestination
	case KindTimeout:
		return ErrTimeout
	case KindIO:
		return ErrIO
	case KindMalformed:
		return ErrMalformed
	default:
		return ErrMalformed
	}
}

// Reason names the exact rule that fired. It is a named type so that a test — or
// any caller — asserts the specific refusal rather than `err != nil`. That
// distinction is the whole value of this taxonomy: a symlink-escape test that
// passes because the total-size cap fired first has stopped testing symlinks, and
// nothing about it looks wrong.
type Reason string

// Reasons for KindTooLarge, one per cap.
const (
	CapCompressedSize   Reason = "compressed archive size"
	CapDecompressedSize Reason = "total decompressed size"
	CapCompressionRatio Reason = "compression ratio"
	CapEntryCount       Reason = "entry count"
	CapEntrySize        Reason = "single entry size"
	CapPathDepth        Reason = "path depth"
	CapPathLength       Reason = "path length"
)

// Reasons for KindRejectedMember, one per member kind or path shape refused
// outright.
const (
	RejectAbsolutePath      Reason = "absolute path"
	RejectTraversal         Reason = "parent directory traversal"
	RejectSymlink           Reason = "symlink member"
	RejectHardlink          Reason = "hardlink member"
	RejectDevice            Reason = "device node member"
	RejectFIFO              Reason = "fifo member"
	RejectMemberType        Reason = "unsupported member type"
	RejectPathChars         Reason = "unsafe characters in path"
	RejectEmptyPath         Reason = "empty path"
	RejectDuplicate         Reason = "duplicate path"
	RejectPluginAdoptingDir Reason = "subdirectory would make this a claude-code plugin"
)

// Reasons for KindUnsafeDestination. These are about the filesystem the CLI is
// writing to, not about the archive: something is already present where an
// extracted path has to go.
const (
	RejectDestSymlink      Reason = "existing destination path component is a symlink"
	RejectDestExists       Reason = "destination path already exists"
	RejectDestUnresolvable Reason = "destination path cannot be resolved inside the root"
)

// Reasons for KindIO.
const (
	IOMkdir Reason = "create directory"
	IOOpen  Reason = "create file"
	IOWrite Reason = "write file"
	IOSync  Reason = "fsync file"
)

// ReasonTimeBudget is the reason for KindTimeout; Error.Detail carries the budget.
const ReasonTimeBudget Reason = "wall clock budget"

// Error carries the class, the exact rule, and the offending member. Detail holds
// anything free-form (a limit, a duration) that would otherwise be smuggled into
// Reason and break equality comparison in tests.
type Error struct {
	Kind   Kind
	Reason Reason
	Path   string
	Detail string
	cause  error
}

func (e *Error) Error() string {
	msg := e.Kind.sentinel().Error()
	if e.Reason != "" {
		msg += ": " + string(e.Reason)
	}
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	if e.Path != "" {
		msg += fmt.Sprintf(" (member %q)", e.Path)
	}
	if e.cause != nil {
		msg += ": " + e.cause.Error()
	}
	return msg
}

// Unwrap exposes the class sentinel so errors.Is works, plus the underlying cause
// when there is one.
func (e *Error) Unwrap() []error {
	if e.cause == nil {
		return []error{e.Kind.sentinel()}
	}
	return []error{e.Kind.sentinel(), e.cause}
}

// ReasonOf returns the Reason of the first *Error in err's chain, or "" when there
// is none. Callers and tests use it to assert the specific rule that fired.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// PathOf returns the offending member path recorded on the first *Error in err's
// chain, or "".
func PathOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Path
	}
	return ""
}

func malformed(detail string, cause error) *Error {
	return &Error{Kind: KindMalformed, Detail: detail, cause: cause}
}

func tooLarge(capName Reason, member string) *Error {
	return &Error{Kind: KindTooLarge, Reason: capName, Path: member}
}

func rejected(reason Reason, member string) *Error {
	return &Error{Kind: KindRejectedMember, Reason: reason, Path: member}
}

func unsafeDest(reason Reason, member string, cause error) *Error {
	return &Error{Kind: KindUnsafeDestination, Reason: reason, Path: member, cause: cause}
}

func ioFailure(reason Reason, member string, cause error) *Error {
	return &Error{Kind: KindIO, Reason: reason, Path: member, cause: cause}
}
