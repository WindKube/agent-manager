package archive

import (
	"errors"
	"fmt"

	"github.com/WindKube/agent-manager/cli/archiveguard"
)

// The failure classes a caller must tell apart: a publisher problem, a security
// refusal, a machine that is already wrong, a slow link, or a full disk.
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

// Reason names the exact rule that fired, so a test asserts the specific refusal
// rather than err != nil.
type Reason string

// Reasons for KindTooLarge, one per cap.
const (
	CapCompressedSize   = Reason(archiveguard.CapCompressedSize)
	CapDecompressedSize = Reason(archiveguard.CapDecompressedSize)
	CapCompressionRatio = Reason(archiveguard.CapCompressionRatio)
	CapEntryCount       = Reason(archiveguard.CapEntryCount)
	CapEntrySize        = Reason(archiveguard.CapEntrySize)
	CapPathDepth        = Reason(archiveguard.CapPathDepth)
	CapPathLength       = Reason(archiveguard.CapPathLength)
)

// Reasons for KindRejectedMember. The member-kind ones keep their " member"
// suffix, which differs from archiveguard's wording; see reasonFor.
const (
	RejectAbsolutePath      Reason = Reason(archiveguard.RejectAbsolutePath)
	RejectTraversal         Reason = Reason(archiveguard.RejectTraversal)
	RejectSymlink           Reason = "symlink member"
	RejectHardlink          Reason = "hardlink member"
	RejectDevice            Reason = "device node member"
	RejectFIFO              Reason = "fifo member"
	RejectMemberType        Reason = Reason(archiveguard.RejectMemberType)
	RejectPathChars         Reason = Reason(archiveguard.RejectPathChars)
	RejectEmptyPath         Reason = Reason(archiveguard.RejectEmptyPath)
	RejectDuplicate         Reason = "duplicate path"
	RejectPluginAdoptingDir Reason = "subdirectory would make this a claude-code plugin"
)

// Reasons for KindUnsafeDestination: something is already present where an extracted path has to go.
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
const ReasonTimeBudget = Reason(archiveguard.ReasonTimeBudget)

// Error carries the class, the exact rule and the offending member. Detail holds
// free-form text so Reason stays comparable.
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

func (e *Error) Unwrap() []error {
	if e.cause == nil {
		return []error{e.Kind.sentinel()}
	}
	return []error{e.Kind.sentinel(), e.cause}
}

// ReasonOf returns the Reason of the first *Error in err's chain, or "" when there is none.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// PathOf returns the offending member path of the first *Error in err's chain, or "".
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

// fromGuard translates an archiveguard.Violation into this package's Error and
// passes anything else through.
func fromGuard(err error) error {
	var v *archiveguard.Violation
	if !errors.As(err, &v) {
		return err
	}
	switch v.Kind {
	case archiveguard.KindTimeout:
		return &Error{Kind: KindTimeout, Reason: ReasonTimeBudget, Detail: v.Detail, cause: v.Cause}
	case archiveguard.KindTooLarge:
		return tooLarge(reasonFor(v.Rule), v.Path)
	default:
		return rejected(reasonFor(v.Rule), v.Path)
	}
}

func reasonFor(r archiveguard.Rule) Reason {
	switch r {
	case archiveguard.RejectSymlink:
		return RejectSymlink
	case archiveguard.RejectHardlink:
		return RejectHardlink
	case archiveguard.RejectDevice:
		return RejectDevice
	case archiveguard.RejectFIFO:
		return RejectFIFO
	default:
		return Reason(r)
	}
}
