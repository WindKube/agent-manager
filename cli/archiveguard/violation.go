// Package archiveguard holds the security checks shared by every extractor of untrusted archives.
// It does no I/O, so a fix here lands in every extractor at once.
package archiveguard

import "fmt"

// Kind classifies a Violation.
type Kind int

// The classes of Violation.
const (
	KindTooLarge Kind = iota + 1
	KindRejected
	KindTimeout
)

// Rule names the exact check that fired.
type Rule string

// Rules for KindTooLarge, one per cap.
const (
	CapCompressedSize   Rule = "compressed archive size"
	CapDecompressedSize Rule = "total decompressed size"
	CapCompressionRatio Rule = "compression ratio"
	CapEntryCount       Rule = "entry count"
	CapEntrySize        Rule = "single entry size"
	CapPathDepth        Rule = "path depth"
	CapPathLength       Rule = "path length"
)

// Rules for KindRejected, one per member kind or path shape refused outright.
const (
	RejectAbsolutePath Rule = "absolute path"
	RejectTraversal    Rule = "parent directory traversal"
	RejectSymlink      Rule = "symlink"
	RejectHardlink     Rule = "hardlink"
	RejectDevice       Rule = "device node"
	RejectFIFO         Rule = "fifo"
	RejectSocket       Rule = "socket"
	RejectMemberType   Rule = "unsupported member type"
	RejectPathChars    Rule = "unsafe characters in path"
	RejectEmptyPath    Rule = "empty path"
)

// ReasonTimeBudget is the Rule of every KindTimeout violation.
const ReasonTimeBudget Rule = "wall clock budget"

// Violation is a refusal by one of this package's checks. Extractors translate
// it into their own error type.
type Violation struct {
	Kind Kind
	Rule Rule
	// Path is the offending member, truncated for CapPathLength and cleaned for CapPathDepth.
	Path string
	// Detail is free-form context; for KindTimeout it is the budget.
	Detail string
	Cause  error
}

func (v *Violation) Error() string {
	msg := string(v.Rule)
	if v.Detail != "" {
		msg += " (" + v.Detail + ")"
	}
	if v.Path != "" {
		msg += fmt.Sprintf(" (member %q)", v.Path)
	}
	if v.Cause != nil {
		msg += ": " + v.Cause.Error()
	}
	return msg
}

func (v *Violation) Unwrap() error { return v.Cause }

func tooLarge(rule Rule, member string) *Violation {
	return &Violation{Kind: KindTooLarge, Rule: rule, Path: member}
}

func rejected(rule Rule, member string) *Violation {
	return &Violation{Kind: KindRejected, Rule: rule, Path: member}
}
