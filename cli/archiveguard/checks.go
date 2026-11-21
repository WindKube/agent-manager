package archiveguard

import (
	"archive/tar"
	"io/fs"
	"path"
	"strings"
)

// ValidatePath checks an archive member name and returns its cleaned form.
// A name for the archive root itself, such as "./", comes back as "." with
// isDir true and should be recorded as nothing. Every refusal is a *Violation.
func ValidatePath(name string, lim Limits) (clean string, isDir bool, err error) {
	lim = lim.WithDefaults()
	if len(name) > lim.MaxPathBytes {
		return "", false, tooLarge(CapPathLength, truncate(name))
	}
	if name == "" {
		return "", false, rejected(RejectEmptyPath, name)
	}
	// A backslash is a separator to any Windows consumer, so `a\..\..\x` is a
	// traversal path.Clean would pass; a NUL truncates the path for any C consumer.
	if strings.ContainsAny(name, "\\\x00") {
		return "", false, rejected(RejectPathChars, name)
	}
	if path.IsAbs(name) || hasDriveLetter(name) {
		return "", false, rejected(RejectAbsolutePath, name)
	}
	isDir = strings.HasSuffix(name, "/")
	clean = path.Clean(strings.TrimSuffix(name, "/"))
	if clean == "." || clean == "" {
		if isDir {
			return ".", true, nil
		}
		return "", false, rejected(RejectEmptyPath, name)
	}
	// Cleaning is normalisation, not sanitisation: the rejection runs on the
	// cleaned form, so no `..` can cancel itself out on the way through.
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, rejected(RejectTraversal, name)
	}
	if strings.Count(clean, "/")+1 > lim.MaxPathDepth {
		return "", false, tooLarge(CapPathDepth, clean)
	}
	return clean, isDir, nil
}

// TarMemberRule returns the rule a tar member of this type breaks, or "" for a
// regular file or a directory. It switches on the typeflag, never on
// FileInfo().Mode(): an unknown typeflag reports a regular-file mode.
func TarMemberRule(typeflag byte) Rule {
	switch typeflag {
	case tar.TypeReg, tar.TypeDir:
		return ""
	case tar.TypeSymlink:
		return RejectSymlink
	case tar.TypeLink:
		return RejectHardlink
	case tar.TypeChar, tar.TypeBlock:
		return RejectDevice
	case tar.TypeFifo:
		return RejectFIFO
	default:
		return RejectMemberType
	}
}

// ZipMemberRule returns the rule a zip member with this mode breaks, or "" for
// a regular file or a directory.
func ZipMemberRule(mode fs.FileMode) Rule {
	switch {
	case mode.IsRegular(), mode.IsDir():
		return ""
	case mode&fs.ModeSymlink != 0:
		return RejectSymlink
	case mode&(fs.ModeDevice|fs.ModeCharDevice) != 0:
		return RejectDevice
	case mode&fs.ModeNamedPipe != 0:
		return RejectFIFO
	case mode&fs.ModeSocket != 0:
		return RejectSocket
	default:
		return RejectMemberType
	}
}

// Droppable reports whether an extractor may skip a member breaking r instead of refusing the
// archive. Only links qualify: ordinary repositories carry them, whereas a device, fifo or socket
// says the archive is hostile or broken.
func (r Rule) Droppable() bool {
	return r == RejectSymlink || r == RejectHardlink
}

// RejectMember returns the *Violation for a member refused under rule r.
func RejectMember(r Rule, member string) error {
	return rejected(r, member)
}

func hasDriveLetter(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func truncate(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
