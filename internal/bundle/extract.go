package bundle

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

// The four failure kinds a caller must be able to tell apart: a malformed
// archive, an archive that busts a cap, a member we refuse outright, and an
// extraction that ran out of wall clock.
var (
	ErrMalformed      = errors.New("malformed archive")
	ErrTooLarge       = errors.New("archive exceeds extraction limits")
	ErrRejectedMember = errors.New("archive member rejected")
	ErrTimeout        = errors.New("extraction exceeded its time budget")
)

type ErrorKind int

const (
	KindMalformed ErrorKind = iota + 1
	KindTooLarge
	KindRejectedMember
	KindTimeout
)

func (k ErrorKind) String() string {
	switch k {
	case KindMalformed:
		return "malformed"
	case KindTooLarge:
		return "too-large"
	case KindRejectedMember:
		return "rejected-member"
	case KindTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

func (k ErrorKind) sentinel() error {
	switch k {
	case KindTooLarge:
		return ErrTooLarge
	case KindRejectedMember:
		return ErrRejectedMember
	case KindTimeout:
		return ErrTimeout
	default:
		return ErrMalformed
	}
}

// Reason values for KindTooLarge, one per cap.
const (
	CapCompressedSize   = "compressed archive size"
	CapDecompressedSize = "total decompressed size"
	CapCompressionRatio = "compression ratio"
	CapEntryCount       = "entry count"
	CapEntrySize        = "single entry size"
	CapPathDepth        = "path depth"
	CapPathLength       = "path length"
)

// Reason values for KindRejectedMember, one per member kind or path shape refused outright.
const (
	RejectAbsolutePath = "absolute path"
	RejectTraversal    = "parent directory traversal"
	RejectSymlink      = "symlink"
	RejectHardlink     = "hardlink"
	RejectDevice       = "device node"
	RejectFIFO         = "fifo"
	RejectSocket       = "socket"
	RejectDuplicate    = "duplicate path"
	RejectMemberType   = "unsupported member type"
	RejectPathChars    = "unsafe characters in path"
	RejectEmptyPath    = "empty path"
)

// Error carries the kind, so a caller can report "malformed archive" versus "too large"
// versus "rejected member", the specific cap or rule, and the offending member.
type Error struct {
	Kind   ErrorKind
	Reason string
	Path   string
	cause  error
}

func (e *Error) Error() string {
	msg := e.Kind.sentinel().Error()
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Path != "" {
		msg += fmt.Sprintf(" (member %q)", e.Path)
	}
	if e.cause != nil {
		msg += ": " + e.cause.Error()
	}
	return msg
}

// Unwrap exposes the sentinel so errors.Is(err, ErrTooLarge) works, plus the underlying
// cause when there is one.
func (e *Error) Unwrap() []error {
	if e.cause == nil {
		return []error{e.Kind.sentinel()}
	}
	return []error{e.Kind.sentinel(), e.cause}
}

func malformed(reason string, cause error) *Error {
	return &Error{Kind: KindMalformed, Reason: reason, cause: cause}
}

func tooLarge(capName, member string) *Error {
	return &Error{Kind: KindTooLarge, Reason: capName, Path: member}
}

func rejected(reason, member string) *Error {
	return &Error{Kind: KindRejectedMember, Reason: reason, Path: member}
}

type extractor struct {
	// parent is the caller's context and ctx adds our own wall-clock cap on top of it.
	// Both are kept so alive can tell whose budget expired.
	parent context.Context
	ctx    context.Context
	limits Limits
	guard  ratioGuard
	seen   map[string]struct{}
	count  int
	out    *Bundle
}

func newExtractor(ctx context.Context, lim Limits) (*extractor, context.CancelFunc) {
	lim = lim.withDefaults()
	// The wall-clock cap is a deadline over the whole extraction, checked on every read,
	// every member and every chunk: an archive can pass every size check and still take
	// forever, and so can the peer feeding it to us.
	cctx, cancel := context.WithTimeout(ctx, lim.MaxDuration)
	return &extractor{
		parent: ctx,
		ctx:    cctx,
		limits: lim,
		guard:  ratioGuard{limits: lim},
		seen:   make(map[string]struct{}),
		out:    New(),
	}, cancel
}

// alive reports our own wall-clock cap as an extraction failure, but passes the caller's
// cancellation or deadline straight through: a shutdown or a request timeout is not an
// archive defect and must not be reported as one, nor be blamed on a budget that never
// expired. The caller's context is checked first because ctx inherits its deadline, so
// both are done at once when the caller's is the shorter of the two.
func (e *extractor) alive() error {
	if parentErr := e.parent.Err(); parentErr != nil {
		return fmt.Errorf("extraction stopped: %w", parentErr)
	}
	if ctxErr := e.ctx.Err(); ctxErr != nil {
		return &Error{Kind: KindTimeout, Reason: e.limits.MaxDuration.String(), cause: ctxErr}
	}
	return nil
}

// clockFirst prefers the clock's verdict over a read failure. A read that failed because
// the budget or the caller's context expired is a timeout or a cancellation, never a
// malformed archive: without this, running out of time would be reported as an archive
// defect and the upload blamed for it.
func (e *extractor) clockFirst(err error) error {
	if clockErr := e.alive(); clockErr != nil {
		return clockErr
	}
	return err
}

// reader makes every read observe the clock, so a peer that trickles bytes cannot outlast
// MaxDuration however slowly it feeds us.
func (e *extractor) reader(r io.Reader) io.Reader {
	return &clockReader{e: e, r: r}
}

type clockReader struct {
	e *extractor
	r io.Reader
}

func (c *clockReader) Read(p []byte) (int, error) {
	if err := c.e.alive(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// Extract sniffs .zip or .tar.gz and extracts under lim. The archive is
// buffered first: the compressed cap has to be enforced before extraction
// begins, and zip needs random access anyway. Peak memory is the compressed
// buffer plus the decompressed tree, so lim.MaxCompressedBytes and
// lim.MaxDecompressedBytes are also the caller's memory budget per concurrent
// extraction.
func Extract(ctx context.Context, r io.Reader, lim Limits) (*Bundle, error) {
	lim = lim.withDefaults()
	// The wall-clock budget starts before the first byte is read. Buffering the upload is
	// part of the extraction: a peer that trickles bytes would otherwise hold a goroutine
	// and the whole compressed buffer for as long as it liked, with MaxDuration bounding
	// only the work that happens after the last byte arrives.
	e, cancel := newExtractor(ctx, lim)
	defer cancel()

	data, err := readCapped(e.reader(r), lim.MaxCompressedBytes)
	if err != nil {
		return nil, e.clockFirst(err)
	}
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")), bytes.HasPrefix(data, []byte("PK\x05\x06")):
		return e.zip(bytes.NewReader(data), int64(len(data)))
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		return e.tarGz(bytes.NewReader(data))
	default:
		return nil, malformed("unrecognised archive format, expected .zip or .tar.gz", nil)
	}
}

// ExtractZip extracts a zip whose bytes are addressable. size must be the real byte count
// of the archive, never a declared one: it is the ceiling on the compression-ratio
// denominator.
func ExtractZip(ctx context.Context, ra io.ReaderAt, size int64, lim Limits) (*Bundle, error) {
	lim = lim.withDefaults()
	e, cancel := newExtractor(ctx, lim)
	defer cancel()
	return e.zip(ra, size)
}

func (e *extractor) zip(ra io.ReaderAt, size int64) (*Bundle, error) {
	if size > e.limits.MaxCompressedBytes {
		return nil, tooLarge(CapCompressedSize, "")
	}
	// size is the ceiling on the ratio denominator, so it is set here from the real byte
	// count and never from anything the archive declares about itself.
	e.guard.archiveSize = size
	zr, zipErr := zip.NewReader(&countingReaderAt{ra: ra, guard: &e.guard}, size)
	if zipErr != nil {
		return nil, e.clockFirst(malformed("cannot read zip directory", zipErr))
	}
	return e.extractZip(zr)
}

// ExtractTarGz extracts a gzipped tar from a stream. Compressed bytes are counted as they
// are consumed, so the ratio denominator grows with real input rather than with anything
// the archive declares.
func ExtractTarGz(ctx context.Context, r io.Reader, lim Limits) (*Bundle, error) {
	lim = lim.withDefaults()
	e, cancel := newExtractor(ctx, lim)
	defer cancel()
	return e.tarGz(r)
}

func (e *extractor) tarGz(r io.Reader) (*Bundle, error) {
	// One byte past the cap is enough to know the archive is over it, and it stops the
	// gzip reader from pulling an unbounded stream into memory.
	counted := &countingReader{
		r:     io.LimitReader(e.reader(r), e.limits.MaxCompressedBytes+1),
		guard: &e.guard,
	}
	gz, gzErr := gzip.NewReader(counted)
	if gzErr != nil {
		return nil, e.clockFirst(malformed("cannot read gzip header", gzErr))
	}
	defer gz.Close()

	b, walkErr := e.walkTar(tar.NewReader(gz))
	if walkErr == nil {
		walkErr = e.drainTrailer(gz)
	}
	// Checked before walkErr: an oversized archive shows up as a truncated stream, and
	// "too large" is the honest reason for it.
	if e.guard.compressed > e.limits.MaxCompressedBytes {
		return nil, tooLarge(CapCompressedSize, "")
	}
	if walkErr != nil {
		return nil, walkErr
	}
	return b, nil
}

type zipEntry struct {
	file  *zip.File
	clean string
	dir   bool
	mode  fs.FileMode
}

func (e *extractor) extractZip(zr *zip.Reader) (*Bundle, error) {
	// Pass one validates paths, member kinds and counts straight from the central
	// directory, so an archive with too many entries or a path nested too deeply is
	// rejected before a single compressed byte is decompressed.
	entries := make([]zipEntry, 0, len(zr.File))
	for _, f := range zr.File {
		if err := e.alive(); err != nil {
			return nil, err
		}
		mode := f.Mode()
		clean, isDir, err := e.acceptMember(f.Name, mode, zipMemberReason(mode))
		if err != nil {
			return nil, err
		}
		entries = append(entries, zipEntry{file: f, clean: clean, dir: isDir, mode: mode})
	}

	for _, ent := range entries {
		if ent.dir {
			continue
		}
		if err := e.alive(); err != nil {
			return nil, err
		}
		rc, openErr := ent.file.Open()
		if openErr != nil {
			return nil, e.clockFirst(malformed("cannot open member", openErr))
		}
		data, readErr := e.readMember(rc, ent.clean)
		rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if addErr := e.out.Add(ent.clean, ent.mode, data); addErr != nil {
			return nil, rejected(RejectDuplicate, ent.clean)
		}
	}
	return e.out, nil
}

func (e *extractor) walkTar(tr *tar.Reader) (*Bundle, error) {
	for {
		if err := e.alive(); err != nil {
			return nil, err
		}
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			return e.out, nil
		}
		if nextErr != nil {
			return nil, e.clockFirst(malformed("cannot read tar header", nextErr))
		}
		// A global PAX header is archive metadata, not a member: it has no path of its own
		// and git archive emits one on every tarball. Passing over it is not skipping a
		// member.
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		mode := hdr.FileInfo().Mode()
		clean, isDir, memberErr := e.acceptMember(hdr.Name, mode, tarMemberReason(hdr.Typeflag))
		if memberErr != nil {
			return nil, memberErr
		}
		if isDir {
			continue
		}
		data, readErr := e.readMember(tr, clean)
		if readErr != nil {
			return nil, readErr
		}
		if addErr := e.out.Add(clean, mode, data); addErr != nil {
			return nil, rejected(RejectDuplicate, clean)
		}
	}
}

// acceptMember applies every path rule and every member-kind rule. memberReason is the
// rejection reason for this member's type, or "" when the type is a plain file or a
// directory.
func (e *extractor) acceptMember(name string, mode fs.FileMode, memberReason string) (clean string, isDir bool, err error) {
	if memberReason != "" {
		return "", false, rejected(memberReason, name)
	}
	e.count++
	if e.count > e.limits.MaxEntries {
		return "", false, tooLarge(CapEntryCount, name)
	}
	clean, isDir, err = e.validatePath(name)
	if err != nil {
		return "", false, err
	}
	// Directories are implicit in a Bundle but still occupy a path, so a directory
	// colliding with a file, or with another directory, is a duplicate like any other.
	if _, dup := e.seen[clean]; dup {
		return "", false, rejected(RejectDuplicate, name)
	}
	e.seen[clean] = struct{}{}
	return clean, isDir || mode.IsDir(), nil
}

func (e *extractor) validatePath(name string) (clean string, isDir bool, err error) {
	if len(name) > e.limits.MaxPathBytes {
		return "", false, tooLarge(CapPathLength, truncate(name))
	}
	if name == "" {
		return "", false, rejected(RejectEmptyPath, name)
	}
	// A backslash is a path separator to any Windows consumer of this tree, so `a\..\..\x`
	// is a traversal that would otherwise be waved through. A NUL truncates the path for
	// any C consumer. Neither belongs in a plugin path.
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
			// The archive root itself: nothing to record, and nothing to reject.
			return ".", true, nil
		}
		return "", false, rejected(RejectEmptyPath, name)
	}
	// Cleaning is normalisation, not sanitisation: the rejection below runs on the cleaned
	// form, so no `..` can reach a stored path by cancelling itself out on the way.
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, rejected(RejectTraversal, name)
	}
	if strings.Count(clean, "/")+1 > e.limits.MaxPathDepth {
		return "", false, tooLarge(CapPathDepth, clean)
	}
	return clean, isDir, nil
}

const readChunk = 32 << 10

// readMember streams one member into memory. It takes no size from the archive, not even
// to pre-size the buffer: declared sizes are attacker-controlled, so every cap here is
// measured against bytes the reader actually produced.
func (e *extractor) readMember(r io.Reader, member string) ([]byte, error) {
	data := make([]byte, 0, readChunk)
	chunk := make([]byte, readChunk)
	var got int64
	for {
		if err := e.alive(); err != nil {
			return nil, err
		}
		n, readErr := r.Read(chunk)
		if n > 0 {
			got += int64(n)
			if got > e.limits.MaxEntryBytes {
				return nil, tooLarge(CapEntrySize, member)
			}
			if gErr := e.guard.produced(int64(n), member); gErr != nil {
				return nil, gErr
			}
			data = append(data, chunk[:n]...)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return data, nil
			}
			return nil, e.clockFirst(malformed("cannot read member", readErr))
		}
	}
}

// maxTrailerBytes bounds what may follow the tar end-of-archive marker. GNU tar pads to
// 10 KiB, so this is generous; anything past it is not padding.
const maxTrailerBytes = 1 << 20

// drainTrailer reads to the end of the compressed stream so its own checksum is verified.
// Without it a truncated upload is invisible: the tar end marker arrives first and the
// short tree looks complete.
func (e *extractor) drainTrailer(r io.Reader) error {
	n, err := io.Copy(io.Discard, io.LimitReader(e.reader(r), maxTrailerBytes+1))
	if err != nil {
		return e.clockFirst(malformed("cannot read archive trailer", err))
	}
	if n > maxTrailerBytes {
		return malformed("trailing data after end of archive", nil)
	}
	return nil
}

// ratioGuard enforces the total decompressed cap and the compression ratio on every chunk
// as it is produced. Waiting until the end is the bug this exists to avoid: by then the
// bomb has already landed.
type ratioGuard struct {
	limits       Limits
	archiveSize  int64
	compressed   int64
	decompressed int64
}

func (g *ratioGuard) consumed(n int64) {
	if n > 0 {
		g.compressed += n
	}
}

func (g *ratioGuard) produced(n int64, member string) error {
	g.decompressed += n
	if g.decompressed > g.limits.MaxDecompressedBytes {
		return tooLarge(CapDecompressedSize, member)
	}
	// The denominator is real input consumed, clamped to the archive's real size when it
	// is known: a zip can point several members at the same bytes and re-read its central
	// directory, so without the clamp an attacker could inflate their own allowance.
	denom := g.compressed
	if g.archiveSize > 0 && denom > g.archiveSize {
		denom = g.archiveSize
	}
	allowed := denom * g.limits.MaxCompressionRatio
	if allowed < g.limits.RatioGraceBytes {
		allowed = g.limits.RatioGraceBytes
	}
	if g.decompressed > allowed {
		return tooLarge(CapCompressionRatio, member)
	}
	return nil
}

type countingReader struct {
	r     io.Reader
	guard *ratioGuard
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.guard.consumed(int64(n))
	return n, err
}

type countingReaderAt struct {
	ra    io.ReaderAt
	guard *ratioGuard
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.ra.ReadAt(p, off)
	c.guard.consumed(int64(n))
	return n, err
}

func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, malformed("cannot read archive", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, tooLarge(CapCompressedSize, "")
	}
	if len(data) == 0 {
		return nil, malformed("empty archive", nil)
	}
	return data, nil
}

func tarMemberReason(typeflag byte) string {
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

func zipMemberReason(mode fs.FileMode) string {
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
