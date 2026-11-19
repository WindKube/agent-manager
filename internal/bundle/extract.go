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

	"github.com/WindKube/agent-manager/cli/archiveguard"
)

// Limits bounds one extraction; see archiveguard.Limits.
type Limits = archiveguard.Limits

// DefaultMaxCompressedBytes is the upload limit the product states.
const DefaultMaxCompressedBytes = archiveguard.DefaultMaxCompressedBytes

// DefaultLimits returns every cap at its default.
func DefaultLimits() Limits { return archiveguard.DefaultLimits() }

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
	CapCompressedSize   = string(archiveguard.CapCompressedSize)
	CapDecompressedSize = string(archiveguard.CapDecompressedSize)
	CapCompressionRatio = string(archiveguard.CapCompressionRatio)
	CapEntryCount       = string(archiveguard.CapEntryCount)
	CapEntrySize        = string(archiveguard.CapEntrySize)
	CapPathDepth        = string(archiveguard.CapPathDepth)
	CapPathLength       = string(archiveguard.CapPathLength)
)

// Reason values for KindRejectedMember, one per member kind or path shape refused outright.
const (
	RejectAbsolutePath = string(archiveguard.RejectAbsolutePath)
	RejectTraversal    = string(archiveguard.RejectTraversal)
	RejectSymlink      = string(archiveguard.RejectSymlink)
	RejectHardlink     = string(archiveguard.RejectHardlink)
	RejectDevice       = string(archiveguard.RejectDevice)
	RejectFIFO         = string(archiveguard.RejectFIFO)
	RejectSocket       = string(archiveguard.RejectSocket)
	RejectDuplicate    = "duplicate path"
	RejectMemberType   = string(archiveguard.RejectMemberType)
	RejectPathChars    = string(archiveguard.RejectPathChars)
	RejectEmptyPath    = string(archiveguard.RejectEmptyPath)
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

// fromGuard translates an archiveguard.Violation into this package's Error. A
// timeout's Reason is the budget itself, as it always was here.
func fromGuard(err error) error {
	var v *archiveguard.Violation
	if !errors.As(err, &v) {
		return err
	}
	switch v.Kind {
	case archiveguard.KindTimeout:
		return &Error{Kind: KindTimeout, Reason: v.Detail, cause: v.Cause}
	case archiveguard.KindTooLarge:
		return tooLarge(string(v.Rule), v.Path)
	default:
		return rejected(string(v.Rule), v.Path)
	}
}

type extractor struct {
	clock  *archiveguard.Clock
	limits Limits
	guard  *archiveguard.Guard
	seen   map[string]struct{}
	out    *Bundle
}

func newExtractor(ctx context.Context, lim Limits) (*extractor, context.CancelFunc) {
	lim = lim.WithDefaults()
	// The wall-clock cap is a deadline over the whole extraction, checked on every read,
	// every member and every chunk: an archive can pass every size check and still take
	// forever, and so can the peer feeding it to us.
	clock, cancel := archiveguard.StartClock(ctx, lim.MaxDuration)
	return &extractor{
		clock:  clock,
		limits: lim,
		guard:  archiveguard.NewGuard(lim),
		seen:   make(map[string]struct{}),
		out:    New(),
	}, cancel
}

// alive reports our own wall-clock cap as a KindTimeout Error and passes the caller's
// cancellation or deadline straight through.
func (e *extractor) alive() error {
	return fromGuard(e.clock.Err())
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
	return archiveguard.ClockReader(r, e.alive)
}

// Extract sniffs .zip or .tar.gz and extracts under lim. The archive is
// buffered first: the compressed cap has to be enforced before extraction
// begins, and zip needs random access anyway. Peak memory is the compressed
// buffer plus the decompressed tree, so lim.MaxCompressedBytes and
// lim.MaxDecompressedBytes are also the caller's memory budget per concurrent
// extraction.
func Extract(ctx context.Context, r io.Reader, lim Limits) (*Bundle, error) {
	lim = lim.WithDefaults()
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
	lim = lim.WithDefaults()
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
	e.guard.SetArchiveSize(size)
	zr, zipErr := zip.NewReader(e.guard.ReaderAt(ra), size)
	if zipErr != nil {
		return nil, e.clockFirst(malformed("cannot read zip directory", zipErr))
	}
	return e.extractZip(zr)
}

// ExtractTarGz extracts a gzipped tar from a stream. Compressed bytes are counted as they
// are consumed, so the ratio denominator grows with real input rather than with anything
// the archive declares.
func ExtractTarGz(ctx context.Context, r io.Reader, lim Limits) (*Bundle, error) {
	lim = lim.WithDefaults()
	e, cancel := newExtractor(ctx, lim)
	defer cancel()
	return e.tarGz(r)
}

func (e *extractor) tarGz(r io.Reader) (*Bundle, error) {
	// One byte past the cap is enough to know the archive is over it, and it stops the
	// gzip reader from pulling an unbounded stream into memory.
	counted := e.guard.Reader(io.LimitReader(e.reader(r), e.limits.MaxCompressedBytes+1))
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
	if err := e.guard.CheckCompressed(); err != nil {
		return nil, fromGuard(err)
	}
	if walkErr != nil {
		return nil, walkErr
	}
	return b, nil
}

type zipEntry struct {
	file  *zip.File
	clean string
	skip  bool
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
		clean, skip, err := e.acceptMember(f.Name, mode, archiveguard.ZipMemberRule(mode))
		if err != nil {
			return nil, err
		}
		entries = append(entries, zipEntry{file: f, clean: clean, skip: skip, mode: mode})
	}

	for _, ent := range entries {
		if ent.skip {
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
		clean, skip, memberErr := e.acceptMember(hdr.Name, mode, archiveguard.TarMemberRule(hdr.Typeflag))
		if memberErr != nil {
			return nil, memberErr
		}
		if skip {
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

// acceptMember applies every path rule and every member-kind rule. rule is what this
// member's type breaks, or "" for a plain file or a directory. skip is true for anything
// that contributes no file to the tree: a directory, or a dropped link.
//
// A symlink or a hardlink is dropped and recorded rather than refusing the archive
// (archiveguard.Rule.Droppable): a bundle cannot represent either and nothing here writes
// to a filesystem, while ordinary repositories carry them. Every other refused kind, and
// every path-shape rejection, stays fatal.
func (e *extractor) acceptMember(name string, mode fs.FileMode, rule archiveguard.Rule) (clean string, skip bool, err error) {
	if rule != "" && !rule.Droppable() {
		return "", false, fromGuard(archiveguard.RejectMember(rule, name))
	}
	if countErr := e.guard.CountEntry(name); countErr != nil {
		return "", false, fromGuard(countErr)
	}
	// A dropped member is validated like any other, so its recorded path is never an
	// unchecked one.
	clean, isDir, err := archiveguard.ValidatePath(name, e.limits)
	if err != nil {
		return "", false, fromGuard(err)
	}
	// Directories are implicit in a Bundle but still occupy a path, so a directory
	// colliding with a file, or with another directory, is a duplicate like any other.
	if _, dup := e.seen[clean]; dup {
		return "", false, rejected(RejectDuplicate, name)
	}
	e.seen[clean] = struct{}{}
	if rule != "" {
		e.out.skip(clean, string(rule))
		return "", true, nil
	}
	return clean, isDir || mode.IsDir(), nil
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
			if gErr := e.guard.Produced(int64(n), got, member); gErr != nil {
				return nil, fromGuard(gErr)
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

// drainTrailer reads to the end of the compressed stream so its own checksum is verified.
func (e *extractor) drainTrailer(r io.Reader) error {
	err := archiveguard.DrainTrailer(e.reader(r))
	if errors.Is(err, archiveguard.ErrTrailingData) {
		return malformed("trailing data after end of archive", nil)
	}
	if err != nil {
		return e.clockFirst(malformed("cannot read archive trailer", err))
	}
	return nil
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
