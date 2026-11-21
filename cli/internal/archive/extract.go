package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/WindKube/agent-manager/cli/archiveguard"
	"github.com/WindKube/agent-manager/cli/internal/layout"
)

// Limits bounds one extraction; see archiveguard.Limits.
type Limits = archiveguard.Limits

// DefaultLimits returns every cap at its default.
func DefaultLimits() Limits { return archiveguard.DefaultLimits() }

// zstdMagic is the only frame magic a decoder is built for. A leading skippable
// frame is legal zstd and refused anyway: the hub never emits one.
var zstdMagic = [4]byte{0x28, 0xB5, 0x2F, 0xFD}

// decoderMaxMemory bounds the decoder's allocation before ratioGuard sees a byte.
// It is a floor under the caps, not a replacement for them.
const decoderMaxMemory = 1 << 28

const (
	readChunk = 32 << 10

	// dirPerm is subject to the umask on purpose: the install fingerprint records
	// the mode as written, so a mode the process could not produce is never forced.
	dirPerm fs.FileMode = 0o755

	execPerm fs.FileMode = 0o755
	filePerm fs.FileMode = 0o644
)

// Result reports what one extraction wrote; paths are slash-separated and relative to dest.
type Result struct {
	Dest              string
	Files             []string
	Dirs              []string
	CompressedBytes   int64
	DecompressedBytes int64
}

// Extract writes a tar+zstd bundle into dest under lim. dest must not exist and its parent must:
// creating the root here makes every component beneath it one this call made, so none can be a symlink.
// It does not clean up after a failure, check home containment, or verify the digest.
func Extract(ctx context.Context, r io.Reader, dest string, lim Limits) (*Result, error) {
	lim = lim.WithDefaults()

	e, cancel := newExtractor(ctx, lim)
	defer cancel()

	root, err := createDest(dest)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	e.root = root
	e.result.Dest = dest

	if err := e.run(r); err != nil {
		return nil, err
	}
	return &e.result, nil
}

// createDest makes dest through its parent's os.Root, since between os.Mkdir and os.OpenRoot(dest)
// another process could replace dest with a symlink.
func createDest(dest string) (*os.Root, error) {
	dest = filepath.Clean(dest)
	parent, leaf := filepath.Split(dest)
	if parent == "" {
		parent = "."
	}
	if leaf == "" || leaf == "." || leaf == ".." {
		return nil, unsafeDest(RejectDestUnresolvable, dest, fmt.Errorf("destination has no directory name"))
	}

	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return nil, unsafeDest(RejectDestUnresolvable, dest, err)
	}
	defer func() { _ = parentRoot.Close() }()

	if mkErr := parentRoot.Mkdir(leaf, dirPerm); mkErr != nil {
		if errors.Is(mkErr, fs.ErrExist) {
			return nil, existingDestError(parentRoot, leaf, dest)
		}
		return nil, ioFailure(IOMkdir, dest, mkErr)
	}

	root, rootErr := parentRoot.OpenRoot(leaf)
	if rootErr != nil {
		return nil, unsafeDest(RejectDestUnresolvable, dest, rootErr)
	}
	return root, nil
}

// existingDestError tells a symlink in the way from anything else: the former
// means this machine is already being steered somewhere.
func existingDestError(r *os.Root, name, reported string) error {
	info, err := r.Lstat(name)
	if err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return unsafeDest(RejectDestSymlink, reported, nil)
	}
	return unsafeDest(RejectDestExists, reported, nil)
}

type extractor struct {
	clock  *archiveguard.Clock
	limits Limits
	guard  *archiveguard.Guard
	root   *os.Root

	seen     map[string]struct{}
	seenFold map[string]string
	created  map[string]struct{}
	dirOrder []string

	result Result
}

func newExtractor(ctx context.Context, lim Limits) (*extractor, context.CancelFunc) {
	clock, cancel := archiveguard.StartClock(ctx, lim.MaxDuration)
	return &extractor{
		clock:    clock,
		limits:   lim,
		guard:    archiveguard.NewGuard(lim),
		seen:     make(map[string]struct{}),
		seenFold: make(map[string]string),
		created:  map[string]struct{}{".": {}},
	}, cancel
}

func (e *extractor) run(r io.Reader) error {
	src := e.guard.Reader(io.LimitReader(archiveguard.ClockReader(r, e.alive), e.limits.MaxCompressedBytes+1))

	var magic [4]byte
	if _, err := io.ReadFull(src, magic[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return e.budgetFirst(malformed("empty archive", nil))
		}
		return e.budgetFirst(malformed("cannot read archive header", err))
	}
	// Sniffed before a decoder exists; tar+zstd is the only format the hub serves.
	if magic != zstdMagic {
		return malformed("unrecognised archive format, expected tar+zstd", nil)
	}

	dec, err := zstd.NewReader(
		io.MultiReader(bytes.NewReader(magic[:]), src),
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(decoderMaxMemory),
	)
	if err != nil {
		return e.budgetFirst(malformed("cannot read zstd stream", err))
	}
	defer dec.Close()

	walkErr := e.walkTar(tar.NewReader(dec))
	if walkErr == nil {
		walkErr = e.drainTrailer(dec)
	}
	// Checked before walkErr: an archive over the compressed cap surfaces as a truncated stream.
	if err := e.guard.CheckCompressed(); err != nil {
		return fromGuard(err)
	}
	if walkErr != nil {
		return walkErr
	}
	if len(e.result.Files) == 0 && len(e.result.Dirs) == 0 {
		return malformed("archive contains no members", nil)
	}

	e.result.CompressedBytes = e.guard.Compressed()
	e.result.DecompressedBytes = e.guard.Decompressed()
	e.syncDirs()
	return nil
}

func (e *extractor) walkTar(tr *tar.Reader) error {
	for {
		if err := e.budget(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			// Checked even on a clean end: an expired budget can surface as a short
			// stream whose tar end-marker arrives first.
			return e.alive()
		}
		if err != nil {
			return e.budgetFirst(malformed("cannot read tar header", err))
		}
		// A global PAX header is archive metadata, not a member; `git archive` emits one on every tarball.
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}

		clean, isDir, err := e.acceptMember(hdr)
		if err != nil {
			return err
		}
		if isDir {
			if err := e.ensureDir(clean); err != nil {
				return err
			}
			continue
		}
		if err := e.writeFile(clean, hdr.FileInfo().Mode(), tr); err != nil {
			return err
		}
	}
}

// acceptMember applies every member-kind and path rule before a byte of the body is read.
func (e *extractor) acceptMember(hdr *tar.Header) (clean string, isDir bool, err error) {
	// Every refused kind is fatal here, links included: unlike the hub this
	// extractor writes to disk, so it never drops a member it cannot represent.
	if rule := archiveguard.TarMemberRule(hdr.Typeflag); rule != "" {
		return "", false, fromGuard(archiveguard.RejectMember(rule, hdr.Name))
	}
	if countErr := e.guard.CountEntry(hdr.Name); countErr != nil {
		return "", false, fromGuard(countErr)
	}

	clean, isDir, err = e.validatePath(hdr.Name)
	if err != nil {
		return "", false, err
	}
	if clean == "." {
		return ".", true, nil
	}

	// A directory occupies a path exactly as a file does.
	if _, dup := e.seen[clean]; dup {
		return "", false, rejected(RejectDuplicate, hdr.Name)
	}
	// SKILL.md and Skill.md are one file on darwin and two on linux, so refuse everywhere.
	// Folding is ASCII only; O_EXCL below backstops the rest.
	fold := strings.ToLower(clean)
	if prev, dup := e.seenFold[fold]; dup {
		return "", false, &Error{
			Kind:   KindRejectedMember,
			Reason: RejectDuplicate,
			Path:   hdr.Name,
			Detail: "differs only in case from " + prev,
		}
	}
	e.seen[clean] = struct{}{}
	e.seenFold[fold] = clean

	return clean, isDir, nil
}

func (e *extractor) validatePath(name string) (clean string, isDir bool, err error) {
	clean, isDir, err = archiveguard.ValidatePath(name, e.limits)
	if err != nil {
		return "", false, fromGuard(err)
	}
	if clean == "." {
		return clean, isDir, nil
	}
	if reason := e.rejectPluginAdoption(clean, isDir); reason != "" {
		return "", false, rejected(reason, name)
	}
	return clean, isDir, nil
}

// rejectPluginAdoption refuses a top-level subdirectory that would make Claude Code treat the skill
// as a plugin. Deeper is inert.
func (e *extractor) rejectPluginAdoption(clean string, isDir bool) Reason {
	first, _, nested := strings.Cut(clean, "/")
	// A plain file named `hooks` at the root does not trigger adoption.
	if !nested && !isDir {
		return ""
	}
	if layout.IsClaudeCodePluginAdoptingSubdir(first) {
		return RejectPluginAdoptingDir
	}
	return ""
}

// ensureDir creates clean and every component above it, refusing anything this extraction did not
// create. That is what defeats the directory, symlink-inside-it, write-through-it escape.
func (e *extractor) ensureDir(clean string) error {
	if clean == "." || clean == "" {
		return nil
	}
	if _, done := e.created[clean]; done {
		return nil
	}
	if err := e.ensureDir(path.Dir(clean)); err != nil {
		return err
	}
	if err := e.root.Mkdir(clean, dirPerm); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return existingDestError(e.root, clean, clean)
		}
		return ioFailure(IOMkdir, clean, err)
	}
	e.created[clean] = struct{}{}
	e.dirOrder = append(e.dirOrder, clean)
	e.result.Dirs = append(e.result.Dirs, clean)
	return nil
}

// writeFile streams one member to disk, checking every cap before each chunk is written. The
// archive's declared size is attacker-controlled and never used.
func (e *extractor) writeFile(clean string, mode fs.FileMode, r io.Reader) error {
	if err := e.ensureDir(path.Dir(clean)); err != nil {
		return err
	}

	perm := filePerm
	if mode.Perm()&0o111 != 0 {
		perm = execPerm
	}
	// O_EXCL refuses to follow a symlink at the leaf and refuses to overwrite.
	// Only the executable bit survives from the header.
	f, err := e.root.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return existingDestError(e.root, clean, clean)
		}
		return ioFailure(IOOpen, clean, err)
	}

	if err := e.copyMember(f, r, clean); err != nil {
		_ = f.Close()
		return err
	}
	// A file fsync failure is fatal: content durability is this package's,
	// directory-entry durability is the swap's.
	if syncErr := f.Sync(); syncErr != nil {
		_ = f.Close()
		return ioFailure(IOSync, clean, syncErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		return ioFailure(IOWrite, clean, closeErr)
	}

	e.result.Files = append(e.result.Files, clean)
	return nil
}

func (e *extractor) copyMember(w io.Writer, r io.Reader, member string) error {
	chunk := make([]byte, readChunk)
	var got int64
	for {
		if err := e.budget(); err != nil {
			return err
		}
		n, readErr := r.Read(chunk)
		if n > 0 {
			got += int64(n)
			if gErr := e.guard.Produced(int64(n), got, member); gErr != nil {
				return fromGuard(gErr)
			}
			if _, wErr := w.Write(chunk[:n]); wErr != nil {
				return ioFailure(IOWrite, member, wErr)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return e.budgetFirst(malformed("cannot read member", readErr))
		}
	}
}

// drainTrailer reads to the end of the stream so zstd verifies its frame checksum.
func (e *extractor) drainTrailer(r io.Reader) error {
	err := archiveguard.DrainTrailer(archiveguard.ClockReader(r, e.alive))
	if errors.Is(err, archiveguard.ErrTrailingData) {
		return malformed("trailing data after end of archive", nil)
	}
	if err != nil {
		return e.budgetFirst(malformed("cannot read archive trailer", err))
	}
	return nil
}

// syncDirs makes the created directories durable, deepest first. Failures are
// ignored: the write ordering keeps state consistent, the fsync only narrows a window.
func (e *extractor) syncDirs() {
	for i := len(e.dirOrder) - 1; i >= 0; i-- {
		e.syncDir(e.dirOrder[i])
	}
	e.syncDir(".")
}

func (e *extractor) syncDir(name string) {
	d, err := e.root.Open(name)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// alive reports our own wall-clock cap as a KindTimeout Error but passes the
// caller's cancellation through: a Ctrl-C is not an archive defect.
func (e *extractor) alive() error {
	return fromGuard(e.clock.Err())
}

// budget is alive plus the compressed cap, re-checked here because an error from
// under the zstd decoder may not survive the decoder's own error handling.
func (e *extractor) budget() error {
	if err := e.alive(); err != nil {
		return err
	}
	return fromGuard(e.guard.CheckCompressed())
}

// budgetFirst prefers a busted budget over a read failure: a read that failed
// because the clock expired is a timeout, not a malformed archive.
func (e *extractor) budgetFirst(err error) error {
	if bErr := e.budget(); bErr != nil {
		return bErr
	}
	return err
}
