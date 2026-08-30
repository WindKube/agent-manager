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

	"github.com/WindKube/agent-manager/cli/internal/layout"
)

// zstdMagic is the only frame magic this package will build a decoder for
// (RFC 8878 §3.1.1). A leading skippable frame (0x184D2A5x) is legal zstd and is
// refused anyway: the hub's bundle.Pack never emits one, so accepting it would be
// a decode path with no legitimate producer.
var zstdMagic = [4]byte{0x28, 0xB5, 0x2F, 0xFD}

// decoderMaxMemory is the same floor the hub puts under its own decoder: it bounds
// the decoder's allocation before a single byte reaches the cap checks in
// ratioGuard. It is a floor under those checks, never a replacement for them — the
// decoder's own limit is per frame and says nothing about a ratio.
const decoderMaxMemory = 1 << 28

const (
	readChunk = 32 << 10

	// dirPerm is the mode requested for every directory this package creates. The
	// umask applies on top, which is deliberate: R4 records the fingerprint mode from
	// lstat on the file as written, so a mode the process could not actually produce
	// must never be forced here.
	dirPerm fs.FileMode = 0o755

	execPerm fs.FileMode = 0o755
	filePerm fs.FileMode = 0o644
)

// Result reports what one extraction wrote. Paths are slash-separated and relative
// to the destination root, in the order the archive presented them.
type Result struct {
	Dest              string
	Files             []string
	Dirs              []string
	CompressedBytes   int64
	DecompressedBytes int64
}

// Extract writes a tar+zstd bundle into dest under lim.
//
// dest must NOT exist and its parent must: this package creates the destination
// root itself, which is what makes its containment invariant total — every path
// component beneath dest is one this call made with os.Mkdir, so none of them can
// be a symlink, and the leaf of every file is opened O_EXCL. os.Root sits
// underneath as the backstop, so even a component swapped by another process while
// this runs cannot resolve outside dest.
//
// What Extract deliberately does NOT do:
//
//   - It does not clean up after a failure. The partially written tree is left
//     exactly as it stands. The caller created dest's parent and owns removal
//     (apply/stage.go removes the staging directory), and a removal that failed
//     here would mask the refusal behind an unrelated I/O error and destroy the
//     evidence of what a hostile bundle managed to write.
//   - It does not check that dest is inside the invoking user's home. FR-020 is a
//     check on the RESOLVED path and internal/apply owns it; agent directories are
//     frequently symlinks into a dotfiles repo, so resolving here and refusing
//     would break the common case rather than protect it.
//   - It does not verify the bundle's digest. FR-014 requires that before anything
//     reaches this package.
func Extract(ctx context.Context, r io.Reader, dest string, lim Limits) (*Result, error) {
	lim = lim.withDefaults()

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

// createDest makes dest and returns a root confined to it.
//
// The parent is opened as an os.Root first and dest is created through it, rather
// than os.Mkdir followed by os.OpenRoot(dest). Those two look equivalent and are
// not: between the mkdir and the open, another process can replace dest with a
// symlink, and os.OpenRoot resolves its own argument normally, so the root would
// then be confined to somewhere else entirely. Going through the parent's root
// closes that window.
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

// existingDestError distinguishes "something is in the way" from "a symlink is in
// the way". The distinction is worth the extra lstat: the second means this machine
// is already being steered somewhere, and it reads very differently in a log.
func existingDestError(r *os.Root, name, reported string) error {
	info, err := r.Lstat(name)
	if err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return unsafeDest(RejectDestSymlink, reported, nil)
	}
	return unsafeDest(RejectDestExists, reported, nil)
}

type extractor struct {
	// parent is the caller's context; ctx adds our own wall-clock cap on top of it.
	// Both are kept so alive can tell whose budget expired — a cancelled sync is not
	// an archive defect and must not be reported as one.
	parent context.Context
	ctx    context.Context

	limits Limits
	guard  ratioGuard
	root   *os.Root

	seen     map[string]struct{}
	seenFold map[string]string
	created  map[string]struct{}
	dirOrder []string
	count    int

	result Result
}

func newExtractor(ctx context.Context, lim Limits) (*extractor, context.CancelFunc) {
	cctx, cancel := context.WithTimeout(ctx, lim.MaxDuration)
	return &extractor{
		parent:   ctx,
		ctx:      cctx,
		limits:   lim,
		guard:    ratioGuard{limits: lim},
		seen:     make(map[string]struct{}),
		seenFold: make(map[string]string),
		created:  map[string]struct{}{".": {}},
	}, cancel
}

func (e *extractor) run(r io.Reader) error {
	src := &countingReader{
		r:     io.LimitReader(&clockReader{e: e, r: r}, e.limits.MaxCompressedBytes+1),
		guard: &e.guard,
	}

	var magic [4]byte
	if _, err := io.ReadFull(src, magic[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return e.budgetFirst(malformed("empty archive", nil))
		}
		return e.budgetFirst(malformed("cannot read archive header", err))
	}
	// Sniffed before a decoder exists, so a stream that is not zstd never reaches
	// one. tar+zstd is the only format the hub serves; see doc.go for why .zip and
	// .tar.gz are not accepted here even though the hub's own ingestion takes them.
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
	// Checked before walkErr: an archive over the compressed cap shows up as a
	// truncated stream, and "too large" is the honest reason for it.
	if e.guard.compressed > e.limits.MaxCompressedBytes {
		return tooLarge(CapCompressedSize, "")
	}
	if walkErr != nil {
		return walkErr
	}
	if len(e.result.Files) == 0 && len(e.result.Dirs) == 0 {
		return malformed("archive contains no members", nil)
	}

	e.result.CompressedBytes = e.guard.compressed
	e.result.DecompressedBytes = e.guard.decompressed
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
			// The clock is consulted even on a clean end of archive. A decoder that
			// gave up because the budget expired can surface as a short stream whose
			// tar end-marker arrives first, and reporting that as a successful — or
			// merely empty — extraction would turn the wall-clock cap into a field
			// nothing reads.
			return e.alive()
		}
		if err != nil {
			return e.budgetFirst(malformed("cannot read tar header", err))
		}
		// A global PAX header is archive metadata, not a member: it has no path of its
		// own and `git archive` emits one on every tarball. Passing over it is not
		// skipping a member, so it is not counted against MaxEntries either.
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

// acceptMember applies every member-kind and path rule before a byte of the
// member's body is read.
func (e *extractor) acceptMember(hdr *tar.Header) (clean string, isDir bool, err error) {
	// Switched on the typeflag, never on FileInfo().Mode(): a header with an
	// unrecognised typeflag reports a regular-file mode, so a mode-based check would
	// wave it straight through. Verified against archive/tar.
	if reason := tarMemberReason(hdr.Typeflag); reason != "" {
		return "", false, rejected(reason, hdr.Name)
	}

	e.count++
	if e.count > e.limits.MaxEntries {
		return "", false, tooLarge(CapEntryCount, hdr.Name)
	}

	clean, isDir, err = e.validatePath(hdr.Name)
	if err != nil {
		return "", false, err
	}
	if clean == "." {
		return ".", true, nil
	}

	// A directory occupies a path exactly as a file does, so a directory colliding
	// with a file — or with another directory — is a duplicate like any other.
	if _, dup := e.seen[clean]; dup {
		return "", false, rejected(RejectDuplicate, hdr.Name)
	}
	// Case-folded collisions are refused on EVERY platform, not only where the
	// filesystem would collapse them. A bundle carrying both SKILL.md and Skill.md is
	// one file on darwin and two on linux; accepting it on linux would mean
	// the same digest installs a different tree per platform, which breaks FR-024's
	// all-or-nothing guarantee and R4's install fingerprint. Uniform refusal is the
	// only behaviour that is the same everywhere. Folding is ASCII-cheap on purpose:
	// darwin's HFS+/APFS folding is Unicode and far wider than this, so the O_EXCL
	// open below remains the backstop for a collision this misses.
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
	if len(name) > e.limits.MaxPathBytes {
		return "", false, tooLarge(CapPathLength, truncate(name))
	}
	if name == "" {
		return "", false, rejected(RejectEmptyPath, name)
	}
	// A backslash is a path separator to some consumers of this tree, so
	// `a\..\..\x` is a traversal that path.Clean would wave through. A NUL truncates
	// the path for any C consumer. Neither belongs in a bundle path.
	//
	// The NUL half is unreachable through archive/tar and kept anyway: Go's
	// tar.Reader trims name[100] at the first NUL and rejects a PAX record
	// containing one, so a NUL cannot arrive via this decoder today. It is one
	// stdlib change or one hand-rolled reader away from arriving, and the check
	// costs nothing. extract_test.go exercises it against validatePath directly and
	// says why it cannot go through Extract.
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
	// Cleaning is normalisation, not sanitisation: the rejection runs on the cleaned
	// form, so no `..` reaches a written path by cancelling itself out on the way.
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, rejected(RejectTraversal, name)
	}
	if strings.Count(clean, "/")+1 > e.limits.MaxPathDepth {
		return "", false, tooLarge(CapPathDepth, clean)
	}
	if reason := e.rejectPluginAdoption(clean, isDir); reason != "" {
		return "", false, rejected(reason, name)
	}
	return clean, isDir, nil
}

// rejectPluginAdoption refuses a bundle that would change its own kind on disk. The
// destination root IS the skill directory (layout.ClaudeCode.UserSkillDir is the
// rename target), so it is the top-level subdirectories of the archive that decide
// adoption, and only those are checked: a `references/hooks/` deeper in the tree is
// inert and refusing it would reject legitimate content.
//
// Only claude-code skills ship (R2), which is why this is unconditional rather than
// an option. If a target whose unit is not a skill directory is ever added, this
// becomes a field on Limits and stops being a bare rule.
func (e *extractor) rejectPluginAdoption(clean string, isDir bool) Reason {
	first, _, nested := strings.Cut(clean, "/")
	// A plain file named `hooks` at the root is a file, not a subdirectory, and does
	// not trigger adoption. Only a directory does.
	if !nested && !isDir {
		return ""
	}
	if layout.IsClaudeCodePluginAdoptingSubdir(first) {
		return RejectPluginAdoptingDir
	}
	return ""
}

// ensureDir creates clean and every component above it, refusing anything already
// present that this extraction did not create.
//
// This is the single invariant the package rests on. os.Mkdir cannot create a
// symlink and fails when one is already there, so a component that Mkdir created is
// known to be a real directory; a component already present is refused rather than
// reused, because the destination root was created empty moments ago and anything
// inside it arrived from somewhere else. That is what makes the three-member escape
// impossible — directory, then a symlink inside it pointing out, then a write
// through the symlink whose path is clean and relative at every step. The symlink
// member is refused outright by acceptMember, and even if it were not, the write
// would land on a component this extraction did not create.
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

// writeFile streams one member to disk. Every cap is checked BEFORE the chunk that
// would breach it is written, which is the whole point: a cap checked after the copy
// is not a cap, the bytes are already on the disk. No size is taken from the
// archive, not even to pre-size a buffer — a declared size is attacker-controlled,
// so every cap is measured against bytes the reader actually produced.
func (e *extractor) writeFile(clean string, mode fs.FileMode, r io.Reader) error {
	if err := e.ensureDir(path.Dir(clean)); err != nil {
		return err
	}

	perm := filePerm
	if mode.Perm()&0o111 != 0 {
		perm = execPerm
	}
	// O_EXCL is load-bearing twice over: it refuses to follow a symlink at the leaf,
	// and it refuses to overwrite. Setuid, setgid, sticky and group/world-write bits
	// from the header are discarded — the archive chooses executable or not, and
	// nothing else.
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
	// Content durability is this package's, directory-entry durability is the swap's
	// (R3, and doc.go). A file fsync failure is fatal: a bundle half of whose bytes
	// may not survive a power cut is not installed.
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
			if got > e.limits.MaxEntryBytes {
				return tooLarge(CapEntrySize, member)
			}
			if gErr := e.guard.produced(int64(n), member); gErr != nil {
				return gErr
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

// maxTrailerBytes bounds what may follow the tar end-of-archive marker. GNU tar pads
// to 10 KiB, so this is generous; anything past it is not padding.
const maxTrailerBytes = 1 << 20

// drainTrailer reads to the end of the compressed stream so zstd verifies its own
// frame checksum. Without it a truncated bundle is invisible: the tar end marker
// arrives first and a short tree looks complete.
func (e *extractor) drainTrailer(r io.Reader) error {
	n, err := io.Copy(io.Discard, io.LimitReader(&clockReader{e: e, r: r}, maxTrailerBytes+1))
	if err != nil {
		return e.budgetFirst(malformed("cannot read archive trailer", err))
	}
	if n > maxTrailerBytes {
		return malformed("trailing data after end of archive", nil)
	}
	return nil
}

// syncDirs makes the directories this extraction created durable, deepest first.
// Failures are ignored on purpose: R3 established that the write ordering — the
// installation record is written after the swap — is what actually keeps state
// consistent. The fsync narrows a window; it does not create the safety, so it
// must not be able to fail an otherwise good extraction.
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

// alive reports our own wall-clock cap as an extraction failure but passes the
// caller's cancellation or deadline straight through: a Ctrl-C or a sync-wide
// timeout is not an archive defect. The caller's context is checked first because
// ctx inherits its deadline, so both are done at once when the caller's is shorter.
func (e *extractor) alive() error {
	if parentErr := e.parent.Err(); parentErr != nil {
		return fmt.Errorf("extraction stopped: %w", parentErr)
	}
	if ctxErr := e.ctx.Err(); ctxErr != nil {
		return &Error{
			Kind:   KindTimeout,
			Reason: ReasonTimeBudget,
			Detail: e.limits.MaxDuration.String(),
			cause:  ctxErr,
		}
	}
	return nil
}

// budget is alive plus the compressed cap. The compressed cap is re-checked in the
// loops rather than only from the counting reader because an error returned from
// under the zstd decoder may not survive the decoder's own error handling, and a cap
// whose enforcement depends on somebody else's error wrapping is not enforced.
func (e *extractor) budget() error {
	if err := e.alive(); err != nil {
		return err
	}
	if e.guard.compressed > e.limits.MaxCompressedBytes {
		return tooLarge(CapCompressedSize, "")
	}
	return nil
}

// budgetFirst prefers a busted budget over a read failure. A read that failed
// because the clock expired is a timeout and one that failed because the archive
// ran past the compressed cap is too-large — neither is a malformed archive.
// Without this, running out of time is reported as an archive defect and the
// publisher gets blamed for a slow link, and an oversized upload is reported as
// corrupt because the truncation is all the decoder can see.
func (e *extractor) budgetFirst(err error) error {
	if bErr := e.budget(); bErr != nil {
		return bErr
	}
	return err
}

// clockReader makes every read of the compressed stream observe the clock, so a peer
// that trickles bytes cannot outlast MaxDuration however slowly it feeds us.
//
// What it does NOT catch: a reader that blocks forever inside a single Read. The
// clock is checked before each call, not concurrently with it, and interrupting a
// blocked read means abandoning a goroutine holding the decoder's buffers. The
// caller's own context and the HTTP client's response-header and body timeouts are
// the defence against that; this is the defence against a reader that returns a
// byte at a time forever.
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

// ratioGuard enforces the total decompressed cap and the compression ratio on every
// chunk as it is produced. Waiting until the end is the bug it exists to avoid: by
// then the bomb has landed.
type ratioGuard struct {
	limits       Limits
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
	// The denominator is real input consumed. There is no clamp to a declared archive
	// size here, unlike the hub's zip path: this is a single forward stream, so no
	// member can point at bytes another member already paid for.
	allowed := g.compressed * g.limits.MaxCompressionRatio
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

func tarMemberReason(typeflag byte) Reason {
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
