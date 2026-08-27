package bundle

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/klauspost/compress/zstd"
)

// epoch is the mtime written for every member. FR-007 makes the digest a version's
// identity, so nothing outside the tree itself may reach the bytes.
var epoch = time.Unix(0, 0).UTC()

// packWindowSize is pinned rather than left to the encoder default so an upgrade cannot
// silently change the digest of an already-published tree.
const packWindowSize = 1 << 20

// unpackMaxMemory bounds the decoder's own allocation before a single byte reaches the cap
// checks in ratioGuard. It is a floor under those checks, not a replacement for them.
const unpackMaxMemory = 1 << 28

// Pack serialises a bundle as tar.zst and returns the bytes, their sha256 and their
// length. The output is deterministic, which FR-007 immutability depends on: members are
// written in path order, mtimes and ownership are zeroed, modes come from the two-value
// set Bundle normalises to, and the encoder is single-threaded because multi-threaded zstd
// blocks the input differently per host CPU count.
func Pack(b *Bundle) (packed io.Reader, digest [32]byte, size int64, err error) {
	var buf bytes.Buffer
	enc, encErr := zstd.NewWriter(&buf,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(packWindowSize),
	)
	if encErr != nil {
		return nil, [32]byte{}, 0, fmt.Errorf("create zstd encoder: %w", encErr)
	}
	if tarErr := writeTar(tar.NewWriter(enc), b); tarErr != nil {
		enc.Close()
		return nil, [32]byte{}, 0, tarErr
	}
	if closeErr := enc.Close(); closeErr != nil {
		return nil, [32]byte{}, 0, fmt.Errorf("finish zstd stream: %w", closeErr)
	}
	out := buf.Bytes()
	return bytes.NewReader(out), sha256.Sum256(out), int64(len(out)), nil
}

func writeTar(tw *tar.Writer, b *Bundle) error {
	for _, f := range b.Files() {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.Path,
			Mode:     int64(f.Mode.Perm()),
			Size:     int64(len(f.Data)),
			ModTime:  epoch,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header for %q: %w", f.Path, err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return fmt.Errorf("write tar body for %q: %w", f.Path, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("finish tar stream: %w", err)
	}
	return nil
}

// Unpack reads a stored tar.zst back into a Bundle. It re-applies the extraction caps and
// the member rules: a bundle read out of object storage is still bytes off a network, and
// what could not be extracted must not become unpackable either.
func Unpack(ctx context.Context, r io.Reader, lim Limits) (*Bundle, error) {
	lim = lim.withDefaults()
	e, cancel := newExtractor(ctx, lim)
	defer cancel()

	counted := &countingReader{
		r:     io.LimitReader(e.reader(r), lim.MaxCompressedBytes+1),
		guard: &e.guard,
	}
	dec, decErr := zstd.NewReader(counted,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(unpackMaxMemory),
	)
	if decErr != nil {
		return nil, e.clockFirst(malformed("cannot read zstd stream", decErr))
	}
	defer dec.Close()

	b, walkErr := e.walkTar(tar.NewReader(dec))
	if walkErr == nil {
		walkErr = e.drainTrailer(dec)
	}
	if e.guard.compressed > lim.MaxCompressedBytes {
		return nil, tooLarge(CapCompressedSize, "")
	}
	if walkErr != nil {
		return nil, walkErr
	}
	return b, nil
}
