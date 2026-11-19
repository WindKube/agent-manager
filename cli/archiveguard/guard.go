package archiveguard

import (
	"errors"
	"io"
)

// Guard tracks one extraction's budget: entries seen, compressed bytes
// consumed and decompressed bytes produced. Every cap is checked as bytes
// stream, never after: by then a bomb has already landed. A Guard is not safe
// for concurrent use.
type Guard struct {
	lim          Limits
	archiveSize  int64
	compressed   int64
	decompressed int64
	entries      int
}

// NewGuard returns a Guard enforcing lim, with defaults applied.
func NewGuard(lim Limits) *Guard {
	return &Guard{lim: lim.WithDefaults()}
}

// SetArchiveSize clamps the ratio denominator to the archive's real byte count.
// A zip can point several members at the same bytes and re-read its central
// directory, so without the clamp an attacker inflates their own allowance.
// size must be measured, never declared by the archive.
func (g *Guard) SetArchiveSize(size int64) { g.archiveSize = size }

// Consumed records n compressed bytes read from the input.
func (g *Guard) Consumed(n int64) {
	if n > 0 {
		g.compressed += n
	}
}

// Compressed returns the compressed bytes consumed so far.
func (g *Guard) Compressed() int64 { return g.compressed }

// Decompressed returns the decompressed bytes produced so far.
func (g *Guard) Decompressed() int64 { return g.decompressed }

// CheckCompressed refuses once more than MaxCompressedBytes have been consumed.
// An oversized stream usually surfaces as a truncated one, so extractors ask
// this before reporting a read failure as malformed.
func (g *Guard) CheckCompressed() error {
	if g.compressed > g.lim.MaxCompressedBytes {
		return tooLarge(CapCompressedSize, "")
	}
	return nil
}

// CountEntry records one more member and refuses past MaxEntries.
func (g *Guard) CountEntry(member string) error {
	g.entries++
	if g.entries > g.lim.MaxEntries {
		return tooLarge(CapEntryCount, member)
	}
	return nil
}

// Produced records n decompressed bytes of member, whose running total is
// entryTotal, and refuses the chunk that busts the per-entry cap, the total
// cap or the compression ratio. Call it before the chunk is used.
func (g *Guard) Produced(n, entryTotal int64, member string) error {
	if entryTotal > g.lim.MaxEntryBytes {
		return tooLarge(CapEntrySize, member)
	}
	g.decompressed += n
	if g.decompressed > g.lim.MaxDecompressedBytes {
		return tooLarge(CapDecompressedSize, member)
	}
	denom := g.compressed
	if g.archiveSize > 0 && denom > g.archiveSize {
		denom = g.archiveSize
	}
	allowed := denom * g.lim.MaxCompressionRatio
	if allowed < g.lim.RatioGraceBytes {
		allowed = g.lim.RatioGraceBytes
	}
	if g.decompressed > allowed {
		return tooLarge(CapCompressionRatio, member)
	}
	return nil
}

// Reader counts every byte read from r as consumed.
func (g *Guard) Reader(r io.Reader) io.Reader { return &countingReader{r: r, g: g} }

// ReaderAt counts every byte read from ra as consumed.
func (g *Guard) ReaderAt(ra io.ReaderAt) io.ReaderAt { return &countingReaderAt{ra: ra, g: g} }

type countingReader struct {
	r io.Reader
	g *Guard
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.g.Consumed(int64(n))
	return n, err
}

type countingReaderAt struct {
	ra io.ReaderAt
	g  *Guard
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.ra.ReadAt(p, off)
	c.g.Consumed(int64(n))
	return n, err
}

// MaxTrailerBytes bounds what may follow the tar end marker; GNU tar pads to 10 KiB.
const MaxTrailerBytes = 1 << 20

// ErrTrailingData reports more than MaxTrailerBytes after the end of the archive.
var ErrTrailingData = errors.New("trailing data after end of archive")

// DrainTrailer reads r to its end so the compression layer verifies its own
// checksum; without it a truncated archive looks complete once the tar end
// marker arrives. It returns ErrTrailingData or the read error.
func DrainTrailer(r io.Reader) error {
	n, err := io.Copy(io.Discard, io.LimitReader(r, MaxTrailerBytes+1))
	if err != nil {
		return err
	}
	if n > MaxTrailerBytes {
		return ErrTrailingData
	}
	return nil
}
