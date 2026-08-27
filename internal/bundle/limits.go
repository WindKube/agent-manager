package bundle

import "time"

// Extraction caps (research R3). Every value here is a security parameter, so each states
// why it is that number instead of a round one.
const (
	// DefaultMaxCompressedBytes is the upload limit the product states (FR-001); every
	// other size cap is derived from it.
	DefaultMaxCompressedBytes int64 = 25 << 20

	// DefaultMaxDecompressedBytes is 10:1 over the upload cap. Real plugin trees are
	// text; anything past this is not a plugin.
	DefaultMaxDecompressedBytes int64 = 250 << 20

	// DefaultMaxCompressionRatio: a 25 MB zip bomb expands to gigabytes. This is the cap
	// that actually stops bombs, because a size cap alone lets a 24 MB archive consume
	// 249 MB first, so it is enforced continuously as bytes stream and never after.
	DefaultMaxCompressionRatio int64 = 100

	// DefaultRatioGraceBytes keeps the ratio cap off the back of tiny archives: tar block
	// padding and repeated boilerplate push a few-hundred-byte archive past 100:1 without
	// any malice, and a bomb held under 1 MiB has not landed.
	DefaultRatioGraceBytes int64 = 1 << 20

	// DefaultMaxEntries: the largest seeded plugin has ~30 files. Three orders of headroom.
	DefaultMaxEntries = 10_000

	// DefaultMaxEntryBytes: no individual file in a plugin needs more, and it caps the
	// decompression-bomb-in-one-member case.
	DefaultMaxEntryBytes int64 = 25 << 20

	// DefaultMaxPathDepth: skills/x/references/y/z is depth 5.
	DefaultMaxPathDepth = 32

	// DefaultMaxPathBytes sits below every filesystem limit we might later write to.
	DefaultMaxPathBytes = 1024

	// DefaultMaxDuration bounds a pathological archive that passes every size check.
	DefaultMaxDuration = 60 * time.Second
)

// Limits bounds one extraction. A zero field takes the default rather than meaning
// "unlimited": these are security caps, so the empty value must be the safe one.
type Limits struct {
	MaxCompressedBytes   int64
	MaxDecompressedBytes int64
	MaxCompressionRatio  int64
	RatioGraceBytes      int64
	MaxEntries           int
	MaxEntryBytes        int64
	MaxPathDepth         int
	MaxPathBytes         int
	MaxDuration          time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxCompressedBytes:   DefaultMaxCompressedBytes,
		MaxDecompressedBytes: DefaultMaxDecompressedBytes,
		MaxCompressionRatio:  DefaultMaxCompressionRatio,
		RatioGraceBytes:      DefaultRatioGraceBytes,
		MaxEntries:           DefaultMaxEntries,
		MaxEntryBytes:        DefaultMaxEntryBytes,
		MaxPathDepth:         DefaultMaxPathDepth,
		MaxPathBytes:         DefaultMaxPathBytes,
		MaxDuration:          DefaultMaxDuration,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxCompressedBytes <= 0 {
		l.MaxCompressedBytes = d.MaxCompressedBytes
	}
	if l.MaxDecompressedBytes <= 0 {
		l.MaxDecompressedBytes = d.MaxDecompressedBytes
	}
	if l.MaxCompressionRatio <= 0 {
		l.MaxCompressionRatio = d.MaxCompressionRatio
	}
	if l.RatioGraceBytes <= 0 {
		l.RatioGraceBytes = d.RatioGraceBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxEntryBytes <= 0 {
		l.MaxEntryBytes = d.MaxEntryBytes
	}
	if l.MaxPathDepth <= 0 {
		l.MaxPathDepth = d.MaxPathDepth
	}
	if l.MaxPathBytes <= 0 {
		l.MaxPathBytes = d.MaxPathBytes
	}
	if l.MaxDuration <= 0 {
		l.MaxDuration = d.MaxDuration
	}
	return l
}
