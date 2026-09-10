package archive

import "time"

// Extraction caps; every value is a security parameter. The numbers match the
// hub's internal/bundle/limits.go on purpose: a stricter CLI refuses a
// legitimately published package, a laxer one is the hole this package closes.
const (
	// DefaultMaxCompressedBytes is the hub's upload limit; every other size cap derives from it.
	DefaultMaxCompressedBytes int64 = 25 << 20

	// DefaultMaxDecompressedBytes is 10:1 over the upload cap; skill trees are text.
	DefaultMaxDecompressedBytes int64 = 250 << 20

	// DefaultMaxCompressionRatio is the cap that actually stops bombs, so it is
	// enforced per chunk before the write, never at the end.
	DefaultMaxCompressionRatio int64 = 100

	// DefaultRatioGraceBytes keeps the ratio cap off tiny archives, where tar padding alone passes 100:1.
	DefaultRatioGraceBytes int64 = 1 << 20

	// DefaultMaxEntries: the largest seeded package has ~30 files.
	DefaultMaxEntries = 10_000

	// DefaultMaxEntryBytes caps the bomb-in-one-member case independently of the total.
	DefaultMaxEntryBytes int64 = 25 << 20

	// DefaultMaxPathDepth: skills/x/references/y/z is depth 5.
	DefaultMaxPathDepth = 32

	// DefaultMaxPathBytes sits below every filesystem limit we might write to.
	DefaultMaxPathBytes = 1024

	// DefaultMaxDuration bounds a trickling peer that passes every size check.
	DefaultMaxDuration = 60 * time.Second
)

// Limits bounds one extraction. A zero field takes the default rather than
// meaning unlimited: the empty value must be the safe one.
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
