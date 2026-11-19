package archiveguard

import "time"

// Extraction caps. Every value is a security parameter, so each states why it
// is that number instead of a round one.
const (
	// DefaultMaxCompressedBytes is the upload limit the product states; every
	// other size cap is derived from it.
	DefaultMaxCompressedBytes int64 = 25 << 20

	// DefaultMaxDecompressedBytes is 10:1 over the upload cap. Real plugin and
	// skill trees are text; anything past this is not one.
	DefaultMaxDecompressedBytes int64 = 250 << 20

	// DefaultMaxCompressionRatio is the cap that actually stops bombs: a size cap
	// alone lets a 24 MB archive consume 249 MB first, so it is enforced per
	// chunk as bytes stream, never at the end.
	DefaultMaxCompressionRatio int64 = 100

	// DefaultRatioGraceBytes keeps the ratio cap off tiny archives, where tar
	// padding alone passes 100:1, and a bomb held under 1 MiB has not landed.
	DefaultRatioGraceBytes int64 = 1 << 20

	// DefaultMaxEntries: the largest seeded package has ~30 files.
	DefaultMaxEntries = 10_000

	// DefaultMaxEntryBytes caps the bomb-in-one-member case independently of the total.
	DefaultMaxEntryBytes int64 = 25 << 20

	// DefaultMaxPathDepth: skills/x/references/y/z is depth 5.
	DefaultMaxPathDepth = 32

	// DefaultMaxPathBytes sits below every filesystem limit we might write to.
	DefaultMaxPathBytes = 1024

	// DefaultMaxDuration bounds a pathological or trickling archive that passes every size check.
	DefaultMaxDuration = 60 * time.Second
)

// Limits bounds one extraction. A non-positive field takes the default rather
// than meaning unlimited: these are security caps, so the empty value must be
// the safe one.
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

// DefaultLimits returns every cap at its default.
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

// WithDefaults replaces every non-positive field with its default.
func (l Limits) WithDefaults() Limits {
	d := DefaultLimits()
	orDefault(&l.MaxCompressedBytes, d.MaxCompressedBytes)
	orDefault(&l.MaxDecompressedBytes, d.MaxDecompressedBytes)
	orDefault(&l.MaxCompressionRatio, d.MaxCompressionRatio)
	orDefault(&l.RatioGraceBytes, d.RatioGraceBytes)
	orDefault(&l.MaxEntries, d.MaxEntries)
	orDefault(&l.MaxEntryBytes, d.MaxEntryBytes)
	orDefault(&l.MaxPathDepth, d.MaxPathDepth)
	orDefault(&l.MaxPathBytes, d.MaxPathBytes)
	orDefault(&l.MaxDuration, d.MaxDuration)
	return l
}

func orDefault[T int | int64 | time.Duration](field *T, def T) {
	if *field <= 0 {
		*field = def
	}
}
