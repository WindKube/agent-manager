package view

import "strconv"

// The Storage screen's view models (US7 scenario 2; 001 FR-053, US8 scenario 3).
//
// Every figure on this screen comes from the api, which read it from the object
// store or from stored rows. Nothing here computes one: this file only decides
// how an already-known value or an already-known "we don't know" reads.

// BucketSetting is one of the bucket's own settings. Known false is UNKNOWN, and
// it renders as that word rather than as a dash or a blank cell: this system
// configures and surfaces object lock and retention, it does not enforce them,
// so a screen that rendered a decline-to-answer as "off" would be claiming a
// protection that may not be there.
type BucketSetting struct {
	Value string
	Known bool
}

// Label is the setting cell's text.
func (s BucketSetting) Label() string {
	if !s.Known {
		return "Unknown"
	}
	if s.Value == "" {
		return "—"
	}
	return s.Value
}

// BucketSettingRow is one row of the bucket-settings table.
type BucketSettingRow struct {
	Label   string
	Setting BucketSetting
}

// BucketSettings is the panel of five, in the design's order.
type BucketSettings struct {
	Versioning  BucketSetting
	ObjectLock  BucketSetting
	Encryption  BucketSetting
	WriteAccess BucketSetting
	Retention   BucketSetting
}

// Rows is the table the screen renders.
func (b BucketSettings) Rows() []BucketSettingRow {
	return []BucketSettingRow{
		{Label: "Versioning", Setting: b.Versioning},
		{Label: "Object lock", Setting: b.ObjectLock},
		{Label: "Encryption", Setting: b.Encryption},
		{Label: "Write access", Setting: b.WriteAccess},
		{Label: "Retention", Setting: b.Retention},
	}
}

// KeyLayoutRow is one row of the key-layout table.
type KeyLayoutRow struct {
	Prefix  string
	Objects int
}

// FetchRow is one row of the recent-fetches list.
type FetchRow struct {
	ID   string
	At   string
	Kind string
	// Ref is the reference as submitted, credentials already redacted. It is
	// bundle-adjacent, publisher-supplied text and is rendered escaped like
	// everything else on this screen (001 FR-055).
	Ref     string
	Outcome string
	// Detail is the redacted error message, "" when Outcome is "ok".
	Detail string
}

// OutcomeLabel is the pill's text. The vocabulary is the api's and it can grow
// with a new failure mode; an outcome this screen has not been taught still
// renders under its own name rather than vanishing.
func (r FetchRow) OutcomeLabel() string {
	switch r.Outcome {
	case "ok":
		return "OK"
	case "invalid-ref":
		return "Invalid reference"
	case "blocked":
		return "Blocked"
	case "unreachable":
		return "Unreachable"
	case "malformed":
		return "Malformed archive"
	case "too-large":
		return "Too large"
	case "rejected-member":
		return "Rejected member"
	case "extract-timeout":
		return "Extraction timed out"
	default:
		return r.Outcome
	}
}

// OutcomeTone colours the pill.
func (r FetchRow) OutcomeTone() string {
	if r.Outcome == "ok" {
		return "ok"
	}
	return "dan"
}

// Storage is the whole screen.
type Storage struct {
	ObjectCount int
	// CompressedSize is already rendered — see hub.humanSize, the same formatter
	// the catalog's version table uses, so one byte count reads the same way
	// everywhere in this product.
	CompressedSize string
	// Truncated is true when the bucket holds more objects than the api's report
	// walked. The two figures above are then a lower bound, not the total.
	Truncated bool
	Region    string
	KeyLayout []KeyLayoutRow
	// ReadCacheHitRate is "" when the api reports none, which is unknown and not
	// zero: nothing today can compute one at all (see hub.Storage's comment).
	ReadCacheHitRate string
	Bucket           BucketSettings
	RecentFetches    []FetchRow

	GovernanceState
}

// RegionLabel is the headline card's region figure.
func (s Storage) RegionLabel() string {
	if s.Region == "" {
		return "Unknown"
	}
	return s.Region
}

// ReadCacheLabel is the headline card's cache figure.
func (s Storage) ReadCacheLabel() string {
	if s.ReadCacheHitRate == "" {
		return "Unknown"
	}
	return s.ReadCacheHitRate
}

// Cards is the headline row.
func (s Storage) Cards() []StatCard {
	objects := StatCard{Label: "Objects", Value: strconv.Itoa(s.ObjectCount)}
	if s.Truncated {
		objects.Tone = "warn"
		objects.Note = "more than this report counted"
	}

	size := StatCard{Label: "Compressed size", Value: s.CompressedSize, Note: "as stored"}
	if s.CompressedSize == "" {
		size.Value = "—"
	}

	region := StatCard{Label: "Bucket region", Value: s.RegionLabel()}
	if s.Region == "" {
		region.Tone = "warn"
	}

	cache := StatCard{Label: "CLI read-cache hit rate", Value: s.ReadCacheLabel(), Note: "of CLI reads"}
	if s.ReadCacheHitRate == "" {
		cache.Note = "no sync report carries this figure yet"
	}

	return []StatCard{objects, size, region, cache}
}

// Empty is the recent-fetches list having nothing in it.
func (s Storage) Empty() bool { return len(s.RecentFetches) == 0 }
