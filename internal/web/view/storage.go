package view

import "strconv"

// BucketSetting is one bucket setting. !Known renders as "Unknown", never as a dash that reads as "off".
type BucketSetting struct {
	Value string
	Known bool
}

func (s BucketSetting) Label() string {
	if !s.Known {
		return "Unknown"
	}
	if s.Value == "" {
		return "—"
	}
	return s.Value
}

type BucketSettingRow struct {
	Label   string
	Setting BucketSetting
}

type BucketSettings struct {
	Versioning  BucketSetting
	ObjectLock  BucketSetting
	Encryption  BucketSetting
	WriteAccess BucketSetting
	Retention   BucketSetting
}

func (b BucketSettings) Rows() []BucketSettingRow {
	return []BucketSettingRow{
		{Label: "Versioning", Setting: b.Versioning},
		{Label: "Object lock", Setting: b.ObjectLock},
		{Label: "Encryption", Setting: b.Encryption},
		{Label: "Write access", Setting: b.WriteAccess},
		{Label: "Retention", Setting: b.Retention},
	}
}

type KeyLayoutRow struct {
	Prefix  string
	Objects int
}

type FetchRow struct {
	ID   string
	At   string
	Kind string
	// Ref is the reference as submitted, with credentials already redacted.
	Ref     string
	Outcome string
	// Detail is the redacted error message, "" when Outcome is "ok".
	Detail string
}

// OutcomeLabel renders an unknown outcome under its own name rather than dropping it.
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

func (r FetchRow) OutcomeTone() string {
	if r.Outcome == "ok" {
		return "ok"
	}
	return "dan"
}

type Storage struct {
	ObjectCount    int
	CompressedSize string
	// Truncated means the figures above are a lower bound.
	Truncated bool
	Region    string
	KeyLayout []KeyLayoutRow
	// ReadCacheHitRate is "" when the api reports none: unknown, not zero.
	ReadCacheHitRate string
	Bucket           BucketSettings
	RecentFetches    []FetchRow

	GovernanceState
}

func (s Storage) RegionLabel() string {
	if s.Region == "" {
		return "Unknown"
	}
	return s.Region
}

func (s Storage) ReadCacheLabel() string {
	if s.ReadCacheHitRate == "" {
		return "Unknown"
	}
	return s.ReadCacheHitRate
}

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

func (s Storage) Empty() bool { return len(s.RecentFetches) == 0 }
