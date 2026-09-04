package contract

import "time"

// The Storage screen's surface (001 FR-053, 003 US7 scenario 2, US8 scenario 3):
// object count, compressed size, region, the key layout, the bucket's own
// settings and recent fetch outcomes — every figure read from the object store
// or from stored data, none of it compiled into the product.

// BucketSetting is one of the bucket's own settings. Known is false when the
// bucket declined to answer — a call the api's read-only key cannot make, a
// store with no such concept (memblob in tests) — and a screen renders that as
// UNKNOWN, never as a default: this system configures and surfaces object lock
// and retention, it does not enforce them, so a screen that guessed would be
// claiming a protection that may not be there.
type BucketSetting struct {
	Value string `json:"value,omitempty" doc:"The bucket's own answer, in its own words." example:"enabled"`
	Known bool   `json:"known"`
}

// BucketSettings is the panel of five, each independently knowable or not.
type BucketSettings struct {
	Versioning BucketSetting `json:"versioning"`
	ObjectLock BucketSetting `json:"objectLock"`
	Encryption BucketSetting `json:"encryption"`
	// WriteAccess is a fact about THIS role's own credential, not the bucket's
	// report: the api process is always handed a read-only object-store key
	// (compose's x-blob-read), and only `worker fetcher` ever holds one that can
	// write (constitution principle II). It is therefore always known.
	WriteAccess BucketSetting `json:"writeAccess"`
	Retention   BucketSetting `json:"retention"`
}

// StorageKeyCount is one row of the key-layout table.
type StorageKeyCount struct {
	Prefix  string `json:"prefix" example:"skills"`
	Objects int64  `json:"objects" example:"430"`
}

// FetchAttemptSummary is one row of the storage screen's recent-fetches list.
type FetchAttemptSummary struct {
	ID           string    `json:"id" format:"uuid"`
	OccurredAt   time.Time `json:"occurredAt"`
	SourceKind   string    `json:"sourceKind" enum:"upload,git,archive-url"`
	RequestedRef string    `json:"requestedRef" doc:"The reference as submitted, credentials already redacted. Rendered escaped (FR-055)." example:"https://github.com/example/terraform-review"`
	Outcome      string    `json:"outcome" enum:"ok,invalid-ref,blocked,unreachable,malformed,too-large,rejected-member,extract-timeout"`
	Detail       string    `json:"detail,omitempty" doc:"The redacted error message. Empty when Outcome is ok."`
}

// StorageReport is the whole screen.
type StorageReport struct {
	ObjectCount     int64 `json:"objectCount" doc:"Objects under skills/ and profiles/, counted up to the report's listing cap." example:"482"`
	CompressedBytes int64 `json:"compressedBytes" doc:"Total size of the objects counted above, as the bucket reports it." example:"1288490188"`
	// Truncated is true when the bucket holds more objects than the cap this
	// report lists: the two figures above are then a lower bound, not the total.
	Truncated bool `json:"truncated"`
	// Region is absent when the store this deployment uses carries no region —
	// file:// in a container-free dev mode, or mem:// in a test.
	Region    string            `json:"region,omitempty" example:"us-east-1"`
	KeyLayout []StorageKeyCount `json:"keyLayout" doc:"Object counts by top-level prefix: skills/ and profiles/."`
	// ReadCacheHitRate is absent, not zero, until a sync report carries a cache
	// figure to compute it from — sync_event has none today, so this is always
	// absent. Zero would claim every read missed the cache; nothing here knows
	// that.
	ReadCacheHitRate *float64              `json:"readCacheHitRate,omitempty" doc:"Fraction of CLI reads served from a local cache. Absent when no sync report carries this figure."`
	Bucket           BucketSettings        `json:"bucket"`
	RecentFetches    []FetchAttemptSummary `json:"recentFetches" doc:"The most recent ingestion attempts, successful or not, newest first."`
}
