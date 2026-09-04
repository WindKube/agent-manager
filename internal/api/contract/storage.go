package contract

import "time"

// BucketSetting is one of the bucket's own settings. Known is false when the
// bucket declined to answer it — a call the api's read-only key cannot make,
// or a store with no such concept — and it renders as unknown, not a default.
type BucketSetting struct {
	Value string `json:"value,omitempty" doc:"The bucket's own answer, in its own words." example:"enabled"`
	Known bool   `json:"known"`
}

// BucketSettings is the panel of five, each independently knowable or not.
type BucketSettings struct {
	Versioning BucketSetting `json:"versioning"`
	ObjectLock BucketSetting `json:"objectLock"`
	Encryption BucketSetting `json:"encryption"`
	// WriteAccess is this role's own credential, not the bucket's report, so it
	// is always known.
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
	RequestedRef string    `json:"requestedRef" doc:"The reference as submitted, credentials already redacted." example:"https://github.com/example/terraform-review"`
	Outcome      string    `json:"outcome" enum:"ok,invalid-ref,blocked,unreachable,malformed,too-large,rejected-member,extract-timeout"`
	Detail       string    `json:"detail,omitempty" doc:"The redacted error message. Empty when Outcome is ok."`
}

// StorageReport is the whole Storage screen.
type StorageReport struct {
	ObjectCount     int64 `json:"objectCount" doc:"Objects under skills/ and profiles/, counted up to the report's listing cap." example:"482"`
	CompressedBytes int64 `json:"compressedBytes" doc:"Total size of the objects counted above, as the bucket reports it." example:"1288490188"`
	// Truncated is true when the bucket holds more objects than the cap this
	// report lists, so the two figures above are a lower bound.
	Truncated bool `json:"truncated"`
	// Region is absent when the store carries no region (file:// or mem://).
	Region    string            `json:"region,omitempty" example:"us-east-1"`
	KeyLayout []StorageKeyCount `json:"keyLayout" doc:"Object counts by top-level prefix: skills/ and profiles/."`
	// ReadCacheHitRate is absent, not zero, until a sync report can carry a
	// cache figure to compute it from.
	ReadCacheHitRate *float64              `json:"readCacheHitRate,omitempty" doc:"Fraction of CLI reads served from a local cache. Absent when no sync report carries this figure."`
	Bucket           BucketSettings        `json:"bucket"`
	RecentFetches    []FetchAttemptSummary `json:"recentFetches" doc:"The most recent ingestion attempts, successful or not, newest first."`
}
