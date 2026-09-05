package fixture

import (
	"context"
	"time"

	"agent-manager/internal/web/view"
)

// Storage implements web.StorageSource for the screen tests.
//
// ReadCacheHitRate is left "": the real api can never answer that figure
// today, and a fixture that showed one would exercise a claim the product
// cannot make.
func (c *Catalog) Storage(context.Context) (view.Storage, error) {
	now := fixtureNow()
	return view.Storage{
		ObjectCount:    3912,
		CompressedSize: "2.4 GB",
		Region:         "eu-central-1",
		KeyLayout: []view.KeyLayoutRow{
			{Prefix: "skills", Objects: 3890},
			{Prefix: "profiles", Objects: 22},
		},
		Bucket: view.BucketSettings{
			Versioning:  view.BucketSetting{Known: true, Value: "enabled"},
			ObjectLock:  view.BucketSetting{Known: true, Value: "compliance, 90 days"},
			Encryption:  view.BucketSetting{Known: true, Value: "aws:kms"},
			WriteAccess: view.BucketSetting{Known: true, Value: "fetcher role only"},
			Retention:   view.BucketSetting{Known: true, Value: "18 months"},
		},
		RecentFetches: []view.FetchRow{
			{
				ID: "b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e01", At: view.Timestamp(now.Add(-6 * time.Hour)),
				Kind: "git", Ref: "skills/community/release-notes/1.2.7/bundle.tar.zst", Outcome: "ok",
			},
			{
				ID: "b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e02", At: view.Timestamp(now.Add(-2 * 24 * time.Hour)),
				Kind: "git", Ref: "skills/example/terraform-module-review/2.4.1/bundle.tar.zst", Outcome: "ok",
			},
			{
				ID: "b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e03", At: view.Timestamp(now.Add(-2 * 24 * time.Hour)),
				Kind: "archive-url", Ref: "https://example.dev/community/slack-digest.tar.gz",
				Outcome: "unreachable", Detail: "connection reset while downloading the archive",
			},
			{
				ID: "b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e04", At: view.Timestamp(now.Add(-4 * 24 * time.Hour)),
				Kind: "upload", Ref: "pii-redactor-1.4.2.zip", Outcome: "ok",
			},
			{
				ID: "b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e05", At: view.Timestamp(now.Add(-5 * 24 * time.Hour)),
				Kind: "git", Ref: "skills/example/k8s-incident-triage/1.9.0/bundle.tar.zst", Outcome: "ok",
			},
		},
	}, nil
}
