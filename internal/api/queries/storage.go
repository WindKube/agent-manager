package queries

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/blob"
)

const (
	// maxStorageObjects bounds the listing this report walks. A production bucket
	// can hold far more objects than a report should hold in memory at once; past
	// this cap the count and size are a lower bound and Truncated says so.
	maxStorageObjects = 10_000
	recentFetchLimit  = 20
)

// Storage answers GET /v1/storage.
func Storage(ctx context.Context, db bun.IDB, bucket blob.Inspector) (contract.StorageReport, error) {
	report := contract.StorageReport{
		KeyLayout:     []contract.StorageKeyCount{},
		RecentFetches: []contract.FetchAttemptSummary{},
	}

	attrs, truncated, err := bucket.ListLimited(ctx, "", maxStorageObjects)
	if err != nil {
		return contract.StorageReport{}, fmt.Errorf("list the bucket: %w", err)
	}
	report.Truncated = truncated
	report.Region = bucket.Region()

	var skills, profiles int64
	for _, obj := range attrs {
		report.ObjectCount++
		report.CompressedBytes += obj.Size
		switch {
		case strings.HasPrefix(obj.Key, blob.SkillsPrefix+"/"):
			skills++
		case strings.HasPrefix(obj.Key, blob.ProfilesPrefix+"/"):
			profiles++
		}
	}
	report.KeyLayout = []contract.StorageKeyCount{
		{Prefix: blob.SkillsPrefix, Objects: skills},
		{Prefix: blob.ProfilesPrefix, Objects: profiles},
	}

	report.Bucket = bucketSettings(ctx, bucket)

	fetches, err := recentFetches(ctx, db)
	if err != nil {
		return contract.StorageReport{}, err
	}
	report.RecentFetches = fetches

	// models.SyncEvent carries no cache-hit figure, so there is nothing to
	// compute a rate from; unknown, not zero.
	report.ReadCacheHitRate = nil

	return report, nil
}

// bucketSettings reads the bucket's own settings through the raw S3 client, so
// no second client is constructed. A store that is not S3 — memblob in a unit
// test — cannot produce one, which is deliberately the same answer a real
// bucket gives when the api's read-only key lacks a permission: every setting
// below is unknown either way.
func bucketSettings(ctx context.Context, bucket blob.Inspector) contract.BucketSettings {
	settings := contract.BucketSettings{
		Versioning: unknownSetting(),
		ObjectLock: unknownSetting(),
		Encryption: unknownSetting(),
		Retention:  unknownSetting(),
		// This role's own credential, not the bucket's report, so always known.
		WriteAccess: contract.BucketSetting{Known: true, Value: "read-only; only the fetcher role can write"},
	}

	var client *s3.Client
	if !bucket.As(&client) || client == nil {
		return settings
	}
	name := aws.String(bucket.Name())

	if out, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: name}); err == nil {
		value := "not enabled"
		if out.Status != "" {
			value = string(out.Status)
		}
		settings.Versioning = contract.BucketSetting{Known: true, Value: value}
	}

	out, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: name})
	switch {
	case err == nil && out.ObjectLockConfiguration != nil:
		settings.ObjectLock = contract.BucketSetting{Known: true, Value: objectLockValue(out.ObjectLockConfiguration)}
	case notConfigured(err):
		settings.ObjectLock = contract.BucketSetting{Known: true, Value: "not enabled"}
	}

	enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: name})
	switch {
	case err == nil:
		settings.Encryption = contract.BucketSetting{Known: true, Value: encryptionValue(enc.ServerSideEncryptionConfiguration)}
	case notConfigured(err):
		settings.Encryption = contract.BucketSetting{Known: true, Value: "none"}
	}

	lc, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: name})
	switch {
	case err == nil:
		settings.Retention = contract.BucketSetting{Known: true, Value: retentionValue(lc.Rules)}
	case notConfigured(err):
		settings.Retention = contract.BucketSetting{Known: true, Value: retentionValue(nil)}
	}

	return settings
}

func unknownSetting() contract.BucketSetting { return contract.BucketSetting{} }

// S3 answers "this bucket has no such configuration" with an error, which is a
// known setting, unlike a permission or transport failure.
func notConfigured(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "ObjectLockConfigurationNotFoundError", "ServerSideEncryptionConfigurationNotFoundError", "NoSuchLifecycleConfiguration":
		return true
	}
	return false
}

func objectLockValue(cfg *types.ObjectLockConfiguration) string {
	if cfg.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		return "not enabled"
	}
	if cfg.Rule == nil || cfg.Rule.DefaultRetention == nil {
		return "enabled, no default retention"
	}
	retention := cfg.Rule.DefaultRetention
	mode := strings.ToLower(string(retention.Mode))
	switch {
	case retention.Days != nil:
		return fmt.Sprintf("%s, %d days", mode, *retention.Days)
	case retention.Years != nil:
		return fmt.Sprintf("%s, %d years", mode, *retention.Years)
	default:
		return mode
	}
}

func encryptionValue(cfg *types.ServerSideEncryptionConfiguration) string {
	if cfg == nil || len(cfg.Rules) == 0 || cfg.Rules[0].ApplyServerSideEncryptionByDefault == nil {
		return "none"
	}
	return string(cfg.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm)
}

func retentionValue(rules []types.LifecycleRule) string {
	for _, rule := range rules {
		if rule.Expiration != nil && rule.Expiration.Days != nil {
			return fmt.Sprintf("%d days", *rule.Expiration.Days)
		}
	}
	return "no expiration rule"
}

const fetchAttemptSelect = `
select
  fat.id,
  fat.occurred_at,
  fat.source_kind::text,
  fat.requested_ref,
  fat.outcome::text,
  coalesce(fat.detail, '')
from fetch_attempt as fat
order by fat.occurred_at desc, fat.id desc
limit ?`

func recentFetches(ctx context.Context, db bun.IDB) ([]contract.FetchAttemptSummary, error) {
	rows, err := db.QueryContext(ctx, fetchAttemptSelect, recentFetchLimit)
	if err != nil {
		return nil, fmt.Errorf("read recent fetches: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []contract.FetchAttemptSummary{}
	for rows.Next() {
		var f contract.FetchAttemptSummary
		if err := rows.Scan(&f.ID, &f.OccurredAt, &f.SourceKind, &f.RequestedRef, &f.Outcome, &f.Detail); err != nil {
			return nil, fmt.Errorf("scan a fetch attempt: %w", err)
		}
		f.OccurredAt = f.OccurredAt.UTC()
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read recent fetches: %w", err)
	}
	return out, nil
}
