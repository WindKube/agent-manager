package hub

import (
	"context"
	"fmt"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// Storage reads GET /v1/storage and returns view.Storage directly: there is
// exactly one caller, so no separate hub-owned type is worth the indirection.
func (c *Client) Storage(ctx context.Context) (view.Storage, error) {
	resp, err := c.api.GetStorageWithResponse(ctx)
	if err != nil {
		return view.Storage{}, fmt.Errorf("read the storage report: %w", err)
	}
	if resp.JSON200 == nil {
		return view.Storage{}, fmt.Errorf("read the storage report: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	out := view.Storage{
		ObjectCount:    int(body.ObjectCount),
		CompressedSize: humanSize(body.CompressedBytes),
		Truncated:      body.Truncated,
		Region:         deref(body.Region),
		KeyLayout:      make([]view.KeyLayoutRow, 0, len(body.KeyLayout)),
		RecentFetches:  make([]view.FetchRow, 0, len(body.RecentFetches)),
		Bucket: view.BucketSettings{
			Versioning:  bucketSetting(body.Bucket.Versioning),
			ObjectLock:  bucketSetting(body.Bucket.ObjectLock),
			Encryption:  bucketSetting(body.Bucket.Encryption),
			WriteAccess: bucketSetting(body.Bucket.WriteAccess),
			Retention:   bucketSetting(body.Bucket.Retention),
		},
	}
	if body.ReadCacheHitRate != nil {
		out.ReadCacheHitRate = fmt.Sprintf("%.0f%%", *body.ReadCacheHitRate*100)
	}
	for _, entry := range body.KeyLayout {
		out.KeyLayout = append(out.KeyLayout, view.KeyLayoutRow{Prefix: entry.Prefix, Objects: int(entry.Objects)})
	}
	for _, fetch := range body.RecentFetches {
		out.RecentFetches = append(out.RecentFetches, view.FetchRow{
			ID:      fetch.Id.String(),
			At:      view.Timestamp(fetch.OccurredAt),
			Kind:    string(fetch.SourceKind),
			Ref:     fetch.RequestedRef,
			Outcome: string(fetch.Outcome),
			Detail:  deref(fetch.Detail),
		})
	}
	return out, nil
}

func bucketSetting(from apiclient.BucketSetting) view.BucketSetting {
	return view.BucketSetting{Known: from.Known, Value: deref(from.Value)}
}
