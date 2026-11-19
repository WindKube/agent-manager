package fakeapi

import (
	"time"

	"github.com/google/uuid"

	"agent-manager/internal/apiclient"
)

func seedOrganization() apiclient.Organization {
	return apiclient.Organization{
		Provider: apiclient.OrganizationProvider{
			Issuer:                      "https://idp.fixture.invalid",
			ClientId:                    "am-hub-fixture",
			Scopes:                      []string{"openid", "profile", "email", "groups"},
			DeviceAuthorizationEndpoint: ptr("https://idp.fixture.invalid/device"),
		},
		Policy: apiclient.OrganizationPolicy{
			ScanGate:             apiclient.OrganizationPolicyScanGateApproval,
			RequireSignedBundles: true,
			CommunityNeedsReview: true,
		},
		Mappings: []apiclient.GroupRoleMapping{
			{GroupName: "eng-platform", Role: apiclient.GroupRoleMappingRoleCatalogAdmin},
			{GroupName: "eng-security", Role: apiclient.GroupRoleMappingRoleScannerReviewer},
		},
		Categories: []apiclient.OrganizationCategory{
			{Id: uuid.MustParse("d290f1ee-6c54-4b01-90e6-d701748f0851"), Name: "Infrastructure", Slug: "infrastructure", Count: 4},
			{Id: uuid.MustParse("e290f1ee-6c54-4b01-90e6-d701748f0852"), Name: "Documentation", Slug: "documentation", Count: 1},
		},
	}
}

func seedStorage(now time.Time) apiclient.StorageReport {
	known := func(v string) apiclient.BucketSetting { return apiclient.BucketSetting{Known: true, Value: &v} }
	fetch := func(id string, ago time.Duration, kind apiclient.FetchAttemptSummarySourceKind, ref string,
		outcome apiclient.FetchAttemptSummaryOutcome) apiclient.FetchAttemptSummary {
		return apiclient.FetchAttemptSummary{
			Id: uuid.MustParse(id), OccurredAt: now.Add(-ago), SourceKind: kind, RequestedRef: ref, Outcome: outcome,
		}
	}

	unreachable := fetch("b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e03", 2*day, apiclient.FetchAttemptSummarySourceKindArchiveUrl,
		"https://example.dev/community/slack-digest.tar.gz", apiclient.FetchAttemptSummaryOutcomeUnreachable)
	unreachable.Detail = ptr("connection reset while downloading the archive")

	return apiclient.StorageReport{
		ObjectCount:     3912,
		CompressedBytes: 2576980378, // 2.4 GiB
		Region:          ptr("eu-central-1"),
		KeyLayout: []apiclient.StorageKeyCount{
			{Prefix: "skills", Objects: 3890},
			{Prefix: "profiles", Objects: 22},
		},
		Bucket: apiclient.BucketSettings{
			Versioning:  known("enabled"),
			ObjectLock:  known("compliance, 90 days"),
			Encryption:  known("aws:kms"),
			WriteAccess: known("fetcher role only"),
			Retention:   known("18 months"),
		},
		RecentFetches: []apiclient.FetchAttemptSummary{
			fetch("b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e01", 6*time.Hour, apiclient.FetchAttemptSummarySourceKindGit,
				"skills/community/release-notes/1.2.7/bundle.tar.zst", apiclient.FetchAttemptSummaryOutcomeOk),
			fetch("b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e02", 2*day, apiclient.FetchAttemptSummarySourceKindGit,
				"skills/example/terraform-module-review/2.4.1/bundle.tar.zst", apiclient.FetchAttemptSummaryOutcomeOk),
			unreachable,
			fetch("b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e04", 4*day, apiclient.FetchAttemptSummarySourceKindUpload,
				"pii-redactor-1.4.2.zip", apiclient.FetchAttemptSummaryOutcomeOk),
			fetch("b3e6a5b7-6b7b-4a34-8e0e-1a2b3c4d5e05", 5*day, apiclient.FetchAttemptSummarySourceKindGit,
				"skills/example/k8s-incident-triage/1.9.0/bundle.tar.zst", apiclient.FetchAttemptSummaryOutcomeOk),
		},
	}
}

// seedRuntime is a fetch queue working a small backlog, a scan queue with one
// discarded and one retrying job, and 24 hourly buckets with a quiet gap.
func seedRuntime(now time.Time) apiclient.RuntimeReport {
	history := make([]apiclient.RunBucket, 24)
	for i := range history {
		fetch, scan := int64(4), int64(1)
		if i > 8 && i < 14 {
			fetch, scan = 0, 0
		}
		if i == 23 {
			fetch, scan = 6, 3
		}
		history[i] = apiclient.RunBucket{
			StartsAt: now.Truncate(time.Hour).Add(time.Duration(i-23) * time.Hour),
			Fetch:    fetch, Scan: scan,
		}
	}

	const signature = "rule pack load failed: signature mismatch for pack 2026.09.10"
	return apiclient.RuntimeReport{
		BucketMinutes: 60,
		Queues: []apiclient.QueueSummary{
			{Queue: apiclient.QueueSummaryQueueFetch, Counts: apiclient.QueueJobCounts{Available: 2, Running: 1, Completed: 4180, Retryable: 1}},
			{Queue: apiclient.QueueSummaryQueueScan, Counts: apiclient.QueueJobCounts{Running: 1, Completed: 4102, Discarded: 1, Cancelled: 3}},
		},
		Errors: apiclient.RuntimeErrors{
			Discarded: []apiclient.RuntimeJob{{
				Id: 48213, Queue: apiclient.RuntimeJobQueueScan, Kind: "scan", Attempt: 5, MaxAttempts: 5,
				ScheduledAt: now.Add(-3 * time.Hour), FinalizedAt: ptr(now.Add(-3 * time.Hour)),
				Errors: []apiclient.JobAttemptError{
					{At: now.Add(-4 * time.Hour), Attempt: 4, Error: signature},
					{At: now.Add(-3 * time.Hour), Attempt: 5, Error: signature},
				},
			}},
			Retrying: []apiclient.RuntimeJob{{
				Id: 48310, Queue: apiclient.RuntimeJobQueueFetch, Kind: "fetch", Attempt: 2, MaxAttempts: 5,
				ScheduledAt: now.Add(15 * time.Minute),
				Errors: []apiclient.JobAttemptError{
					{At: now.Add(-10 * time.Minute), Attempt: 2, Error: "unreachable: dial tcp: connection reset while downloading the archive"},
				},
			}},
		},
		RunHistory: history,
	}
}
