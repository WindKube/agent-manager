package fetcher

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/blob"
	"agent-manager/internal/store/models"
)

func TestConflictMessageNamesTheStateBlockingRegistration(t *testing.T) {
	ref := blob.VersionRef{Namespace: "acme", Name: "widget", Semver: "1.2.3"}

	cases := []struct {
		name    string
		version *models.Version
		want    []string
		reject  []string
	}{
		{
			name:    "a version whose fetch never landed does not claim to be published",
			version: &models.Version{Verdict: models.VerdictScanning, Visible: false, Digest: nil},
			want:    []string{"acme/widget@1.2.3", "fetch has not finished"},
			reject:  []string{"already published"},
		},
		{
			name:    "a published version still awaiting scan reads as published",
			version: &models.Version{Verdict: models.VerdictScanning, Visible: true, Digest: []byte{0xab}},
			want:    []string{"acme/widget@1.2.3", "already published", "immutable"},
		},
		{
			name:    "a clean published version reads as published",
			version: &models.Version{Verdict: models.VerdictClean, Visible: true, Digest: []byte{0xab}},
			want:    []string{"acme/widget@1.2.3", "already published", "immutable"},
		},
		{
			name:    "a flagged version names the scanner's verdict",
			version: &models.Version{Verdict: models.VerdictFlagged, Visible: true, Digest: []byte{0xab}},
			want:    []string{"acme/widget@1.2.3", "flagged", "immutable"},
		},
		{
			name:    "a rejected version names the scanner's verdict",
			version: &models.Version{Verdict: models.VerdictRejected, Visible: true, Digest: []byte{0xab}},
			want:    []string{"acme/widget@1.2.3", "rejected", "immutable"},
		},
		{
			name:    "the race the insert-time catch loses has no row left to describe",
			version: nil,
			want:    []string{"acme/widget@1.2.3", "immutable"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := conflictMessage(ref, tc.version)
			for _, want := range tc.want {
				require.Contains(t, got, want)
			}
			for _, reject := range tc.reject {
				require.NotContains(t, got, reject)
			}
		})
	}
}
