package fetcher

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/worker"
)

func TestSelectTagsPicksNewerReleasesMatchingThePatternOldestFirst(t *testing.T) {
	tags := []string{
		"v1.2.0", "v1.10.0", "v1.9.0", "v2.0.0-rc.1", "v2.0.0", "release-3.0.0",
		"v1.3", "latest", "v1.11.0+build.7", "1.12.0", "v01.13.0",
	}

	for _, tc := range []struct {
		name    string
		pattern string
		known   []string
		limit   int
		want    []Candidate
	}{
		{
			name: "semver order, not string order, and only above the newest known version",
			// 1.10.0 sorts above 1.9.0; v1.3 is not semver, 1.12.0 lacks the v the
			// pattern asks for, v01.13.0 has a leading zero and v1.11.0+build.7
			// carries build metadata that no version sort can tell apart.
			pattern: "v*", known: []string{"1.2.0", "1.9.0-rc.1"}, limit: 5,
			want: []Candidate{{"v1.9.0", "1.9.0"}, {"v1.10.0", "1.10.0"}, {"v2.0.0", "2.0.0"}},
		},
		{
			name:    "a known version above a tag hides it, whatever state that version is in",
			pattern: "v*", known: []string{"1.10.0"}, limit: 5,
			want: []Candidate{{"v2.0.0", "2.0.0"}},
		},
		{
			name:    "a prerelease is registered only when the pattern names one",
			pattern: "v*-*", known: []string{"1.10.0"}, limit: 5,
			want: []Candidate{{"v2.0.0-rc.1", "2.0.0-rc.1"}},
		},
		{
			name:    "another prefix is another pattern",
			pattern: "release-*", known: []string{"1.0.0"}, limit: 5,
			want: []Candidate{},
		},
		{
			name:    "the cap keeps the oldest, so the next check continues from there",
			pattern: "v*", known: nil, limit: 2,
			want: []Candidate{{"v1.2.0", "1.2.0"}, {"v1.9.0", "1.9.0"}},
		},
		{
			name:    "nothing newer is nothing",
			pattern: "v*", known: []string{"9.0.0"}, limit: 5,
			want: []Candidate{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, SelectTags(tags, tc.pattern, tc.known, tc.limit))
		})
	}
}

func TestATagPatternMustBeAGlob(t *testing.T) {
	for _, ok := range []string{"v*", "release-*", "v[0-9]*", "*"} {
		require.True(t, ValidTagPattern(ok), ok)
	}
	for _, bad := range []string{"", "v[", fmt.Sprintf("%0101d", 0)} {
		require.False(t, ValidTagPattern(bad), bad)
	}
}

func TestTheUpstreamCheckIsScheduledAtTheConfiguredIntervalAndNoFaster(t *testing.T) {
	jobs, err := Definition().Periodic(worker.Config{UpstreamInterval: time.Hour})
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	_, err = Definition().Periodic(worker.Config{UpstreamInterval: 4 * time.Minute})
	require.ErrorContains(t, err, "AGENT_MANAGER_UPSTREAM_INTERVAL is 4m0s; it must be at least 5m0s")
}
