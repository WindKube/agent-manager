package queries_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
)

// The FR-044 predicate is the one piece of authorisation logic in this package
// that is pure, so it gets a container-free test of its own. The integration
// suite proves it filters in SQL; this proves which clauses it emits, which is
// what a refactor is most likely to quietly drop.
func TestReadablePredicateEmitsOneClausePerWayIn(t *testing.T) {
	for _, tc := range []struct {
		name        string
		principal   auth.Principal
		wantClauses []string
		wantMissing []string
		wantArgs    int
	}{
		{
			name:        "an identity with no email, subject or group can still read organisation profiles",
			principal:   auth.Principal{},
			wantClauses: []string{"p.visibility = 'organisation'"},
			wantMissing: []string{"membership"},
			wantArgs:    0,
		},
		{
			name:      "a direct membership is matched by email and subject",
			principal: auth.Principal{Email: "kwiatrzyk@example.com", Subject: "sub-kw"},
			wantClauses: []string{
				"p.visibility = 'organisation'",
				"m.subject_kind = 'user'",
				"m.profile_id = p.id",
			},
			wantMissing: []string{"m.subject_kind = 'group'"},
			wantArgs:    1,
		},
		{
			name:      "a group membership is matched by group name",
			principal: auth.Principal{Groups: []string{"eng-security"}},
			wantClauses: []string{
				"p.visibility = 'organisation'",
				"m.subject_kind = 'group'",
			},
			wantMissing: []string{"m.subject_kind = 'user'"},
			wantArgs:    1,
		},
		{
			name: "both ways in are one subquery, not two",
			principal: auth.Principal{
				Email:  "anowak@example.com",
				Groups: []string{"eng-security"},
			},
			wantClauses: []string{"m.subject_kind = 'user'", "m.subject_kind = 'group'"},
			wantArgs:    2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			predicate, args := queries.Readable("p", tc.principal)

			for _, clause := range tc.wantClauses {
				require.Containsf(t, predicate, clause, "predicate was %s", predicate)
			}
			for _, clause := range tc.wantMissing {
				require.NotContainsf(t, predicate, clause, "predicate was %s", predicate)
			}
			require.Len(t, args, tc.wantArgs)

			// Both ways in share one subquery, and a principal that can match no
			// membership row gets none at all.
			wantSubqueries := 0
			if tc.wantArgs > 0 {
				wantSubqueries = 1
			}
			require.Equal(t, wantSubqueries, strings.Count(predicate, "exists (select 1 from membership"),
				"predicate was %s", predicate)
		})
	}
}

func TestReadablePredicateHonoursTheAliasItIsGiven(t *testing.T) {
	predicate, _ := queries.Readable("prf", auth.Principal{Email: "a@example.com"})
	require.Contains(t, predicate, "prf.visibility")
	require.Contains(t, predicate, "m.profile_id = prf.id")
}
