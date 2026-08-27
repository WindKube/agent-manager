// Package queries is the read side of the api role (constitution principle
// VIII). A query is read-only, opens no transaction and is free to use
// purpose-built SQL instead of the object mapper's relation loading.
//
// This is command/query separation in code, not in infrastructure: there is no
// command bus, no event sourcing, no read replica and no eventual consistency to
// design around. The constitution rejects CQRS-as-architecture explicitly, so
// nothing here builds toward one.
package queries

import (
	"errors"
	"strings"

	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
)

// ErrNotFound is returned when a row does not exist OR the caller may not read
// it. One error for both, on purpose: distinguishing them would enumerate the
// profiles FR-044 says a client must not be able to enumerate.
var ErrNotFound = errors.New("not found")

// Readable renders the FR-044 readability predicate for one principal, as a SQL
// fragment over the given alias of table `profile`, plus its arguments in order.
//
// It exists exactly once and every profile-scoped statement composes it —
// listProfiles, getRevision and reportSync all call it. Three hand-written
// copies of an authorisation predicate is how one of them silently drifts.
//
// The predicate is the whole point of FR-044: a client sees exactly the profiles
// its identity may read and no others. It is a WHERE clause and never a filter
// applied to a fetched list, so an unreadable profile is not merely hidden — it
// is never selected, never counted, never returned to Go at all.
//
// Three ways a profile becomes readable, and nothing else is one:
//
//   - organisation visibility, which is what FR-037's "Organisation" means and
//     what makes the design's `contractors -> read-only, org profiles only`
//     expressible;
//   - a direct user membership naming this identity;
//   - a group membership naming one of the identity's mapped groups.
func Readable(alias string, p auth.Principal) (predicate string, args []any) {
	var subject []string
	if refs := p.Refs(); len(refs) > 0 {
		subject = append(subject, "(m.subject_kind = 'user' and m.subject_ref in (?))")
		args = append(args, bun.List(refs))
	}
	if len(p.Groups) > 0 {
		subject = append(subject, "(m.subject_kind = 'group' and m.subject_ref in (?))")
		args = append(args, bun.List(p.Groups))
	}

	clauses := []string{alias + ".visibility = 'organisation'"}
	if len(subject) > 0 {
		clauses = append(clauses, "exists (select 1 from membership as m where m.profile_id = "+
			alias+".id and ("+strings.Join(subject, " or ")+"))")
	}
	return "(" + strings.Join(clauses, " or ") + ")", args
}
