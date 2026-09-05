// Package queries is the read side of the api role. A query is read-only,
// opens no transaction and is free to use purpose-built SQL instead of the
// object mapper's relation loading. This is command/query separation in
// code, not in infrastructure: no command bus, event sourcing, read
// replica, or eventual consistency to design around.
package queries

import (
	"errors"
	"strings"

	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
)

// ErrNotFound is returned when a row does not exist or the caller may not
// read it. One error for both, on purpose: distinguishing them would
// enumerate the profiles a client must not be able to enumerate.
var ErrNotFound = errors.New("not found")

// Readable renders the readability predicate for one principal, as a SQL
// fragment over the given alias of table `profile`, plus its arguments in
// order. It exists exactly once and every profile-scoped statement composes
// it: three hand-written copies of an authorisation predicate is how one of
// them silently drifts.
//
// It is a WHERE clause and never a filter applied to a fetched list, so an
// unreadable profile is not merely hidden — it is never selected, never
// counted, never returned to Go at all.
//
// Three ways a profile becomes readable, and nothing else is one:
// organisation visibility; a direct user membership naming this identity;
// or a group membership naming one of the identity's mapped groups.
func Readable(alias string, p auth.Principal) (predicate string, args []any) {
	subject, args, matchable := subjectPredicate("m", p)

	clauses := []string{alias + ".visibility = 'organisation'"}
	if matchable {
		clauses = append(clauses, "exists (select 1 from membership as m where m.profile_id = "+
			alias+".id and "+subject+")")
	}
	return "(" + strings.Join(clauses, " or ") + ")", args
}

// subjectPredicate renders "this membership row names this identity", over
// the given alias of table `membership`, plus its arguments in order. It is
// separate from Readable because Readable asks whether any row names the
// caller, while the profile detail asks which role the rows that name them
// carry — spelling the email/subject/group matching twice is how the two
// come to disagree.
//
// matchable is false when the principal can match no membership row at all.
// A caller must then leave the clause out altogether rather than emit a
// subquery that is constantly false, keeping the emitted predicate for an
// anonymous-ish identity down to the visibility test.
func subjectPredicate(alias string, p auth.Principal) (predicate string, args []any, matchable bool) {
	var clauses []string
	if refs := p.Refs(); len(refs) > 0 {
		clauses = append(clauses, "("+alias+".subject_kind = 'user' and "+alias+".subject_ref in (?))")
		args = append(args, bun.List(refs))
	}
	if len(p.Groups) > 0 {
		clauses = append(clauses, "("+alias+".subject_kind = 'group' and "+alias+".subject_ref in (?))")
		args = append(args, bun.List(p.Groups))
	}
	if len(clauses) == 0 {
		return "", nil, false
	}
	return "(" + strings.Join(clauses, " or ") + ")", args, true
}
