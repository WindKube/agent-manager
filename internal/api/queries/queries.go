// Package queries is the read side of the api role: read-only, no
// transactions, free to use purpose-built SQL.
package queries

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/auth"
)

// ErrNotFound is returned when a row does not exist or the caller may not
// read it; one error for both so a client cannot enumerate private profiles.
var ErrNotFound = errors.New("not found")

// Readable renders the profile readability predicate for p as a SQL fragment
// over alias, plus its args. Every profile-scoped statement must compose this
// single copy, as a WHERE clause, so unreadable profiles are never selected
// or counted. A service token reads only the profiles its sync scopes name
// that its creator can read now.
func Readable(alias string, p auth.Principal) (predicate string, args []any) {
	if p.IsServiceToken() {
		slugs := p.ServiceToken.Profiles()
		if len(slugs) == 0 {
			return "false", nil
		}
		creator, creatorArgs := Readable(alias, p.ServiceToken.Creator)
		return "(" + alias + ".slug in (?) and " + creator + ")", append([]any{bun.List(slugs)}, creatorArgs...)
	}

	subject, args, matchable := subjectPredicate("m", p)

	clauses := []string{alias + ".visibility = 'organisation'"}
	if matchable {
		clauses = append(clauses, "exists (select 1 from membership as m where m.profile_id = "+
			alias+".id and "+subject+")")
	}
	return "(" + strings.Join(clauses, " or ") + ")", args
}

// PackageReadable is Readable for table `package`. The owner clause is
// separate from the team clause so an owner never loses their own package to
// a group they later leave. A service token needs read:catalog and then reads
// only what its creator can read now; Bundle widens this for sync scopes.
func PackageReadable(alias string, p auth.Principal) (predicate string, args []any) {
	if p.IsServiceToken() {
		if !p.ServiceToken.Allows(auth.ScopeReadCatalog) {
			return "false", nil
		}
		return PackageReadable(alias, p.ServiceToken.Creator)
	}

	clauses := []string{alias + ".visibility = 'organisation'"}
	if p.IdentityID != uuid.Nil {
		clauses = append(clauses, alias+".owner_identity_id = ?")
		args = append(args, p.IdentityID)
	}
	if len(p.Groups) > 0 {
		clauses = append(clauses, "("+alias+".visibility = 'team' and exists ("+
			"select 1 from identity as owner_idt where owner_idt.id = "+alias+".owner_identity_id "+
			"and owner_idt.groups && ?::text[]))")
		args = append(args, pgdialect.Array(p.Groups))
	}
	return "(" + strings.Join(clauses, " or ") + ")", args
}

// subjectPredicate renders "this membership row names this identity" over
// alias. Readable and the profile detail share it so their matching cannot
// disagree. matchable is false when p can match no row; callers then omit the
// clause instead of emitting a constantly false subquery.
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
