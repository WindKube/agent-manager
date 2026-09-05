package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/uptrace/bun"
)

// Sessions resolves opaque server-side session tokens; it never creates one
// (that's a command in internal/api/commands, which writes an audit row).
type Sessions struct {
	db bun.IDB
}

func NewSessions(db bun.IDB) Sessions { return Sessions{db: db} }

// sessionResolveSQL joins the session, its identity and mapped roles in one
// statement, since this runs on every authenticated request. Two non-stylistic
// details: `?` not `$1` (bun formats placeholders inline, so `$N` reaches
// Postgres unbound), and the arrays render as JSON (pgx's stdlib driver
// won't scan a Postgres array into a []string over database/sql).
const sessionResolveSQL = `
select
  i.id,
  i.subject,
  coalesce(i.email, '') as email,
  coalesce(i.display_name, '') as display_name,
  array_to_json(i.groups)::text as groups,
  coalesce((
    select json_agg(m.role)
    from group_role_map as m
    where m.group_name = any (i.groups)
  )::text, '[]') as mapped_roles
from session as s
join identity as i on i.id = s.identity_id
where s.token_hash = ? and s.expires_at > now()`

// Resolve exchanges a raw bearer token for a principal. The token is hashed
// before it reaches the query, so the plaintext never appears in a
// statement, a query log or a database row.
func (s Sessions) Resolve(ctx context.Context, token string) (Principal, error) {
	if token == "" {
		return Principal{}, ErrUnauthenticated
	}

	var (
		p           Principal
		groupsJSON  string
		rolesJSON   string
		mappedRoles []string
	)
	row := s.db.QueryRowContext(ctx, sessionResolveSQL, HashToken(token))
	err := row.Scan(&p.IdentityID, &p.Subject, &p.Email, &p.DisplayName, &groupsJSON, &rolesJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Principal{}, ErrUnauthenticated
	case err != nil:
		return Principal{}, fmt.Errorf("resolve session: %w", err)
	}
	if err := json.Unmarshal([]byte(groupsJSON), &p.Groups); err != nil {
		return Principal{}, fmt.Errorf("decode identity groups: %w", err)
	}
	if err := json.Unmarshal([]byte(rolesJSON), &mappedRoles); err != nil {
		return Principal{}, fmt.Errorf("decode mapped roles: %w", err)
	}

	p.Role = HighestRole(mappedRoles)
	p.Source = SourceWeb
	return p, nil
}

// Source values for the audit row's source column.
const (
	SourceWeb    = "web"
	SourceSystem = "system"
)

func CLISource(host string) string { return "cli / " + host }
