package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/uptrace/bun"
)

// Sessions resolves opaque server-side session tokens. It reads; it never
// creates one — creating a session is a command (it writes an audit row inside
// the login transaction), and it lives in internal/api/commands.
type Sessions struct {
	db bun.IDB
}

func NewSessions(db bun.IDB) Sessions { return Sessions{db: db} }

// sessionResolveSQL is one statement: the session, the identity it belongs to,
// and the roles that identity's groups map to. One statement rather than three
// because this runs on every authenticated request.
//
// Two details that are not stylistic:
//
//   - `?` and never `$1`. bun formats placeholders inline and passes no args to
//     the driver, so a `$N` reaches Postgres unbound (SQLSTATE 42P02).
//   - the two arrays are rendered as JSON in the statement. bun's raw query path
//     is database/sql, and pgx's stdlib driver hands a Postgres array over that
//     seam as its text form, which will not scan into a []string. Asking for JSON
//     needs no array parser and no driver-specific type.
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

// Resolve exchanges a raw bearer token for a principal.
//
// The token is hashed before it reaches the query, so the plaintext never
// appears in a statement, a query log or a database row. An unknown or expired
// token is one error, not two: telling them apart tells an attacker whether a
// token ever existed.
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

// Source values for the audit row's source column (FR-050).
const (
	SourceWeb    = "web"
	SourceSystem = "system"
)

// CLISource names a machine client's host, which is the form FR-050 requires.
func CLISource(host string) string { return "cli / " + host }
