//go:build integration

package api_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type installRow struct{ pkg, version, target string }

func machineInstalls(t *testing.T, machine uuid.UUID) []installRow {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		select p.namespace || '/' || p.name, v.semver, i.target::text
		from machine_install i join package p on p.id = i.package_id join version v on v.id = i.version_id
		where i.machine_id = $1 order by 1, 3`, machine)
	require.NoError(t, err)
	defer rows.Close()
	var out []installRow
	for rows.Next() {
		var r installRow
		require.NoError(t, rows.Scan(&r.pkg, &r.version, &r.target))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func machineSkips(t *testing.T, machine uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		select entry || coalesce(' ' || target::text || ' ' || component || ': ' || reason, '')
		from machine_skip where machine_id = $1 order by 1`, machine)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestASecondReportReplacesTheMachinesInstallsForItsProfile(t *testing.T) {
	ctx := context.Background()
	h := liveHandler(t)
	machine := uuid.New()

	report := func(installed, skippedComponents string) {
		t.Helper()
		body := fmt.Sprintf(`{"profile":"platform-baseline","revision":2,"host":"inv-laptop","targets":["claude-code","codex"],
			"machineId":%q,"os":"darwin","arch":"arm64","amctlVersion":"0.9.0",
			"skipped":["acme/legacy-helper"],"installed":[%s],"skippedComponents":[%s]}`,
			machine, installed, skippedComponents)
		rec := request(t, h, http.MethodPost, "/v1/sync", kw.token, body)
		require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	}

	report(`{"id":"acme/code-review","version":"2.4.1","target":"claude-code","changed":true},
		{"id":"acme/threat-model","version":"1.0.0","target":"codex","changed":true}`,
		`{"entry":"acme/code-review","target":"claude-code","component":"mcp-server lint","reason":"no claude CLI"}`)
	require.Equal(t, []installRow{
		{"acme/code-review", "2.4.1", "claude-code"},
		{"acme/threat-model", "1.0.0", "codex"},
	}, machineInstalls(t, machine))
	require.Equal(t, []string{
		"acme/code-review claude-code mcp-server lint: no claude CLI",
		"acme/legacy-helper",
	}, machineSkips(t, machine))

	var firstSeen, lastSeen1 string
	require.NoError(t, pool.QueryRow(ctx, `select first_seen_at::text, last_seen_at::text from machine where id = $1`,
		machine).Scan(&firstSeen, &lastSeen1))

	// code-review untouched keeps its component skip; threat-model is gone.
	report(`{"id":"acme/code-review","version":"2.4.1","target":"claude-code"}`, "")
	require.Equal(t, []installRow{{"acme/code-review", "2.4.1", "claude-code"}}, machineInstalls(t, machine))
	require.Equal(t, []string{
		"acme/code-review claude-code mcp-server lint: no claude CLI",
		"acme/legacy-helper",
	}, machineSkips(t, machine))

	// Rewritten with every component placed: its old skip goes.
	report(`{"id":"acme/code-review","version":"2.4.1","target":"claude-code","changed":true}`, "")
	require.Equal(t, []string{"acme/legacy-helper"}, machineSkips(t, machine))

	var host, os, arch, version, firstSeen2, lastSeen2 string
	var revisionSeq int
	require.NoError(t, pool.QueryRow(ctx, `select m.hostname, m.os, m.arch, m.amctl_version,
		m.first_seen_at::text, m.last_seen_at::text, r.seq
		from machine m join revision r on r.id = m.last_revision_id where m.id = $1`, machine).
		Scan(&host, &os, &arch, &version, &firstSeen2, &lastSeen2, &revisionSeq))
	require.Equal(t, []string{"inv-laptop", "darwin", "arm64", "0.9.0"}, []string{host, os, arch, version})
	require.Equal(t, firstSeen, firstSeen2, "first seen is set once")
	require.GreaterOrEqual(t, lastSeen2, lastSeen1)
	require.Equal(t, 2, revisionSeq)
	require.Equal(t, 3, countRows(t, fmt.Sprintf(
		`select count(*) from audit_event where kind = 'sync' and data ->> 'machineId' = '%s'`, machine)),
		"the sync audit row is the record of each report; the inventory writes none of its own")
}

func TestAReportOnlyReplacesTheReportedProfilesInstalls(t *testing.T) {
	h := liveHandler(t)
	machine := uuid.New()

	for _, body := range []string{
		`{"profile":"platform-baseline","revision":2,"host":"two-profiles","targets":["claude-code"],"machineId":%q,
			"installed":[{"id":"acme/code-review","version":"2.4.1","target":"claude-code"}]}`,
		`{"profile":"kw-private","revision":1,"host":"two-profiles","targets":["codex"],"machineId":%q,
			"installed":[{"id":"acme/threat-model","version":"1.0.0","target":"codex"}]}`,
	} {
		rec := request(t, h, http.MethodPost, "/v1/sync", kw.token, fmt.Sprintf(body, machine))
		require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	}
	require.Equal(t, []installRow{
		{"acme/code-review", "2.4.1", "claude-code"},
		{"acme/threat-model", "1.0.0", "codex"},
	}, machineInstalls(t, machine))
}

func TestAReportWithoutAMachineIDIsRecordedWithNoMachine(t *testing.T) {
	h := liveHandler(t)
	machines := countRows(t, "select count(*) from machine")
	events := countRows(t, "select count(*) from sync_event")

	rec := request(t, h, http.MethodPost, "/v1/sync", kw.token,
		`{"profile":"platform-baseline","revision":2,"host":"old-client","targets":["claude-code"]}`)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	require.Equal(t, events+1, countRows(t, "select count(*) from sync_event"))
	require.Equal(t, machines, countRows(t, "select count(*) from machine"))
}

func TestAReportNamingAVersionTheHubDoesNotHoldWritesNothing(t *testing.T) {
	h := liveHandler(t)
	machine := uuid.New()
	events := countRows(t, "select count(*) from sync_event")
	audits := countRows(t, "select count(*) from audit_event")

	for _, installed := range []string{
		`{"id":"acme/code-review","version":"9.9.9","target":"claude-code"}`,
		`{"id":"acme/code-review","version":"2.4.1","target":"claude-code"},{"id":"acme/code-review","version":"2.4.1","target":"claude-code"}`,
		`{"id":"no-namespace","version":"1.0.0","target":"claude-code"}`,
	} {
		rec := request(t, h, http.MethodPost, "/v1/sync", kw.token, fmt.Sprintf(
			`{"profile":"platform-baseline","revision":2,"host":"bad","targets":["claude-code"],"machineId":%q,"installed":[%s]}`,
			machine, installed))
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	}
	require.Equal(t, events, countRows(t, "select count(*) from sync_event"))
	require.Equal(t, audits, countRows(t, "select count(*) from audit_event"))
	require.Equal(t, 0, countRows(t, fmt.Sprintf("select count(*) from machine where id = '%s'", machine)))
}

func TestAServiceTokenReportIsAttributedToTheTokenAndItsCreator(t *testing.T) {
	ctx := context.Background()
	h := liveHandler(t)
	created := createServiceToken(t, kw, "ci-inventory", "sync:profile/kw-private")
	machine := uuid.New()

	rec := request(t, h, http.MethodPost, "/v1/sync", created.Secret, fmt.Sprintf(
		`{"profile":"kw-private","revision":1,"host":"ci-runner-7","targets":["claude-code"],"machineId":%q,
		"installed":[{"id":"acme/code-review","version":"2.4.1","target":"claude-code","changed":true}]}`, machine))
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())

	var tokenID *uuid.UUID
	var identity uuid.UUID
	require.NoError(t, pool.QueryRow(ctx, `select last_service_token_id, last_identity_id from machine where id = $1`,
		machine).Scan(&tokenID, &identity))
	require.NotNil(t, tokenID)
	require.Equal(t, created.Token.ID, *tokenID)
	require.Equal(t, principalFor(t, kw).IdentityID, identity)

	// The same machine reported by a person afterwards is theirs, not the token's.
	rec = request(t, h, http.MethodPost, "/v1/sync", kw.token, fmt.Sprintf(
		`{"profile":"kw-private","revision":1,"host":"ci-runner-7","targets":["claude-code"],"machineId":%q}`, machine))
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	require.NoError(t, pool.QueryRow(ctx, `select last_service_token_id from machine where id = $1`, machine).Scan(&tokenID))
	require.Nil(t, tokenID)
	require.Empty(t, machineInstalls(t, machine), "no installed list is an empty profile")
}
