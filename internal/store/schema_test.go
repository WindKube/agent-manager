// No `integration` tag on purpose: these container-free staleness guards over
// internal/store/schema and data-model.md are the ones CI's `go test ./...` runs.
package store_test

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/store/models"
)

func TestEnumSQLIsTheGoConstSets(t *testing.T) {
	b, err := os.ReadFile("schema/01-enums.sql")
	require.NoError(t, err)

	var got []string
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "create type") {
			got = append(got, line)
		}
	}

	require.Equal(t, models.EnumDDL(), got,
		"internal/store/schema/01-enums.sql is a hand-maintained copy of models.EnumDDL(); run it through EnumDDL again after changing an enum")
}

// Blind spot: this only sees the loader's output, not the hand-written foreign
// keys in 03-constraints.sql; TestDataModelDeclaresTheSameForeignKeys covers those.
func TestGeneratedTableSQLMatchesTheModels(t *testing.T) {
	b, err := os.ReadFile("schema/02-tables.sql")
	require.NoError(t, err)

	generated := parseGeneratedTables(t, string(b))

	db := bun.NewDB(nil, pgdialect.New())
	db.RegisterModel(models.All()...)
	tables := db.Dialect().Tables()

	wanted := map[string]bool{}
	for _, model := range models.All() {
		table := tables.Get(reflect.TypeOf(model).Elem())
		require.NotNil(t, table, "bun does not know model %T", model)
		wanted[table.Name] = true

		t.Run(table.Name, func(t *testing.T) {
			require.Contains(t, generated, table.Name,
				"table is registered in models.All() but absent from the generated SQL — run 'task migrate:schema'")
			for _, field := range table.Fields {
				require.Contains(t, generated[table.Name], field.Name,
					"column %s.%s exists on the Bun model but not in the generated SQL — run 'task migrate:schema'",
					table.Name, field.Name)
			}
		})
	}

	for table := range generated {
		require.True(t, wanted[table],
			"the generated SQL creates table %q, which no model in models.All() claims — run 'task migrate:schema'", table)
	}
}

var (
	createTableRE = regexp.MustCompile(`^CREATE TABLE "([^"]+)" \((.*)\);$`)
	columnRE      = regexp.MustCompile(`"([^"]+)" `)
)

// parseGeneratedTables fails on any unrecognised line, since a skipped CREATE
// TABLE would make the coverage assertion vacuous.
func parseGeneratedTables(t *testing.T, sql string) map[string]map[string]bool {
	t.Helper()

	out := map[string]map[string]bool{}
	for _, line := range strings.Split(sql, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "", strings.HasPrefix(line, "--"), strings.HasPrefix(line, "ALTER TABLE "):
			continue
		}

		m := createTableRE.FindStringSubmatch(line)
		require.NotNil(t, m, "unrecognised line in the generated SQL: %s", line)

		body := m[2]
		// Trim trailing constraint clauses so their quoted names don't read as columns.
		i := strings.Index(body, ", PRIMARY KEY (")
		require.GreaterOrEqual(t, i, 0, "every generated table must declare a primary key: %s", line)
		body = body[:i]

		columns := map[string]bool{}
		for _, c := range columnRE.FindAllStringSubmatch(body, -1) {
			columns[c[1]] = true
		}
		require.NotEmpty(t, columns, "no columns parsed out of: %s", line)
		out[m[1]] = columns
	}
	return out
}

// wantForeignKeys is the full foreign-key set the schema must hold. Transcribe it
// by hand from internal/store/migrations; generating it from either compared side
// would make that check a tautology.
//
// Fifteen cannot come from the Bun models (FK column in the primary key, the
// package<->version cycle, the composite key) and live in 03-constraints.sql.
var wantForeignKeys = []string{
	// Not emitted by the loader.
	"capability(version_id) -> version",
	"component(version_id) -> version",
	"membership(profile_id) -> profile",
	"override(finding_id) -> finding",
	"package(latest_version_id) -> version",
	// Sits beside, not instead of, the single-column package(publisher_id) key.
	"package(publisher_id,namespace) -> publisher",
	"profile_entry(package_id) -> package",
	"profile_entry(profile_id) -> profile",
	"scan_check(scan_id) -> scan",
	"signature(version_id) -> version",
	"sync_target(profile_id) -> profile",
	"version_tag(version_id) -> version",
	"machine_install(machine_id) -> machine",
	"machine_install(profile_id) -> profile",
	"machine_install(package_id) -> package",
	// Emitted by the loader.
	"device_authorization(approved_by_identity_id) -> identity",
	"finding(scan_id) -> scan",
	"finding(version_id) -> version",
	"finding_evidence(finding_id) -> finding",
	"machine(last_identity_id) -> identity",
	"machine(last_profile_id) -> profile",
	"machine(last_revision_id) -> revision",
	"machine(last_service_token_id) -> service_token",
	"machine_install(version_id) -> version",
	"machine_skip(machine_id) -> machine",
	"machine_skip(profile_id) -> profile",
	"override(reviewer_identity_id) -> identity",
	"package(category_id) -> category",
	"package(owner_identity_id) -> identity",
	"package(parent_package_id) -> package",
	"package(publisher_id) -> publisher",
	"profile(forked_from_id) -> profile",
	"profile_entry(pinned_version_id) -> version",
	"revision(profile_id) -> profile",
	"scan(version_id) -> version",
	"service_token(created_by_identity_id) -> identity",
	"session(identity_id) -> identity",
	"sync_event(identity_id) -> identity",
	"sync_event(profile_id) -> profile",
	"sync_event(revision_id) -> revision",
	"sync_event(service_token_id) -> service_token",
	"version(package_id) -> package",
	"webhook_delivery(subscription_id) -> webhook_subscription",
	"webhook_subscription(created_by_identity_id) -> identity",
}

const dataModelPath = "../../specs/001-agent-manager-hub/data-model.md"

// TestEveryForeignKeyIsPresent checks the database against wantForeignKeys;
// this checks the design doc against the same list, without a container.
func TestDataModelDeclaresTheSameForeignKeys(t *testing.T) {
	got := parseDesignForeignKeys(t, dataModelPath)

	// Guard against a layout change that silently breaks extraction.
	require.NotEmpty(t, got,
		"no foreign keys were extracted from %s at all — the table layouts have changed and this test is now vacuous", dataModelPath)
	require.GreaterOrEqual(t, len(got), 20,
		"only %d foreign keys were extracted from %s, which is too few to be a real reading of it", len(got), dataModelPath)

	want := append([]string(nil), wantForeignKeys...)
	sort.Strings(want)

	require.Equal(t, want, got,
		"data-model.md and wantForeignKeys disagree: either the design declares a foreign key the schema does not implement, or the schema grew one the design never asked for")
}

var (
	designTableRE  = regexp.MustCompile("^#{2,3}\\s+`([a-z_]+)`")
	designColumnRE = regexp.MustCompile("^`([a-z_]+)`\\s*(.*)$")
	designFKRE     = regexp.MustCompile(`\bfk\b`)
	// The optional parenthesised list declares a composite key, e.g.
	// `fk (publisher_id, namespace) → publisher`, on one of its columns only.
	designTargetRE = regexp.MustCompile("\\bfk\\s*(?:\\(([a-z_, ]+)\\)\\s*)?→\\s*`?([a-z_]+)`?")
)

// parseDesignForeignKeys reads `table(column) -> target` from the design doc's
// vertical and compact table layouts. It never infers a target from the column
// name: stripping `_id` gets role-qualified columns like reviewer_identity_id wrong.
func parseDesignForeignKeys(t *testing.T, path string) []string {
	t.Helper()

	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var (
		out   []string
		table string
	)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)

		if m := designTableRE.FindStringSubmatch(line); m != nil {
			table = m[1]
			continue
		}
		if !strings.HasPrefix(line, "|") {
			continue
		}

		cells := splitDesignRow(line)
		for i, cell := range cells {
			column, spec, ok := splitDesignCell(cell)
			if !ok {
				continue
			}
			// Vertical layout: type in the next cell. A next cell naming its own
			// column means compact layout, and must not be borrowed.
			if spec == "" && i+1 < len(cells) {
				if _, _, named := splitDesignCell(cells[i+1]); !named {
					spec = cells[i+1]
				}
			}
			if !designFKRE.MatchString(spec) {
				continue
			}
			require.NotEmpty(t, table, "a foreign key appears before any table heading: %s", line)

			m := designTargetRE.FindStringSubmatch(spec)
			require.NotNil(t, m,
				"%s.%s is declared `fk` without naming its target — write `fk → <table>`. "+
					"Guessing the target from the column name is what this test refuses to do: "+
					"stripping `_id` gets override.reviewer_identity_id wrong, and a plausible "+
					"wrong target is worse than a failure here", table, column)

			columns := column
			if m[1] != "" {
				columns = strings.Join(strings.Fields(strings.ReplaceAll(m[1], ",", " ")), ",")
			}
			out = append(out, fmt.Sprintf("%s(%s) -> %s", table, columns, m[2]))
		}
	}
	sort.Strings(out)

	return out
}

func splitDesignRow(line string) []string {
	cells := strings.Split(strings.Trim(line, "|"), "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

// splitDesignCell splits a cell opening with a backticked column name into name and rest.
func splitDesignCell(cell string) (column, spec string, ok bool) {
	m := designColumnRE.FindStringSubmatch(cell)
	if m == nil {
		return "", "", false
	}
	return m[1], strings.TrimSpace(m[2]), true
}
