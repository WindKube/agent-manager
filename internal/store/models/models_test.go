package models_test

import (
	"fmt"
	"go/types"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/schema"
	"golang.org/x/tools/go/packages"

	"agent-manager/internal/fetch"
	"agent-manager/internal/store/models"
)

const modelsPkg = "agent-manager/internal/store/models"

// wantTables is the table list from data-model.md. It is spelled out rather than
// derived so that adding a struct without adding it here fails, and so a reviewer
// can diff this list against the document.
var wantTables = []string{
	// Catalog
	"publisher", "category", "package", "version", "version_tag", "component",
	"capability", "signature",
	// Scanning
	"scan", "scan_check", "finding", "finding_evidence", "override",
	// Profiles
	"profile", "profile_entry", "revision", "membership", "sync_target",
	// Identity
	"identity", "group_role_map", "device_authorization", "session",
	// Governance
	"org_policy", "audit_event", "sync_event", "fetch_attempt",
	// Job hand-off
	"outbox",
}

// builtinSQLTypes are the non-enum column types the models use. Anything else in
// a `type:` option has to be a declared Postgres enum.
var builtinSQLTypes = []string{
	"bigint", "boolean", "bytea", "integer", "jsonb", "text", "text[]",
	"timestamptz", "uuid",
}

func registerAll(t *testing.T) *schema.Tables {
	t.Helper()
	tables := schema.NewTables(pgdialect.New())
	// Register panics on an unresolvable relation, so this call is itself the
	// assertion that every join: target exists.
	tables.Register(models.All()...)
	return tables
}

func TestEveryModelIsRegisteredExactlyOnce(t *testing.T) {
	all := models.All()

	seen := map[string]int{}
	for _, m := range all {
		typ := reflect.TypeOf(m)
		require.Equal(t, reflect.Pointer, typ.Kind(), "models.All must hold pointers, bun panics otherwise")
		require.Equal(t, reflect.Struct, typ.Elem().Kind())
		seen[typ.Elem().Name()]++
	}
	for name, count := range seen {
		require.Equalf(t, 1, count, "%s appears %d times in models.All", name, count)
	}
	require.Len(t, all, len(wantTables))
}

func TestEveryExportedStructIsARegisteredModel(t *testing.T) {
	registered := map[string]bool{}
	for _, m := range models.All() {
		registered[reflect.TypeOf(m).Elem().Name()] = true
	}

	loaded, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo,
	}, modelsPkg)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	require.Empty(t, loaded[0].Errors)

	scope := loaded[0].Types.Scope()
	var exported []string
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		named, ok := obj.Type().(*types.Named)
		if !ok {
			continue
		}
		if _, ok := named.Underlying().(*types.Struct); !ok {
			continue
		}
		exported = append(exported, name)
	}
	require.NotEmpty(t, exported)

	// The Atlas loader turns every exported struct in this package into a Bun
	// model, so an exported struct that is not in models.All would become an
	// unintended table in the generated migration.
	for _, name := range exported {
		require.Truef(t, registered[name],
			"exported struct %s is not in models.All: the Atlas loader would still emit a table for it", name)
	}
	require.Len(t, exported, len(wantTables))
}

func TestTableNamesMatchTheDataModel(t *testing.T) {
	tables := registerAll(t)

	var got []string
	for _, table := range tables.All() {
		got = append(got, table.Name)
	}
	sort.Strings(got)

	want := slices.Clone(wantTables)
	sort.Strings(want)
	require.Equal(t, want, got)
}

func TestEveryModelHasAPrimaryKey(t *testing.T) {
	for _, table := range registerAll(t).All() {
		require.NotEmptyf(t, table.PKs, "table %s has no primary key", table.Name)
	}
}

func TestEveryTimestampColumnIsTimestamptz(t *testing.T) {
	for _, table := range registerAll(t).All() {
		for _, field := range table.Fields {
			if field.IndirectType != reflect.TypeFor[time.Time]() {
				continue
			}
			require.Equalf(t, "timestamptz", strings.ToLower(field.UserSQLType),
				"%s.%s is %s, must be timestamptz", table.Name, field.Name, field.UserSQLType)
		}
	}
}

func TestEveryEnumColumnNamesADeclaredPostgresType(t *testing.T) {
	declared := models.EnumTypes()

	found := map[string]bool{}
	for _, table := range registerAll(t).All() {
		for _, field := range table.Fields {
			sqlType := strings.ToLower(field.UserSQLType)
			if slices.Contains(builtinSQLTypes, sqlType) {
				continue
			}
			_, ok := declared[sqlType]
			require.Truef(t, ok,
				"%s.%s has type %q, which is neither a builtin nor a declared enum",
				table.Name, field.Name, sqlType)
			found[sqlType] = true
		}
	}

	// Nothing is declared that no column uses: a stale enum type would be created
	// by the migration and diffed forever.
	for name := range declared {
		require.Truef(t, found[name], "enum type %s is declared but no column uses it", name)
	}
}

func TestEveryStringEnumFieldUsesAnEnumGoType(t *testing.T) {
	declared := models.EnumTypes()

	for _, table := range registerAll(t).All() {
		for _, field := range table.Fields {
			if _, ok := declared[strings.ToLower(field.UserSQLType)]; !ok {
				continue
			}
			// A plain string here would let an unchecked value reach an enum column.
			require.NotEqualf(t, reflect.TypeFor[string](), field.IndirectType,
				"%s.%s is a Postgres enum but a plain Go string", table.Name, field.Name)
			zero := reflect.New(field.IndirectType).Elem().Interface()
			_, ok := zero.(models.Enum)
			require.Truef(t, ok, "%s.%s (%s) does not implement models.Enum",
				table.Name, field.Name, field.IndirectType)
		}
	}
}

type enumCase struct {
	pgType string
	valid  func(string) bool
}

func enumCheck[T interface {
	~string
	models.Enum
}](pgType string) enumCase {
	return enumCase{pgType: pgType, valid: func(s string) bool { return T(s).Valid() }}
}

func enumCases() []enumCase {
	return []enumCase{
		enumCheck[models.PackageKind](models.PGPackageKind),
		enumCheck[models.PackageVisibility](models.PGPackageVisibility),
		enumCheck[models.DistTag](models.PGDistTag),
		enumCheck[models.Verdict](models.PGVerdict),
		enumCheck[models.ComponentKind](models.PGComponentKind),
		enumCheck[models.CapabilitySource](models.PGCapabilitySource),
		enumCheck[models.CapabilityLevel](models.PGCapabilityLevel),
		enumCheck[models.SignatureKind](models.PGSignatureKind),
		enumCheck[models.SignatureResult](models.PGSignatureResult),
		enumCheck[models.CheckResult](models.PGCheckResult),
		enumCheck[models.FindingSeverity](models.PGFindingSeverity),
		enumCheck[models.FindingState](models.PGFindingState),
		enumCheck[models.ProfileVisibility](models.PGProfileVisibility),
		enumCheck[models.VersionPolicy](models.PGVersionPolicy),
		enumCheck[models.EntryMode](models.PGEntryMode),
		enumCheck[models.MembershipRole](models.PGMembershipRole),
		enumCheck[models.SubjectKind](models.PGSubjectKind),
		enumCheck[models.SyncTargetKind](models.PGSyncTargetKind),
		enumCheck[models.OrgRole](models.PGOrgRole),
		enumCheck[models.DeviceAuthState](models.PGDeviceAuthState),
		enumCheck[models.ScanGate](models.PGScanGate),
		enumCheck[models.ActorKind](models.PGActorKind),
		enumCheck[models.AuditKind](models.PGAuditKind),
		enumCheck[models.OutboxState](models.PGOutboxState),
		enumCheck[models.EvidenceRole](models.PGEvidenceRole),
		enumCheck[models.FetchSourceKind](models.PGFetchSourceKind),
		enumCheck[models.FetchOutcome](models.PGFetchOutcome),
	}
}

// TestFetchSourceKindHoldsExactlyTheSourceKindsTheFetcherCanProduce is the guard
// the doc comment on models.FetchSourceKind promises. The enum is a hand-written
// copy of fetch.SourceKind — models must stay free of the fetch tree because the
// Atlas provider loads this package, and internal/fetch must not learn about the
// database — and a copy nothing compares is a copy that goes stale. A fourth
// source added over there would otherwise reach production as a failed insert on
// fetch_attempt.source_kind, on the failure path, where nothing exercises it.
func TestFetchSourceKindHoldsExactlyTheSourceKindsTheFetcherCanProduce(t *testing.T) {
	// Transcribed from internal/fetch/source.go, not derived from it: this is the
	// side of the comparison that has to be independent.
	want := []string{
		string(fetch.SourceUpload),
		string(fetch.SourceGit),
		string(fetch.SourceArchiveURL),
	}
	require.Equal(t, want, models.EnumTypes()[models.PGFetchSourceKind])

	for _, v := range want {
		require.Truef(t, models.FetchSourceKind(v).Valid(), "fetch.SourceKind %q is not a valid FetchSourceKind", v)
	}
}

func TestEveryEnumTypeHasACase(t *testing.T) {
	got := map[string]bool{}
	for _, c := range enumCases() {
		require.Falsef(t, got[c.pgType], "%s has two cases", c.pgType)
		got[c.pgType] = true
	}
	for name := range models.EnumTypes() {
		require.Truef(t, got[name], "enum type %s has no Valid() case in this test", name)
	}
}

func TestEnumValidAcceptsOnlyItsOwnValues(t *testing.T) {
	declared := models.EnumTypes()

	for _, c := range enumCases() {
		t.Run(c.pgType+" accepts every declared value", func(t *testing.T) {
			require.NotEmpty(t, declared[c.pgType])
			for _, v := range declared[c.pgType] {
				require.Truef(t, c.valid(v), "%s should accept %q", c.pgType, v)
			}
		})

		t.Run(c.pgType+" rejects values outside its set", func(t *testing.T) {
			for _, v := range []string{"", " ", "unknown", strings.ToUpper(declared[c.pgType][0])} {
				require.Falsef(t, c.valid(v), "%s should reject %q", c.pgType, v)
			}
			// Every other enum's values, which catches a Valid() wired to the wrong
			// type name: a copy-paste that would let dist_tag accept "plugin".
			for other, values := range declared {
				if other == c.pgType {
					continue
				}
				for _, v := range values {
					if slices.Contains(declared[c.pgType], v) {
						continue
					}
					require.Falsef(t, c.valid(v), "%s should reject %s value %q", c.pgType, other, v)
				}
			}
		})
	}
}

func TestEnumDDLCoversEveryTypeExactlyOnce(t *testing.T) {
	ddl := models.EnumDDL()
	require.Len(t, ddl, len(models.EnumTypes()))
	require.Equal(t, ddl, models.EnumDDL(), "EnumDDL must be deterministic, it feeds a migration")

	for name, values := range models.EnumTypes() {
		quoted := make([]string, 0, len(values))
		for _, v := range values {
			quoted = append(quoted, "'"+v+"'")
		}
		want := fmt.Sprintf("create type %s as enum (%s);", name, strings.Join(quoted, ", "))
		require.Containsf(t, ddl, want, "EnumDDL is missing %s", name)
	}
}

func TestSemverSortOrdersVersions(t *testing.T) {
	// Ascending semver precedence. Sorting the computed keys as plain strings must
	// reproduce this order exactly.
	ordered := []string{
		"0.0.1",
		"0.1.0",
		"0.9.0",
		"0.10.0",
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.9.0",
		"1.10.0",
		"1.10.1",
		"2.0.0-rc.1",
		"2.0.0",
		"10.0.0",
	}

	type keyed struct {
		semver string
		key    string
	}
	got := make([]keyed, 0, len(ordered))
	for _, v := range ordered {
		key, err := models.SemverSort(v)
		require.NoErrorf(t, err, "SemverSort(%q)", v)
		got = append(got, keyed{semver: v, key: key})
	}

	sort.SliceStable(got, func(i, j int) bool { return got[i].key < got[j].key })

	var sorted []string
	for _, k := range got {
		sorted = append(sorted, k.semver)
	}
	require.Equal(t, ordered, sorted)
}

func TestSemverSortIgnoresBuildMetadataAndVPrefix(t *testing.T) {
	base, err := models.SemverSort("1.2.3")
	require.NoError(t, err)

	for _, spelling := range []string{"v1.2.3", "1.2.3+build.5", "v1.2.3+20260827", " 1.2.3 "} {
		got, err := models.SemverSort(spelling)
		require.NoErrorf(t, err, "SemverSort(%q)", spelling)
		require.Equalf(t, base, got, "SemverSort(%q) must equal SemverSort(\"1.2.3\")", spelling)
	}
}

func TestSemverSortRejectsUnusableVersions(t *testing.T) {
	cases := map[string]string{
		"empty":                    "",
		"two segments":             "1.2",
		"four segments":            "1.2.3.4",
		"non numeric segment":      "1.x.0",
		"leading zero segment":     "1.02.0",
		"segment wider than pad":   "12345678901.0.0",
		"empty prerelease":         "1.0.0-",
		"empty prerelease segment": "1.0.0-alpha..1",
		"prerelease bad character": "1.0.0-alpha_1",
		"prerelease too long":      "1.0.0-aaaaaaaaaaaaaaaaaaaaa",
	}
	for name, semver := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := models.SemverSort(semver)
			require.Error(t, err)
		})
	}
}

func TestSemverSortKeyIsFixedWidthForReleases(t *testing.T) {
	// major+minor+patch padded to 10 each, plus the one release flag digit.
	const releaseKeyLen = 31
	for _, v := range []string{"0.0.0", "1.2.3", "999.999.999", "9999999999.9999999999.9999999999"} {
		key, err := models.SemverSort(v)
		require.NoError(t, err)
		require.Lenf(t, key, releaseKeyLen, "SemverSort(%q)", v)
		require.Equal(t, "1", key[len(key)-1:], "a release must carry the high flag")
	}

	pre, err := models.SemverSort("1.2.3-rc.1")
	require.NoError(t, err)
	require.Equal(t, "0", pre[releaseKeyLen-1:releaseKeyLen], "a prerelease must carry the low flag")
}

func TestNewIDIsUUIDv7AndSortsByCreationTime(t *testing.T) {
	const n = 200

	ids := make([]uuid.UUID, 0, n)
	for range n {
		id := models.NewID()
		require.Equal(t, uuid.Version(7), id.Version())
		require.Equal(t, uuid.RFC4122, id.Variant())
		ids = append(ids, id)
	}

	// v7 is time-ordered, which is why it is worth the extra call over v4: the
	// primary key gives index locality and creation order for free.
	for i := 1; i < len(ids); i++ {
		prev, cur := ids[i-1].String(), ids[i].String()
		require.Lessf(t, prev, cur, "uuid v7 %d (%s) does not sort after %s", i, cur, prev)
	}
}

// TestBunEmitsNoForeignKeyWhereTheColumnIsPartOfThePrimaryKey pins a fact the
// migration layer depends on. Bun only emits a FOREIGN KEY for a belongs-to or
// has-one relation whose base columns are *not* primary keys (see
// schema.Relation.References). data-model.md gives several tables a primary key
// that is also a foreign key — `signature.version_id`, `override.finding_id` —
// so those constraints cannot come from the struct tags and have to be added by
// the migration's SQL layer. If this list shrinks because Bun changed, the
// migration is adding a duplicate; if it grows, a foreign key went missing.
func TestBunEmitsNoForeignKeyWhereTheColumnIsPartOfThePrimaryKey(t *testing.T) {
	want := []string{
		"capability.version_id -> version.id",
		"component.version_id -> version.id",
		"membership.profile_id -> profile.id",
		"override.finding_id -> finding.id",
		"profile_entry.package_id -> package.id",
		"profile_entry.profile_id -> profile.id",
		"scan_check.scan_id -> scan.id",
		"signature.version_id -> version.id",
		"sync_target.profile_id -> profile.id",
		"version_tag.version_id -> version.id",
	}

	var got []string
	for _, table := range registerAll(t).All() {
		for _, rel := range table.Relations {
			if rel.Type != schema.BelongsToRelation && rel.Type != schema.HasOneRelation {
				continue
			}
			if rel.References() {
				continue
			}
			// has-one points the other way round and never needs a key on this side.
			if rel.Type == schema.HasOneRelation {
				continue
			}
			got = append(got, fmt.Sprintf("%s.%s -> %s.%s",
				table.Name, rel.BasePKs[0].Name, rel.JoinTable.Name, rel.JoinPKs[0].Name))
		}
	}
	sort.Strings(got)
	require.Equal(t, want, got)
}

func TestEveryRelationTargetIsARegisteredTable(t *testing.T) {
	tables := registerAll(t)

	known := map[string]bool{}
	for _, table := range tables.All() {
		known[table.Name] = true
	}
	for _, table := range tables.All() {
		for name, rel := range table.Relations {
			require.NotNilf(t, rel.JoinTable, "%s.%s has no join table", table.Name, name)
			require.Truef(t, known[rel.JoinTable.Name],
				"%s.%s joins %s, which is not in models.All", table.Name, name, rel.JoinTable.Name)
		}
	}
}
