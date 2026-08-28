//go:build integration

// The package detail endpoint against a real Postgres (US3, T058, T062).
//
// The catalog fixtures are reused rather than a second seed written: the point of
// T062 is that BOTH VARIANTS render for EVERY seeded package, and a fixture set
// built for this file would be a set chosen to pass it.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

func detail(t *testing.T, handler http.Handler, token, id string) contract.PackageDetail {
	t.Helper()

	rec := request(t, handler, http.MethodGet, "/v1/packages/"+id, token, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var page contract.PackageDetail
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	return page
}

// T062. Every package the design seeds opens, and each one obeys the invariants
// of its variant. Driven off designPackages rather than a list written here, so a
// package added to the catalog fixtures cannot skip this by omission.
func TestEverySeededPackageOpensAsTheVariantItIs(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)

	for i := range designPackages {
		spec := &designPackages[i]
		id := namespaceOf(spec.publisher) + "/" + spec.name

		t.Run(id, func(t *testing.T) {
			page := detail(t, handler, kw.token, id)

			require.Equal(t, id, page.ID)
			require.Equal(t, spec.name, page.Name)
			require.Equal(t, string(spec.kind), page.Kind)
			require.Equal(t, spec.publisher, page.Publisher.Slug,
				"the publisher is the whole two-segment slug, not the id's namespace")
			require.Equal(t, spec.category, page.Category)
			require.Equal(t, spec.semver, page.Version, "the panels describe the latest visible version")
			require.Equal(t, string(spec.verdict), page.Verdict)
			require.ElementsMatch(t, spec.tags, page.Tags)

			// The variant split. A skill's manifest column holds SKILL.md
			// frontmatter and a plugin's holds plugin.json, and the response names
			// which of the two it is returning rather than leaving the caller to
			// infer it from Kind.
			if spec.kind == models.PackageKindSkill {
				require.Equal(t, "SKILL.md", page.ManifestObject)
			} else {
				require.Equal(t, "plugin.json", page.ManifestObject)
			}
			require.NotEmpty(t, page.Manifest)
			require.True(t, json.Valid([]byte(page.Manifest)),
				"the column is jsonb for both kinds, so a skill's frontmatter is stored as json")

			// Every seeded version is unscanned, so both capability lists are empty
			// AND `scanned` is false. The two facts are asserted separately because
			// they are separable: a scan that found nothing produces the same empty
			// lists with `scanned` true, and reading emptiness as "never scanned"
			// is the mistake this flag exists to prevent.
			require.False(t, page.Capabilities.Scanned)
			require.Empty(t, page.Capabilities.Inferred)
			require.Empty(t, page.Capabilities.Expected)

			require.NotEmpty(t, page.Versions, "the latest version is at least one row")
			require.Equal(t, spec.semver, page.Versions[0].Version)
			require.Equal(t, fmt.Sprintf("skills/%s/%s/%s/bundle.tar.zst",
				namespaceOf(spec.publisher), spec.name, spec.semver), page.Versions[0].ObjectKey,
				"FR-019 asks for the whole key, not a suffix")
			require.Regexp(t, `^sha256:[0-9a-f]{64}$`, page.Versions[0].Digest)
		})
	}
}

// The private package the catalog refuses to list is also not openable. Without
// this the detail page would be a second, quieter definition of "published".
func TestAPackageTheCatalogWillNotListIsNotOpenableEither(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)

	rec := request(t, handler, http.MethodGet, "/v1/packages/"+restrictedPackage, kw.token, "")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

// One 404 for "no such package" and for "not yours". Distinguishing them would
// confirm the existence of packages a caller may not see.
func TestAnUnknownPackageAndAnUnreadableOneAreTheSame404(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)

	for _, id := range []string{"example/no-such-package", "nosuchnamespace/platform-toolkit", restrictedPackage} {
		rec := request(t, handler, http.MethodGet, "/v1/packages/"+id, kw.token, "")
		require.Equal(t, http.StatusNotFound, rec.Code, id)

		var problem contract.Error
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problem))
		require.NotContains(t, problem.Detail, "platform-toolkit",
			"the refusal must not echo back which of the three reasons it was")
	}
}

// D1, and the reason this file exists at all. The design's "Used in profiles"
// panel names every profile using the package unconditionally; three of the four
// seeded profiles are private.
//
// Two identities with different memberships must see different lists, and the
// profile neither of them can read must appear for neither. The pin count is
// asserted in the same subtest and not a separate one, because the leak this
// closes is the DIFFERENCE between a scoped list and an unscoped count: testing
// them apart is what lets that difference survive.
func TestTheDependentsPanelAndThePinCountAreBothScopedToTheReader(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)

	const id = "example/platform-toolkit"
	ctx := context.Background()

	// platform-toolkit sits in all four seeded profiles, at `latest`. Pinning them
	// all at its latest version is what makes the count non-zero; the entries are
	// restored afterwards so the catalog's `uses` column, which counts these rows,
	// is unaffected either way.
	var versionID, packageID string
	require.NoError(t, pool.QueryRow(ctx,
		`select ver.id::text, pkg.id::text from package pkg
		   join version ver on ver.id = pkg.latest_version_id
		  where pkg.namespace = 'example' and pkg.name = 'platform-toolkit'`).Scan(&versionID, &packageID))

	_, err := pool.Exec(ctx,
		`update profile_entry set mode = 'pinned', pinned_version_id = $1 where package_id = $2`,
		versionID, packageID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, restoreErr := pool.Exec(context.Background(),
			`update profile_entry set mode = 'latest', pinned_version_id = null where package_id = $1`,
			packageID)
		require.NoError(t, restoreErr)
	})

	for _, tc := range []struct {
		name  string
		who   *actor
		want  []string
		never string
	}{
		{
			// The organisation profile plus the private one they own.
			name:  "a direct member sees the organisation profile and their own",
			who:   &kw,
			want:  []string{"kw-private", "platform-baseline"},
			never: "nobody-home",
		},
		{
			// A different pair, through a group membership rather than a direct one.
			name:  "a group member sees a different pair through the same package",
			who:   &an,
			want:  []string{"platform-baseline", "security-review"},
			never: "kw-private",
		},
		{
			// An unmapped group grants nothing beyond the organisation profile.
			name:  "an outsider sees only the organisation profile",
			who:   &contractor,
			want:  []string{"platform-baseline"},
			never: "security-review",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := detail(t, handler, tc.who.token, id)

			slugs := make([]string, 0, len(page.Dependents))
			for _, dependent := range page.Dependents {
				slugs = append(slugs, dependent.Slug)
				require.Equal(t, "pinned", dependent.Mode)
				require.Equal(t, "1.3.0", dependent.Version)
			}
			require.ElementsMatch(t, tc.want, slugs)
			require.NotContains(t, slugs, tc.never)
			require.NotContains(t, slugs, "nobody-home",
				"no identity in this suite may read it, so it may appear for none of them")

			require.Equal(t, len(tc.want), page.Versions[0].PinnedBy,
				"the count must agree with the list: a larger count states the number "+
					"of profiles this reader cannot see")
			require.Less(t, page.Versions[0].PinnedBy, 4,
				"four profiles pin this version and no seeded identity may read all four")
		})
	}
}

// The plugin variant's component list, and the skill variant's parent. Neither is
// in the catalog fixtures — the catalog needs neither — so both are added here
// and removed again.
func TestThePluginVariantListsItsComponentsAndTheSkillVariantNamesItsParent(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)

	ctx := context.Background()

	var pluginVersionID string
	require.NoError(t, pool.QueryRow(ctx,
		`select pkg.latest_version_id::text from package pkg
		  where pkg.namespace = 'example' and pkg.name = 'platform-toolkit'`).Scan(&pluginVersionID))

	for _, component := range []struct {
		kind, name, path, note string
	}{
		{"skill", "terraform-module-review", "skills/terraform-module-review", "SKILL.md + scripts/"},
		{"skill", "adr-writer", "skills/adr-writer", "SKILL.md"},
		{"mcp", "terraform-registry", "mcp.json", "stdio"},
		{"ext", "hooks", "hooks", "postinstall.sh"},
	} {
		_, err := pool.Exec(ctx,
			`insert into component (version_id, path, kind, name, note)
			 values ($1, $2, $3::component_kind, $4, $5)`,
			pluginVersionID, component.path, component.kind, component.name, component.note)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), `delete from component where version_id = $1`, pluginVersionID)
		require.NoError(t, err)
	})

	t.Run("a plugin lists the components the file tree revealed", func(t *testing.T) {
		page := detail(t, handler, kw.token, "example/platform-toolkit")
		require.Len(t, page.Components, 4)

		// Ordered by the enum's declaration order — skill, mcp, ext — which is the
		// design's order and not the alphabetical one. Sorting the text would put
		// ext first, so this assertion is what holds `order by kind` to meaning the
		// enum rather than the string.
		kinds := make([]string, 0, len(page.Components))
		for _, component := range page.Components {
			kinds = append(kinds, component.Kind)
		}
		require.Equal(t, []string{"skill", "skill", "mcp", "ext"}, kinds)
		require.Equal(t, "adr-writer", page.Components[0].Name, "and by name within a kind")

		// The catalog fixtures store a minimal manifest with no `$schema`, and the
		// honest answer to "which spec version" is then none rather than a guess.
		require.Empty(t, page.Origin.SpecVersion)
	})

	t.Run("the spec version is read out of the manifest's $schema and nowhere else", func(t *testing.T) {
		// Agent Plugins 1.0.0 has no `agentPluginsVersion` field — the design's
		// manifest is non-conformant (R1) — so `$schema` is the only place either
		// specification's version appears. Written here rather than into the shared
		// fixtures because every other assertion in this file wants the minimal one.
		_, updateErr := pool.Exec(ctx,
			`update version set manifest = $1 where id = $2`,
			`{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",`+
				`"name":"platform-toolkit","description":"Platform guardrails."}`,
			pluginVersionID)
		require.NoError(t, updateErr)
		t.Cleanup(func() {
			_, restoreErr := pool.Exec(context.Background(),
				`update version set manifest = $1 where id = $2`,
				`{"name":"platform-toolkit"}`, pluginVersionID)
			require.NoError(t, restoreErr)
		})

		page := detail(t, handler, kw.token, "example/platform-toolkit")
		require.Equal(t, "1.0.0", page.Origin.SpecVersion)
		require.Equal(t, "Platform guardrails.", page.Description,
			"the description comes from the version's manifest — package has no such column")
	})

	// pii-redactor is seeded standalone. Making it a component of security-review-kit
	// is the only way to reach the skill variant's parent branch, because nothing in
	// the catalog fixtures sets parent_package_id.
	_, err := pool.Exec(ctx,
		`update package set parent_package_id = (
		   select id from package where namespace = 'example' and name = 'security-review-kit')
		  where namespace = 'example' and name = 'pii-redactor'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, restoreErr := pool.Exec(context.Background(),
			`update package set parent_package_id = null
			  where namespace = 'example' and name = 'pii-redactor'`)
		require.NoError(t, restoreErr)
	})

	t.Run("a skill distributed inside a plugin names the parent package", func(t *testing.T) {
		page := detail(t, handler, kw.token, "example/pii-redactor")

		require.Equal(t, "example/security-review-kit", page.Origin.ParentID)
		require.Equal(t, "security-review-kit", page.Origin.ParentName)
		// D3: there is no parent VERSION and the response carries none. The design's
		// "distributed inside Platform Toolkit 1.3.0" would have to read the parent's
		// current latest, which rewrites itself when the parent publishes.
		require.Empty(t, page.Origin.SpecVersion,
			"agentskills.io publishes no schema, so a skill states no spec version")
	})

	t.Run("a standalone skill names no parent", func(t *testing.T) {
		page := detail(t, handler, kw.token, "example/adr-writer")
		require.Empty(t, page.Origin.ParentID)
		require.Empty(t, page.Origin.ParentName)
	})
}
