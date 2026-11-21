//go:build integration

// The package detail endpoint against a real Postgres. It reuses the catalog fixtures,
// since a seed written for this file would be chosen to pass it.
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

// Driven off designPackages, so a package added to the catalog fixtures cannot skip this.
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

			// The response names which manifest it returns rather than leaving the caller to infer it.
			if spec.kind == models.PackageKindSkill {
				require.Equal(t, "SKILL.md", page.ManifestObject)
			} else {
				require.Equal(t, "plugin.json", page.ManifestObject)
			}
			require.NotEmpty(t, page.Manifest)
			require.True(t, json.Valid([]byte(page.Manifest)),
				"the column is jsonb for both kinds, so a skill's frontmatter is stored as json")

			// Asserted separately: a clean scan also yields empty lists, but with `scanned` true.
			require.False(t, page.Capabilities.Scanned)
			require.Empty(t, page.Capabilities.Inferred)
			require.Empty(t, page.Capabilities.Expected)

			require.NotEmpty(t, page.Versions, "the latest version is at least one row")
			require.Equal(t, spec.semver, page.Versions[0].Version)
			require.Equal(t, fmt.Sprintf("skills/%s/%s/%s/bundle.tar.zst",
				namespaceOf(spec.publisher), spec.name, spec.semver), page.Versions[0].ObjectKey,
				"the whole key, not a suffix")
			require.Regexp(t, `^sha256:[0-9a-f]{64}$`, page.Versions[0].Digest)
		})
	}
}

// Otherwise the detail page would be a second, quieter definition of "published".
func TestAPackageTheCatalogWillNotListIsNotOpenableEither(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)

	rec := request(t, handler, http.MethodGet, "/v1/packages/"+restrictedPackage, kw.token, "")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

// One 404 for "no such package" and "not yours", or the status confirms existence.
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

// "Used in profiles" must be scoped to what the caller can read. The pin count is asserted
// in the same subtest because the leak is the difference between a scoped list and an unscoped count.
func TestTheDependentsPanelAndThePinCountAreBothScopedToTheReader(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)

	const id = "example/platform-toolkit"
	ctx := context.Background()

	// Pinning makes the count non-zero; entries are restored so the catalog's `uses` column is unaffected.
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

// The catalog fixtures have neither components nor parents, so both are added here and removed.
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
	_, err := pool.Exec(ctx,
		`insert into component (version_id, path, kind, name, note, event, matcher, target)
		 values ($1, 'com.anthropic.claude-code/hooks/hooks.json#/hooks/PreToolUse/0/hooks/0', 'hook',
		         'PreToolUse', 'command', 'PreToolUse', 'Bash', './guard.sh')`, pluginVersionID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := pool.Exec(context.Background(), `delete from component where version_id = $1`, pluginVersionID)
		require.NoError(t, cleanupErr)
	})

	t.Run("a plugin lists the components the file tree revealed", func(t *testing.T) {
		page := detail(t, handler, kw.token, "example/platform-toolkit")
		require.Len(t, page.Components, 5)

		// Enum declaration order (skill, mcp, ext), not alphabetical.
		kinds := make([]string, 0, len(page.Components))
		for _, component := range page.Components {
			kinds = append(kinds, component.Kind)
		}
		require.Equal(t, []string{"skill", "skill", "mcp", "ext", "hook"}, kinds)
		require.Equal(t, "adr-writer", page.Components[0].Name, "and by name within a kind")

		hook := page.Components[4]
		require.Equal(t, "PreToolUse", hook.Event)
		require.Equal(t, "Bash", hook.Matcher)
		require.Equal(t, "./guard.sh", hook.Target)
		require.Empty(t, page.Components[2].Transport, "a row with no surface columns renders none")

		// No `$schema` in the manifest means no spec version rather than a guess.
		require.Empty(t, page.Origin.SpecVersion)
	})

	t.Run("the spec version is read out of the manifest's $schema and nowhere else", func(t *testing.T) {
		// Agent Plugins 1.0.0 has no version field, so `$schema` is the only place the spec version appears.
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

	// Nothing in the catalog fixtures sets parent_package_id.
	_, err = pool.Exec(ctx,
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
		// No parent version: it would have to be the parent's current latest, which moves on publish.
		require.Empty(t, page.Origin.SpecVersion,
			"agentskills.io publishes no schema, so a skill states no spec version")
	})

	t.Run("a standalone skill names no parent", func(t *testing.T) {
		page := detail(t, handler, kw.token, "example/adr-writer")
		require.Empty(t, page.Origin.ParentID)
		require.Empty(t, page.Origin.ParentName)
	})
}

// Provenance is read off the package and each version as recorded; a package
// registered before sources were recorded has none rather than an empty one.
func TestTheDetailCarriesThePackageSourceAndEachVersionsCommit(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)
	ctx := context.Background()

	require.Nil(t, detail(t, handler, kw.token, "example/platform-toolkit").Source)

	const commit = "3f9c2e1d8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e"
	_, err := pool.Exec(ctx, `
		with pkg as (
		  update package set source_kind = 'git', source_url = 'https://github.com/acme/skills',
		         source_ref = 'v1.3.0', source_subdirectory = 'pdf'
		   where namespace = 'example' and name = 'platform-toolkit'
		  returning latest_version_id)
		update version set source_url = 'https://github.com/acme/skills', source_ref = 'v1.3.0', source_commit = $1
		 where id = (select latest_version_id from pkg)`, commit)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, restoreErr := pool.Exec(context.Background(), `
			with pkg as (
			  update package set source_kind = null, source_url = null, source_ref = null, source_subdirectory = null
			   where namespace = 'example' and name = 'platform-toolkit'
			  returning latest_version_id)
			update version set source_url = null, source_ref = null, source_commit = null
			 where id = (select latest_version_id from pkg)`)
		require.NoError(t, restoreErr)
	})

	page := detail(t, handler, kw.token, "example/platform-toolkit")
	require.Equal(t, &contract.PackageSource{
		Kind: "git", URL: "https://github.com/acme/skills", Ref: "v1.3.0", Subdirectory: "pdf",
	}, page.Source)
	require.Equal(t, commit, page.Versions[0].SourceCommit)
	require.Equal(t, "v1.3.0", page.Versions[0].SourceRef)
	require.Equal(t, "https://github.com/acme/skills", page.Versions[0].SourceURL)
}

// setPackageTracking over the wire: offered only for a git package, gated
// like visibility, and answered with the package as it now reads.
func TestTrackingAGitPackagesUpstreamIsTheOwnersOrACatalogAdmins(t *testing.T) {
	handler := liveHandler(t)
	seedCatalog(t)
	ctx := context.Background()
	const path = "/v1/packages/example/platform-toolkit/tracking"

	rec := request(t, handler, http.MethodPut, path, kw.token, `{"trackUpstream":true}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, "a package with no git source has no upstream")
	require.Nil(t, detail(t, handler, kw.token, "example/platform-toolkit").Tracking)

	_, err := pool.Exec(ctx, `update package set source_kind = 'git', source_url = 'https://github.com/acme/skills'
	  where namespace = 'example' and name = 'platform-toolkit'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, restoreErr := pool.Exec(context.Background(), `update package
		  set track_upstream = false, tag_pattern = 'v*', source_kind = null, source_url = null
		  where namespace = 'example' and name = 'platform-toolkit'`)
		require.NoError(t, restoreErr)
	})

	rec = request(t, handler, http.MethodPut, path, an.token, `{"trackUpstream":true}`)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	rec = request(t, handler, http.MethodPut, path, kw.token, `{"trackUpstream":true,"tagPattern":"v["}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	rec = request(t, handler, http.MethodPut, path, kw.token, `{"trackUpstream":true,"tagPattern":"release-*"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var page contract.PackageDetail
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Equal(t, &contract.PackageTracking{TrackUpstream: true, TagPattern: "release-*", CanChange: true}, page.Tracking)

	var rows int
	require.NoError(t, pool.QueryRow(ctx, `select count(*) from audit_event
	  where subject_kind = 'package' and subject_id = 'example/platform-toolkit'
	    and data->>'action' = 'tracking-changed' and data->>'tagPattern' = 'release-*'`).Scan(&rows))
	require.Equal(t, 1, rows)
}
