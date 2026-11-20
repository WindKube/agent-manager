//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

func reportMachine(t *testing.T, h http.Handler, token, profile string, revision int, host string, installed ...string) uuid.UUID {
	t.Helper()
	machine := uuid.New()
	body := fmt.Sprintf(`{"profile":%q,"revision":%d,"host":%q,"targets":["claude-code"],"machineId":%q,
		"skipped":["acme/legacy-helper"],"installed":[`, profile, revision, host, machine)
	for i, ref := range installed {
		if i > 0 {
			body += ","
		}
		var id, version string
		_, err := fmt.Sscanf(ref, "%s %s", &id, &version)
		require.NoError(t, err)
		body += fmt.Sprintf(`{"id":%q,"version":%q,"target":"claude-code","changed":true}`, id, version)
	}
	rec := request(t, h, http.MethodPost, "/v1/sync", token, body+"]}")
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	return machine
}

func listMachines(t *testing.T, h http.Handler, token, query string) contract.MachineList {
	t.Helper()
	rec := request(t, h, http.MethodGet, "/v1/machines?pageSize=200&"+query, token, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var out contract.MachineList
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

func machineIDs(list contract.MachineList) []string {
	out := []string{}
	for i := range list.Machines {
		out = append(out, list.Machines[i].ID)
	}
	return out
}

func TestTheMachineInventoryIsVisibleToItsReportersAndToCatalogAdmins(t *testing.T) {
	ctx := context.Background()
	h := liveHandler(t)

	// A private package of kw's, which an cannot read even when installed on an's machine.
	secret, secretVersion := models.NewID(), models.NewID()
	_, err := pool.Exec(ctx, `insert into package (id, publisher_id, namespace, name, kind, visibility, owner_identity_id)
		select $1, id, 'acme', 'kw-secret', 'skill', 'private', $2 from publisher where slug = 'acme/platform'`,
		secret, principalFor(t, kw).IdentityID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `insert into version (id, package_id, semver, semver_sort, object_key, digest, manifest, dist_tag, verdict, visible)
		values ($1, $2, '1.0.0', '1.0.0', 'skills/acme/kw-secret/1.0.0/bundle.tar.zst', $3, '{}', 'latest', 'clean', true)`,
		secretVersion, secret, bundleSHA)
	require.NoError(t, err)

	anMachine := reportMachine(t, h, an.token, "platform-baseline", 2, "an-laptop",
		"acme/code-review 2.4.1", "acme/kw-secret 1.0.0")
	contractorMachine := reportMachine(t, h, contractor.token, "platform-baseline", 1, "contractor-laptop",
		"acme/code-review 0.9.0")
	token := createServiceToken(t, an, "an-ci", "sync:profile/platform-baseline")
	ciMachine := reportMachine(t, h, token.Secret, "platform-baseline", 2, "an-ci-runner", "acme/threat-model 1.0.0")

	t.Run("a person sees the machines they or their tokens reported", func(t *testing.T) {
		require.ElementsMatch(t, []string{anMachine.String(), ciMachine.String()}, machineIDs(listMachines(t, h, an.token, "")))
		require.Equal(t, []string{contractorMachine.String()}, machineIDs(listMachines(t, h, contractor.token, "")))
		all := machineIDs(listMachines(t, h, kw.token, ""))
		require.Subset(t, all, []string{anMachine.String(), contractorMachine.String(), ciMachine.String()},
			"a catalog-admin sees every machine")
	})

	t.Run("a package filter narrows and counts per version", func(t *testing.T) {
		list := listMachines(t, h, kw.token, "package=acme/code-review")
		require.Subset(t, machineIDs(list), []string{anMachine.String(), contractorMachine.String()})
		require.NotContains(t, machineIDs(list), ciMachine.String())
		counts := map[string]int{}
		for _, v := range list.Versions {
			counts[v.Version] = v.Machines
		}
		require.GreaterOrEqual(t, counts["2.4.1"], 1)
		require.GreaterOrEqual(t, counts["0.9.0"], 1)

		exact := listMachines(t, h, kw.token, "package=acme/code-review&version=0.9.0")
		require.Contains(t, machineIDs(exact), contractorMachine.String())
		require.NotContains(t, machineIDs(exact), anMachine.String())

		mine := listMachines(t, h, an.token, "package=acme/code-review")
		require.Equal(t, []string{anMachine.String()}, machineIDs(mine))
		require.Equal(t, []contract.MachineVersionCount{{Version: "2.4.1", Machines: 1}}, mine.Versions,
			"the counts are bounded by what the caller may see")
	})

	t.Run("a filter naming what the caller cannot read is a 404", func(t *testing.T) {
		for _, query := range []string{"package=acme/kw-secret", "package=acme/nope", "profile=nobody-home",
			"package=acme/code-review&version=9.9.9"} {
			rec := request(t, h, http.MethodGet, "/v1/machines?"+query, an.token, "")
			require.Equal(t, http.StatusNotFound, rec.Code, query)
		}
		rec := request(t, h, http.MethodGet, "/v1/machines?version=1.0.0", an.token, "")
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		require.Contains(t, machineIDs(listMachines(t, h, kw.token, "package=acme/kw-secret")), anMachine.String())
	})

	t.Run("the detail lists readable installs and the latest skips", func(t *testing.T) {
		rec := request(t, h, http.MethodGet, "/v1/machines/"+anMachine.String(), an.token, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var detail contract.MachineDetail
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &detail))
		require.Equal(t, "an-laptop", detail.Machine.Hostname)
		require.Equal(t, []contract.MachineInstall{
			{Package: "acme/code-review", Version: "2.4.1", Target: "claude-code", Profile: "platform-baseline"},
		}, detail.Installs, "kw's private package is not listed to an")
		require.Equal(t, []contract.MachineSkip{{Profile: "platform-baseline", Entry: "acme/legacy-helper"}}, detail.Skipped)

		rec = request(t, h, http.MethodGet, "/v1/machines/"+anMachine.String(), kw.token, "")
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &detail))
		require.Len(t, detail.Installs, 2)

		for _, who := range []string{contractor.token} {
			rec = request(t, h, http.MethodGet, "/v1/machines/"+anMachine.String(), who, "")
			require.Equal(t, http.StatusNotFound, rec.Code)
		}
		rec = request(t, h, http.MethodGet, "/v1/machines/"+ciMachine.String(), token.Secret, "")
		require.Equal(t, http.StatusForbidden, rec.Code, "a service token reads no inventory")

		rec = request(t, h, http.MethodGet, "/v1/machines/"+ciMachine.String(), an.token, "")
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &detail))
		require.Equal(t, "an-ci", detail.Machine.ServiceToken)
	})

	t.Run("a shared machine shows no skip or install of a profile or package the caller cannot read", func(t *testing.T) {
		shared := uuid.New()
		post := func(token, body string) {
			t.Helper()
			rec := request(t, h, http.MethodPost, "/v1/sync", token, fmt.Sprintf(body, shared))
			require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
		}
		post(kw.token, `{"profile":"kw-private","revision":1,"host":"shared-box","targets":["claude-code"],"machineId":%q,
			"skipped":["acme/kw-private-entry"],
			"installed":[{"id":"acme/threat-model","version":"1.0.0","target":"claude-code","changed":true}]}`)
		post(an.token, `{"profile":"platform-baseline","revision":2,"host":"shared-box","targets":["claude-code"],"machineId":%q,
			"skipped":["acme/kw-secret","acme/not-in-catalog"],
			"installed":[{"id":"acme/kw-secret","version":"1.0.0","target":"claude-code","changed":true}],
			"skippedComponents":[{"entry":"acme/kw-secret","target":"claude-code","component":"mcp-server leak","reason":"x"}]}`)

		detailFor := func(token string) contract.MachineDetail {
			t.Helper()
			rec := request(t, h, http.MethodGet, "/v1/machines/"+shared.String(), token, "")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var detail contract.MachineDetail
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &detail))
			return detail
		}
		seen := detailFor(an.token)
		require.Empty(t, seen.Installs, "kw-private's install and kw's private package are both hidden")
		require.Equal(t, []contract.MachineSkip{{Profile: "platform-baseline", Entry: "acme/not-in-catalog"}}, seen.Skipped,
			"an entry the catalog does not hold is shown; a hidden package's and a hidden profile's are not")
		require.NotContains(t, fmt.Sprint(seen), "kw-private")
		require.NotContains(t, fmt.Sprint(seen), "kw-secret")

		all := detailFor(kw.token)
		require.Len(t, all.Installs, 2)
		require.Len(t, all.Skipped, 4)
	})

	t.Run("stale is computed from the last report", func(t *testing.T) {
		_, err := pool.Exec(ctx, `update machine set last_seen_at = now() - interval '15 days' where id = $1`, contractorMachine)
		require.NoError(t, err)
		list := listMachines(t, h, contractor.token, "")
		require.True(t, list.Machines[0].Stale)
		require.Equal(t, 14, list.StaleAfterDays)
		require.Equal(t, []string{contractorMachine.String()}, machineIDs(listMachines(t, h, contractor.token, "stale=true")))
		require.Empty(t, machineIDs(listMachines(t, h, contractor.token, "stale=false")))
		require.NotContains(t, machineIDs(listMachines(t, h, kw.token, "stale=true")), anMachine.String())
	})

	t.Run("only someone who may see a machine forgets it, and that is audited", func(t *testing.T) {
		rec := request(t, h, http.MethodDelete, "/v1/machines/"+anMachine.String(), contractor.token, "")
		require.Equal(t, http.StatusNotFound, rec.Code)
		rec = request(t, h, http.MethodDelete, "/v1/machines/"+anMachine.String(), token.Secret, "")
		require.Equal(t, http.StatusForbidden, rec.Code)

		rec = request(t, h, http.MethodDelete, "/v1/machines/"+anMachine.String(), an.token, "")
		require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
		rec = request(t, h, http.MethodGet, "/v1/machines/"+anMachine.String(), kw.token, "")
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Equal(t, 0, countRows(t, fmt.Sprintf("select count(*) from machine_install where machine_id = '%s'", anMachine)))
		require.Equal(t, 1, countRows(t, fmt.Sprintf(`select count(*) from audit_event
			where kind = 'sync' and subject_kind = 'machine' and subject_id = '%s' and data ->> 'action' = 'forgotten'`, anMachine)))

		rec = request(t, h, http.MethodDelete, "/v1/machines/"+contractorMachine.String(), kw.token, "")
		require.Equal(t, http.StatusNoContent, rec.Code, "a catalog-admin forgets any machine")
	})
}
