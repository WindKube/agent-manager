package web_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	laptopID = "0193f2a0-0000-7000-8000-0000000000a1"
	runnerID = "0193f2a0-0000-7000-8000-0000000000a2"
)

func TestTheMachinesScreenListsMachinesWithTheirStaleness(t *testing.T) {
	_, h := newServer(t)
	rec := get(t, h, "/machines")
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, `href="/machines/`+laptopID+`"`)
	require.Contains(t, body, "dev-laptop-01")
	require.Contains(t, body, "darwin/arm64 · amctl 0.9.0")
	require.Contains(t, body, "example/platform-engineer r4")
	require.Contains(t, body, "token release pipeline of ada@fixture.invalid")
	require.Contains(t, body, `<span class="am-pill am-pill-warn">stale</span>`)
	require.Contains(t, body, "2 machines")
}

func TestTheMachinesScreenSendsItsFiltersToTheAPI(t *testing.T) {
	api, h := newServer(t)
	rec := get(t, h, "/machines?package=community/slack-digest&version=0.5.1&stale=nonsense")
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "dev-laptop-01")
	require.NotContains(t, body, "ci-runner-7")

	calls := api.Calls("listMachines")
	require.Len(t, calls, 1)
	query, err := url.ParseQuery(calls[0].Query)
	require.NoError(t, err)
	require.Equal(t, "community/slack-digest", query.Get("package"))
	require.Equal(t, "0.5.1", query.Get("version"))
	require.Empty(t, query.Get("stale"), "a value the api would refuse is dropped")
}

func TestAFilterTheViewerCannotReadIsA404(t *testing.T) {
	api, h := newServer(t)
	api.Fail("listMachines", http.StatusNotFound)
	rec := get(t, h, "/machines?package=secret/thing")
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Contains(t, rec.Body.String(), `id="machines-missing"`)
}

func TestTheMachineScreenGroupsInstallsByTargetAndNamesSkips(t *testing.T) {
	_, h := newServer(t)
	rec := get(t, h, "/machines/"+laptopID)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, `id="machine-target-claude-code"`)
	require.Contains(t, body, `id="machine-target-codex"`)
	require.Contains(t, body, `href="/packages/example/platform-toolkit"`)
	require.Contains(t, body, "example/platform-toolkit · mcp-server terraform-registry for claude-code")
	require.Contains(t, body, "no claude CLI on PATH")
	require.Contains(t, body, `action="/machines/`+laptopID+`/forget"`)

	require.Equal(t, http.StatusNotFound, get(t, h, "/machines/not-a-uuid").Code)
	require.Equal(t, http.StatusNotFound, get(t, h, "/machines/0193f2a0-0000-7000-8000-0000000000ff").Code)
}

func TestForgettingAMachineRedirectsToTheListWithoutIt(t *testing.T) {
	api, h := newServer(t)
	rec := post(t, h, "/machines/"+runnerID+"/forget", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/machines?outcome=forgotten", rec.Header().Get("Location"))
	require.Len(t, api.Calls("forgetMachine"), 1)

	body := get(t, h, "/machines?outcome=forgotten").Body.String()
	require.Contains(t, body, "Forgotten.")
	require.NotContains(t, body, "ci-runner-7")

	rec = post(t, h, "/machines/"+runnerID+"/forget", url.Values{})
	require.Equal(t, "/machines?outcome=missing", rec.Header().Get("Location"))
}

func TestThePackageScreenCountsAffectedMachinesPerVersion(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/community/slack-digest").Body.String()
	require.Contains(t, body, `id="affected-machines"`)
	require.Contains(t, body, `href="/machines?package=community%2Fslack-digest&amp;version=0.5.1"`)
	require.Contains(t, body, `href="/machines?package=community%2Fslack-digest&amp;version=0.5.0"`)
	require.Contains(t, body, `href="/machines?package=community%2Fslack-digest">2 machines</a>`)
}

func TestAnAffectedMachinesFailureIsSaidAndANotFoundHidesThePanel(t *testing.T) {
	api, h := newServer(t)
	api.Fail("listMachines", http.StatusNotFound)
	require.NotContains(t, get(t, h, "/packages/community/slack-digest").Body.String(), `id="affected-machines"`)

	api, h = newServer(t)
	api.Fail("listMachines", http.StatusInternalServerError)
	body := get(t, h, "/packages/community/slack-digest").Body.String()
	require.Contains(t, body, `id="affected-unavailable"`)
}

func TestTheFindingPaneCountsTheMachinesHoldingItsVersion(t *testing.T) {
	api, h := newServer(t)
	body := get(t, h, "/scanner?finding="+api.Data.Findings[0].Id.String()).Body.String()
	require.Contains(t, body, `id="affected-machines"`)
	require.Contains(t, body, `href="/machines?package=community%2Fslack-digest&amp;version=0.5.1">1 machine</a>`)
}
