package web_test

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const actionsIssuer = "https://token.actions.githubusercontent.com"

func packagePage(t *testing.T, h http.Handler, id string) string {
	t.Helper()
	return html.UnescapeString(get(t, h, "/packages/"+id).Body.String())
}

// Only a signature whose signer matches the package's expected signer may
// read as signed; a verified signature from anybody else must say so.
func TestEveryVersionShowsItsSignatureStatusAndOnlyAMatchReadsAsSigned(t *testing.T) {
	_, h := newServer(t)

	body := packagePage(t, h, "example/platform-toolkit")
	require.Contains(t, body, `data-signature="verified-matching"`)
	require.Contains(t, body, "Signed by expected signer")
	require.Contains(t, body, "signed by https://github.com/example/platform-toolkit/.github/workflows/release.yaml@refs/tags/v1.3.0 via "+actionsIssuer)

	body = packagePage(t, h, "example/adr-writer")
	require.Contains(t, body, `data-signature="verified-no-expected-signer"`)
	require.Contains(t, body, "Signed, no expected signer")
	require.NotContains(t, body, "Signed by expected signer")

	body = packagePage(t, h, "community/release-toolkit")
	require.Contains(t, body, `data-signature="invalid"`)
	require.Contains(t, body, "Signature invalid")
	require.Contains(t, body, "did not verify: the bundle's artifact digest does not match the downloaded archive")

	body = packagePage(t, h, "community/slack-digest")
	require.Contains(t, body, `data-signature="unsigned"`)
	require.Contains(t, body, "Unsigned")
	require.NotContains(t, body, "signed by ")
}

func TestTheExpectedSignerControlShowsWhatIsConfigured(t *testing.T) {
	_, h := newServer(t)

	body := packagePage(t, h, "example/platform-toolkit")
	require.Contains(t, body, `id="package-signer"`)
	require.Contains(t, body, `action="/packages/signer"`)
	require.Contains(t, body, `name="issuer" value="`+actionsIssuer+`"`)
	require.Contains(t, body, `Expected signer: https://github\.com/example/platform-toolkit/\.github/workflows/release\.yaml@refs/tags/v.* via `+actionsIssuer)

	body = packagePage(t, h, "example/adr-writer")
	require.Contains(t, body, "No expected signer: no version of this package counts as signed.")
}

func TestTheExpectedSignerControlIsDisabledWithItsReasonForAnyoneWhoMayNotChangeIt(t *testing.T) {
	api, h := newServer(t)
	detail := api.Data.Details["example/platform-toolkit"]
	detail.Signer.CanChange = false
	api.Data.Details["example/platform-toolkit"] = detail

	body := packagePage(t, h, "example/platform-toolkit")
	require.Contains(t, body, `id="package-signer"`)
	require.NotContains(t, body, `action="/packages/signer"`)
	require.Contains(t, body, "Only this package's owner or a catalog admin may change its expected signer.")
	require.Contains(t, body, "Expected signer: ")
}

// Setting the signer re-judges versions already fetched: the verdict is read
// against the signer as it is now, never one cached at fetch time.
func TestSettingTheExpectedSignerReachesTheApiAndRejudgesEveryVersion(t *testing.T) {
	api, h := newServer(t)
	identity := `https://github\.com/example/architecture-skills/.*`

	rec := post(t, h, "/packages/signer", url.Values{
		"id": {"example/adr-writer"}, "issuer": {" " + actionsIssuer + " "}, "identity": {identity},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=signer-changed")

	calls := api.Calls("setPackageSigner")
	require.Len(t, calls, 1)
	require.Equal(t, "/v1/packages/example/adr-writer/signer", calls[0].Path)
	require.JSONEq(t, `{"issuer":"`+actionsIssuer+`","identity":"`+strings.ReplaceAll(identity, `\`, `\\`)+`"}`, string(calls[0].Body))

	body := html.UnescapeString(get(t, h, "/packages/example/adr-writer?notice=signer-changed").Body.String())
	require.Contains(t, body, "Expected signer saved.")
	require.Contains(t, body, "Signed by expected signer")
	require.NotContains(t, body, "Signed, no expected signer")

	post(t, h, "/packages/signer", url.Values{
		"id": {"example/adr-writer"}, "issuer": {actionsIssuer}, "identity": {`https://github\.com/someone-else/.*`},
	})
	body = packagePage(t, h, "example/adr-writer")
	require.Contains(t, body, "Signed, unexpected signer")
	require.NotContains(t, body, "Signed by expected signer")
}

func TestClearingTheExpectedSignerSendsNeitherField(t *testing.T) {
	api, h := newServer(t)

	rec := post(t, h, "/packages/signer", url.Values{"id": {"example/platform-toolkit"}, "issuer": {""}, "identity": {""}})
	require.Contains(t, rec.Header().Get("Location"), "notice=signer-changed")
	calls := api.Calls("setPackageSigner")
	require.Len(t, calls, 1)
	require.JSONEq(t, `{}`, string(calls[0].Body))

	body := packagePage(t, h, "example/platform-toolkit")
	require.Contains(t, body, "Signed, no expected signer")
	require.NotContains(t, body, "Signed by expected signer")
}

func TestARefusedSignerChangeRedirectsWithItsOwnNotice(t *testing.T) {
	_, h := newServer(t)

	rec := post(t, h, "/packages/signer", url.Values{"id": {"example/adr-writer"}, "issuer": {actionsIssuer}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=signer-refused")

	body := html.UnescapeString(get(t, h, "/packages/example/adr-writer?notice=signer-refused").Body.String())
	require.Contains(t, body, "The hub refused that change: give both an issuer and an identity pattern")
	require.Contains(t, body, "No expected signer")
}

func TestASignerChangeForAPackageThatIsNotThereSaysSo(t *testing.T) {
	_, h := newServer(t)

	rec := post(t, h, "/packages/signer", url.Values{"id": {"example/nope"}, "issuer": {actionsIssuer}, "identity": {".*"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=visibility-missing")
}

func TestTheSignaturePolicyCountsThePackagesItExcludesOutright(t *testing.T) {
	api, h := newServer(t)
	api.Data.Organization.Policy.PackagesWithoutExpectedSigner = 3

	body := html.UnescapeString(get(t, h, "/org").Body.String())
	require.Contains(t, body, "matches the package's expected signer")
	require.Contains(t, body, "3 published packages have no expected signer, so they resolve nothing while this is on.")

	api.Data.Organization.Policy.PackagesWithoutExpectedSigner = 0
	body = html.UnescapeString(get(t, h, "/org").Body.String())
	require.NotContains(t, body, `id="org-unsignable"`)
}
