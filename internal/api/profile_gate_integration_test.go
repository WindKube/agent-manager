//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// Each scan gate driven through GET /v1/profiles/{slug}. The resolver's rules have unit
// tests; these test the wiring (gate from org_policy, every version reaching the
// resolver), so each reads the same profile under two states and requires the answer
// to move. Fixtures are torn down because other tests count catalog packages and scans.

// gateVersion is one row of a fixture package's history; a flagged one carries the
// rule and path the policy note quotes.
type gateVersion struct {
	semver  string
	verdict models.Verdict
	latest  bool
	ruleID  string
	path    string
}

type gatePackage struct {
	id       string
	versions map[string]uuid.UUID
	findings map[string]uuid.UUID
}

func seedGatePackage(t *testing.T, name string, versions ...gateVersion) gatePackage {
	t.Helper()
	ctx := t.Context()

	insert := func(model any) {
		_, err := db.NewInsert().Model(model).Exec(ctx)
		require.NoError(t, err)
	}

	publisher := &models.Publisher{
		ID: models.NewID(), Slug: "gate/team-" + name, DisplayName: "Gate " + name,
	}
	insert(publisher)

	// package.latest_version_id and version.package_id point at each other, so the pointer goes first.
	t.Cleanup(func() {
		for _, statement := range []string{
			`update package set latest_version_id = null where publisher_id = ?`,
			`delete from override where finding_id in (
			   select f.id from finding f join version v on v.id = f.version_id
			   join package p on p.id = v.package_id where p.publisher_id = ?)`,
			`delete from finding where version_id in (
			   select v.id from version v join package p on p.id = v.package_id
			   where p.publisher_id = ?)`,
			`delete from scan where version_id in (
			   select v.id from version v join package p on p.id = v.package_id
			   where p.publisher_id = ?)`,
			`delete from signature where version_id in (
			   select v.id from version v join package p on p.id = v.package_id
			   where p.publisher_id = ?)`,
			`delete from version where package_id in (select id from package where publisher_id = ?)`,
			`delete from package where publisher_id = ?`,
			`delete from publisher where id = ?`,
		} {
			_, err := db.ExecContext(context.Background(), statement, publisher.ID)
			require.NoError(t, err)
		}
	})

	pkg := &models.Package{
		ID: models.NewID(), PublisherID: publisher.ID, Namespace: "gate", Name: name,
		Kind: models.PackageKindSkill, Visibility: models.PackageVisibilityOrganisation,
	}
	insert(pkg)

	out := gatePackage{
		id:       "gate/" + name,
		versions: map[string]uuid.UUID{},
		findings: map[string]uuid.UUID{},
	}
	for _, spec := range versions {
		sortable, err := models.SemverSort(spec.semver)
		require.NoError(t, err)

		version := &models.Version{
			ID: models.NewID(), PackageID: pkg.ID, Semver: spec.semver, SemverSort: sortable,
			ObjectKey: fmt.Sprintf("skills/gate/%s/%s/bundle.tar.zst", name, spec.semver),
			Digest:    bundleSHA, Manifest: json.RawMessage(`{"name":"` + name + `"}`),
			Tags: []string{}, DistTag: models.DistTagNone, Verdict: spec.verdict, Visible: true,
		}
		if spec.latest {
			version.DistTag = models.DistTagLatest
		}
		insert(version)
		out.versions[spec.semver] = version.ID

		if spec.latest {
			_, err = db.NewUpdate().Model((*models.Package)(nil)).
				Set("latest_version_id = ?", version.ID).Where("id = ?", pkg.ID).Exec(ctx)
			require.NoError(t, err)
		}
		if spec.ruleID == "" {
			continue
		}

		// Exactly one open finding: an acceptance is void while any other finding on the
		// version is open, which would make the accepts below silent no-ops.
		scan := &models.Scan{
			ID: models.NewID(), VersionID: version.ID, PackVersion: "gate-1.0.0",
			Verdict: spec.verdict,
		}
		insert(scan)
		finding := &models.Finding{
			ID: models.NewID(), ScanID: scan.ID, VersionID: version.ID, RuleID: spec.ruleID,
			Severity: models.FindingSeverityHigh, Title: spec.ruleID + " raised",
			EvidencePath: spec.path, State: models.FindingStateOpen,
		}
		insert(finding)
		out.findings[spec.semver] = finding.ID
	}
	return out
}

// newGateProfile creates a profile through the api and removes it afterwards. Call it
// after seedGatePackage so its cleanup runs first: profile_entry references package.
func newGateProfile(t *testing.T, slug, name string) {
	t.Helper()
	newProfile(t, curator, slug, name)

	t.Cleanup(func() {
		for _, table := range []string{"profile_entry", "membership", "sync_target", "revision"} {
			_, err := db.ExecContext(context.Background(),
				`delete from `+table+` where profile_id in (select id from profile where slug = ?)`,
				slug)
			require.NoError(t, err)
		}
		_, err := db.ExecContext(context.Background(), `delete from profile where slug = ?`, slug)
		require.NoError(t, err)
	})
}

// setGate writes the org-wide scan gate and restores the previous one. Safe because
// tests in a package run sequentially; the restore is registered before the write.
func setGate(t *testing.T, gate models.ScanGate) {
	t.Helper()

	var previous string
	require.NoError(t, db.QueryRowContext(t.Context(),
		`select scan_gate::text from org_policy where id = ?`, models.OrgPolicySingletonID).
		Scan(&previous))
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(),
			`update org_policy set scan_gate = ? where id = ?`,
			previous, models.OrgPolicySingletonID)
		require.NoError(t, err)
	})

	_, err := db.ExecContext(t.Context(), `update org_policy set scan_gate = ? where id = ?`,
		string(gate), models.OrgPolicySingletonID)
	require.NoError(t, err)
}

// acceptFindingAs accepts through the api, not an INSERT: the override and its audit
// row are written by one transaction.
func acceptFindingAs(t *testing.T, who actor, finding uuid.UUID, note string, days int) {
	t.Helper()

	send(t, who, http.MethodPost, "/v1/findings/"+finding.String()+"/accept",
		fmt.Sprintf(`{"note":%q,"expiresInDays":%d}`, note, days), http.StatusOK)
}

// The version below the flagged latest is also flagged, so only an api that hands the
// resolver every version can reach the clean 1.0.0.
func TestUnderTheBlockGateAFlaggedEntryResolvesToItsMostRecentCleanVersionAndTheNoteSaysSo(t *testing.T) {
	pkg := seedGatePackage(t, "block-fallback",
		gateVersion{semver: "1.0.0", verdict: models.VerdictClean},
		gateVersion{semver: "1.4.0", verdict: models.VerdictFlagged,
			ruleID: "SH-DEP-009", path: "scripts/install.sh"},
		gateVersion{semver: "2.0.0", verdict: models.VerdictFlagged, latest: true,
			ruleID: "SH-NET-002", path: "hooks/postinstall.sh"},
	)

	slug := "gate/block-fallback"
	newGateProfile(t, slug, "Block fallback")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	setGate(t, models.ScanGateWarnWithOverride)
	before := entryByID(t, profileDetail(t, curator, slug), pkg.id)
	require.Equal(t, "2.0.0", before.Version)
	require.Equal(t, "warned", before.Outcome)

	setGate(t, models.ScanGateBlock)
	detail := profileDetail(t, curator, slug)
	require.Equal(t, string(models.ScanGateBlock), detail.Gate,
		"the screen reports the gate it resolved under, and it is read from org_policy")

	entry := entryByID(t, detail, pkg.id)
	require.Equal(t, "1.0.0", entry.Version,
		"block falls back to the most recent CLEAN version, and 1.4.0 is flagged too: "+
			"answering 1.4.0 means the walk stops at the first older row, and answering "+
			"nothing means the older rows never reached the resolver")
	require.Equal(t, "downgraded", entry.Outcome,
		"'downgraded' and 'resolved' are different rows on the screen: one of them is a "+
			"version the owner did not ask for")
	require.Equal(t, string(models.VerdictClean), entry.Verdict)
	require.Nil(t, entry.Skip, "the entry resolved, so it is not an exclusion")
	require.Nil(t, entry.Override, "an acceptance does not lift a block, so none is recorded")
	require.NotEmpty(t, entry.Digest, "the row shows the identity the lockfile would freeze")

	// Without the note a downgrade silently shows an older version than the catalog offers.
	require.Contains(t, entry.Note, "2.0.0", "the note names the version that was refused")
	require.Contains(t, entry.Note, "SH-NET-002 in hooks/postinstall.sh",
		"a note that cannot name the finding states a policy with no reason")
	require.Contains(t, entry.Note, "blocks flagged versions")
	require.Contains(t, entry.Note, "resolved to 1.0.0, the most recent clean version")

	// The Scan badge is the catalog's answer and does not move with the gate.
	require.Equal(t, "2.0.0", entry.LatestVersion)
	require.Equal(t, string(models.VerdictFlagged), entry.LatestVerdict)
}

// The fixture has a clean version to fall back to; that is the only way to tell
// `approval` (exclude) from `block` (downgrade).
func TestUnderTheApprovalGateAnUnapprovedFlaggedVersionIsExcludedAndNamesTheApprovalItNeeds(t *testing.T) {
	pkg := seedGatePackage(t, "approval-hold",
		gateVersion{semver: "1.0.0", verdict: models.VerdictClean},
		gateVersion{semver: "2.0.0", verdict: models.VerdictFlagged, latest: true,
			ruleID: "SH-EXE-013", path: "SKILL.md"},
	)

	// The fallback really is resolvable, so the exclusion below is the gate's decision.
	fallback, err := db.NewSelect().Model((*models.Version)(nil)).
		Where("id = ? and visible and digest is not null", pkg.versions["1.0.0"]).
		Count(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, fallback)

	slug := "gate/approval-hold"
	newGateProfile(t, slug, "Approval hold")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	setGate(t, models.ScanGateWarnWithOverride)
	before := entryByID(t, profileDetail(t, curator, slug), pkg.id)
	require.Equal(t, "2.0.0", before.Version)
	require.Nil(t, before.Skip)

	setGate(t, models.ScanGateApproval)
	detail := profileDetail(t, curator, slug)
	require.Equal(t, string(models.ScanGateApproval), detail.Gate)

	entry := entryByID(t, detail, pkg.id)
	require.Equal(t, "skipped", entry.Outcome)
	require.Empty(t, entry.Version,
		"approval EXCLUDES the entry; resolving 1.0.0 here would be a quiet downgrade "+
			"that hides the review somebody is waiting on")
	require.Empty(t, entry.Verdict)
	require.Nil(t, entry.Override)

	require.NotNil(t, entry.Skip, "an excluded package is reported, never omitted")
	require.Equal(t, "flagged-awaiting-approval", entry.Skip.Reason)
	require.Equal(t, "2.0.0", entry.Skip.WouldHaveResolvedTo,
		"the exclusion has to name the version the owner expected to get")
	require.Equal(t, "SH-EXE-013 in SKILL.md", entry.Skip.Detail)

	require.Contains(t, entry.Note, "requires a named reviewer to approve it",
		"the scenario asks for the requirement to be REPORTED, not merely for the entry to vanish")
	require.Contains(t, entry.Note, "not quietly downgraded to an older version")
	require.Contains(t, entry.Note, "SH-EXE-013 in SKILL.md")

	// One row per package the profile holds, not per package that survived.
	require.Len(t, detail.Entries, 1)
	require.Equal(t, "2.0.0", entry.LatestVersion)
	require.Equal(t, string(models.VerdictFlagged), entry.LatestVerdict)

	// The requirement is satisfiable: a named reviewer's approval makes the same entry resolve.
	acceptFindingAs(t, an, pkg.findings["2.0.0"], "Reviewed with the publisher", 9)

	approved := entryByID(t, profileDetail(t, curator, slug), pkg.id)
	require.Equal(t, "2.0.0", approved.Version)
	require.Equal(t, "overridden", approved.Outcome)
	require.Nil(t, approved.Skip)
	require.NotNil(t, approved.Override)
	require.Equal(t, an.claims.Email, approved.Override.Reviewer)
	require.Contains(t, approved.Note, "the scan gate requires approval")
	require.Contains(t, approved.Note, an.claims.Email)
}

// One accept produces both the override the resolver reads and the audit row, in one transaction.
func TestUnderWarnWithOverrideAnActiveOverrideResolvesTheFlaggedVersionAndShowsInTheAuditLog(t *testing.T) {
	pkg := seedGatePackage(t, "override-warned",
		gateVersion{semver: "1.0.0", verdict: models.VerdictClean},
		gateVersion{semver: "2.0.0", verdict: models.VerdictFlagged, latest: true,
			ruleID: "SH-FS-021", path: "hooks/postinstall.sh"},
	)

	slug := "gate/override-warned"
	newGateProfile(t, slug, "Override warned")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)
	setGate(t, models.ScanGateWarnWithOverride)

	// Without an override the flagged version is still included; the note says which case it is.
	before := entryByID(t, profileDetail(t, curator, slug), pkg.id)
	require.Equal(t, "2.0.0", before.Version)
	require.Equal(t, "warned", before.Outcome)
	require.Nil(t, before.Override)
	require.Contains(t, before.Note, "No reviewer has accepted this finding")

	logged := auditRowCount(t)
	acceptFindingAs(t, an, pkg.findings["2.0.0"], "Egress is to our own collector", 12)
	require.Equal(t, logged+1, auditRowCount(t), "one decision, one audit row")

	detail := profileDetail(t, curator, slug)
	require.Equal(t, string(models.ScanGateWarnWithOverride), detail.Gate)

	entry := entryByID(t, detail, pkg.id)
	require.Equal(t, "2.0.0", entry.Version, "the FLAGGED version resolves, not the clean 1.0.0")
	require.Equal(t, "overridden", entry.Outcome,
		"'warned' and 'overridden' are different rows on the screen, and the difference is "+
			"whether a person's name is on the decision")
	require.Equal(t, string(models.VerdictFlagged), entry.Verdict,
		"an acceptance does not make the version clean; it makes it resolvable under this gate")
	require.Nil(t, entry.Skip)

	require.NotNil(t, entry.Override, "the active acceptance is what the row reports")
	require.Equal(t, an.claims.Email, entry.Override.Reviewer)
	require.Equal(t, "Egress is to our own collector", entry.Override.Note)
	require.WithinDuration(t, time.Now().UTC().Add(12*24*time.Hour), entry.Override.ExpiresAt,
		time.Minute, "the acceptance is bounded, and the row shows until when")

	require.Contains(t, entry.Note, an.claims.Email)
	require.Contains(t, entry.Note, "accepted the finding")
	require.Contains(t, entry.Note, "resolves with a warning")
	require.Contains(t, entry.Note, "SH-FS-021 in hooks/postinstall.sh")

	// Read back through the api rather than off the table.
	page := getJSON[contract.AuditPage](t, liveHandler(t), kw.token, "/v1/audit?pageSize=5")
	require.NotEmpty(t, page.Entries)

	row := page.Entries[0]
	require.Equal(t, string(models.AuditKindApprove), row.Kind)
	require.Equal(t, an.claims.Email, row.Actor,
		"names the person, not the service account the transaction ran as")
	require.Equal(t, string(models.ActorKindIdentity), row.ActorKind)
	require.Equal(t, "web", row.Source)
	require.Contains(t, row.Text, pkg.id+"@2.0.0",
		"an audit row that does not say what was overridden is not an audit row")
	require.Contains(t, row.Text, "SH-FS-021")
}
