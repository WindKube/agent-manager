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

// 001 US5 scenarios 2, 3 and 4 — one per organisation scan gate — driven through
// the real GET /v1/profiles/{slug} against a real Postgres (003 T089).
//
// internal/domain/resolve already has a unit test of the rules themselves, so
// nothing here is about whether `block` blocks. What is under test is the WIRING,
// and every part of it is a plausible way to build this wrongly while the
// resolver's own suite stays green:
//
//   - the gate comes out of the `org_policy` row, not out of a default;
//   - the resolver is handed EVERY published version of a package, so a fallback
//     to an older one is reachable at all;
//   - a version's flag and a reviewer's acceptance arrive as facts about the
//     VERSION rather than about one finding on it;
//   - the note the screen renders is the resolver's own sentence, not a second
//     account written in a query or a template.
//
// Each test therefore reads the SAME profile under two states and requires the
// answer to MOVE. One read under one gate would pass against an api that ignored
// the gate entirely and happened to agree with it.
//
// The fixtures are rows on the migrated schema, built and torn down per test.
// Torn down because they are organisation-visible packages carrying a latest
// version and a scan, which is exactly what catalog_integration_test.go counts
// when it asserts the unfiltered total is ten and what the median-scan-time test
// needs the `scan` table to itself for.

// ---- fixtures ----------------------------------------------------------------

// gateVersion is one row of a fixture package's history. A flagged one carries a
// rule and an evidence path because the policy note quotes both, and a note that
// cannot name the finding states a policy with no reason.
type gateVersion struct {
	semver  string
	verdict models.Verdict
	latest  bool
	ruleID  string
	path    string
}

// gatePackage is what a gate test resolves against: the catalog id the profile
// names, and the ids a test needs to act on a specific version or finding.
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

	// Dependency order rather than a cascade: package.latest_version_id and
	// version.package_id point at each other, so the pointer is cleared first.
	// Same shape as seedGovernance's teardown and for the same reason.
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

		// Exactly ONE open finding per flagged version. The gate reads an
		// acceptance as void while any finding on the same version is still open,
		// so a second finding would make the accept in scenarios 3 and 4 a silent
		// no-op and the tests would be asserting the wrong mechanism.
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

// newGateProfile creates a profile through the api and removes it afterwards.
//
// It must be called AFTER seedGatePackage so its cleanup, being registered
// later, runs FIRST: profile_entry points at package, and the package fixture
// cannot delete rows an entry still references.
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

// setGate writes the organisation's scan gate and restores whatever it found.
//
// The gate is a singleton row and there is deliberately no per-request override,
// so writing org-wide policy is the ONLY way to reach these three branches
// through the api — which is the whole point of T089 being an integration test.
// It is safe because Go runs one test of a package at a time and the integration
// target does not shuffle; the restore is registered before the write, so a test
// that fails part way still hands `warn-with-override` back to everything after it.
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

// acceptFindingAs records a reviewer's acceptance through the real operation.
//
// Through the api and not an INSERT, because the override the gate reads and the
// audit row scenario 4 asks for are written by ONE transaction in
// commands.AcceptFinding. A fixture that wrote the `override` row directly would
// test the gate against a state the product cannot produce, and would assert
// nothing whatsoever about the audit half of the scenario.
func acceptFindingAs(t *testing.T, who actor, finding uuid.UUID, note string, days int) {
	t.Helper()

	send(t, who, http.MethodPost, "/v1/findings/"+finding.String()+"/accept",
		fmt.Sprintf(`{"note":%q,"expiresInDays":%d}`, note, days), http.StatusOK)
}

// ---- US5 scenario 2: block ---------------------------------------------------

// "Given the gate is `block` and a profile contains a flagged package, when the
// profile resolves, then that package resolves to its most recent clean version,
// and the screen states this in the policy note."
//
// The version directly below the flagged latest is ALSO flagged, so "the most
// recent clean version" is a different answer from "the one before the latest".
// That is what makes this an api test rather than a resolver test: an
// implementation that handed the resolver only `package.latest_version_id`, or
// only the two newest rows, cannot reach 1.0.0 at all and would answer with an
// exclusion that looks entirely reasonable on the screen.
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

	// The control the scenario is a delta from: under a gate that includes flagged
	// versions, this entry takes the flagged latest.
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

	// The scenario's second half. The note is the whole reason a downgrade is not
	// a lie: without it the screen silently shows an older version than the
	// catalog offers and nobody can tell why.
	require.Contains(t, entry.Note, "2.0.0", "the note names the version that was refused")
	require.Contains(t, entry.Note, "SH-NET-002 in hooks/postinstall.sh",
		"a note that cannot name the finding states a policy with no reason")
	require.Contains(t, entry.Note, "blocks flagged versions")
	require.Contains(t, entry.Note, "resolved to 1.0.0, the most recent clean version")

	// The Scan badge is the CATALOG's answer and does not move with the gate.
	// Conflating the two is how a row comes to claim a package is clean because
	// the version the gate fell back to is.
	require.Equal(t, "2.0.0", entry.LatestVersion)
	require.Equal(t, string(models.VerdictFlagged), entry.LatestVerdict)
}

// ---- US5 scenario 3: approval ------------------------------------------------

// "Given the gate is `approval`, when a profile containing an unapproved flagged
// version resolves, then that package is excluded and reported as requiring a
// named reviewer approval."
//
// The fixture deliberately HAS a clean version to fall back to, because that is
// the only way to tell `approval` from `block`: excluding an entry when there was
// nothing to resolve to proves nothing. Installing the older version instead
// would answer a question nobody asked and bury the pending review.
func TestUnderTheApprovalGateAnUnapprovedFlaggedVersionIsExcludedAndNamesTheApprovalItNeeds(t *testing.T) {
	pkg := seedGatePackage(t, "approval-hold",
		gateVersion{semver: "1.0.0", verdict: models.VerdictClean},
		gateVersion{semver: "2.0.0", verdict: models.VerdictFlagged, latest: true,
			ruleID: "SH-EXE-013", path: "SKILL.md"},
	)

	// Stated rather than assumed: the fallback the exclusion below refuses to take
	// really is on the shelf, so the exclusion is the gate's decision and not the
	// seed having quietly written something unresolvable.
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

	require.NotNil(t, entry.Skip, "FR-036: an excluded package is reported, never omitted")
	require.Equal(t, "flagged-awaiting-approval", entry.Skip.Reason)
	require.Equal(t, "2.0.0", entry.Skip.WouldHaveResolvedTo,
		"the exclusion has to name the version the owner expected to get")
	require.Equal(t, "SH-EXE-013 in SKILL.md", entry.Skip.Detail)

	require.Contains(t, entry.Note, "requires a named reviewer to approve it",
		"the scenario asks for the requirement to be REPORTED, not merely for the entry to vanish")
	require.Contains(t, entry.Note, "not quietly downgraded to an older version")
	require.Contains(t, entry.Note, "SH-EXE-013 in SKILL.md")

	// The row is still drawn — one row per package the profile holds, not one per
	// package that survived.
	require.Len(t, detail.Entries, 1)
	require.Equal(t, "2.0.0", entry.LatestVersion)
	require.Equal(t, string(models.VerdictFlagged), entry.LatestVerdict)

	// The requirement the exclusion reports is real and satisfiable: a named
	// reviewer approves the finding, nothing else moves, and the same entry under
	// the same gate now resolves with that name on it. Without this half,
	// "requires a named reviewer" is a sentence the screen prints and nothing
	// honours.
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

// ---- US5 scenario 4: warn-with-override --------------------------------------

// "Given the gate is `warn-with-override` and an active override exists, then the
// flagged version resolves with a warning and the override is visible in the
// audit log."
//
// Both halves come from ONE act — the accept — and that is why this test is worth
// its container: the override the resolver reads and the audit row a reviewer is
// held to are written by the same transaction, and a test that seeded the
// override row directly would prove neither that the api can produce that state
// nor that anybody is accountable for it.
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

	// Before anybody signs. FR-035 includes a flagged version under this gate
	// whether or not an override exists, and the note says which of the two it is.
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
		time.Minute, "FR-028: the acceptance is bounded, and the row shows until when")

	require.Contains(t, entry.Note, an.claims.Email)
	require.Contains(t, entry.Note, "accepted the finding")
	require.Contains(t, entry.Note, "resolves with a warning")
	require.Contains(t, entry.Note, "SH-FS-021 in hooks/postinstall.sh")

	// The scenario's second half, read back through the api rather than off the
	// table: the override is IN the audit log, named, attributed and sourced.
	page := getJSON[contract.AuditPage](t, liveHandler(t), kw.token, "/v1/audit?pageSize=5")
	require.NotEmpty(t, page.Entries)

	row := page.Entries[0]
	require.Equal(t, string(models.AuditKindApprove), row.Kind)
	require.Equal(t, an.claims.Email, row.Actor,
		"FR-051 names the person, not the service account the transaction ran as")
	require.Equal(t, string(models.ActorKindIdentity), row.ActorKind)
	require.Equal(t, "web", row.Source)
	require.Contains(t, row.Text, pkg.id+"@2.0.0",
		"an audit row that does not say what was overridden is not an audit row")
	require.Contains(t, row.Text, "SH-FS-021")
}
