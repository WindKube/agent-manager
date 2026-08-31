//go:build integration

// The product's central claim, end to end, on a database nobody seeded (T076,
// T077).
//
// Everything else in this package starts from rows a helper wrote. This file
// starts from a URL: a person registers a package, the fetcher goes and gets it,
// the scanner reads the bytes that landed and reaches a verdict, a reviewer
// adjudicates it, and the adjudication changes what a machine can obtain. Each
// hand-off is taken out of the OUTBOX rather than constructed here, so the chain
// itself is under test — a publish that forgot to enqueue its scan would make
// these fail rather than be papered over by a fabricated job.
//
// The suite this file joins applies the migrations and nothing else. That is
// SC-107's condition, not an accident: a governance test that leans on the seed
// proves the seed writes plausible rows, which is not the claim.
package scanner_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/fetch"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/fetcher"
	"agent-manager/internal/worker/scanner"
	"agent-manager/internal/worker/scanner/checks"
)

// ---- the forge --------------------------------------------------------------

// loopForge serves one repository's tarball endpoint, and 404s everything else so
// a wrong ref reads as "the remote does not have it" rather than as the fixture.
//
// A local server rather than a real forge: the test has to be able to state the
// exact bytes it later asserts a finding about, and a network dependency in a
// test is a flake with extra steps. The outbound client below is the REAL
// SSRF-hardened one with this server's loopback address allowlisted, so the
// policy is exercised rather than bypassed.
func loopForge(t *testing.T, repo string, files map[string]string) string {
	t.Helper()

	prefix := "/api/v3/repos/org/" + repo + "/tarball/"
	tarball := loopTarball(t, repo+"-9e3f1c2", files)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	t.Cleanup(server.Close)

	return server.URL
}

// loopTarball builds what a forge's tarball endpoint returns: a gzipped tar whose
// every path sits under one wrapper directory named for the commit.
func loopTarball(t *testing.T, wrapper string, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for path, body := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: wrapper + "/" + path,
			Mode: 0o644,
			Size: int64(len(body)),
		}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// flatten renders one of this package's scan fixtures as a forge would hold it.
// The loop is deliberately fed the SAME hostile and benign trees the scan tests
// use: if the two drifted, a green loop would say nothing about the fixtures the
// rules are actually verified against.
func flatten(tree fstest.MapFS) map[string]string {
	out := make(map[string]string, len(tree))
	for path, file := range tree {
		out[path] = string(file.Data)
	}
	return out
}

// ---- the two roles, sharing one bucket --------------------------------------

// loopHarness is both background roles as the bootstrap would have built them,
// over one bucket. The asymmetry is the point and is visible in the two Deps: the
// fetcher holds BlobWrite, the scanner holds only a reader, and the bytes the
// scanner judges are the bytes the fetcher committed rather than a copy the test
// made.
type loopHarness struct {
	fetcher *fetcher.Worker
	scanner *scanner.Worker
	bucket  *blob.Bucket
}

func newLoopHarness(t *testing.T, forgeURLs ...string) loopHarness {
	t.Helper()
	ctx := context.Background()

	bucket, err := blob.Open(ctx, "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })

	allowlist := make([]string, 0, len(forgeURLs))
	for _, raw := range forgeURLs {
		parsed, parseErr := url.Parse(raw)
		require.NoError(t, parseErr)
		allowlist = append(allowlist, parsed.Host)
	}
	client, err := fetch.New(fetch.Options{Timeout: 20 * time.Second, Allowlist: allowlist})
	require.NoError(t, err)

	fetchWorker, err := fetcher.New(worker.Deps{
		DB:        db,
		BlobRead:  bucket.Reader(),
		BlobWrite: bucket.Writer(),
		Fetch:     client,
		Log:       zerolog.New(io.Discard),
	})
	require.NoError(t, err)

	scanWorker, err := scanner.New(worker.Deps{
		DB:       db,
		BlobRead: bucket.Reader(),
		Log:      zerolog.New(io.Discard),
	}, scanner.Options{})
	require.NoError(t, err)

	return loopHarness{fetcher: fetchWorker, scanner: scanWorker, bucket: bucket}
}

// ---- the people -------------------------------------------------------------

func importer() auth.Principal {
	return auth.Principal{
		IdentityID: models.NewID(),
		Subject:    "sub-importer",
		Email:      "importer@example.com",
		Role:       models.OrgRoleCatalogAdmin,
		Source:     auth.SourceWeb,
	}
}

// reviewer is a real identity row, because `override.reviewer_identity_id` is a
// foreign key: an exception with nobody accountable for it is not a state the
// schema allows, and a principal carrying an id no identity table holds would
// fail at the constraint rather than at the assertion.
func reviewer(t *testing.T, subject string) auth.Principal {
	t.Helper()

	id := models.NewID()
	email := subject + "@example.com"
	_, err := pool.Exec(context.Background(),
		`insert into identity (id, subject, email, display_name) values ($1, $2, $3, $4)`,
		id, subject, email, "Reviewer "+subject)
	require.NoError(t, err)

	return auth.Principal{
		IdentityID: id,
		Subject:    subject,
		Email:      email,
		Role:       models.OrgRoleScannerReviewer,
		Source:     auth.SourceWeb,
	}
}

// ---- the loop itself --------------------------------------------------------

// imported is what one trip round the loop produced.
type imported struct {
	packageID uuid.UUID
	versionID uuid.UUID
	namespace string
	name      string
	semver    string
}

// importPackage runs the whole ingestion path a person's import takes, taking
// every hand-off out of the outbox.
//
// Reading the jobs rather than building them is what makes this a test of the
// CHAIN. The relay is not run — that is internal/outbox's own suite — but the
// payload is decoded exactly as the relay would hand it to River, and each job is
// re-validated, so a publish that enqueued a payload the consumer cannot read
// fails here instead of in production.
func (h loopHarness) importPackage(t *testing.T, p auth.Principal, in commands.Registration) imported {
	t.Helper()
	ctx := context.Background()

	registered, err := commands.RegisterPackage(ctx, db, p, in)
	require.NoError(t, err)

	versionID := uuid.MustParse(registered.VersionID)
	require.NoError(t, h.fetcher.Fetch(ctx, outboxFetchJob(t, versionID)))

	scanJob := outboxScanJob(t, versionID)
	require.NoError(t, h.scanner.Scan(ctx, scanJob, false))

	return imported{
		packageID: scanJob.PackageID,
		versionID: versionID,
		namespace: scanJob.Namespace,
		name:      scanJob.Name,
		semver:    scanJob.Semver,
	}
}

func outboxFetchJob(t *testing.T, versionID uuid.UUID) fetcher.Job {
	t.Helper()

	var payload []byte
	require.NoError(t, pool.QueryRow(context.Background(),
		`select payload from outbox
		  where job_kind = 'fetch' and idempotency_key like 'fetch:' || $1 || ':%'
		  order by created_at desc limit 1`, versionID).Scan(&payload),
		"the registration must have enqueued its fetch in the same transaction (principle IX)")

	var job fetcher.Job
	require.NoError(t, json.Unmarshal(payload, &job))
	require.NoError(t, job.Validate())
	return job
}

func outboxScanJob(t *testing.T, versionID uuid.UUID) scanner.Job {
	t.Helper()

	var payload []byte
	require.NoError(t, pool.QueryRow(context.Background(),
		`select payload from outbox
		  where job_kind = 'scan' and payload ->> 'versionId' = $1
		  order by created_at desc limit 1`, versionID.String()).Scan(&payload),
		"the publish must have enqueued the scan in the same transaction: a committed version "+
			"nothing will ever scan is a version stuck at 'Scanning' for ever")

	var job scanner.Job
	require.NoError(t, json.Unmarshal(payload, &job))
	require.NoError(t, job.Validate())
	return job
}

// ---- what a profile resolves to ---------------------------------------------

// containedIn puts the package in a profile, floating on the latest version. This
// is a profile a machine could sync, written directly because the api that builds
// one is US5's (T079..T083) and does not exist yet.
func containedIn(t *testing.T, slug string, pkg imported) {
	t.Helper()

	profileID := models.NewID()
	_, err := pool.Exec(context.Background(),
		`insert into profile (id, slug, name, visibility, default_policy)
		 values ($1, $2, $3, 'organisation', 'floating-latest')`,
		profileID, slug, "Loop "+slug)
	require.NoError(t, err)

	_, err = pool.Exec(context.Background(),
		`insert into profile_entry (profile_id, package_id, mode, position)
		 values ($1, $2, 'latest', 1)`,
		profileID, pkg.packageID)
	require.NoError(t, err)
}

// resolvesToServableBytes reports whether a floating entry on this package still
// gives a machine something to sync: the package's own latest pointer, and then
// the api's own answer to "may these bytes be served".
//
// It composes two production reads and adds no rule of its own. In particular it
// does NOT restate the org gate — `BundleRef.Distributable` is the gate-independent
// half of resolution (FR-029), which is precisely why a rejection is assertable
// here while an acceptance is not. The gate arithmetic that turns an override into
// a lockfile entry lands with the profile resolver in T078/T083; when it does,
// THIS is the helper to replace with a call to it.
func resolvesToServableBytes(t *testing.T, pkg imported) bool {
	t.Helper()
	ctx := context.Background()

	var latest uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		`select latest_version_id from package where id = $1`, pkg.packageID).Scan(&latest))
	require.Equal(t, pkg.versionID, latest,
		"a floating entry resolves to the package's latest version, so that is what must be judged")

	ref, err := queries.Bundle(ctx, db, pkg.namespace, pkg.name, pkg.semver)
	if err != nil {
		require.ErrorIs(t, err, queries.ErrNotFound)
		return false
	}
	return ref.Distributable()
}

func setScanGate(t *testing.T, gate models.ScanGate) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`insert into org_policy
		   (id, scan_gate, default_version_policy, require_signed_bundles,
		    community_needs_review, rescan_on_new_version, allow_personal_profiles)
		 values (1, $1, 'floating-latest', false, true, false, true)
		 on conflict (id) do update set scan_gate = excluded.scan_gate`, string(gate))
	require.NoError(t, err)
}

// requireNoSeededData is SC-107's "with no seeded rows involved", stated rather
// than assumed.
//
// It names the tables `internal/seed` writes that nothing in this suite does. If
// somebody wires the seed into this suite's TestMain for convenience, the loop
// tests stop proving what they claim and this is what says so — a green loop over
// seeded rows is the exact false positive SC-107 was written against.
func requireNoSeededData(t *testing.T) {
	t.Helper()

	for _, table := range []string{"category", "membership", "sync_target", "sync_event", "revision"} {
		require.Zerof(t, countRows(t, "select count(*) from "+table),
			"%s holds rows: this suite must run against migrations alone (SC-107)", table)
	}
}

// ---- T076 / SC-107 / SC-108 -------------------------------------------------

// The claim the whole product rests on: bytes a person pointed at become a
// verdict, and a reviewer's decision about that verdict changes what a machine
// can obtain.
//
// The assertion that matters is the LAST one, and it is deliberately not an audit
// row. An approval that files a beautifully worded audit row and changes nothing a
// resolver reads is the failure this test exists to catch, so every decision below
// is measured as a state delta against a snapshot taken before it.
func TestTheWholeLoopFromAnImportedHostilePackageToAChangedResolution(t *testing.T) {
	requireNoSeededData(t)
	ctx := context.Background()

	hostileURL := loopForge(t, "cost-report", flatten(hostileTree()))
	h := newLoopHarness(t, hostileURL)

	pkg := h.importPackage(t, importer(), commands.Registration{
		Source:    fetch.SourceGit,
		URL:       hostileURL + "/org/cost-report",
		Ref:       "v1.0.0",
		Publisher: "loopone/team",
		Name:      "cost-report",
		Kind:      models.PackageKindSkill,
	})
	containedIn(t, "loop-one", pkg)

	// FR-124: the import left "Scanning" on its own, from real bytes.
	require.Equal(t, string(models.VerdictFlagged), versionVerdict(t, pkg.versionID))
	require.True(t, resolvesToServableBytes(t, pkg),
		"a flagged version is quarantined by the gate, not withdrawn: its bytes are still servable")

	findingID := openFindingOn(t, pkg.versionID, "SH-NET-002")

	before, err := queries.Finding(ctx, db, findingID)
	require.NoError(t, err)
	require.Equal(t, string(models.FindingStateOpen), before.State)
	require.Nil(t, before.Override, "nobody has decided anything yet")

	// FR-025 against a real scan rather than a hand-seeded matrix: the pane carries
	// every check that RAN, passes included. The seed writes no finding_evidence at
	// all — deliberately, because the scanner is its writer — so the evidence pane
	// only ever has rows when they came from bytes, which is what this asserts.
	registry, err := checks.Default()
	require.NoError(t, err)
	require.Len(t, before.Checks, len(registry.IDs()),
		"a pane showing only failures cannot be told apart from one where nothing else ran")
	require.Condition(t, func() bool {
		for _, check := range before.Checks {
			if check.Result == string(models.CheckResultPass) {
				return true
			}
		}
		return false
	}, "the matrix has to carry the passes, or FR-025 buys nothing")

	require.NotEmpty(t, before.Evidence)
	require.Equal(t, "primary", before.Evidence[0].Role, "the cause leads")
	require.Contains(t, before.Evidence[0].Quote, "collector.exfil.example",
		"the evidence is quoted from the bundle's own bytes, which is what makes a finding checkable")

	summaryBefore, err := queries.ScannerSummary(ctx, db, 30)
	require.NoError(t, err)

	// --- the acceptance ------------------------------------------------------

	who := reviewer(t, "sec-lead")
	decision, err := commands.AcceptFinding(ctx, db, who, commands.Decision{
		FindingID: findingID,
		Note:      "accepted for the pilot; the collector host is ours",
		Days:      12,
	})
	require.NoError(t, err)
	require.Equal(t, string(models.FindingStateApproved), decision.State)

	after, err := queries.Finding(ctx, db, findingID)
	require.NoError(t, err)
	require.Equal(t, string(models.FindingStateApproved), after.State)
	require.NotNil(t, after.Override,
		"the override IS the decision: without it the gate has nothing to read and the "+
			"approval changed nothing a resolver can act on")
	require.Equal(t, who.Email, after.Override.Reviewer)
	require.Equal(t, "accepted for the pilot; the collector host is ours", after.Override.Note)
	require.NotNil(t, after.Override.ExpiresAt, "FR-028: an acceptance is bounded, never open-ended")
	require.WithinDuration(t, time.Now().UTC().Add(12*24*time.Hour), *after.Override.ExpiresAt, time.Minute)

	require.Equal(t, string(models.VerdictFlagged), after.Verdict,
		"an acceptance must not launder the version clean: it stays flagged and the "+
			"override is what the gate reads (001 US4 scenario 3)")
	require.Equal(t, string(models.VerdictFlagged), versionVerdict(t, pkg.versionID))

	summaryAfter, err := queries.ScannerSummary(ctx, db, 30)
	require.NoError(t, err)
	require.Equal(t, summaryBefore.OverridesActive+1, summaryAfter.OverridesActive,
		"the Scanner screen's active-override figure is the reviewer's decision made visible")
	require.NotNil(t, summaryAfter.NearestExpiry)

	require.True(t, resolvesToServableBytes(t, pkg),
		"an acceptance does not withdraw the bytes")

	// --- the rejection -------------------------------------------------------
	//
	// A second package, because rejection is terminal: doing both to one version
	// would test the second decision against a state the first had already left.

	benignURL := loopForge(t, "digest-report", flatten(hostileTree()))
	h2 := newLoopHarness(t, benignURL)
	doomed := h2.importPackage(t, importer(), commands.Registration{
		Source:    fetch.SourceGit,
		URL:       benignURL + "/org/digest-report",
		Ref:       "v2.0.0",
		Publisher: "looptwo/team",
		Name:      "cost-report",
		Kind:      models.PackageKindSkill,
	})
	containedIn(t, "loop-two", doomed)

	require.True(t, resolvesToServableBytes(t, doomed),
		"before the decision, a profile holding this package resolves to bytes a machine can fetch")

	doomedFinding := openFindingOn(t, doomed.versionID, "SH-NET-002")
	rejected, err := commands.RejectFinding(ctx, db, who, commands.Decision{
		FindingID: doomedFinding,
		Note:      "the egress host is not ours and never was",
	})
	require.NoError(t, err)
	require.Equal(t, string(models.VerdictRejected), rejected.Verdict)

	// SC-108, and the only assertion in this file that is about resolution rather
	// than about state: the same profile, the same package, the same query — and a
	// different answer, because a person decided.
	require.False(t, resolvesToServableBytes(t, doomed),
		"a rejected version must not be resolvable by any profile (FR-029)")

	// "Regardless of gate" is a requirement about a value this path must not read.
	// Driving all three modes is what would catch the day somebody makes the
	// refusal conditional on policy.
	for _, gate := range []models.ScanGate{
		models.ScanGateBlock, models.ScanGateApproval, models.ScanGateWarnWithOverride,
	} {
		setScanGate(t, gate)
		require.False(t, resolvesToServableBytes(t, doomed),
			"gate %s: FR-029 makes rejection terminal regardless of what the org policy says", gate)
	}

	// And terminal means terminal: an acceptance cannot walk it back, because
	// un-rejecting is a real operation with real consequences and belongs to
	// whoever designs the reversal.
	_, err = commands.AcceptFinding(ctx, db, who, commands.Decision{
		FindingID: doomedFinding,
		Note:      "on reflection",
	})
	require.ErrorIs(t, err, commands.ErrFindingRejected)
	require.False(t, resolvesToServableBytes(t, doomed))
}

// SC-107 on its own terms: an import reaches a TERMINAL verdict, and the loop
// does not reach it by flagging everything.
//
// The pair is the test. A scanner that answered `flagged` unconditionally would
// satisfy "reaches a terminal verdict" and be worthless, and one that answered
// `clean` unconditionally would satisfy it and be worse.
func TestAPackageImportedOnAnUnseededDatabaseReachesATerminalVerdictEitherWay(t *testing.T) {
	requireNoSeededData(t)

	hostileURL := loopForge(t, "hostile-import", flatten(hostileTree()))
	benignURL := loopForge(t, "benign-import", flatten(benignTree()))
	h := newLoopHarness(t, hostileURL, benignURL)

	hostile := h.importPackage(t, importer(), commands.Registration{
		Source: fetch.SourceGit, URL: hostileURL + "/org/hostile-import", Ref: "v1.0.0",
		Publisher: "loopthree/team", Name: "cost-report", Kind: models.PackageKindSkill,
	})
	benign := h.importPackage(t, importer(), commands.Registration{
		Source: fetch.SourceGit, URL: benignURL + "/org/benign-import", Ref: "v1.0.0",
		Publisher: "loopfour/team", Name: "cost-report", Kind: models.PackageKindSkill,
	})

	require.Equal(t, string(models.VerdictFlagged), versionVerdict(t, hostile.versionID))
	require.Equal(t, string(models.VerdictClean), versionVerdict(t, benign.versionID))

	for _, pkg := range []imported{hostile, benign} {
		require.NotEqual(t, string(models.VerdictScanning), versionVerdict(t, pkg.versionID),
			"FR-124: a version registered through the product must not sit at 'Scanning' for ever")
		require.True(t, visibleInCatalog(t, pkg.versionID),
			"SC-107: it reaches the catalog carrying the verdict it reached")
	}
}

func openFindingOn(t *testing.T, versionID uuid.UUID, ruleID string) uuid.UUID {
	t.Helper()

	var id uuid.UUID
	require.NoError(t, pool.QueryRow(context.Background(),
		`select id from finding where version_id = $1 and rule_id = $2 and state = 'open'`,
		versionID, ruleID).Scan(&id),
		"the scan of real bytes must have raised %s, or there is nothing to adjudicate", ruleID)
	return id
}

func visibleInCatalog(t *testing.T, versionID uuid.UUID) bool {
	t.Helper()

	var visible bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`select visible from version where id = $1`, versionID).Scan(&visible))
	return visible
}

// ---- T077 / SC-111 ----------------------------------------------------------

// auditCase is one mutating action and the row it must be accountable for.
//
// setup and drive are separate because the measurement window is around drive
// alone: signing out needs a session, and a case that opened one inside the window
// would be measuring a sign-in as well and asserting two rows were one.
type auditCase struct {
	action    string
	kind      models.AuditKind
	actorKind models.ActorKind
	setup     func(t *testing.T)
	// drive performs the action and returns the actor the row must name.
	drive func(t *testing.T) string
}

// One row per action. Exactly one.
//
// Zero means the action is unaccounted for. Two means every figure derived from
// the log is wrong — and two is the likelier defect, because the second row is
// usually written by a helper somebody added for good reasons.
//
// What is measured is the delta over the WHOLE table, not over the row's own kind.
// A command that wrote its `approve` row and also a stray `policy` row would pass
// a per-kind count, and that is precisely the shape of double-counting this gate
// exists for. The new row is then identified by id rather than by "the newest",
// so the assertion is about the row the action wrote and not about a row that
// happens to sort first.
//
// Every mutating action the product can presently perform is here. When a later
// phase adds one — publishing a revision (T083), sharing a profile (T081), an
// administration change (US7) — its case belongs in this table rather than in a
// test of its own: the value of a sweep is that somebody has to look at the list.
func TestEveryMutatingActionWritesExactlyOneAuditRow(t *testing.T) {
	requireNoSeededData(t)
	ctx := context.Background()

	forgeURL := loopForge(t, "sweep-report", flatten(hostileTree()))
	h := newLoopHarness(t, forgeURL)
	who := reviewer(t, "sweep-reviewer")

	// The three ingestion stages share one registration and run in table order: a
	// scan cannot precede the bytes it reads, so splitting them into independent
	// cases would buy nothing and cost three imports.
	var sweepVersion uuid.UUID
	var signedOutToken string

	for _, tc := range []auditCase{
		{
			action: "a person signs in", kind: models.AuditKindLogin,
			actorKind: models.ActorKindIdentity,
			drive: func(t *testing.T) string {
				t.Helper()
				_, err := commands.Login(ctx, db, commands.LoginInput{
					Claims:     auth.Claims{Subject: "sub-sweep-in", Email: "sweep-in@example.com"},
					SessionTTL: time.Hour,
					Source:     auth.SourceWeb,
				})
				require.NoError(t, err)
				return "sweep-in@example.com"
			},
		},
		{
			// Sign-out reuses kind `login` because `audit_kind` has no `logout`
			// value and adding one is a migration this feature does not carry. The
			// text is what separates the two halves, which is what the audit screen
			// renders anyway — and it is still exactly one row, which is the claim.
			action: "a person signs out", kind: models.AuditKindLogin,
			actorKind: models.ActorKindIdentity,
			setup: func(t *testing.T) {
				t.Helper()
				session, err := commands.Login(ctx, db, commands.LoginInput{
					Claims:     auth.Claims{Subject: "sub-sweep-out", Email: "sweep-out@example.com"},
					SessionTTL: time.Hour,
					Source:     auth.SourceWeb,
				})
				require.NoError(t, err)
				signedOutToken = session.Token
			},
			drive: func(t *testing.T) string {
				t.Helper()
				p := auth.Principal{
					Subject: "sub-sweep-out", Email: "sweep-out@example.com", Source: auth.SourceWeb,
				}
				require.NoError(t, commands.SignOut(ctx, db, p, signedOutToken))
				return p.Email
			},
		},
		{
			action: "a person registers a package", kind: models.AuditKindFetch,
			actorKind: models.ActorKindIdentity,
			drive: func(t *testing.T) string {
				t.Helper()
				p := importer()
				registered, err := commands.RegisterPackage(ctx, db, p, commands.Registration{
					Source: fetch.SourceGit, URL: forgeURL + "/org/sweep-report", Ref: "v4.0.0",
					Publisher: "loopsweep/team", Name: "cost-report", Kind: models.PackageKindSkill,
				})
				require.NoError(t, err)
				sweepVersion = uuid.MustParse(registered.VersionID)
				return p.Email
			},
		},
		{
			action: "the fetcher publishes the bytes", kind: models.AuditKindFetch,
			actorKind: models.ActorKindSystem,
			drive: func(t *testing.T) string {
				t.Helper()
				require.NoError(t, h.fetcher.Fetch(ctx, outboxFetchJob(t, sweepVersion)))
				return fetcher.RoleName
			},
		},
		{
			action: "the scanner records a verdict", kind: models.AuditKindScan,
			actorKind: models.ActorKindSystem,
			drive: func(t *testing.T) string {
				t.Helper()
				require.NoError(t, h.scanner.Scan(ctx, outboxScanJob(t, sweepVersion), false))
				return scanner.RoleName
			},
		},
		{
			action: "a reviewer accepts a finding", kind: models.AuditKindApprove,
			actorKind: models.ActorKindIdentity,
			drive: func(t *testing.T) string {
				t.Helper()
				_, err := commands.AcceptFinding(ctx, db, who, commands.Decision{
					FindingID: openFindingOn(t, sweepVersion, "SH-NET-002"),
					Note:      "reviewed with the vendor",
				})
				require.NoError(t, err)
				return who.Email
			},
		},
		{
			// Rejection also writes kind `approve`, for the same reason sign-out
			// writes `login`: the enum has no `reject` value. Still one row.
			action: "a reviewer rejects a finding", kind: models.AuditKindApprove,
			actorKind: models.ActorKindIdentity,
			drive: func(t *testing.T) string {
				t.Helper()
				_, err := commands.RejectFinding(ctx, db, who, commands.Decision{
					FindingID: openFindingOn(t, sweepVersion, "SH-SH-001"),
					Note:      "not remediable",
				})
				require.NoError(t, err)
				return who.Email
			},
		},
	} {
		t.Run(tc.action, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}

			before := auditIDs(t)
			actor := tc.drive(t)
			written := auditRowsSince(t, before)

			require.Lenf(t, written, 1,
				"%s must write exactly one audit row: zero leaves the action unaccounted for, "+
					"two makes every figure derived from the log wrong", tc.action)
			require.Equal(t, string(tc.kind), written[0].kind)
			require.Equal(t, string(tc.actorKind), written[0].actorKind)
			require.Equal(t, actor, written[0].actor,
				"the row has to name who did it, or the log cannot answer the only question it is for")
			require.NotEmpty(t, written[0].source, "FR-050: a row records where the action came from")
			require.NotEmpty(t, written[0].text, "a row with no text is a row nobody can read")
		})
	}

	// The other half of exactly-one. Both background roles are delivered
	// at-least-once by design (principle IX), so a redelivery that wrote a second
	// row would double-count every ingestion in the log — silently, because each
	// individual delivery looks correct.
	t.Run("a redelivered fetch and a redelivered scan write no second row", func(t *testing.T) {
		before := auditIDs(t)
		require.NoError(t, h.fetcher.Fetch(ctx, outboxFetchJob(t, sweepVersion)))
		require.NoError(t, h.scanner.Scan(ctx, outboxScanJob(t, sweepVersion), false))
		require.Empty(t, auditRowsSince(t, before))
	})
}

type auditRow struct{ kind, actorKind, actor, source, text string }

func auditIDs(t *testing.T) []uuid.UUID {
	t.Helper()

	rows, err := pool.Query(context.Background(), `select id from audit_event`)
	require.NoError(t, err)
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

// auditRowsSince returns every row that is not in the given set. Identifying the
// new rows by id rather than by timestamp is what makes the count exact:
// `occurred_at` is the transaction clock and two rows written microseconds apart
// can carry the same value, so "the newest row" is not always the row the action
// under test wrote.
func auditRowsSince(t *testing.T, before []uuid.UUID) []auditRow {
	t.Helper()

	if before == nil {
		before = []uuid.UUID{}
	}
	rows, err := pool.Query(context.Background(),
		`select kind::text, actor_kind::text, actor, source, text
		   from audit_event where id <> all($1) order by occurred_at, id`, before)
	require.NoError(t, err)
	defer rows.Close()

	var out []auditRow
	for rows.Next() {
		var row auditRow
		require.NoError(t, rows.Scan(&row.kind, &row.actorKind, &row.actor, &row.source, &row.text))
		out = append(out, row)
	}
	require.NoError(t, rows.Err())
	return out
}
