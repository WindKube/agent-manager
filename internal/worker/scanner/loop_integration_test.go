//go:build integration

// The import-to-resolution loop end to end on an unseeded database. Each
// hand-off is read from the outbox rather than constructed, so a publish that
// forgot to enqueue its next job fails here.
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
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/fetch"
	"agent-manager/internal/signing/signingtest"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/fetcher"
	"agent-manager/internal/worker/scanner"
	"agent-manager/internal/worker/scanner/checks"
)

// loopForge serves one repository's tag lookup and tarball and 404s everything
// else. The real SSRF-hardened client is used with this server allowlisted.
func loopForge(t *testing.T, repo string, files map[string]string) string {
	t.Helper()

	prefix := "/api/v3/repos/org/" + repo + "/"
	tarball := loopTarball(t, repo+"-9e3f1c2", files)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, prefix)
		switch {
		case ok && strings.HasPrefix(rest, "git/ref/tags/"):
			_, _ = w.Write([]byte(`{"object":{"type":"commit","sha":"9e3f1c2a8b7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f"}}`))
		case ok && strings.HasPrefix(rest, "tarball/"):
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(tarball)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
	t.Cleanup(server.Close)

	return server.URL
}

// loopTarball builds a forge-style gzipped tar under one wrapper directory.
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

// flatten reuses the scan tests' fixtures so the loop and the scan tests cannot drift apart.
func flatten(tree fstest.MapFS) map[string]string {
	out := make(map[string]string, len(tree))
	for path, file := range tree {
		out[path] = string(file.Data)
	}
	return out
}

// loopHarness runs the fetcher and scanner over one bucket, so the scanner
// judges exactly the bytes the fetcher committed.
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
		DB:         db,
		BlobRead:   bucket.Reader(),
		BlobWrite:  bucket.Writer(),
		Fetch:      client,
		Signatures: signingtest.New(t).Verifier(),
		Log:        zerolog.New(io.Discard),
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

var (
	importerIdentityOnce sync.Once
	importerIdentityID   uuid.UUID
)

// importer is backed by a real identity row because `package.owner_identity_id`
// is a foreign key.
func importer() auth.Principal {
	importerIdentityOnce.Do(func() {
		importerIdentityID = models.NewID()
		_, err := pool.Exec(context.Background(),
			`insert into identity (id, subject, email, display_name) values ($1, $2, $3, $4)`,
			importerIdentityID, "sub-importer", "importer@example.com", "Importer")
		if err != nil {
			panic("seed the loop suite's importer identity: " + err.Error())
		}
	})

	return auth.Principal{
		IdentityID: importerIdentityID,
		Subject:    "sub-importer",
		Email:      "importer@example.com",
		Role:       models.OrgRoleCatalogAdmin,
		Source:     auth.SourceWeb,
	}
}

// reviewer is backed by a real identity row because `override.reviewer_identity_id`
// is a foreign key.
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

type imported struct {
	packageID uuid.UUID
	versionID uuid.UUID
	namespace string
	name      string
	semver    string
}

// importPackage runs register, fetch and scan, decoding each job from the
// outbox as the relay would so an unreadable payload fails here.
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
		"the registration must have enqueued its fetch in the same transaction")

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

// containedIn puts the package in a profile, floating on the latest version.
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

// resolvesToServableBytes reports whether a floating entry on this package
// still resolves to servable bytes. It composes production reads only and does
// not apply the org gate, so it can assert a rejection but not an acceptance.
func resolvesToServableBytes(t *testing.T, pkg imported) bool {
	t.Helper()
	ctx := context.Background()

	var latest uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		`select latest_version_id from package where id = $1`, pkg.packageID).Scan(&latest))
	require.Equal(t, pkg.versionID, latest,
		"a floating entry resolves to the package's latest version, so that is what must be judged")

	// The zero principal suffices: every package here is organisation-visible.
	ref, err := queries.Bundle(ctx, db, auth.Principal{}, pkg.namespace, pkg.name, pkg.semver)
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
		 values (1, $1, 'floating-latest', false, false, false, true)
		 on conflict (id) do update set scan_gate = excluded.scan_gate`, string(gate))
	require.NoError(t, err)
}

// requireNoSeededData checks tables only `internal/seed` writes, so wiring the
// seed into this suite fails loudly instead of masking a broken loop.
func requireNoSeededData(t *testing.T) {
	t.Helper()

	for _, table := range []string{"category", "membership", "sync_target", "sync_event", "revision"} {
		require.Zerof(t, countRows(t, "select count(*) from "+table),
			"%s holds rows: this suite must run against migrations alone", table)
	}
}

// A reviewer's decision must change what a machine can obtain, not just write an
// audit row, so each decision is measured as a state delta.
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

	require.Equal(t, string(models.VerdictFlagged), versionVerdict(t, pkg.versionID))
	require.True(t, resolvesToServableBytes(t, pkg),
		"a flagged version is quarantined by the gate, not withdrawn: its bytes are still servable")

	findingID := openFindingOn(t, pkg.versionID, "SH-NET-002")

	before, err := queries.Finding(ctx, db, findingID, auth.Principal{}, true)
	require.NoError(t, err)
	require.Equal(t, string(models.FindingStateOpen), before.State)
	require.Nil(t, before.Override, "nobody has decided anything yet")

	// The pane carries every check that ran, passes included, and evidence
	// quoted from the real bytes.
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
	}, "the matrix has to carry the passes")

	require.NotEmpty(t, before.Evidence)
	require.Equal(t, "primary", before.Evidence[0].Role, "the cause leads")
	require.Contains(t, before.Evidence[0].Quote, "collector.exfil.example",
		"the evidence is quoted from the bundle's own bytes, which is what makes a finding checkable")

	summaryBefore, err := queries.ScannerSummary(ctx, db, 30)
	require.NoError(t, err)

	who := reviewer(t, "sec-lead")
	decision, err := commands.AcceptFinding(ctx, db, who, commands.Decision{
		FindingID: findingID,
		Note:      "accepted for the pilot; the collector host is ours",
		Days:      12,
	})
	require.NoError(t, err)
	require.Equal(t, string(models.FindingStateApproved), decision.State)

	after, err := queries.Finding(ctx, db, findingID, auth.Principal{}, true)
	require.NoError(t, err)
	require.Equal(t, string(models.FindingStateApproved), after.State)
	require.NotNil(t, after.Override,
		"the override IS the decision: without it the gate has nothing to read and the "+
			"approval changed nothing a resolver can act on")
	require.Equal(t, who.Email, after.Override.Reviewer)
	require.Equal(t, "accepted for the pilot; the collector host is ours", after.Override.Note)
	require.NotNil(t, after.Override.ExpiresAt, "an acceptance is bounded, never open-ended")
	require.WithinDuration(t, time.Now().UTC().Add(12*24*time.Hour), *after.Override.ExpiresAt, time.Minute)

	require.Equal(t, string(models.VerdictFlagged), after.Verdict,
		"an acceptance must not launder the version clean: it stays flagged and the "+
			"override is what the gate reads")
	require.Equal(t, string(models.VerdictFlagged), versionVerdict(t, pkg.versionID))

	summaryAfter, err := queries.ScannerSummary(ctx, db, 30)
	require.NoError(t, err)
	require.Equal(t, summaryBefore.OverridesActive+1, summaryAfter.OverridesActive,
		"the Scanner screen's active-override figure is the reviewer's decision made visible")
	require.NotNil(t, summaryAfter.NearestExpiry)

	require.True(t, resolvesToServableBytes(t, pkg),
		"an acceptance does not withdraw the bytes")

	packageRef := pkg.namespace + "/" + pkg.name
	history, err := queries.Audit(ctx, db,
		queries.AuditFilter{SubjectKind: "package", SubjectID: packageRef}, 1, queries.MaxAuditPageSize)
	require.NoError(t, err)
	actions := map[string]contract.AuditEntry{}
	for _, entry := range history.Entries {
		require.Equal(t, pkg.namespace, entry.Namespace)
		require.Equal(t, packageRef, entry.Data["package"])
		actions[entry.Data["action"].(string)] = entry
	}
	require.Len(t, actions, 4, "registered, stored, scanned and accepted, and nothing about another package")
	for _, action := range []string{"registered", "stored", "scanned"} {
		require.Equal(t, "version", actions[action].SubjectKind, action)
		require.Equal(t, packageRef+"@"+pkg.semver, actions[action].SubjectID, action)
	}
	require.Equal(t, "flagged", actions["scanned"].Data["verdict"])
	require.Equal(t, "finding", actions["accepted"].SubjectKind)
	require.Equal(t, findingID.String(), actions["accepted"].SubjectID)
	require.Equal(t, "SH-NET-002", actions["accepted"].Data["ruleId"])

	// A second package, because rejection is terminal.

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

	require.False(t, resolvesToServableBytes(t, doomed),
		"a rejected version must not be resolvable by any profile")

	// Rejection must hold regardless of the org gate.
	for _, gate := range []models.ScanGate{
		models.ScanGateBlock, models.ScanGateApproval, models.ScanGateWarnWithOverride,
	} {
		setScanGate(t, gate)
		require.False(t, resolvesToServableBytes(t, doomed),
			"gate %s: rejection is terminal regardless of what the org policy says", gate)
	}

	// An acceptance cannot walk a rejection back.
	_, err = commands.AcceptFinding(ctx, db, who, commands.Decision{
		FindingID: doomedFinding,
		Note:      "on reflection",
	})
	require.ErrorIs(t, err, commands.ErrFindingRejected)
	require.False(t, resolvesToServableBytes(t, doomed))
}

// The hostile/benign pair rules out a scanner that answers one verdict unconditionally.
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
			"a version registered through the product must not sit at 'Scanning' for ever")
		require.True(t, visibleInCatalog(t, pkg.versionID),
			"it reaches the catalog carrying the verdict it reached")
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

// auditCase separates setup from drive because only drive is inside the
// measurement window.
type auditCase struct {
	action    string
	kind      models.AuditKind
	actorKind models.ActorKind
	setup     func(t *testing.T)
	// drive performs the action and returns the actor the row must name.
	drive func(t *testing.T) string
}

// The delta is measured over the whole audit table, not per kind, so a stray
// second row of another kind is caught. The list must cover every reachable
// mutating action; ApproveDevice and DenyDevice have no HTTP operation yet.
func TestEveryMutatingActionWritesExactlyOneAuditRow(t *testing.T) {
	requireNoSeededData(t)
	ctx := context.Background()

	forgeURL := loopForge(t, "sweep-report", flatten(hostileTree()))
	h := newLoopHarness(t, forgeURL)
	who := reviewer(t, "sweep-reviewer")

	// Cases run in table order and share state: ingestion stages build on one
	// registration and profile commands on one profile.
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
			// Sign-out reuses kind `login`: `audit_kind` has no `logout` value.
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
			// Rejection writes kind `approve`: the enum has no `reject` value.
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
		{
			action: "the CLI reports a sync", kind: models.AuditKindSync,
			actorKind: models.ActorKindIdentity,
			setup: func(t *testing.T) {
				t.Helper()
				sweepProfile(t, "sweep-workstation")
			},
			drive: func(t *testing.T) string {
				t.Helper()
				require.NoError(t, commands.ReportSync(ctx, db, who, contract.SyncReport{
					Profile:  "sweep-workstation",
					Revision: 1,
					Host:     "a-laptop",
					Targets:  []string{"claude-code"},
				}))
				return who.Email
			},
		},
		{
			action: "a person creates a profile", kind: models.AuditKindProfile,
			actorKind: models.ActorKindIdentity,
			drive: func(t *testing.T) string {
				t.Helper()
				_, err := commands.CreateProfile(ctx, db, who, commands.ProfileCreation{
					Slug: "sweep/curated", Name: "Sweep curated",
				})
				require.NoError(t, err)
				return who.Email
			},
		},
		{
			action: "an owner sets the packages in a profile", kind: models.AuditKindProfile,
			actorKind: models.ActorKindIdentity,
			drive: func(t *testing.T) string {
				t.Helper()
				require.NoError(t, commands.SetProfileEntries(ctx, db, who, "sweep/curated",
					contract.ProfileEntries{Entries: []contract.ProfileEntrySetting{
						{ID: sweepPackageID(t, sweepVersion), Mode: "latest"},
					}}))
				return who.Email
			},
		},
		{
			action: "an owner shares a profile", kind: models.AuditKindShare,
			actorKind: models.ActorKindIdentity,
			drive: func(t *testing.T) string {
				t.Helper()
				require.NoError(t, commands.SetProfileSharing(ctx, db, who, "sweep/curated",
					contract.ProfileSharing{Members: []contract.ProfileShare{
						{Kind: "user", Ref: who.Email, Role: "owner"},
						{Kind: "group", Ref: "eng-platform", Role: "consumer"},
					}}))
				return who.Email
			},
		},
		{
			action: "an owner chooses the sync targets", kind: models.AuditKindProfile,
			actorKind: models.ActorKindIdentity,
			drive: func(t *testing.T) string {
				t.Helper()
				require.NoError(t, commands.SetProfileTargets(ctx, db, who, "sweep/curated",
					contract.ProfileTargetSelection{Targets: []string{"claude-code"}}))
				return who.Email
			},
		},
		{
			action: "an owner publishes a revision", kind: models.AuditKindProfile,
			actorKind: models.ActorKindIdentity,
			setup: func(t *testing.T) {
				// The resolver refuses to guess a gate, so the policy row must exist.
				t.Helper()
				setScanGate(t, models.ScanGateWarnWithOverride)
			},
			drive: func(t *testing.T) string {
				t.Helper()
				lockfile, err := commands.PublishRevision(ctx, db, who, "sweep/curated",
					"the sweep's revision")
				require.NoError(t, err)
				require.Equal(t, 1, lockfile.Revision)
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
			require.NotEmpty(t, written[0].source, "a row records where the action came from")
			require.NotEmpty(t, written[0].text, "a row with no text is a row nobody can read")
		})
	}

	t.Run("a redelivered fetch and a redelivered scan write no second row", func(t *testing.T) {
		before := auditIDs(t)
		require.NoError(t, h.fetcher.Fetch(ctx, outboxFetchJob(t, sweepVersion)))
		require.NoError(t, h.scanner.Scan(ctx, outboxScanJob(t, sweepVersion), false))
		require.Empty(t, auditRowsSince(t, before))
	})

	// A double-click: the state is right either way, so only the audit log shows
	// a second rejection.
	t.Run("a second rejection of the same finding is refused and writes nothing", func(t *testing.T) {
		var finding uuid.UUID
		require.NoError(t, pool.QueryRow(ctx,
			`select id from finding where version_id = $1 and rule_id = $2 and state = 'rejected'`,
			sweepVersion, "SH-SH-001").Scan(&finding))

		before := auditIDs(t)
		_, err := commands.RejectFinding(ctx, db, who, commands.Decision{
			FindingID: finding, Note: "the same decision again",
		})
		require.ErrorIs(t, err, commands.ErrFindingRejected,
			"a second rejection was accepted, so the api reported a decision it did not take")
		require.Empty(t, auditRowsSince(t, before),
			"the log gained a second rejection of one finding, and the reason recorded "+
				"for it is now whichever row a reader happens to read")
	})
}

// sweepProfile inserts rows directly so only ReportSync runs inside the
// measurement window.
func sweepProfile(t *testing.T, slug string) {
	t.Helper()

	profileID := models.NewID()
	_, err := db.NewInsert().Model(&models.Profile{
		ID:            profileID,
		Slug:          slug,
		Name:          "Sweep workstation",
		Visibility:    models.ProfileVisibilityOrganisation,
		DefaultPolicy: models.VersionPolicyPinned,
	}).Exec(context.Background())
	require.NoError(t, err)

	_, err = db.NewInsert().Model(&models.Revision{
		ID:        models.NewID(),
		ProfileID: profileID,
		Seq:       1,
		Lockfile:  json.RawMessage(`{"entries":[]}`),
		ObjectKey: "profiles/" + slug + "/r1.json",
		CreatedBy: "sweep",
	}).Exec(context.Background())
	require.NoError(t, err)
}

// sweepPackageID returns the `namespace/name` a profile entry addresses.
func sweepPackageID(t *testing.T, versionID uuid.UUID) string {
	t.Helper()

	var id string
	require.NoError(t, pool.QueryRow(context.Background(), `
select pkg.namespace || '/' || pkg.name from package as pkg
join version as ver on ver.package_id = pkg.id where ver.id = $1`, versionID).Scan(&id))
	return id
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

// auditRowsSince identifies new rows by id because `occurred_at` is the
// transaction clock and can tie.
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
