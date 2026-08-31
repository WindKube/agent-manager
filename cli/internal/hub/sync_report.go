package hub

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// This file is T044: report one completed sync to the hub, exactly once
// (FR-032), never retried, and never able to fail the sync (FR-033).
//
// # R6, MEASURED RATHER THAN ASSUMED: reportSync is ADDITIVE, not idempotent
//
// The task line says to confirm server-side idempotence before implementing a
// retry. The hub is in this repository, so it was read rather than guessed, and
// the answer decides the whole policy below.
//
//   - `internal/api/commands/sync.go` ReportSync opens one transaction and does
//     a plain INSERT of a `models.SyncEvent` whose ID is `models.NewID()` — a
//     fresh UUID per call — plus one audit row. There is no ON CONFLICT clause,
//     no natural key lookup and no read of an existing event.
//   - `internal/store/schema/02-tables.sql` declares
//     `CREATE TABLE "sync_event" (... PRIMARY KEY ("id"))`. The only other
//     constraints on it are the three foreign keys
//     (`internal/store/schema_test.go`). There is no unique index over
//     (identity_id, profile_id, revision_id, host), so nothing on the server
//     collapses two identical reports into one row.
//   - `internal/api/integration_test.go`
//     TestReportSyncWritesOneSyncEventAndOneAuditRow asserts `before+1` for both
//     tables after one POST. A second identical POST therefore gives `before+2`.
//   - The frozen contract carries no idempotency key: POST /v1/sync's body is
//     profile, revision, host, targets and skipped, and there is no
//     `Idempotency-Key` header in `contracts/openapi.yaml`.
//
// So a duplicate report is ADDITIVE: a second sync_event row and a second audit
// row for one sync. Hub SC-008 is "every state-changing action produces exactly
// one audit row — verified by exercising each mutating endpoint and asserting
// the count delta is one", so a retry is not a harmless duplicate, it is that
// success criterion broken by this client.
//
// # THE POLICY THAT FOLLOWS: AT MOST ONE ATTEMPT
//
// There is NO retry here, and adding one is not an improvement to make later.
// The failures a retry exists for — a timeout, a connection reset, a 503 read
// after the body was written — are exactly the failures in which the report may
// ALREADY have landed. With no idempotency key and no server-side dedup, a
// retry after an ambiguous failure is a coin flip between one row and two, and
// two is the outcome that makes an audit trail lie. FR-032's "exactly once"
// is therefore implemented as at-most-once ON THE WIRE, and the missing report
// is surfaced to a human (FR-033) instead of being papered over.
//
// A 429 with Retry-After looks like the one safe exception, because a rate
// limiter answers before the handler runs. It is not taken: this file cannot
// tell a 429 raised by a limiter in front of the handler from one raised by a
// proxy after it forwarded the request, and the CLI ships separately from
// whatever sits in front of the hub. What DOES make a retry safe is an
// idempotency key on the endpoint, which is a contract change, not a client
// one.
//
// # WHAT CHANGES IF THE HUB EVER DEDUPES
//
// One thing, in one place: Reporter.Report would loop on Class.Retryable().
// Nothing else here would move, which is why the reason is written down at
// length rather than left as "no retry".

// ErrReportInput marks a sync report this client refuses to send, because the
// hub would answer 422 and the CLI would then report a failed sync report for a
// bug it could have caught locally.
var ErrReportInput = errors.New("unusable sync report")

// ErrAlreadyReported marks a second Report call for a sync already reported by
// this process. It is how FR-032's "exactly once" becomes a property of this
// type rather than of the caller's control flow.
//
// It is an error and not a silent no-op on purpose: a second call is a bug in
// the caller, and a bug that returns nil is a bug nobody finds. It is safe to
// make it loud because FR-033 routes every failure here to a warning, so the
// worst it can do is print a line — it cannot fail a sync.
var ErrAlreadyReported = errors.New("this sync has already been reported to the hub")

// Report is one completed sync, as POST /v1/sync's body needs it.
//
// Revision is an int and not a string: `head` is a REQUEST, never a state, and
// the contract types this field as an integer. Whoever asked for `head` must
// substitute the number the lockfile came back with (FR-013) before it reaches
// here, and a value below 1 is refused rather than sent.
type Report struct {
	// Profile is the profile slug that was synced. One report per profile: the
	// body has a single `profile` field, so a two-profile sync is two reports,
	// each naming its own resolved revision.
	Profile string

	// Revision is the RESOLVED revision number, as the lockfile stated it.
	Revision int

	// Host is this machine's name, for the audit row.
	Host string

	// Targets is the agent directories actually managed by this sync. The hub
	// stores nothing per target (hub FR-039) — they land in the audit text —
	// but the field is required and must be non-empty.
	Targets []string

	// SkippedLocally is the entry ids THIS CLIENT did not install, and it is
	// deliberately not the lockfile's own `skipped` array: the hub already
	// knows what it withheld. A bundle the hub answered 403 for, or one whose
	// bytes did not match the digest the lockfile locked, is a local skip and
	// belongs here.
	SkippedLocally []string
}

// body builds the wire value, validating everything the hub would 422 on and
// normalising the two lists so that one sync produces one deterministic body.
func (r Report) body() (SyncReport, error) {
	profile := strings.TrimSpace(r.Profile)
	host := strings.TrimSpace(r.Host)
	switch {
	case profile == "":
		return SyncReport{}, fmt.Errorf("%w: no profile slug", ErrReportInput)
	case host == "":
		return SyncReport{}, fmt.Errorf("%w: no host", ErrReportInput)
	case r.Revision < 1:
		return SyncReport{}, fmt.Errorf("%w: profile %s has revision %d; `head` must be replaced by the "+
			"number the lockfile resolved to before it is reported (FR-013)", ErrReportInput, profile, r.Revision)
	case len(r.Targets) == 0:
		return SyncReport{}, fmt.Errorf("%w: profile %s names no target; the hub requires at least one",
			ErrReportInput, profile)
	}

	targets := make([]SyncReportTargets, 0, len(r.Targets))
	seen := make(map[string]struct{}, len(r.Targets))
	for _, raw := range r.Targets {
		t := SyncReportTargets(raw)
		// Refused rather than dropped. A target value this build sends that the
		// hub does not know is a client bug, and silently omitting it would
		// report a sync of fewer targets than were written.
		if !t.Valid() {
			return SyncReport{}, fmt.Errorf("%w: profile %s reports target %q, which the contract does not define",
				ErrReportInput, profile, raw)
		}
		if _, dup := seen[raw]; dup {
			continue
		}
		seen[raw] = struct{}{}
		targets = append(targets, t)
	}
	slices.Sort(targets)

	out := SyncReport{Profile: profile, Revision: int64(r.Revision), Host: host, Targets: targets}
	if skipped := dedupeSorted(r.SkippedLocally); len(skipped) > 0 {
		// Omitted entirely when empty: the field is optional, and sending an
		// empty array would make the audit text say "0 entries skipped locally".
		out.Skipped = &skipped
	}
	return out, nil
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// reportKey identifies one sync for the exactly-once latch. Host is in it
// because one process could legitimately report for two hosts in a test, and
// leaving it out would make the second one look like a duplicate.
type reportKey struct {
	profile  string
	revision int
	host     string
}

// Reporter sends sync reports for one hub, at most once each.
//
// It is a type rather than a function because "exactly once" needs state, and a
// sync.Once at each call site is precisely the arrangement that survives until
// somebody adds a second call site.
type Reporter struct {
	hub *Hub

	mu   sync.Mutex
	sent map[reportKey]struct{}
}

// NewReporter pairs a reporter with a hub.
func NewReporter(h *Hub) (*Reporter, error) {
	if h == nil {
		return nil, errors.New("sync reporter: no hub given")
	}
	return &Reporter{hub: h, sent: map[reportKey]struct{}{}}, nil
}

// Report sends one sync report. It makes at most one request and never retries;
// see the file comment for the R6 measurement that decides that.
//
// The error is returned plainly, for the caller to put on the diagnostic stream
// (FR-033). It is deliberately not wrapped in anything that reads as fatal: the
// bytes are already on disk, and refusing to admit the sync happened would be
// the wrong correction.
//
// The latch is claimed BEFORE the request, so a report whose response never
// arrived is not retried by a second Report call either. That is the same
// at-most-once decision seen from the caller's side.
func (r *Reporter) Report(ctx context.Context, rep Report) error {
	body, err := rep.body()
	if err != nil {
		return err
	}
	key := reportKey{profile: body.Profile, revision: int(body.Revision), host: body.Host}

	r.mu.Lock()
	if _, dup := r.sent[key]; dup {
		r.mu.Unlock()
		return fmt.Errorf("%w: profile %s at revision %d on %s", ErrAlreadyReported, key.profile, key.revision, key.host)
	}
	r.sent[key] = struct{}{}
	r.mu.Unlock()

	if err := r.hub.ReportSync(ctx, body); err != nil {
		return fmt.Errorf("reporting the sync of %s at revision %d: %w", key.profile, key.revision, err)
	}
	return nil
}

// Reported reports whether this process has already sent a report for that
// sync. It exists so a caller can assert exactly-once without reaching into the
// hub, and so a test can prove the latch rather than infer it from a request
// count.
func (r *Reporter) Reported(rep Report) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.sent[reportKey{profile: strings.TrimSpace(rep.Profile), revision: rep.Revision, host: strings.TrimSpace(rep.Host)}]
	return ok
}
