package hub

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// This file reports one completed sync at most once, never retried: the
// hub's ReportSync handler INSERTs with no unique index and no idempotency
// key, so retrying after an ambiguous failure risks a lying duplicate row.
// Do not add a retry, even for 429 — that needs a contract change first.

// ErrReportInput: refused locally rather than sent to 422 on a bug this client could catch itself.
var ErrReportInput = errors.New("unusable sync report")

// ErrAlreadyReported is loud, not a silent no-op: a second call is a caller
// bug, and every failure here only routes to a warning anyway.
var ErrAlreadyReported = errors.New("this sync has already been reported to the hub")

// Report is one completed sync, as POST /v1/sync's body needs it. Revision
// must already be the resolved number the lockfile came back with, never the
// `head` request that produced it.
type Report struct {
	// One report per profile: the body has a single `profile` field.
	Profile string

	Revision int

	// Host is this machine's name, for the audit row.
	Host string

	// Required, non-empty: the hub stores nothing per target beyond the audit text.
	Targets []string

	// SkippedLocally is what THIS CLIENT skipped, not the lockfile's own array.
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
		// Omitted when empty, not sent as []: an empty array reads as "0 skipped".
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

// reportKey identifies one sync for the exactly-once latch.
type reportKey struct {
	profile  string
	revision int
	host     string
}

// Reporter sends sync reports for one hub, at most once each per reportKey.
type Reporter struct {
	hub *Hub

	mu   sync.Mutex
	sent map[reportKey]struct{}
}

func NewReporter(h *Hub) (*Reporter, error) {
	if h == nil {
		return nil, errors.New("sync reporter: no hub given")
	}
	return &Reporter{hub: h, sent: map[reportKey]struct{}{}}, nil
}

// Report sends one sync report, at most once; see the file comment for why
// there is no retry. The latch is claimed before the request, so a report
// whose response never arrived is not retried by a second call either.
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

// Reported lets a caller (or test) assert exactly-once without a request count.
func (r *Reporter) Reported(rep Report) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.sent[reportKey{profile: strings.TrimSpace(rep.Profile), revision: rep.Revision, host: strings.TrimSpace(rep.Host)}]
	return ok
}
