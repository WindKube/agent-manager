package hub

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"
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

	// Required, non-empty.
	Targets []string

	// SkippedLocally is what THIS CLIENT skipped, not the lockfile's own array.
	SkippedLocally []string

	// MachineID is this client's persisted random id; zero sends no inventory.
	MachineID    uuid.UUID
	OS           string
	Arch         string
	AmctlVersion string

	// Installed is every entry of this profile on disk after the sync.
	Installed []Install

	// SkippedComponents is what this sync did not place of the entries it wrote.
	SkippedComponents []ComponentSkip
}

// Install is one installed entry; Changed means this sync wrote it.
type Install struct {
	ID, Version, Target string
	Changed             bool
}

// ComponentSkip is one plugin component this sync did not place.
type ComponentSkip struct {
	Entry, Target, Component, Reason string
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
	if r.MachineID != uuid.Nil {
		if err := r.inventory(&out); err != nil {
			return SyncReport{}, err
		}
	}
	return out, nil
}

// inventory adds the machine's fields. Installed is always sent with a
// machine id, even empty: the hub replaces this profile's installs with it.
func (r Report) inventory(out *SyncReport) error {
	id := r.MachineID
	out.MachineId = &id
	optional := func(s string) *string {
		if s = strings.TrimSpace(s); s == "" {
			return nil
		}
		return &s
	}
	out.Os, out.Arch, out.AmctlVersion = optional(r.OS), optional(r.Arch), optional(r.AmctlVersion)

	installed := make([]SyncInstall, 0, len(r.Installed))
	for _, in := range r.Installed {
		t := SyncInstallTarget(in.Target)
		if !t.Valid() {
			return fmt.Errorf("%w: profile %s reports %s installed for target %q, which the contract does not define",
				ErrReportInput, out.Profile, in.ID, in.Target)
		}
		inst := SyncInstall{Id: in.ID, Version: in.Version, Target: t}
		if in.Changed {
			changed := true
			inst.Changed = &changed
		}
		installed = append(installed, inst)
	}
	slices.SortFunc(installed, func(a, b SyncInstall) int {
		return strings.Compare(a.Id+"\x00"+string(a.Target), b.Id+"\x00"+string(b.Target))
	})
	out.Installed = &installed

	if len(r.SkippedComponents) == 0 {
		return nil
	}
	skips := make([]SyncComponentSkip, 0, len(r.SkippedComponents))
	for _, sk := range r.SkippedComponents {
		t := SyncComponentSkipTarget(sk.Target)
		if !t.Valid() {
			return fmt.Errorf("%w: profile %s reports a skipped component of %s for target %q, which the contract does not define",
				ErrReportInput, out.Profile, sk.Entry, sk.Target)
		}
		skips = append(skips, SyncComponentSkip{Entry: sk.Entry, Target: t, Component: sk.Component, Reason: sk.Reason})
	}
	slices.SortFunc(skips, func(a, b SyncComponentSkip) int {
		return strings.Compare(a.Entry+"\x00"+string(a.Target)+"\x00"+a.Component,
			b.Entry+"\x00"+string(b.Target)+"\x00"+b.Component)
	})
	out.SkippedComponents = &skips
	return nil
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
