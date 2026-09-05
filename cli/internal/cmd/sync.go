package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/cache"
	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// revisionHead is the contract's own spelling of "whatever is current".
const revisionHead = "head"

// syncDeps is everything `sync` reaches outside its own process, gathered so
// sync_test.go can drive the real code paths against the fake hub. A struct and
// not package variables, for the reason loginDeps gives.
type syncDeps struct {
	httpClient *http.Client // nil means net/http's default
	hostname   func() (string, error)
	backends   []keyring.BackendType // nil means the policy order
	// lookupEnv also serves CLAUDE_CONFIG_DIR: claude-code doesn't read
	// XDG_CONFIG_HOME, so an XDG-first resolver would install nowhere it opens.
	lookupEnv func(string) (string, bool)
	now       func() time.Time
}

func productionSyncDeps() syncDeps {
	return syncDeps{hostname: os.Hostname, lookupEnv: os.LookupEnv, now: time.Now}
}

// syncFlags is sync's own flag set, per command instance.
type syncFlags struct {
	profiles  []string
	revisions []string
	force     bool
}

// newSyncCmd builds `amctl sync`. `--revision head` (default) applies to
// every profile; a bare number needs exactly one --profile, since revisions
// are per-profile; `<slug>=<head|number>`, repeatable, pins named profiles so
// a cross-profile version conflict is still caught before anything writes.
// With no --profile, only the profiles already in the record are synced —
// never "every readable profile" — and an empty record is refused, not guessed.
func newSyncCmd(opts *Options) *cobra.Command {
	flags := &syncFlags{}
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Apply a hub's resolved lockfile to this machine",
		Long: "Fetches each named profile's resolved revision, verifies every bundle's digest\n" +
			"before anything is written, installs each entry atomically into the agent\n" +
			"directories the profile's targets name, and reports what the hub told it to skip.\n\n" +
			"With no --profile, the profiles already in this machine's record are synced at\n" +
			"head. --revision takes `head`, a number (with a single --profile), or a\n" +
			"repeatable `<profile>=<head|number>` to pin several profiles in one run.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSync(cmd.Context(), opts, *flags, productionSyncDeps())
		},
	}
	cmd.Flags().StringArrayVar(&flags.profiles, "profile", nil,
		"profile slug to sync; repeatable (default: the profiles already in this machine's record)")
	cmd.Flags().StringArrayVar(&flags.revisions, "revision", nil,
		"`head`, a revision number, or `<profile>=<head|number>`; repeatable for the last form")
	// --force is defensible only because apply names every path it destroys
	// on the diagnostic stream first; see internal/apply's override().
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"overwrite a destination amctl's record does not claim, or one modified since install, naming what is destroyed")
	return cmd
}

// runSync's order is the requirement: hostname first (the report is filed
// under it), then Prepare (home proved writable, hub canonicalised, both
// before any packet leaves), then the credential (so a machine with none
// refuses having made zero requests), then the per-home lock — taken before
// the first request, not the first write, since downloads populate a shared cache.
func runSync(ctx context.Context, opts *Options, flags syncFlags, deps syncDeps) error {
	s := opts.Streams()

	host, err := machineHostname(deps.hostname)
	if err != nil {
		return err
	}

	return Prepare(opts.Hub, func(home Home, target Hub) error {
		cred, err := resolveSyncCredential(home, s, deps, target)
		if err != nil {
			return err
		}

		client, err := hub.New(hub.Config{
			URL:            target.URL,
			Token:          cred.Credential.Token,
			AllowPlaintext: opts.AllowPlaintextHub,
			HTTPClient:     deps.httpClient,
			UserAgent:      userAgent(),
		})
		if err != nil {
			return Refuse(err)
		}
		if client.Insecure() {
			s.Warnf("%s is plaintext: the bearer token and every bundle cross the network in the clear", target.URL)
		}

		run := &syncRun{
			opts: opts, flags: flags, deps: deps, s: s,
			home: home, target: target, client: client, host: host,
		}
		return WithLock(home, func(l *Lock) error {
			run.lock = l
			return run.do(ctx)
		})
	})
}

// resolveSyncCredential resolves AMCTL_TOKEN or the store's credential,
// refusing (no TTY prompt) when neither has one. The store opens lazily
// inside credentials.Resolver, so AMCTL_TOKEN never touches the keychain.
func resolveSyncCredential(home Home, s *output.Streams, deps syncDeps, target Hub) (credentials.Resolved, error) {
	resolver := credentials.Resolver{
		Open: func() (*credentials.Store, error) {
			return openStore(home, s, deps.backends)
		},
		LookupEnv: lookupEnv(deps.lookupEnv),
	}
	res, found, err := resolver.Resolve(target.URL)
	switch {
	case err != nil:
		if errors.Is(err, credentials.ErrFileMode) {
			return credentials.Resolved{}, Refuse(err)
		}
		return credentials.Resolved{}, err
	case !found:
		// No TTY, so name both ways to supply a credential rather than asking.
		return credentials.Resolved{}, Refusef(
			"no credential for %s: run `amctl login --hub %s`, or set %s in the environment",
			target.URL, target.URL, credentials.TokenEnvVar)
	}
	if res.Credential.Expired(nowOr(deps.now)()) {
		// Refused rather than tried: a 401 from the hub would misdirect the
		// user to the hub instead of their own expired token.
		return credentials.Resolved{}, Refusef(
			"the credential for %s expired at %s: run `amctl login --hub %s`",
			target.URL, res.Credential.ExpiresAt.UTC().Format(time.RFC3339), target.URL)
	}
	s.Debugf("using the credential from %s", res.Location)
	return res, nil
}

// syncRun is one sync, under the lock. Everything it needs is a field so that
// the steps read as steps rather than as a parameter list.
type syncRun struct {
	opts  *Options
	flags syncFlags
	deps  syncDeps
	s     *output.Streams

	home   Home
	target Hub
	client *hub.Hub
	host   string

	// lock is carried this far, not discarded at WithLock, so Lock.Lost can
	// still be consulted — the mitigation for a frozen, reclaimed holder.
	lock *Lock
}

// stillOurs is what internal/apply asks before each entry: a lock reclaimed
// while frozen means another amctl already owns the tree. Not a Refusal —
// nothing the user did caused it — CodeFailure means "re-run" here.
func (r *syncRun) stillOurs() error {
	if r.lock == nil || !r.lock.Lost() {
		return nil
	}
	return fmt.Errorf("this sync no longer holds %s: another amctl reclaimed it, which happens when this "+
		"process was suspended or frozen for longer than the lock's staleness window; "+
		"the entries already installed are recorded, and re-running converges the rest",
		r.lock.Path())
}

// do is the sync, in the order the requirements impose. Read the step comments
// before reordering anything.
func (r *syncRun) do(ctx context.Context) error {
	recordPath := record.Path(r.home.HubDir(r.target))
	rec, err := record.Load(recordPath, r.target.URL)
	if err != nil {
		return Refuse(err) // every Load failure is a refusal a user can fix
	}

	profiles, err := chooseProfiles(r.flags.profiles, rec)
	if err != nil {
		return err
	}
	revisions, err := parseRevisions(r.flags.revisions, profiles)
	if err != nil {
		return err
	}

	lockfiles, err := r.fetchLockfiles(ctx, profiles, revisions)
	if err != nil {
		return err
	}

	configDir, _ := lookupEnv(r.deps.lookupEnv)(layout.ClaudeCodeConfigDirEnv)
	reg, err := layout.NewRegistry(layout.Config{HomeDir: r.home.UserHome, ClaudeConfigDir: configDir})
	if err != nil {
		return err
	}
	targets, writable := r.resolveTargets(reg, lockfiles)

	p, err := plan.Compute(plan.Inputs{Lockfiles: lockfiles, Record: rec, Targets: targets})
	if err != nil {
		return err
	}
	r.reportSkips(p)

	res := r.newResult(lockfiles)
	appendSkips(&res, p)
	if p.Refuses() {
		// FR-012 and FR-023, refused BEFORE a byte is staged. The result is
		// still emitted so `--output json` carries the conflict list; the
		// error is what sets the exit code.
		for i := range p.Conflicts {
			res.Conflicts = append(res.Conflicts, output.Change{
				Package: p.Conflicts[i].ID, Target: string(p.Conflicts[i].Target),
			})
			r.s.Errorf("%s", p.Conflicts[i].String())
		}
		if emitErr := r.opts.Emit(res); emitErr != nil {
			return emitErr
		}
		return Refuse(p.ConflictError())
	}

	bundles := cache.New(cache.Dir(r.home.Root)) // fetched and verified before any entry is staged; see prefetch
	downloader, err := hub.NewDownloader(r.client, bundles)
	if err != nil {
		return err
	}
	if r.opts.Offline {
		downloader = downloader.Offline()
	}
	fetch, err := r.prefetch(ctx, downloader, p, lockfiles)
	if err != nil {
		return err
	}
	attempted := writesPerProfile(p) // before the drop; see report's landed-nothing check
	p = withoutEntries(p, fetch.dropped)

	applied, err := r.apply(ctx, p, rec, recordPath, lockfiles, writable, fetch)
	if applied == nil {
		return err // nothing attempted, so nothing to report or emit
	}
	_ = err // re-derived by syncError from the Result below, not returned as-is
	r.fill(&res, applied, fetch)
	r.report(ctx, lockfiles, writable, fetch, attempted, applied) // after the tree's final state

	if emitErr := r.opts.Emit(res); emitErr != nil {
		return emitErr
	}
	// A locally skipped entry (gate 403) does not move the exit code: that's
	// a correct outcome, not a failure to retry. `partial` and `skipped`
	// under --output json carry the detail instead.
	if res.Changed() {
		r.opts.Outcome = CodeChanged
	} else {
		r.opts.Outcome = CodeNoChanges
	}
	return syncError(applied, fetch.failures)
}

// chooseProfiles resolves which profiles this run reconciles; see newSyncCmd.
func chooseProfiles(requested []string, rec *record.Record) ([]string, error) {
	if len(requested) > 0 {
		out := make([]string, 0, len(requested))
		seen := map[string]struct{}{}
		for _, raw := range requested {
			slug := strings.TrimSpace(raw)
			if slug == "" {
				return nil, Refusef("--profile was given an empty value")
			}
			if _, dup := seen[slug]; dup {
				continue // `--profile a --profile a` is deduplicated, not refused
			}
			seen[slug] = struct{}{}
			out = append(out, slug)
		}
		return out, nil
	}

	out := make([]string, 0, len(rec.Profiles))
	for i := range rec.Profiles {
		out = append(out, rec.Profiles[i].Slug)
	}
	if len(out) == 0 {
		return nil, Refusef("nothing has been synced on this machine yet, so there is no profile to re-converge: " +
			"name one with --profile (`amctl sync --profile <slug>`)")
	}
	slices.Sort(out)
	return out, nil
}

// parseRevisions turns --revision values into one revision per profile; see newSyncCmd.
func parseRevisions(requested, profiles []string) (map[string]string, error) {
	out := make(map[string]string, len(profiles))
	for _, slug := range profiles {
		out[slug] = revisionHead
	}
	if len(requested) == 0 {
		return out, nil
	}

	known := make(map[string]struct{}, len(profiles))
	for _, slug := range profiles {
		known[slug] = struct{}{}
	}

	var bare string
	pinned := map[string]struct{}{}
	for _, raw := range requested {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, Refusef("--revision was given an empty value")
		}
		slug, rev, qualified := strings.Cut(value, "=")
		slug, rev = strings.TrimSpace(slug), strings.TrimSpace(rev)
		if !qualified {
			if bare != "" {
				return nil, Refusef("--revision was given %q and %q; a revision is per profile, so name the "+
					"profile in each: --revision <profile>=<head|number>", bare, value)
			}
			if len(pinned) > 0 {
				return nil, Refusef("--revision mixes the bare form %q with a <profile>=<revision> form; "+
					"use one or the other", value)
			}
			if err := validRevision("--revision", value); err != nil {
				return nil, err
			}
			if value != revisionHead && len(profiles) > 1 {
				return nil, Refusef("--revision %s cannot apply to %d profiles (%s): a revision is sequential "+
					"per profile, so one number names a different state in each; pin them individually with "+
					"--revision <profile>=%s, or sync one profile at a time",
					value, len(profiles), strings.Join(profiles, ", "), value)
			}
			bare = value
			for _, slug := range profiles {
				out[slug] = value
			}
			continue
		}

		if bare != "" {
			return nil, Refusef("--revision mixes the bare form %q with %q; use one or the other", bare, value)
		}
		if slug == "" {
			return nil, Refusef("--revision %q has no profile before the `=`", value)
		}
		if _, ok := known[slug]; !ok {
			return nil, Refusef("--revision %q names profile %q, which this run is not syncing (%s)",
				value, slug, strings.Join(profiles, ", "))
		}
		if _, dup := pinned[slug]; dup {
			return nil, Refusef("--revision pins profile %q twice; one profile has one revision per run", slug)
		}
		if err := validRevision("--revision "+slug+"=", rev); err != nil {
			return nil, err
		}
		pinned[slug] = struct{}{}
		out[slug] = rev
	}
	return out, nil
}

// validRevision restates `^(head|[0-9]+)$` locally so a bad arg is named
// here rather than round-tripped for a 422.
func validRevision(flag, value string) error {
	if value == revisionHead {
		return nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 1 {
		return Refusef("%s%s is neither `head` nor a revision number; revisions start at 1", flag, value)
	}
	return nil
}

// fetchLockfiles resolves each profile's revision; what to install comes
// from here alone.
func (r *syncRun) fetchLockfiles(ctx context.Context, profiles []string, revisions map[string]string) ([]*hub.Lockfile, error) {
	out := make([]*hub.Lockfile, 0, len(profiles))
	for _, slug := range profiles {
		want := revisions[slug]
		r.s.Debugf("resolving profile %s at revision %s", slug, want)
		lf, err := r.client.GetRevision(ctx, slug, want)
		if err != nil {
			return nil, revisionFailure(slug, want, err)
		}
		if want != revisionHead {
			// An exact state was asked for; a different one is not a near miss.
			n, _ := strconv.ParseInt(want, 10, 64)
			if lf.Revision != n {
				return nil, fmt.Errorf("the hub answered revision %d of profile %s when asked for %d",
					lf.Revision, slug, n)
			}
		}
		if lf.Revision < 1 {
			return nil, fmt.Errorf("the hub answered profile %s with revision %d, which is not a revision",
				slug, lf.Revision)
		}
		out = append(out, lf)
	}
	return out, nil
}

// revisionFailure preserves internal/hub's classification with %w rather
// than rewriting it, since flattening would destroy that distinction.
func revisionFailure(slug, revision string, err error) error {
	switch {
	case errors.Is(err, hub.ErrUnauthorised):
		return Refusef("profile %s: %w; run `amctl login` or check %s", slug, err, credentials.TokenEnvVar)
	case errors.Is(err, hub.ErrForbidden):
		return Refusef("profile %s: %w; this credential may not read that profile", slug, err)
	case errors.Is(err, hub.ErrNotFound) && revision != revisionHead:
		return Refusef("profile %s has no revision %s: %w; `amctl sync --profile %s` takes its head",
			slug, revision, err, slug)
	case errors.Is(err, hub.ErrNotFound):
		return Refusef("profile %s: %w", slug, err)
	default:
		return fmt.Errorf("profile %s at revision %s: %w", slug, revision, err)
	}
}

// resolveTargets maps every target the lockfiles name onto something plan can
// reason about, INCLUDING the ones this build cannot write.
//
// It deliberately does NOT use layout.Registry.Select. Select refuses the whole
// selection on the first gated target and returns one error, which would lose
// the thing a report has to say: which profiles asked for it. plan.Compute
// aggregates a gated target across every profile that enabled it into one skip
// per entry, so the per-target Resolve is what feeds it.
//
// An UNKNOWN target is omitted from the slice rather than given an Err,
// because plan distinguishes the two: an omitted name is
// ConflictTargetUnknown ("the hub named something this build has never
// heard of"), which refuses the plan — a target that installs nothing while
// the command exits 0 is the worst failure R2 exists to prevent, and an
// unknown value has no other target to fall back on. An Err is a target this
// build KNOWS and refuses to guess where it reads (e.g. codex, gate R2), which
// plan.Compute turns into a skip per entry rather than a refusal: the
// profile's other targets still install.
func (r *syncRun) resolveTargets(reg *layout.Registry, lockfiles []*hub.Lockfile) (targets []plan.Target, writable map[record.Target]bool) {
	names := map[string]struct{}{}
	for _, lf := range lockfiles {
		for _, t := range lf.Targets {
			if s := string(t); s != "" {
				names[s] = struct{}{}
			}
		}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	slices.Sort(ordered)

	out := make([]plan.Target, 0, len(ordered))
	writable = map[record.Target]bool{}
	for _, name := range ordered {
		t, err := reg.Resolve(record.Target(name))
		switch {
		case err == nil:
			writable[record.Target(name)] = true
			out = append(out, plan.Target{Name: record.Target(name), Dest: destFunc(t)})
		case errors.Is(err, layout.ErrUnknownTarget):
			r.s.Warnf("the lockfile names target %s, which this build does not know: %v", name, err)
		case errors.Is(err, layout.ErrWithdrawnTarget):
			// Reported, not fatal: a withdrawn target (e.g. `agents-md`) is a
			// legal enum value nobody will implement, and refusing over it
			// would make the seeded catalogue unsyncable with no user fix.
			r.s.Warnf("the lockfile names target %s, which this build will not write: %v", name, err)
			out = append(out, plan.Target{Name: record.Target(name), Withdrawn: err})
		default:
			r.s.Warnf("the lockfile names target %s, which this build cannot write: %v", name, err)
			out = append(out, plan.Target{Name: record.Target(name), Err: err})
		}
	}
	return out, writable
}

// destFunc adapts a layout.Target to plan's DestFunc; the destination
// deliberately carries no version, so an upgrade is one rename, not two ops.
func destFunc(t layout.Target) plan.DestFunc {
	return func(id string, kind record.Kind) (string, error) {
		p, err := t.Place(layout.Request{ID: id, Kind: kind})
		if err != nil {
			return "", err
		}
		return p.Dest, nil
	}
}

// reportSkips is FR-011 for every entry the hub excluded, with its own reason,
// plus every entry this build itself could not install, with the kind or the
// target it could not write — never silently omitted either way.
//
// An unrecognised hub reason is reported VERBATIM and flagged as unrecognised
// rather than translated or dropped. The hub may add a seventh reason and this
// client ships separately from it, so a value this build has never seen is
// information, not an error.
func (r *syncRun) reportSkips(p plan.Plan) {
	for i := range p.Skipped {
		sk := p.Skipped[i]
		line := fmt.Sprintf("%s skipped %s", sk.Profile, sk.ID)
		if sk.Target != "" {
			line += " for target " + string(sk.Target)
		}
		if sk.WouldHaveResolvedTo != "" {
			line += " (would have resolved to " + sk.WouldHaveResolvedTo + ")"
		}
		line += ": " + sk.Reason
		if sk.Detail != "" {
			line += " — " + sk.Detail
		}
		if !sk.Recognised {
			line += " [this build does not recognise that reason; it is the hub's, reported unchanged]"
		}
		r.s.Warnf("%s", line)
	}
}

// localSkip is one entry this client did not install (never merged with the
// hub's own skips): POST /v1/sync's `skipped` is defined as the client's own.
type localSkip struct {
	Profile string
	ID      string
	Version string
	Reason  string
}

// bundleFetcher is apply.BundleSource plus a two-phase fetch: every bundle is
// fetched and verified into the cache before the first entry is staged, so
// --offline fails before installing anything rather than mid-tree, a mid-sync
// 403 becomes a dropped plan entry instead of an apply-time failure, and a
// 401 or unreachable hub aborts once instead of failing every entry
// separately. It re-hashes on the phase-two read (~8.8ms warm per 16MiB
// profile) rather than holding every bundle in memory, since the hub's own
// cap (242MiB/entry) makes that an OOM risk.
type bundleFetcher struct {
	downloader *hub.Downloader

	// refs is keyed by profile+id, not id alone: two profiles may name one
	// package via different lockfile entries.
	refs map[string]hub.BundleRef

	// dropped names the plan changes phase one removed, keyed as changeKey.
	dropped map[string]bool

	skips    []localSkip
	failures []error

	// failed mirrors failures as (profile, id, version, reason) for the JSON
	// result and the sync report's `skipped`, so a digest-mismatch drop is
	// never silently absent from the audit trail.
	failed []localSkip
}

func refKey(profile, id string) string { return profile + "\x00" + id }

func changeKey(profile string, target record.Target, id string) string {
	return profile + "\x00" + string(target) + "\x00" + id
}

// Bundle implements apply.BundleSource; the bytes come back re-hashed by
// internal/cache, so nothing can change between check and extraction.
func (f *bundleFetcher) Bundle(ctx context.Context, c plan.Change) ([]byte, error) {
	ref, ok := f.refs[refKey(c.Profile, c.ID)]
	if !ok {
		return nil, fmt.Errorf("internal: no lockfile entry for %s in profile %s", c.ID, c.Profile)
	}
	// Cheap cross-check that plan and lockfile agree; a mismatch here is the
	// one bug that would verify the wrong digest.
	if ref.Digest != c.Digest.Digest {
		return nil, fmt.Errorf("internal: the plan and the lockfile disagree on the digest for %s", c.ID)
	}
	b, err := f.downloader.Fetch(ctx, ref)
	if err != nil {
		return nil, err
	}
	return b.Bytes, nil
}

// prefetch is phase one. See bundleFetcher for why it exists.
func (r *syncRun) prefetch(ctx context.Context, dl *hub.Downloader, p plan.Plan, lockfiles []*hub.Lockfile) (*bundleFetcher, error) {
	f := &bundleFetcher{downloader: dl, refs: map[string]hub.BundleRef{}, dropped: map[string]bool{}}

	for _, lf := range lockfiles {
		for i := range lf.Entries {
			// An id amctl cannot address is a lockfile it does not understand,
			// so ParseBundleRef's refusal aborts rather than skipping the entry.
			ref, err := hub.ParseBundleRef(lf.Entries[i])
			if err != nil {
				return nil, Refusef("profile %s: %w", lf.Profile.Slug, err)
			}
			f.refs[refKey(lf.Profile.Slug, ref.ID)] = ref
		}
	}

	writes := p.Writes()
	for i := range writes {
		c := writes[i]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ref, ok := f.refs[refKey(c.Profile, c.ID)]
		if !ok {
			return nil, fmt.Errorf("internal: no lockfile entry for %s in profile %s", c.ID, c.Profile)
		}
		r.s.Debugf("fetching %s for profile %s", ref, c.Profile)
		b, err := dl.Fetch(ctx, ref)
		if err == nil {
			if b.FromCache {
				r.s.Debugf("%s was already in the bundle cache", ref)
			}
			continue
		}

		switch {
		case errors.Is(err, hub.ErrForbidden):
			// The gate refuses this version now: skip the entry, keep the rest.
			f.skips = append(f.skips, localSkip{
				Profile: c.Profile, ID: c.ID, Version: c.Version,
				Reason: "the hub refused to serve this version's bundle (403): " + err.Error(),
			})
			f.dropped[changeKey(c.Profile, c.Target, c.ID)] = true
			r.s.Warnf("%s: skipping %s at %s — %v", c.Profile, c.ID, c.Version, err)

		case errors.Is(err, hub.ErrOffload):
			// Not the 403 skip above: the object store itself refused (expired
			// signature, clock skew) — a failed download, not a withheld version.
			f.fail(r.s, c, err)

		case errors.Is(err, hub.ErrDigestMismatch):
			f.fail(r.s, c, err)

		case errors.Is(err, hub.ErrNotFound):
			// A hub-side inconsistency, not something this run can fix.
			f.fail(r.s, c, err)

		default:
			// Offline miss or transport/credential failure: abort before any
			// entry is staged, since a 401 now will 401 every remaining entry too.
			return nil, fetchAbort(c, err)
		}
	}
	return f, nil
}

func (f *bundleFetcher) fail(s *output.Streams, c plan.Change, err error) {
	wrapped := fmt.Errorf("%s: %s at %s: %w", c.Profile, c.ID, c.Version, err)
	f.failures = append(f.failures, wrapped)
	f.failed = append(f.failed, localSkip{
		Profile: c.Profile, ID: c.ID, Version: c.Version, Reason: err.Error(),
	})
	f.dropped[changeKey(c.Profile, c.Target, c.ID)] = true
	s.Errorf("%v", wrapped)
}

// fetchAbort names the entry that stopped the run, keeping internal/hub's
// classification in the chain.
func fetchAbort(c plan.Change, err error) error {
	if errors.Is(err, hub.ErrOffline) {
		return Refusef("%s: %s at %s: %w; nothing was installed, so the tree is unchanged",
			c.Profile, c.ID, c.Version, err)
	}
	if errors.Is(err, hub.ErrUnauthorised) {
		return Refusef("%s: %s at %s: %w; run `amctl login`", c.Profile, c.ID, c.Version, err)
	}
	return fmt.Errorf("%s: %s at %s: %w", c.Profile, c.ID, c.Version, err)
}

// withoutEntries removes only the changes phase one dropped, from the three
// sets Writes() draws from: dropping an upgrade leaves the old version
// installed and the record still claiming it, so the next run retries it.
func withoutEntries(p plan.Plan, dropped map[string]bool) plan.Plan {
	if len(dropped) == 0 {
		return p
	}
	keep := func(in []plan.Change) []plan.Change {
		out := make([]plan.Change, 0, len(in))
		for i := range in {
			c := in[i]
			if dropped[changeKey(c.Profile, c.Target, c.ID)] {
				continue
			}
			out = append(out, c)
		}
		return out
	}
	p.Add, p.Upgrade, p.Downgrade = keep(p.Add), keep(p.Upgrade), keep(p.Downgrade)
	return p
}

// apply executes the plan, returning (nil, err) only when nothing could be attempted.
func (r *syncRun) apply(
	ctx context.Context,
	p plan.Plan,
	rec *record.Record,
	recordPath string,
	lockfiles []*hub.Lockfile,
	writable map[record.Target]bool,
	fetch *bundleFetcher,
) (*apply.Result, error) {
	home, err := apply.OpenHome(r.home.UserHome)
	if err != nil {
		return nil, Refuse(err)
	}
	// Checked here too, not just before each entry: the download phase is
	// where a long freeze is most likely to have happened.
	if lost := r.stillOurs(); lost != nil {
		return nil, lost
	}
	applier, err := apply.New(apply.Config{
		Home:       home,
		Record:     rec,
		RecordPath: recordPath,
		Profiles:   profileStates(lockfiles, writable),
		Bundles:    fetch,
		Log:        r.s,
		Force:      r.flags.force,
		Now:        nowOr(r.deps.now),
		Continue:   r.stillOurs,
		// Fingerprints, Verifier, Pruner nil: those features don't exist yet.
		// Both fail closed — a later upgrade refuses naming --force, and a
		// planned removal fails with ErrPruneUnavailable — rather than silently
		// skip.
	})
	if err != nil {
		return nil, err
	}
	return applier.Apply(ctx, p)
}

// profileStates is what the record needs and the plan doesn't carry: each
// profile's resolved revision, and Targets as the intersection of the
// lockfile's advisory list with what this build actually writes (not the
// advisory list itself), since a later run reads it back to decide removals.
func profileStates(lockfiles []*hub.Lockfile, writable map[record.Target]bool) []apply.ProfileState {
	out := make([]apply.ProfileState, 0, len(lockfiles))
	for _, lf := range lockfiles {
		state := apply.ProfileState{Slug: lf.Profile.Slug, Revision: int(lf.Revision)}
		seen := map[record.Target]struct{}{}
		for _, raw := range lf.Targets {
			t := record.Target(raw)
			if !writable[t] {
				continue
			}
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			state.Targets = append(state.Targets, t)
		}
		slices.Sort(state.Targets)
		out = append(out, state)
	}
	return out
}

// newResult is the shell of the one result this verb emits.
func (r *syncRun) newResult(lockfiles []*hub.Lockfile) output.SyncResult {
	res := output.SyncResult{
		Hub:      r.target.URL,
		Profiles: make([]string, 0, len(lockfiles)),
		Added:    []output.Change{},
		Upgraded: []output.Change{},
		Removed:  []output.Change{},
		Skipped:  []output.Skip{},
	}
	for _, lf := range lockfiles {
		res.Profiles = append(res.Profiles, lf.Profile.Slug)
	}
	res.Revision = describeRevisions(lockfiles)
	return res
}

// describeRevisions: one profile gets the bare number, several get
// `slug@revision` pairs, since one number would misstate the others.
func describeRevisions(lockfiles []*hub.Lockfile) string {
	switch len(lockfiles) {
	case 0:
		return ""
	case 1:
		return strconv.FormatInt(lockfiles[0].Revision, 10)
	default:
		parts := make([]string, 0, len(lockfiles))
		for _, lf := range lockfiles {
			parts = append(parts, lf.Profile.Slug+"@"+strconv.FormatInt(lf.Revision, 10))
		}
		return strings.Join(parts, ", ")
	}
}

// fill reports what LANDED (apply's own account), not what the plan intended.
func (r *syncRun) fill(res *output.SyncResult, applied *apply.Result, fetch *bundleFetcher) {
	for i := range applied.Installed {
		inst := applied.Installed[i]
		c := changeOf(inst.Change)
		switch inst.Change.Op {
		case plan.OpDowngrade:
			res.Downgrade = append(res.Downgrade, c)
		case plan.OpUpgrade, plan.OpReplace:
			res.Upgraded = append(res.Upgraded, c)
		default:
			res.Added = append(res.Added, c)
		}
	}
	for i := range applied.Removed {
		rm := applied.Removed[i]
		res.Removed = append(res.Removed, output.Change{
			Package: rm.ID, From: rm.Version, Target: string(rm.Target), Path: rm.Dest,
		})
	}

	// This client's own skips, after the hub's, in the same list: output.Skip
	// is the result's only shape for "resolved but not installed".
	for i := range fetch.skips {
		sk := fetch.skips[i]
		res.Skipped = append(res.Skipped, output.Skip{
			Package: sk.ID, Version: sk.Version, Reason: sk.Reason,
		})
	}

	// A failed entry goes in its own array, not beside skips: a skip is a
	// decision this run carries past, a failure sets the exit code, and a
	// script reading one list shouldn't have to re-derive which is which.
	for i := range fetch.failed {
		fl := fetch.failed[i]
		res.Failed = append(res.Failed, output.Skip{
			Package: fl.ID, Version: fl.Version, Reason: fl.Reason,
		})
	}

	// A retained removal is not partial: the record row went and the
	// directory legitimately stays because another profile still claims it.
	res.Partial = len(applied.Failed) > 0 || len(fetch.failures) > 0 || len(fetch.skips) > 0
	if len(applied.Leftovers) > 0 {
		res.Partial = true
	}
}

// appendSkips puts every plan.Skip on the result — the hub's own exclusions
// verbatim (FR-011), and this build's own for a kind or a target it cannot
// install. It runs before the conflict check so that a REFUSED sync still
// reports them: a user told two profiles disagree also needs to see what was
// withheld, and the refusal does not make that information less true.
func appendSkips(res *output.SyncResult, p plan.Plan) {
	for i := range p.Skipped {
		sk := p.Skipped[i]
		res.Skipped = append(res.Skipped, output.Skip{
			Package: sk.ID, Version: sk.WouldHaveResolvedTo, Target: string(sk.Target), Reason: sk.Reason,
		})
	}
}

func changeOf(c plan.Change) output.Change {
	out := output.Change{Package: c.ID, To: c.Version, Target: string(c.Target), Path: c.Dest}
	if c.From != nil {
		out.From = c.From.Version
	}
	return out
}

// writesPerProfile counts the entries a plan would write, per profile.
func writesPerProfile(p plan.Plan) map[string]int {
	out := map[string]int{}
	writes := p.Writes()
	for i := range writes {
		out[writes[i].Profile]++
	}
	return out
}

// report files the sync report with the hub, one call per profile (POST
// /v1/sync's body has a single `profile` field), after the tree is in its
// final state. A failure is a warning only — the bytes are already on disk —
// and is never retried: the hub has no dedup key, so a retry after an
// ambiguous failure would write two audit rows for one sync.
func (r *syncRun) report(
	ctx context.Context,
	lockfiles []*hub.Lockfile,
	writable map[record.Target]bool,
	fetch *bundleFetcher,
	attempted map[string]int,
	applied *apply.Result,
) {
	reporter, err := hub.NewReporter(r.client)
	if err != nil {
		r.s.Warnf("the sync could not be reported to %s: %v", r.target.URL, err)
		return
	}
	states := profileStates(lockfiles, writable)
	// Both skips and failures feed `skipped`: the wire has one field for
	// "entry ids the CLI skipped locally", and a digest mismatch belongs there.
	skipped := map[string][]string{}
	for i := range fetch.skips {
		sk := fetch.skips[i]
		skipped[sk.Profile] = append(skipped[sk.Profile], sk.ID)
	}
	for i := range fetch.failed {
		fl := fetch.failed[i]
		skipped[fl.Profile] = append(skipped[fl.Profile], fl.ID)
	}
	landed := map[string]int{}
	for i := range applied.Installed {
		landed[applied.Installed[i].Change.Profile]++
	}
	for _, st := range states {
		// Had work and landed none of it: not synced, so don't report it. An
		// already-converged profile (nothing attempted) IS reported.
		if attempted[st.Slug] > 0 && landed[st.Slug] == 0 {
			r.s.Warnf("%s: nothing was installed, so no sync was reported to %s", st.Slug, r.target.URL)
			continue
		}
		targets := make([]string, 0, len(st.Targets))
		for _, t := range st.Targets {
			targets = append(targets, string(t))
		}
		if len(targets) == 0 {
			// Belt-and-braces: the plan would already have refused before here.
			r.s.Warnf("%s: no writable target, so no sync was reported", st.Slug)
			continue
		}
		err := reporter.Report(ctx, hub.Report{
			Profile: st.Slug, Revision: st.Revision, Host: r.host,
			Targets: targets, SkippedLocally: skipped[st.Slug],
		})
		if err != nil {
			r.s.Warnf("the sync of %s at revision %d was not reported to %s: %v; "+
				"the packages are installed, and this report is not retried because the hub records one audit "+
				"row per call and a duplicate cannot be withdrawn",
				st.Slug, st.Revision, r.target.URL, err)
			continue
		}
		r.s.Debugf("reported %s at revision %d to %s", st.Slug, st.Revision, r.target.URL)
	}
}

// syncError: a run whose every failure is a user-fixable refusal exits
// CodeRefused; anything else (digest mismatch, a bundle the hub won't serve)
// is CodeFailure, possibly worth retrying.
func syncError(applied *apply.Result, fetchFailures []error) error {
	joined := errors.Join(append([]error{applied.Err()}, fetchFailures...)...)
	if joined == nil {
		return nil
	}
	if len(fetchFailures) == 0 && len(applied.Failures()) == 0 && len(applied.Refusals()) > 0 {
		return Refuse(joined)
	}
	return joined
}

func nowOr(fn func() time.Time) func() time.Time {
	if fn == nil {
		return time.Now
	}
	return fn
}
