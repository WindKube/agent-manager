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
	// httpClient is the transport for the hub. nil means net/http's default;
	// the fake hub over TLS hands a test a client that trusts its self-signed
	// certificate.
	httpClient *http.Client
	// hostname supplies the machine name the sync report is filed under.
	hostname func() (string, error)
	// backends overrides the credential store order. nil means the policy order.
	backends []keyring.BackendType
	// lookupEnv reads the environment. It serves BOTH the AMCTL_TOKEN
	// precedence (FR-005) and CLAUDE_CONFIG_DIR, which is the only variable
	// that relocates claude-code's skills root — R2 measured that
	// XDG_CONFIG_HOME is not read by the agent at all, so an XDG-first resolver
	// would install to a directory nothing opens.
	lookupEnv func(string) (string, bool)
	// now stamps the record's InstalledAt and decides whether a credential has
	// expired.
	now func() time.Time
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

// newSyncCmd builds `amctl sync`.
//
// # WHAT `--revision` MEANS WHEN THERE ARE TWO PROFILES, AND WHY IT REFUSES
//
// `head` and an exact number are different KINDS of request: one is "whatever
// is current", the other "this exact state, and fail if it is gone". Revisions
// are per profile — the lockfile's own words are "Sequential per profile, no
// gaps" — so one number across two profiles names two unrelated states, and
// `--revision 7` for a profile with four revisions is a 404 that looks exactly
// like a missing profile.
//
// So:
//
//   - `--revision head` (the default) applies to every profile. "Current" is
//     meaningful per profile, so there is nothing to disambiguate.
//   - A bare `--revision 7` is accepted only with exactly ONE `--profile`.
//     With two or more it is REFUSED, naming both flags and the form that
//     works. Applying it to both would pin a profile to a number nobody chose
//     for it.
//   - `--revision <slug>=<7|head>`, repeatable, pins named profiles; any
//     profile not named defaults to head.
//
// The third form is a small grammar and it is here for one reason that nothing
// else can serve: FR-012 requires two profiles that resolve one package to two
// versions to be refused BEFORE anything is written, and that comparison only
// exists inside a single run. Telling the operator to "run sync twice, once per
// profile" would silently give up cross-profile conflict detection, which is
// the one check a pinned multi-profile machine most needs.
//
// Mixing a bare number with a `slug=` form is refused rather than merged: the
// merge would have to invent a precedence, and neither precedence is obvious.
//
// # WHAT `--profile` MEANS WHEN IT IS ABSENT
//
// The profiles already in this machine's installation record, at head. That
// makes a bare `amctl sync` in a cron job mean "keep what this machine has up
// to date" and never "adopt whatever the organisation added since" — a default
// that installed every readable profile would let one hub-side change reach
// every machine at once, which is not a decision a scheduled job should make.
//
// A machine with an empty record and no `--profile` is REFUSED naming the flag
// (FR-037): there is no TTY to ask, and picking a profile for the operator
// would be inventing the answer.
//
// The recorded REVISION is deliberately not reused as a pin. The record is an
// account of what happened, not a declaration of intent — there is no desired
// state file in this design — so treating it as a pin would make a converged
// machine never update again, which is the opposite of what a convergence tool
// is for. `--revision` is how a run is pinned, per invocation, which is exactly
// what FR-010 asks for.
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
	// --force is the FR-029 override. apply names every path it destroys on the
	// diagnostic stream before destroying it, which is the only thing that makes
	// this flag defensible; see internal/apply's override().
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"overwrite a destination amctl's record does not claim, or one modified since install, naming what is destroyed")
	return cmd
}

// runSync is `sync` with its outside world as an argument.
//
// THE ORDER IS THE REQUIREMENT, not an implementation detail:
//
//  1. the hostname, because the sync report is filed under it and a machine
//     with no name cannot be reported;
//  2. Prepare — the home directory is created and PROVED WRITABLE by a real
//     write, and the hub URL is canonicalised, both before any packet leaves
//     (FR-039);
//  3. the credential, resolved from the environment or the store, before a hub
//     client exists. A machine with no credential refuses here having made ZERO
//     requests (FR-037) — asking the hub first would leak the fact that this
//     machine exists and would produce a 401 where the real answer is "you
//     never logged in";
//  4. the per-home lock, held across everything that follows (FR-038). It is
//     taken before the first request rather than just before the first write,
//     because the download populates a cache two runs share, and a lock that
//     only covered the mutation would let two syncs race in the cache.
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

// resolveSyncCredential is FR-005 and FR-037 in one place.
//
// The store is opened LAZILY by credentials.Resolver, so a machine using
// AMCTL_TOKEN never creates a credential directory, never raises a keychain
// dialog and never prints the FR-003 fallback warning. That laziness is the
// whole of FR-005's "takes precedence" and it is the resolver's, not this
// function's — see credentials.Resolver's comment.
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
		// FR-037: no TTY, so name what supplies the credential instead of
		// asking for it. Both routes are named because the right one depends on
		// whether a human or a pipeline is running this.
		return credentials.Resolved{}, Refusef(
			"no credential for %s: run `amctl login --hub %s`, or set %s in the environment",
			target.URL, target.URL, credentials.TokenEnvVar)
	}
	if res.Credential.Expired(nowOr(deps.now)()) {
		// Refused rather than tried. The hub would answer 401 and the message
		// would then say "the hub rejected the credential", which sends the
		// user looking at the hub instead of at their own expired token.
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

	// lock is the per-home sync lock this run holds (FR-038). It is carried
	// this far rather than discarded at WithLock because Lock.Lost is the
	// documented mitigation for the one hazard the lock cannot prevent — a
	// holder frozen past the staleness window whose lock another amctl
	// reclaimed — and a detection nothing consults is not a mitigation. Nil in
	// tests that drive a phase directly.
	lock *Lock
}

// stillOurs is what internal/apply asks before each entry. A run whose lock was
// reclaimed while it was frozen no longer owns the tree: the other amctl is
// already swapping entries in it, and two concurrent swaps of one entry can
// have one process rename the destination aside while the other reclaims it.
//
// Not a Refusal: nothing the user did caused it and nothing they can change
// fixes it. Re-running is the answer, which is what CodeFailure means here.
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
		// Every Load failure — corrupt, wrong schema version, another hub's
		// record, a record amctl could not have written — is a refusal a user
		// can fix, and record.Load's comment says the wrapping is the verb's
		// because internal/record cannot import this package.
		return Refuse(err)
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
	appendHubSkips(&res, p)
	if p.Refuses() {
		// FR-012, FR-023 and R2's unwritable target, all refused BEFORE a byte
		// is staged. The result is still emitted so `--output json` carries the
		// conflict list; the error is what sets the exit code.
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

	// FR-014/FR-018: every bundle is fetched and verified into the cache before
	// the first entry is staged. See prefetch.
	bundles := cache.New(cache.Dir(r.home.Root))
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
	// Counted BEFORE the drop, because "this profile had work and none of it
	// landed" is what decides whether reporting it would be a lie. See report.
	attempted := writesPerProfile(p)
	p = withoutEntries(p, fetch.dropped)

	applied, err := r.apply(ctx, p, rec, recordPath, lockfiles, writable, fetch)
	if applied == nil {
		// Nothing could be attempted, so there is no sync to report and no
		// result to emit that would not be a claim about work never started.
		return err
	}
	// From here the returned error is re-derived by syncError from the Result:
	// the same entry failures, plus the ones phase one already collected, and
	// with the CodeRefused/CodeFailure decision applied. `err` is Apply's join
	// of the first set alone, so it is deliberately not returned as-is.
	_ = err
	r.fill(&res, applied, fetch)

	// FR-032/FR-033. Reported after the tree is in its final state, because the
	// report claims a revision is installed.
	r.report(ctx, lockfiles, writable, fetch, attempted, applied)

	if emitErr := r.opts.Emit(res); emitErr != nil {
		return emitErr
	}
	// FR-036 has four codes and none of them is "partial", so the outcome states
	// what the CLI ACHIEVED and the partial detail goes in the result.
	//
	// A locally skipped entry — the gate answered 403 for that version — does
	// NOT move the exit code. The machine is in the state the hub's gate
	// dictates, which is a correct outcome and not a failure this CLI can fix,
	// and calling it a refusal would tell a wrapper script that retrying might
	// help. What a caller that cares reads instead is `partial` and the
	// `skipped` list under --output json, which is what FR-035 is for; every one
	// of them is also a warning on the diagnostic stream (FR-011).
	if res.Changed() {
		r.opts.Outcome = CodeChanged
	} else {
		r.opts.Outcome = CodeNoChanges
	}
	return syncError(applied, fetch.failures)
}

// chooseProfiles resolves which profiles this run reconciles. See newSyncCmd
// for why an absent --profile means "the ones already in the record".
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
				// Deduplicated rather than refused: `--profile a --profile a`
				// is a harmless mistake, and plan.Compute refuses a duplicate
				// lockfile outright, which would be a confusing place to learn
				// about it.
				continue
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

// parseRevisions turns the --revision values into one revision per profile.
// Every refusal here names the flag and the form that works; see newSyncCmd for
// the decision.
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
				// The refusal this whole design exists for. Revision 7 of one
				// profile and revision 7 of another are unrelated states.
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

// validRevision restates the contract's own `^(head|[0-9]+)$` locally so a bad
// argument is named here rather than round-tripped for a 422. It decides
// nothing about WHICH revision to fetch, which would be the second resolver
// FR-009 forbids.
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

// fetchLockfiles resolves each profile's revision. FR-009 in one line: what to
// install comes from here and from nowhere else.
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
			// The hub was asked for an exact state; a different one is not a
			// near miss. Checked because the alternative is recording a
			// revision the operator did not pin and calling the machine pinned.
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

// revisionFailure turns FR-040's four classes into a sentence that sends the
// reader to the right place. internal/hub has already classified the error, so
// the chain is preserved with %w rather than rewritten — flattening it would
// destroy exactly the distinction FR-040 asks for.
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
// the thing a refusal has to say: which profiles asked for it. plan.Compute
// aggregates a target-level refusal across every profile that enabled it and
// prints one sentence naming them all, so the per-target Resolve is what feeds
// it.
//
// An UNKNOWN target is omitted from the slice rather than given an Err, because
// plan distinguishes the two: an omitted name is ConflictTargetUnknown ("the
// hub named something this build has never heard of"), an Err is
// ConflictTargetUnwritable ("this build knows it and refuses to guess where it
// reads"). Both refuse the plan, and that is the point — R2's whole finding is
// that a target which installs nothing while the command exits 0 is the worst
// failure this tool has.
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
			// REPORTED, NOT FATAL, and this is the one case that is neither of
			// the two above. A withdrawn target is one nobody will ever
			// implement — `agents-md` is the lockfile schema's own example value
			// and a legal member of the frozen enum — so refusing the sync would
			// make the seeded catalogue unsyncable over a value the hub itself
			// suggested, with no user-side fix, because the target list is the
			// hub's. plan.Target.Withdrawn carries that distinction through:
			// omitting the name here instead would make it ConflictTargetUnknown
			// and refuse anyway, which is what this code used to do.
			r.s.Warnf("the lockfile names target %s, which this build will not write: %v", name, err)
			out = append(out, plan.Target{Name: record.Target(name), Withdrawn: err})
		default:
			r.s.Warnf("the lockfile names target %s, which this build cannot write: %v", name, err)
			out = append(out, plan.Target{Name: record.Target(name), Err: err})
		}
	}
	return out, writable
}

// destFunc adapts a layout.Target to plan's DestFunc. Place needs no version —
// the destination deliberately does not contain one, so an upgrade is R3's
// single rename rather than a write plus a removal.
func destFunc(t layout.Target) plan.DestFunc {
	return func(id string, kind record.Kind) (string, error) {
		p, err := t.Place(layout.Request{ID: id, Kind: kind})
		if err != nil {
			return "", err
		}
		return p.Dest, nil
	}
}

// reportSkips is FR-011: every entry the hub excluded, with the hub's own
// reason, never silently omitted.
//
// An unrecognised reason is reported VERBATIM and flagged as unrecognised
// rather than translated or dropped. The hub may add a seventh reason and this
// client ships separately from it, so a value this build has never seen is
// information, not an error.
func (r *syncRun) reportSkips(p plan.Plan) {
	for i := range p.Skipped {
		sk := p.Skipped[i]
		line := fmt.Sprintf("%s skipped %s", sk.Profile, sk.ID)
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

// localSkip is one entry THIS CLIENT did not install, as opposed to one the hub
// withheld. The two are reported side by side and are never merged into one
// list: the hub already knows what it skipped, and POST /v1/sync's `skipped`
// field is defined as the client's own.
type localSkip struct {
	Profile string
	ID      string
	Version string
	Reason  string
}

// bundleFetcher is apply.BundleSource plus the two-phase fetch behind it.
//
// WHY THERE ARE TWO PHASES. Every bundle is fetched and verified into the cache
// BEFORE the first entry is staged, and the per-entry Bundle call then reads it
// back out. That ordering buys three things no per-entry fetch can:
//
//   - FR-018. `--offline` must "complete from cache alone or fail naming what is
//     missing, and MUST NOT leave a partially installed tree". A miss discovered
//     at entry seven has already installed six; a miss discovered in phase one
//     has installed nothing.
//   - FR-011's mid-sync 403. internal/apply treats a BundleSource error as an
//     entry failure, so a 403 handed to it would be a failure rather than a
//     skip. Phase one turns it into a skip and takes the entry out of the plan,
//     which is the only way "the entries either side must still install" is
//     true.
//   - FR-040 economy. A 401 or an unreachable hub aborts phase one instead of
//     producing the same message twelve times.
//
// It costs one extra sha256 per bundle — internal/cache re-hashes on every read
// (FR-017) and phase two is a read — which R4 measured at 8.8 ms warm for a
// whole 15.9 MiB profile. It deliberately does NOT hold every bundle in memory:
// the ceiling entry in the hub's own caps is 242 MiB, and a map of decompressed
// profiles is how a sync gets killed by the OOM reaper on a small box.
type bundleFetcher struct {
	downloader *hub.Downloader

	// refs is keyed by profile and entry id, not by id alone: two profiles may
	// legitimately name one package, and the lockfile entry each carries is the
	// one that must build that profile's request.
	refs map[string]hub.BundleRef

	// dropped names the plan changes phase one removed, keyed as changeKey.
	dropped map[string]bool

	skips    []localSkip
	failures []error

	// failed is the localSkip half of `failures`: the same entries, as
	// (profile, id, version, reason) rather than as a joined error, because the
	// error is what sets the exit code and this is what NAMES the package — in
	// the JSON result and in the sync report's `skipped`. hub.Report's own doc
	// puts a bundle "whose bytes did not match the digest the lockfile locked"
	// in that field, and FR-032 says the report carries the entries skipped
	// locally. Without this list the hub's audit row reads "synced profile P
	// revision N to this host" for a machine that is missing a package because
	// somebody substituted the object — the single event an audit trail most
	// needs to carry.
	failed []localSkip
}

func refKey(profile, id string) string { return profile + "\x00" + id }

func changeKey(profile string, target record.Target, id string) string {
	return profile + "\x00" + string(target) + "\x00" + id
}

// Bundle implements apply.BundleSource. The bytes come back through
// internal/cache, which re-hashed them, so they are the slice that was hashed
// and nothing can change between the check and the extraction (FR-014, FR-017).
func (f *bundleFetcher) Bundle(ctx context.Context, c plan.Change) ([]byte, error) {
	ref, ok := f.refs[refKey(c.Profile, c.ID)]
	if !ok {
		return nil, fmt.Errorf("internal: no lockfile entry for %s in profile %s", c.ID, c.Profile)
	}
	// A cheap cross-check that the plan and the lockfile entry agree. They come
	// from the same document, so a disagreement is a bug here — and it is the
	// one bug that would make the digest verification check the wrong digest.
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
			// ParseBundleRef splits the entry id into NAMESPACE and name — the
			// bundle path's `{publisher}` parameter takes the namespace despite
			// its name — and refuses an id that is not exactly two non-empty
			// segments. An id amctl cannot address is a lockfile it does not
			// understand, so it aborts rather than skipping the entry.
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
			// FR-011 mid-sync: the gate refuses this version now. Skip the
			// entry, keep the rest, and say so with the hub's own status.
			f.skips = append(f.skips, localSkip{
				Profile: c.Profile, ID: c.ID, Version: c.Version,
				Reason: "the hub refused to serve this version's bundle (403): " + err.Error(),
			})
			f.dropped[changeKey(c.Profile, c.Target, c.ID)] = true
			r.s.Warnf("%s: skipping %s at %s — %v", c.Profile, c.ID, c.Version, err)

		case errors.Is(err, hub.ErrOffload):
			// NOT the FR-011 gate skip above, even though it is usually the same
			// 403. The hub answered 307 and the OBJECT STORE refused — an expired
			// pre-signed signature, clock skew, a proxy in front of the store —
			// which is a download that failed, not a version the organisation
			// withheld. Skipping it would install nothing and exit 0 over
			// something a retry fixes.
			f.fail(r.s, c, err)

		case errors.Is(err, hub.ErrDigestMismatch):
			// FR-015: abort THIS entry, leave the machine unchanged for it, exit
			// non-zero. Nothing was written because phase one runs before any
			// staging, and the error already names both digests.
			f.fail(r.s, c, err)

		case errors.Is(err, hub.ErrNotFound):
			// The lockfile names a version the hub will not serve. That is a
			// hub-side inconsistency rather than something this run can fix, so
			// it fails the entry and the rest of the sync continues.
			f.fail(r.s, c, err)

		default:
			// FR-018's offline miss, and every transport or credential failure.
			// All of them abort BEFORE the first entry is staged: an offline
			// miss must not leave a partially installed tree, and a hub that
			// just answered 401 will answer 401 for every remaining entry.
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

// fetchAbort names the entry that stopped the run and keeps internal/hub's
// classification in the chain, so FR-040's four classes survive to the caller.
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

// withoutEntries removes the changes phase one dropped, and only those.
//
// It touches Add, Upgrade and Downgrade — the three sets Writes() draws from —
// and nothing else. Dropping an upgrade leaves the OLD version installed and
// the record still claiming it, which is precisely "the machine is unchanged for
// that entry": the next run retries it.
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

// apply executes the plan. It returns (nil, err) only when nothing could be
// attempted, so the caller knows there is no sync to report.
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
	// Before the first entry is staged, as well as before each one: the download
	// phase is where a long freeze is most likely to have happened.
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
		// Fingerprints, Verifier and Pruner are deliberately nil: T049's R4
		// fingerprint and T048's prune do not exist yet. The consequences are
		// documented rather than hidden — an entry installed now carries no
		// fingerprint, so a later upgrade of it refuses naming --force
		// (internal/apply's verifyUnmodified), and a planned removal fails with
		// ErrPruneUnavailable instead of silently not happening. Both fail
		// closed, which is the direction that does not destroy work.
	})
	if err != nil {
		return nil, err
	}
	return applier.Apply(ctx, p)
}

// profileStates is what the record needs and the plan does not carry: each
// profile's RESOLVED revision (FR-013) and the targets actually written.
//
// Targets is the intersection of the lockfile's advisory list with what this
// build writes, not the advisory list itself, because FR-030 reads it back to
// decide what a later run must remove when a target is disabled.
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

// describeRevisions renders the revisions actually resolved. One profile gets
// the bare number; several get `slug@revision` pairs, because a single number
// would be a different state in each and printing one of them would be a lie
// about the others.
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

// fill maps what happened onto the result. It reports what LANDED, taken from
// apply's own account, rather than what the plan intended: a plan is a
// prediction and this field is a claim.
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

	// This client's own skips, after the hub's. They are in one list because
	// output.Skip is the only shape the result has for "resolved but not
	// installed", and each carries the sentence that says which side decided.
	for i := range fetch.skips {
		sk := fetch.skips[i]
		res.Skipped = append(res.Skipped, output.Skip{
			Package: sk.ID, Version: sk.Version, Reason: sk.Reason,
		})
	}

	// An ABANDONED entry goes in its own array, not beside the skips. Both mean
	// "resolved but not installed" and they exit differently — a skip is a
	// decision this run carries on past, a failure sets the exit code — so a
	// script that read one list would have to re-derive which was which. Before
	// this, a digest mismatch appeared in no array at all: only `partial` said
	// anything had gone wrong, and it did not say which package.
	for i := range fetch.failed {
		fl := fetch.failed[i]
		res.Failed = append(res.Failed, output.Skip{
			Package: fl.ID, Version: fl.Version, Reason: fl.Reason,
		})
	}

	// Partial is plan.md's partially-applied sync: something did not land, and
	// the result must read as partial rather than as an undetailed failure.
	// A RETAINED removal is not partial — the record row went and the directory
	// legitimately stays because another profile still claims it.
	res.Partial = len(applied.Failed) > 0 || len(fetch.failures) > 0 || len(fetch.skips) > 0
	if len(applied.Leftovers) > 0 {
		res.Partial = true
	}
}

// appendHubSkips puts the hub's own exclusions on the result, verbatim (FR-011).
// It runs before the conflict check so that a REFUSED sync still reports them:
// a user told two profiles disagree also needs to see what the hub withheld,
// and the refusal does not make that information less true.
func appendHubSkips(res *output.SyncResult, p plan.Plan) {
	for i := range p.Skipped {
		sk := p.Skipped[i]
		res.Skipped = append(res.Skipped, output.Skip{
			Package: sk.ID, Version: sk.WouldHaveResolvedTo, Reason: sk.Reason,
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

// report is FR-032 and FR-033.
//
// One report per profile, because POST /v1/sync's body has a single `profile`
// field and each profile resolved its own revision. It runs AFTER the tree is in
// its final state, because the report claims a revision is installed.
//
// A failure is a warning and nothing more (FR-033): the bytes are already on
// disk, and refusing to admit the sync happened would be the wrong correction.
// There is no retry — see internal/hub/sync_report.go for the measurement that
// decides that, in short: the hub inserts a fresh sync_event row per call with
// no dedup key, so a retry after an ambiguous failure writes two audit rows for
// one sync and breaks hub SC-008.
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
	// Both lists, because POST /v1/sync's `skipped` is defined as "entry ids the
	// CLI skipped locally" and hub.Report.SkippedLocally's own doc names a
	// bundle whose bytes did not match the locked digest as one of them. The
	// wire has one field for the two, and an audit row that omitted the
	// substituted object would be exactly the row that mattered.
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
		// A profile that had work to do and landed none of it was not synced,
		// and reporting it would put a false row in the hub's audit trail —
		// "this machine is at revision N" — for a machine that is not. An
		// already-converged profile (nothing attempted) IS reported: FR-032 is
		// about a successful sync, and a converged one is the commonest kind.
		if attempted[st.Slug] > 0 && landed[st.Slug] == 0 {
			r.s.Warnf("%s: nothing was installed, so no sync was reported to %s", st.Slug, r.target.URL)
			continue
		}
		targets := make([]string, 0, len(st.Targets))
		for _, t := range st.Targets {
			targets = append(targets, string(t))
		}
		if len(targets) == 0 {
			// Nothing was managed under any target this build writes, so there
			// is nothing to claim. The plan would have refused before here, so
			// this is a belt-and-braces guard rather than a reachable state.
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

// syncError decides the exit code from what went wrong (FR-036).
//
// A run whose every failure is a REFUSAL the user can fix — an unrecorded
// destination, a modification without --force — exits CodeRefused, because
// retrying it changes nothing until the user acts. Anything else, including a
// digest mismatch and a bundle the hub locked but will not serve, is
// CodeFailure: not the user's to fix, and possibly worth retrying.
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
