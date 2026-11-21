package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// statusDeps is status's outside world; see loginDeps.
type statusDeps struct {
	backends []keyring.BackendType
}

func productionStatusDeps() statusDeps { return statusDeps{} }

func newStatusCmd(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report the hub, identity, profiles and any drift",
		Long: "Reports this machine's installation record for one hub: the identity it last\n" +
			"logged in as, each synced profile with its installed revision, and any drift —\n" +
			"a managed file modified since install, or missing.\n\n" +
			"status reads only the local record and credential store; it makes no network\n" +
			"request and works with the hub unreachable or --offline.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runStatus(opts, productionStatusDeps())
		},
	}
}

// runStatus goes through Prepare (which dials nothing) so it reads the same
// per-hub directory login and sync wrote.
func runStatus(opts *Options, deps statusDeps) error {
	s := opts.Streams()

	return Prepare(opts.Hub, func(home Home, target Hub) error {
		recordPath := record.Path(home.HubDir(target))
		rec, err := record.Load(recordPath, target.URL)
		if err != nil {
			return Refuse(err)
		}

		res := output.StatusResult{Hub: target.URL, Identity: identityFor(home, target, s, deps.backends)}
		hasDrift := false
		for i := range rec.Profiles {
			p := &rec.Profiles[i]
			ps, drift := statusOf(p)
			if len(drift) > 0 {
				hasDrift = true
			}
			res.Synced = true
			res.Profiles = append(res.Profiles, ps)
			res.Drift = append(res.Drift, drift...)
		}

		if err := opts.Emit(res); err != nil {
			return err
		}
		if hasDrift {
			return Refusef("the installed tree no longer matches the installation record; re-run `amctl sync` " +
				"to converge, or investigate before doing so")
		}
		opts.Outcome = CodeNoChanges
		return nil
	})
}

// identityFor reads the stored credential's identity. An unopenable store or
// missing credential reports "" rather than fail: status must still print the
// local record when nobody has logged in here.
func identityFor(home Home, target Hub, s *output.Streams, backends []keyring.BackendType) string {
	store, err := openStore(home, s, backends)
	if err != nil {
		s.Warnf("could not open the credential store, so the identity is unknown: %v", err)
		return ""
	}
	cred, ok, err := store.Load(target.URL)
	if err != nil {
		s.Warnf("could not read the credential for %s, so the identity is unknown: %v", target.URL, err)
		return ""
	}
	if !ok {
		return ""
	}
	return cred.Identity
}

func statusOf(p *record.Profile) (output.ProfileStatus, []output.Drift) {
	targets := make([]string, 0, len(p.Targets))
	for _, t := range p.Targets {
		targets = append(targets, string(t))
	}
	slices.Sort(targets)

	ps := output.ProfileStatus{
		Slug:     p.Slug,
		Revision: strconv.Itoa(p.Revision),
		Targets:  targets,
		SyncedAt: p.InstalledAt,
		Entries:  len(p.Entries),
	}

	var drift []output.Drift
	for i := range p.Entries {
		e := &p.Entries[i]
		if reason := driftReason(e); reason != "" {
			drift = append(drift, output.Drift{Package: e.ID, Path: e.Dest, Reason: reason})
		}
	}
	ps.HasDrift = len(drift) > 0
	return ps, drift
}

// driftReason says why e's destination no longer matches what was installed,
// or "" when clean. It reuses sync's TreeFingerprinter so both agree on what
// "modified" means; an entry it cannot verify is reported unverifiable, never
// assumed unmodified.
func driftReason(e *record.Entry) string {
	info, err := os.Lstat(e.Dest)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "missing: recorded as installed at " + e.Dest + " but nothing is there"
	case err != nil:
		return fmt.Sprintf("unverifiable: %s could not be read: %v", e.Dest, err)
	case info.Mode()&fs.ModeSymlink != 0:
		return "unverifiable: " + e.Dest + " is a symlink, which amctl never installs as the entry root"
	}

	changed, err := (apply.TreeFingerprinter{}).Modifications(*e)
	if err != nil {
		return fmt.Sprintf("unverifiable: %v", err)
	}
	if len(changed) == 0 {
		return ""
	}
	return "modified: " + strings.Join(changed, ", ")
}
