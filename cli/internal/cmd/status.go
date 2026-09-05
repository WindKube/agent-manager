package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"

	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// statusDeps is status's outside world. See loginDeps for why it is a struct.
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

// runStatus is `status` with its outside world as an argument.
//
// It goes through Prepare for the same reason logout does: Prepare validates
// the home directory and canonicalises the hub URL, and neither dials the
// network, so there is no ordering to protect here — status just needs the
// same per-hub directory name login and sync wrote.
func runStatus(opts *Options, deps statusDeps) error {
	s := opts.Streams()

	return Prepare(opts.Hub, func(home Home, target Hub) error {
		recordPath := record.Path(home.HubDir(target))
		rec, err := record.Load(recordPath, target.URL)
		if err != nil {
			// Same four refusals record.Load documents for sync: corrupt,
			// wrong schema version, another hub's record, a record amctl could
			// not have written.
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

// identityFor reads the stored credential's identity, the same source login
// wrote it from (internal/cmd/login.go: cred.Identity = the machine's own
// hostname, since none of the hub's endpoints return a caller identity).
//
// A store that cannot be opened or a hub with no stored credential both
// report "" rather than fail: status must still print the local record when
// the hub is unreachable, --offline is set, or nobody has ever logged in here.
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

// statusOf turns one recorded profile into its report and its drift, if any.
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

// driftReason answers whether e's destination still matches what was
// installed, and says why when it does not. Empty means clean.
//
// Absence of evidence is not evidence of absence: an entry recorded without a
// fingerprint is reported UNVERIFIABLE rather than assumed unmodified, the
// same fail-closed rule internal/apply's verifyUnmodified enforces before an
// overwrite (FR-029). Every entry this build has installed so far carries no
// fingerprint — R4's fingerprinter is not wired into a production sync yet —
// so that is the honest answer for all of them today; the byte-for-byte check
// below is what starts running the day it is.
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

	if e.Fingerprint.IsZero() {
		return "unverifiable: installed without a fingerprint, so a modification cannot be detected"
	}
	if e.Fingerprint.Algo != record.FingerprintAlgo {
		return fmt.Sprintf("unverifiable: recorded with fingerprint algorithm %q, this build verifies %q",
			e.Fingerprint.Algo, record.FingerprintAlgo)
	}

	changed, err := modifiedPaths(e.Dest, e.Fingerprint)
	if err != nil {
		return fmt.Sprintf("unverifiable: %v", err)
	}
	if len(changed) == 0 {
		return ""
	}
	return "modified: " + strings.Join(changed, ", ")
}

// modifiedPaths compares dest's current tree against fp, entry-root-relative,
// and names every path that disagrees. Files and Dirs together are a CLOSED
// SET over the root (record.Fingerprint's own contract): a path on disk and
// absent from fp is an addition, a path in fp and absent from disk is a
// removal, and both are modifications alongside a changed hash, size, mode or
// kind.
func modifiedPaths(dest string, fp record.Fingerprint) ([]string, error) {
	seen := make(map[string]bool, len(fp.Files)+len(fp.Dirs))
	var changed []string

	walkErr := filepath.WalkDir(dest, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dest, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		seen[rel] = true

		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			if want, ok := fp.Dirs[rel]; !ok || uint32(info.Mode().Perm()) != want {
				changed = append(changed, rel)
			}
			return nil
		}

		want, ok := fp.Files[rel]
		if !ok {
			changed = append(changed, rel)
			return nil
		}
		kind := record.FileKindRegular
		if info.Mode()&fs.ModeSymlink != 0 {
			kind = record.FileKindSymlink
		}
		if kind != want.Kind || info.Size() != want.Size || uint32(info.Mode().Perm()) != want.Mode {
			changed = append(changed, rel)
			return nil
		}
		sum, err := sha256Hex(path)
		if err != nil {
			return err
		}
		if sum != want.SHA256 {
			changed = append(changed, rel)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	for rel := range fp.Files {
		if !seen[rel] {
			changed = append(changed, rel)
		}
	}
	for rel := range fp.Dirs {
		if !seen[rel] {
			changed = append(changed, rel)
		}
	}
	slices.Sort(changed)
	return changed, nil
}

func sha256Hex(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is entry-root-relative under a recorded, amctl-owned destination
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
