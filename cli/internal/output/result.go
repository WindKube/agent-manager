package output

import (
	"fmt"
	"io"
	"time"
)

// LoginResult is produced by `amctl login`. It has no token field and must never
// gain one: no token may reach any output stream.
type LoginResult struct {
	Hub      string     `json:"hub"`
	Identity string     `json:"identity"`
	Store    string     `json:"store"`
	Expires  *time.Time `json:"expires,omitempty"`
}

func (LoginResult) Kind() string { return "login" }

func (r LoginResult) Human(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "logged in to %s as %s (credential in %s)\n", r.Hub, r.Identity, r.Store); err != nil {
		return err
	}
	if r.Expires != nil {
		_, err := fmt.Fprintf(w, "token expires %s\n", r.Expires.Format(time.RFC3339))
		return err
	}
	return nil
}

// LogoutResult is produced by `amctl logout`. Removed is false when there was
// nothing to remove; logout is idempotent, so that is an outcome, not an error.
type LogoutResult struct {
	Hub     string `json:"hub"`
	Store   string `json:"store"`
	Removed bool   `json:"removed"`
}

func (LogoutResult) Kind() string { return "logout" }

func (r LogoutResult) Human(w io.Writer) error {
	if !r.Removed {
		_, err := fmt.Fprintf(w, "no credential stored for %s\n", r.Hub)
		return err
	}
	_, err := fmt.Fprintf(w, "removed the credential for %s from %s\n", r.Hub, r.Store)
	return err
}

// Change is one entry the plan touches: what it is, where it came from and where it went.
type Change struct {
	Package string `json:"package"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Target  string `json:"target"`
	Path    string `json:"path,omitempty"`
}

// Skip is one entry that was resolved and then not installed: the hub's own
// reason verbatim (FR-011), or this CLI's own reason when it is the one that
// could not install the entry's kind or write its target. Target is set only
// for the latter, since the hub reasons per package rather than per target.
type Skip struct {
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	Target  string `json:"target,omitempty"`
	Reason  string `json:"reason"`
	Detail  string `json:"detail,omitempty"`
}

// SyncResult is produced by `amctl sync` from the plan internal/plan computed.
type SyncResult struct {
	Hub       string   `json:"hub"`
	Profiles  []string `json:"profiles"`
	Revision  string   `json:"revision,omitempty"`
	DryRun    bool     `json:"dry_run"`
	Added     []Change `json:"added"`
	Upgraded  []Change `json:"upgraded"`
	Downgrade []Change `json:"downgraded"`
	Removed   []Change `json:"removed"`
	Skipped   []Skip   `json:"skipped"`

	// Failed is an entry this run abandoned: digest mismatch, unservable version,
	// refused pre-signed URL. Separate from Skipped because a skip exits 0 and a
	// failure sets the exit code.
	Failed []Skip `json:"failed"`

	Conflicts []Change `json:"conflicts"`
	Partial   bool     `json:"partial"`
}

// Changed reports whether this sync modified the tree, which selects between the
// two success exit codes. A dry run never changes anything.
func (r SyncResult) Changed() bool {
	if r.DryRun {
		return false
	}
	return len(r.Added)+len(r.Upgraded)+len(r.Downgrade)+len(r.Removed) > 0
}

func (SyncResult) Kind() string { return "sync" }

func (r SyncResult) Human(w io.Writer) error {
	verb := "synced"
	if r.DryRun {
		verb = "would sync"
	}
	if _, err := fmt.Fprintf(w, "%s %s from %s\n", verb, joinOr(r.Profiles, "no profiles"), r.Hub); err != nil {
		return err
	}
	sets := []struct {
		label   string
		changes []Change
	}{
		{"add", r.Added},
		{"upgrade", r.Upgraded},
		{"downgrade", r.Downgrade},
		{"remove", r.Removed},
		{"conflict", r.Conflicts},
	}
	for _, s := range sets {
		for _, c := range s.changes {
			if _, err := fmt.Fprintf(w, "  %-9s %s %s\n", s.label, c.Package, versionSpan(c)); err != nil {
				return err
			}
		}
	}
	groups, rest := groupTargetUnwritableSkips(r.Skipped)
	for _, g := range groups {
		if _, err := fmt.Fprintf(w, "  %-9s target %s: %d %s, %s%s\n",
			"skip", g.target, g.count, pluralize(g.count, "entry", "entries"), skipTargetUnwritable, detailSuffix(g.detail)); err != nil {
			return err
		}
	}
	for _, s := range rest {
		if _, err := fmt.Fprintf(w, "  %-9s %s %s: %s\n", "skip", s.Package, s.Version, s.Reason); err != nil {
			return err
		}
	}
	for _, s := range r.Failed {
		if _, err := fmt.Fprintf(w, "  %-9s %s %s: %s\n", "fail", s.Package, s.Version, s.Reason); err != nil {
			return err
		}
	}
	if !r.Changed() && !r.DryRun {
		if _, err := fmt.Fprintln(w, "  nothing to do"); err != nil {
			return err
		}
	}
	if r.Partial {
		_, err := fmt.Fprintln(w, "  partially applied: re-run to converge")
		return err
	}
	return nil
}

// Drift is one recorded path whose content on disk no longer matches what was installed there.
type Drift struct {
	Package string `json:"package"`
	Path    string `json:"path"`
	Reason  string `json:"reason"`
}

// ProfileStatus is one synced profile as the installation record holds it.
type ProfileStatus struct {
	Slug     string    `json:"slug"`
	Revision string    `json:"revision"`
	Targets  []string  `json:"targets"`
	SyncedAt time.Time `json:"synced_at"`
	Entries  int       `json:"entries"`
	HasDrift bool      `json:"has_drift"`
}

// StatusResult is produced by `amctl status`, read from the installation record
// and never from the network. A machine that has never synced is a valid result
// with Synced false, not an error.
type StatusResult struct {
	Hub      string          `json:"hub"`
	Identity string          `json:"identity"`
	Synced   bool            `json:"synced"`
	Profiles []ProfileStatus `json:"profiles"`
	Drift    []Drift         `json:"drift"`
}

func (StatusResult) Kind() string { return "status" }

func (r StatusResult) Human(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "hub      %s\n", r.Hub); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "identity %s\n", orNone(r.Identity, "not logged in")); err != nil {
		return err
	}
	if !r.Synced {
		_, err := fmt.Fprintln(w, "nothing has been synced on this machine")
		return err
	}
	for _, p := range r.Profiles {
		if _, err := fmt.Fprintf(w, "profile  %s at %s (%d entries, %s)\n",
			p.Slug, p.Revision, p.Entries, p.SyncedAt.Format(time.RFC3339)); err != nil {
			return err
		}
	}
	for _, d := range r.Drift {
		if _, err := fmt.Fprintf(w, "drift    %s %s: %s\n", d.Package, d.Path, d.Reason); err != nil {
			return err
		}
	}
	return nil
}

// VersionResult is produced by `amctl version`.
type VersionResult struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func (VersionResult) Kind() string { return "version" }

func (r VersionResult) Human(w io.Writer) error {
	_, err := fmt.Fprintf(w, "amctl %s (%s, %s)\n", r.Version, r.Commit, r.Date)
	return err
}

func versionSpan(c Change) string {
	switch {
	case c.From != "" && c.To != "":
		return c.From + " -> " + c.To
	case c.To != "":
		return c.To
	default:
		return c.From
	}
}

func joinOr(values []string, empty string) string {
	if len(values) == 0 {
		return empty
	}
	out := values[0]
	for _, v := range values[1:] {
		out += ", " + v
	}
	return out
}

// skipTargetUnwritable mirrors plan.SkipTargetUnwritable's wire value. Kept as
// a literal rather than an import: this package renders whatever string
// internal/plan put in Skip.Reason and otherwise has no opinion on the hub's
// or the CLI's vocabulary, and importing internal/plan here just to name one
// of its constants would make output depend on the package that depends on it.
const skipTargetUnwritable = "target-unwritable"

// targetSkipGroup is every entry skipped under one target this build cannot
// write, collapsed to a count.
type targetSkipGroup struct {
	target string
	detail string
	count  int
}

// groupTargetUnwritableSkips separates a target-unwritable skip — repeated
// once per entry a gated target would have received — from every other skip,
// and collapses the former by target. A profile with a dozen entries under
// one gated target must print one line naming it, not a dozen identical ones.
func groupTargetUnwritableSkips(skips []Skip) (groups []targetSkipGroup, rest []Skip) {
	index := map[string]int{}
	for _, s := range skips {
		if s.Reason != skipTargetUnwritable || s.Target == "" {
			rest = append(rest, s)
			continue
		}
		if i, ok := index[s.Target]; ok {
			groups[i].count++
			continue
		}
		index[s.Target] = len(groups)
		groups = append(groups, targetSkipGroup{target: s.Target, detail: s.Detail, count: 1})
	}
	return groups, rest
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

func detailSuffix(detail string) string {
	if detail == "" {
		return ""
	}
	return " - " + detail
}

func orNone(value, empty string) string {
	if value == "" {
		return empty
	}
	return value
}
