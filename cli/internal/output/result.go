package output

import (
	"fmt"
	"io"
	"time"
)

// LoginResult is produced by `amctl login` (internal/cmd/login.go).
//
// There is no token field here, and there must never be one: FR-007 forbids a
// token reaching any output stream, and the cheapest way to hold that is for
// the type a renderer can see to have nowhere to put one.
type LoginResult struct {
	Hub      string     `json:"hub"`
	Identity string     `json:"identity"`
	Store    string     `json:"store"`
	Expires  *time.Time `json:"expires,omitempty"`
}

// Kind implements Result.
func (LoginResult) Kind() string { return "login" }

// Human implements Result.
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

// LogoutResult is produced by `amctl logout` (internal/cmd/logout.go).
//
// Removed is false when there was no credential to remove. That is not an
// error — logout is idempotent — but it is a different outcome, and a script
// that cares can tell them apart without parsing prose.
type LogoutResult struct {
	Hub     string `json:"hub"`
	Store   string `json:"store"`
	Removed bool   `json:"removed"`
}

// Kind implements Result.
func (LogoutResult) Kind() string { return "logout" }

// Human implements Result.
func (r LogoutResult) Human(w io.Writer) error {
	if !r.Removed {
		_, err := fmt.Fprintf(w, "no credential stored for %s\n", r.Hub)
		return err
	}
	_, err := fmt.Fprintf(w, "removed the credential for %s from %s\n", r.Hub, r.Store)
	return err
}

// Change is one entry the plan touches: what it is, where it came from and
// where it went. Filled by internal/plan and rendered unchanged.
type Change struct {
	Package string `json:"package"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Target  string `json:"target"`
	Path    string `json:"path,omitempty"`
}

// Skip is one entry the hub resolved but refused to serve, carrying the hub's
// own reason verbatim (FR-011). The reason is the hub's text, not this CLI's
// interpretation of it.
type Skip struct {
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason"`
}

// SyncResult is produced by `amctl sync` (internal/cmd/sync.go), from the plan
// value internal/plan produces. The four change sets are the ones FR-031
// requires `--dry-run` to report in full; Skipped is FR-011; Partial is the
// accepted outcome of plan.md's partially-applied multi-profile sync, which
// must read as partial rather than as an undetailed failure.
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
	Conflicts []Change `json:"conflicts"`
	Partial   bool     `json:"partial"`
}

// Changed reports whether this sync modified the tree, which is what selects
// between the two success exit codes of FR-036. A dry run never changes
// anything by definition, however long its plan is.
func (r SyncResult) Changed() bool {
	if r.DryRun {
		return false
	}
	return len(r.Added)+len(r.Upgraded)+len(r.Downgrade)+len(r.Removed) > 0
}

// Kind implements Result.
func (SyncResult) Kind() string { return "sync" }

// Human implements Result.
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
	for _, s := range r.Skipped {
		if _, err := fmt.Fprintf(w, "  %-9s %s %s: %s\n", "skip", s.Package, s.Version, s.Reason); err != nil {
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

// Drift is one recorded path whose content on disk no longer matches what was
// installed there. Detected by the fingerprint chosen in R4; a false
// "unmodified" destroys a person's edit, so this set failing closed matters
// more than it being small.
type Drift struct {
	Package string `json:"package"`
	Path    string `json:"path"`
	Reason  string `json:"reason"`
}

// ProfileStatus is one synced profile as the installation record holds it: the
// revision actually installed (FR-013), so a later run can tell drift from
// change.
type ProfileStatus struct {
	Slug     string    `json:"slug"`
	Revision string    `json:"revision"`
	Targets  []string  `json:"targets"`
	SyncedAt time.Time `json:"synced_at"`
	Entries  int       `json:"entries"`
	HasDrift bool      `json:"has_drift"`
}

// StatusResult is produced by `amctl status` (internal/cmd/status.go). Its
// fields are exactly the five FR-034 names — hub, identity, profiles,
// revisions and drift — read from the installation record, never from the
// network: status answers offline.
//
// A machine that has never synced is a valid StatusResult with Synced false
// and no profiles, not an error.
type StatusResult struct {
	Hub      string          `json:"hub"`
	Identity string          `json:"identity"`
	Synced   bool            `json:"synced"`
	Profiles []ProfileStatus `json:"profiles"`
	Drift    []Drift         `json:"drift"`
}

// Kind implements Result.
func (StatusResult) Kind() string { return "status" }

// Human implements Result.
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

// VersionResult is produced by `amctl version` (internal/cmd/root.go). It is a
// result rather than a bare Fprintln so that `--output json version` is
// parseable like every other verb.
type VersionResult struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Kind implements Result.
func (VersionResult) Kind() string { return "version" }

// Human implements Result.
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

func orNone(value, empty string) string {
	if value == "" {
		return empty
	}
	return value
}
