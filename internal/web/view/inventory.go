package view

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var machineIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// MachineRow is one machine as the inventory lists it.
type MachineRow struct {
	ID           string
	Hostname     string
	OS           string
	Arch         string
	AmctlVersion string
	FirstSeenAt  time.Time
	LastSeenAt   time.Time
	// LastSeen is LastSeenAt as a phrase, rendered against the reader's clock.
	LastSeen     string
	Stale        bool
	LastProfile  string
	LastRevision int
	ReportedBy   string
	ServiceToken string
}

// Href links the machine's detail.
func (m MachineRow) Href() string { return MachineHref(m.ID) }

// Platform is os/arch and the amctl version, whichever were reported.
func (m MachineRow) Platform() string {
	var parts []string
	if m.OS != "" || m.Arch != "" {
		parts = append(parts, strings.Trim(m.OS+"/"+m.Arch, "/"))
	}
	if m.AmctlVersion != "" {
		parts = append(parts, "amctl "+m.AmctlVersion)
	}
	return strings.Join(parts, " · ")
}

// Revision is the last synced profile at its revision.
func (m MachineRow) Revision() string {
	return m.LastProfile + " r" + strconv.Itoa(m.LastRevision)
}

// Reporter is who filed the last report, naming the token when one did.
func (m MachineRow) Reporter() string {
	if m.ServiceToken != "" {
		return "token " + m.ServiceToken + " of " + m.ReportedBy
	}
	return m.ReportedBy
}

// MachineHref links one machine; an id that is not a uuid links the list.
func MachineHref(id string) string {
	if !machineIDPattern.MatchString(id) {
		return "/machines"
	}
	return "/machines/" + id
}

// MachinesHref links the inventory filtered to one package, and version
// when given.
func MachinesHref(pkg, version string) string {
	return MachineQuery{Package: pkg, Version: version}.Href(1)
}

// MachineQuery is the inventory's filters, carried in the URL.
type MachineQuery struct {
	Package string
	Version string
	Profile string
	Stale   string
	Page    int
}

// Normalise drops what the api would refuse rather than sending it on.
func (q MachineQuery) Normalise() MachineQuery {
	q.Package, q.Version, q.Profile = strings.TrimSpace(q.Package), strings.TrimSpace(q.Version), strings.TrimSpace(q.Profile)
	if q.Package == "" {
		q.Version = ""
	}
	if q.Stale != "true" && q.Stale != "false" {
		q.Stale = ""
	}
	if q.Page < 1 {
		q.Page = 1
	}
	return q
}

// Href is the inventory at page with these filters.
func (q MachineQuery) Href(page int) string {
	values := url.Values{}
	for key, v := range map[string]string{"package": q.Package, "version": q.Version, "profile": q.Profile, "stale": q.Stale} {
		if v != "" {
			values.Set(key, v)
		}
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	if len(values) == 0 {
		return "/machines"
	}
	return "/machines?" + values.Encode()
}

// Filtered reports whether any filter narrows the list.
func (q MachineQuery) Filtered() bool {
	return q.Package != "" || q.Profile != "" || q.Stale != ""
}

// Machines is the inventory screen.
type Machines struct {
	Query          MachineQuery
	Rows           []MachineRow
	Total          int
	Page           int
	PageSize       int
	StaleAfterDays int
	Notice         *Notice

	// Missing is a filter naming a package, version or profile this viewer cannot read.
	Missing bool
	GovernanceState
}

// Pages is how many pages the list spans, at least one.
func (m Machines) Pages() int {
	if m.PageSize < 1 || m.Total == 0 {
		return 1
	}
	return (m.Total + m.PageSize - 1) / m.PageSize
}

// MachineInstall is one installed package on the machine detail.
type MachineInstall struct {
	Package string
	Version string
	Target  string
	Profile string
}

// MachineSkip is one thing a machine did not install.
type MachineSkip struct {
	Profile   string
	Entry     string
	Target    string
	Component string
	Reason    string
}

// What names the skipped thing: the entry, or its component and target.
func (s MachineSkip) What() string {
	if s.Component == "" {
		return s.Entry + " (whole entry)"
	}
	return s.Entry + " · " + s.Component + " for " + s.Target
}

// InstallGroup is one target's installs.
type InstallGroup struct {
	Target   string
	Installs []MachineInstall
}

// MachineDetail is the machine screen.
type MachineDetail struct {
	Machine        MachineRow
	StaleAfterDays int
	Installs       []MachineInstall
	Skipped        []MachineSkip

	Missing bool
	GovernanceState
}

// ByTarget groups installs by target, in the order the api listed them.
func (d MachineDetail) ByTarget() []InstallGroup {
	var out []InstallGroup
	for _, inst := range d.Installs {
		if len(out) == 0 || out[len(out)-1].Target != inst.Target {
			out = append(out, InstallGroup{Target: inst.Target})
		}
		out[len(out)-1].Installs = append(out[len(out)-1].Installs, inst)
	}
	return out
}

// ForgetHref is the forget form's action.
func (d MachineDetail) ForgetHref() string { return MachineHref(d.Machine.ID) + "/forget" }

// VersionMachines is how many machines hold one version.
type VersionMachines struct {
	Version  string
	Machines int
}

// AffectedMachines is the "which machines run this" panel of a package or a finding.
type AffectedMachines struct {
	Package string
	// Version scopes the panel to one version (a finding); empty is every version.
	Version  string
	Total    int
	Versions []VersionMachines
	// Unavailable is the api not answering, not zero machines.
	Unavailable bool
}

// Href links the inventory filtered to what this panel counts.
func (a AffectedMachines) Href() string { return MachinesHref(a.Package, a.Version) }

// VersionHref links the inventory filtered to one version.
func (a AffectedMachines) VersionHref(version string) string { return MachinesHref(a.Package, version) }

// Count is "N machine(s)".
func (a AffectedMachines) Count() string { return MachineCount(a.Total) }

// MachineCount is "N machine(s)".
func MachineCount(n int) string {
	if n == 1 {
		return "1 machine"
	}
	return strconv.Itoa(n) + " machines"
}
