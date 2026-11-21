package contract

import "time"

type Machine struct {
	ID           string    `json:"id" format:"uuid" doc:"The random id the CLI generated for itself."`
	Hostname     string    `json:"hostname" example:"dev-laptop-01"`
	OS           string    `json:"os,omitempty" example:"darwin"`
	Arch         string    `json:"arch,omitempty" example:"arm64"`
	AmctlVersion string    `json:"amctlVersion,omitempty" example:"0.9.0"`
	FirstSeenAt  time.Time `json:"firstSeenAt"`
	LastSeenAt   time.Time `json:"lastSeenAt"`
	Stale        bool      `json:"stale" doc:"No report for longer than staleAfterDays. Computed on read."`
	LastProfile  string    `json:"lastProfile" doc:"Slug of the profile the last report synced." example:"platform-baseline"`
	LastRevision int       `json:"lastRevision" example:"7"`
	ReportedBy   string    `json:"reportedBy" doc:"The person behind the last report: the reporter, or the service token's creator." example:"kw@example.com"`
	ServiceToken string    `json:"serviceToken,omitempty" doc:"Name of the service token that filed the last report, if one did." example:"ci-runner"`
}

type MachineVersionCount struct {
	Version  string `json:"version" example:"2.4.1"`
	Machines int    `json:"machines" doc:"Machines in this listing's scope with this version installed." example:"12"`
}

type MachineList struct {
	Machines       []Machine             `json:"machines" doc:"Most recently seen first."`
	Total          int                   `json:"total" doc:"Machines matching every filter, across all pages." example:"42"`
	Page           int                   `json:"page" example:"1"`
	PageSize       int                   `json:"pageSize" example:"50"`
	StaleAfterDays int                   `json:"staleAfterDays" example:"14"`
	Versions       []MachineVersionCount `json:"versions,omitempty" doc:"With a package filter, how many of the matching machines hold each of its versions."`
}

type MachineInstall struct {
	Package string `json:"package" doc:"namespace/name" example:"acme/code-review"`
	Version string `json:"version" example:"2.4.1"`
	Target  string `json:"target" enum:"claude-code,codex,opencode" example:"claude-code"`
	Profile string `json:"profile" example:"platform-baseline"`
}

type MachineSkip struct {
	Profile   string `json:"profile" example:"platform-baseline"`
	Entry     string `json:"entry" example:"acme/code-review"`
	Target    string `json:"target,omitempty" enum:"claude-code,codex,opencode" doc:"Absent when the whole entry was skipped."`
	Component string `json:"component,omitempty" example:"mcp-server lint"`
	Reason    string `json:"reason,omitempty" example:"no claude CLI on PATH"`
}

type MachineDetail struct {
	Machine        Machine          `json:"machine"`
	StaleAfterDays int              `json:"staleAfterDays" example:"14"`
	Installs       []MachineInstall `json:"installs" doc:"Installs from profiles and of packages this identity may read, as of each profile's last report."`
	Skipped        []MachineSkip    `json:"skipped" doc:"What the latest report of each readable profile did not install, without packages this identity may not read."`
}
