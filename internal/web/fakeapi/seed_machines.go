package fakeapi

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"agent-manager/internal/apiclient"
)

func seedMachines(now time.Time) []apiclient.MachineDetail {
	claude, codex := apiclient.MachineInstallTargetClaudeCode, apiclient.MachineInstallTargetCodex
	return []apiclient.MachineDetail{
		{
			Machine: apiclient.Machine{
				Id: uuid.MustParse("0193f2a0-0000-7000-8000-0000000000a1"), Hostname: "dev-laptop-01",
				Os: ptr("darwin"), Arch: ptr("arm64"), AmctlVersion: ptr("0.9.0"),
				FirstSeenAt: now.Add(-40 * 24 * time.Hour), LastSeenAt: now.Add(-3 * time.Hour),
				LastProfile: "example/platform-engineer", LastRevision: 4, ReportedBy: "ada@fixture.invalid",
			},
			StaleAfterDays: 14,
			Installs: []apiclient.MachineInstall{
				{Package: "community/slack-digest", Version: "0.5.1", Target: claude, Profile: "example/platform-engineer"},
				{Package: "example/platform-toolkit", Version: "1.3.0", Target: claude, Profile: "example/platform-engineer"},
				{Package: "example/platform-toolkit", Version: "1.3.0", Target: codex, Profile: "example/platform-engineer"},
			},
			Skipped: []apiclient.MachineSkip{{
				Profile: "example/platform-engineer", Entry: "example/platform-toolkit",
				Target: ptr(apiclient.MachineSkipTargetClaudeCode), Component: ptr("mcp-server terraform-registry"),
				Reason: ptr("no claude CLI on PATH"),
			}},
		},
		{
			Machine: apiclient.Machine{
				Id: uuid.MustParse("0193f2a0-0000-7000-8000-0000000000a2"), Hostname: "ci-runner-7",
				Os: ptr("linux"), Arch: ptr("amd64"), AmctlVersion: ptr("0.8.2"),
				FirstSeenAt: now.Add(-90 * 24 * time.Hour), LastSeenAt: now.Add(-20 * 24 * time.Hour), Stale: true,
				LastProfile: "example/platform-engineer", LastRevision: 3, ReportedBy: "ada@fixture.invalid",
				ServiceToken: ptr("release pipeline"),
			},
			StaleAfterDays: 14,
			Installs: []apiclient.MachineInstall{
				{Package: "community/slack-digest", Version: "0.5.0", Target: claude, Profile: "example/platform-engineer"},
			},
			Skipped: []apiclient.MachineSkip{},
		},
	}
}

// machineList answers listMachines over d.Machines the way the api filters.
func (d *Data) machineList(r *http.Request) apiclient.MachineList {
	q := r.URL.Query()
	pkg, version, profile, stale := q.Get("package"), q.Get("version"), q.Get("profile"), q.Get("stale")
	out := apiclient.MachineList{Machines: []apiclient.Machine{}, Page: 1, PageSize: 50, StaleAfterDays: 14}
	counts := map[string]int64{}
	var order []string
	for i := range d.Machines {
		m := &d.Machines[i]
		if stale != "" && (stale == "true") != m.Machine.Stale {
			continue
		}
		if profile != "" && m.Machine.LastProfile != profile {
			continue
		}
		matched := pkg == ""
		seen := map[string]bool{}
		for _, inst := range m.Installs {
			if inst.Package != pkg {
				continue
			}
			if !seen[inst.Version] {
				seen[inst.Version] = true
				if counts[inst.Version] == 0 {
					order = append(order, inst.Version)
				}
				counts[inst.Version]++
			}
			if version == "" || inst.Version == version {
				matched = true
			}
		}
		if matched {
			out.Machines = append(out.Machines, m.Machine)
		}
	}
	out.Total = int64(len(out.Machines))
	if pkg != "" {
		versions := make([]apiclient.MachineVersionCount, 0, len(order))
		for _, v := range order {
			versions = append(versions, apiclient.MachineVersionCount{Version: v, Machines: counts[v]})
		}
		out.Versions = &versions
	}
	return out
}
