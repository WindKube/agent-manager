package hub

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The Machines screens' and the Affected machines panels' door to the api.

// Machines reads GET /v1/machines.
func (c *Client) Machines(ctx context.Context, q view.MachineQuery) (view.Machines, error) {
	page := int64(q.Page)
	params := &apiclient.ListMachinesParams{Page: &page}
	if q.Package != "" {
		params.Package = &q.Package
	}
	if q.Version != "" {
		params.Version = &q.Version
	}
	if q.Profile != "" {
		params.Profile = &q.Profile
	}
	if q.Stale != "" {
		stale := apiclient.ListMachinesParamsStale(q.Stale)
		params.Stale = &stale
	}
	list, err := c.listMachines(ctx, params)
	if err != nil {
		return view.Machines{}, err
	}
	out := view.Machines{
		Query: q, Total: int(list.Total), Page: int(list.Page), PageSize: int(list.PageSize),
		StaleAfterDays: int(list.StaleAfterDays), Rows: make([]view.MachineRow, 0, len(list.Machines)),
	}
	for i := range list.Machines {
		out.Rows = append(out.Rows, machineRow(&list.Machines[i]))
	}
	return out, nil
}

// AffectedMachines counts the machines holding a package, per version, or
// one version of it when version is given.
func (c *Client) AffectedMachines(ctx context.Context, pkg, version string) (view.AffectedMachines, error) {
	one := int64(1)
	params := &apiclient.ListMachinesParams{Package: &pkg, PageSize: &one}
	if version != "" {
		params.Version = &version
	}
	list, err := c.listMachines(ctx, params)
	if err != nil {
		return view.AffectedMachines{}, err
	}
	out := view.AffectedMachines{Package: pkg, Version: version, Total: int(list.Total)}
	if list.Versions != nil {
		for _, v := range *list.Versions {
			out.Versions = append(out.Versions, view.VersionMachines{Version: v.Version, Machines: int(v.Machines)})
		}
	}
	return out, nil
}

func (c *Client) listMachines(ctx context.Context, params *apiclient.ListMachinesParams) (*apiclient.MachineList, error) {
	resp, err := c.api.ListMachinesWithResponse(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, fmt.Errorf("list machines: %w", machineError(resp.HTTPResponse, resp.Body))
	}
	return resp.JSON200, nil
}

// Machine reads GET /v1/machines/{id}.
func (c *Client) Machine(ctx context.Context, id string) (view.MachineDetail, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return view.MachineDetail{}, view.ErrNotFound
	}
	resp, err := c.api.GetMachineWithResponse(ctx, parsed)
	if err != nil {
		return view.MachineDetail{}, fmt.Errorf("get machine: %w", err)
	}
	if resp.JSON200 == nil {
		return view.MachineDetail{}, fmt.Errorf("get machine: %w", machineError(resp.HTTPResponse, resp.Body))
	}
	body := resp.JSON200
	out := view.MachineDetail{
		Machine: machineRow(&body.Machine), StaleAfterDays: int(body.StaleAfterDays),
		Installs: make([]view.MachineInstall, 0, len(body.Installs)),
		Skipped:  make([]view.MachineSkip, 0, len(body.Skipped)),
	}
	for _, inst := range body.Installs {
		out.Installs = append(out.Installs, view.MachineInstall{
			Package: inst.Package, Version: inst.Version, Target: string(inst.Target), Profile: inst.Profile,
		})
	}
	for _, sk := range body.Skipped {
		skip := view.MachineSkip{Profile: sk.Profile, Entry: sk.Entry, Component: deref(sk.Component), Reason: deref(sk.Reason)}
		if sk.Target != nil {
			skip.Target = string(*sk.Target)
		}
		out.Skipped = append(out.Skipped, skip)
	}
	return out, nil
}

// ForgetMachine deletes DELETE /v1/machines/{id}.
func (c *Client) ForgetMachine(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return view.ErrNotFound
	}
	resp, err := c.api.ForgetMachineWithResponse(ctx, parsed)
	if err != nil {
		return fmt.Errorf("forget machine: %w", err)
	}
	if resp.StatusCode() == http.StatusNoContent {
		return nil
	}
	return machineError(resp.HTTPResponse, resp.Body)
}

func machineRow(m *apiclient.Machine) view.MachineRow {
	return view.MachineRow{
		ID: m.Id.String(), Hostname: m.Hostname, OS: deref(m.Os), Arch: deref(m.Arch),
		AmctlVersion: deref(m.AmctlVersion), FirstSeenAt: m.FirstSeenAt, LastSeenAt: m.LastSeenAt,
		LastSeen: view.Relative(m.LastSeenAt, time.Now()),
		Stale:    m.Stale, LastProfile: m.LastProfile, LastRevision: int(m.LastRevision),
		ReportedBy: m.ReportedBy, ServiceToken: deref(m.ServiceToken),
	}
}

func machineError(resp *http.Response, body []byte) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return view.ErrNotFound
		case http.StatusForbidden:
			return ErrForbidden
		}
	}
	return statusError(resp, body)
}
