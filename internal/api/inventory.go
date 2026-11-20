package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

func (s *Server) registerInventory() {
	unauthorized := s.errorResponse("Missing, expired or invalid token.")
	forbidden := s.errorResponse("A service token cannot read the machine inventory.")
	visibility := "A catalog-admin sees every machine; anyone else sees the machines whose last " +
		"report was theirs or one of their service tokens'."

	huma.Register(s.api, huma.Operation{
		OperationID: "listMachines",
		Method:      http.MethodGet,
		Path:        "/v1/machines",
		Tags:        []string{"machines"},
		Summary:     "Machines that reported a sync",
		Description: visibility + " A package filter names a package this identity can read, and then " +
			"also counts the matching machines per version. Stale is computed on read.",
		Responses: map[string]*huma.Response{
			"401": unauthorized,
			"403": forbidden,
			"404": s.errorResponse("The package, version or profile filter names nothing this identity can read."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.listMachines)

	huma.Register(s.api, huma.Operation{
		OperationID: "getMachine",
		Method:      http.MethodGet,
		Path:        "/v1/machines/{id}",
		Tags:        []string{"machines"},
		Summary:     "One machine's installs and latest skips",
		Description: visibility + " Installs and skips list only profiles and packages this identity can read.",
		Responses: map[string]*huma.Response{
			"401": unauthorized,
			"403": forbidden,
			"404": s.errorResponse("No such machine, or not one this identity may see."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.getMachine)

	huma.Register(s.api, huma.Operation{
		OperationID:   "forgetMachine",
		Method:        http.MethodDelete,
		Path:          "/v1/machines/{id}",
		Tags:          []string{"machines"},
		Summary:       "Forget a machine",
		DefaultStatus: http.StatusNoContent,
		Description: "Deletes the machine and its inventory and writes one `sync` audit row. " + visibility +
			" The sync events it reported stay. A machine that reports again reappears.",
		Responses: map[string]*huma.Response{
			"204": {Description: "Forgotten."},
			"401": unauthorized,
			"403": forbidden,
			"404": s.errorResponse("No such machine, or not one this identity may see."),
			"500": s.errorResponse("The request could not be completed."),
		},
	}, s.forgetMachine)
}

type listMachinesInput struct {
	Package  string `query:"package" maxLength:"256" doc:"Only machines with this package installed, as namespace/name." example:"acme/code-review"`
	Version  string `query:"version" maxLength:"128" doc:"Only machines with this version of the package installed; needs package." example:"2.4.1"`
	Profile  string `query:"profile" maxLength:"200" doc:"Only machines that reported this profile." example:"platform-baseline"`
	Stale    string `query:"stale" enum:"true,false" doc:"Only stale machines, or only fresh ones."`
	Page     int    `query:"page" minimum:"1" default:"1" doc:"Clamped into range: a page past the end returns the last one."`
	PageSize int    `query:"pageSize" minimum:"1" maximum:"200" default:"50"`
}

func (in *listMachinesInput) Resolve(huma.Context) []error {
	if in.Version != "" && in.Package == "" {
		return []error{&huma.ErrorDetail{Location: "query.version", Message: "version needs package", Value: in.Version}}
	}
	return nil
}

type listMachinesOutput struct {
	Body contract.MachineList
}

func (s *Server) listMachines(ctx context.Context, in *listMachinesInput) (*listMachinesOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	list, err := queries.Machines(ctx, s.deps.DB, principal, queries.MachineFilter{
		Package: in.Package, Version: in.Version, Profile: in.Profile, Stale: in.Stale,
		Page: in.Page, PageSize: in.PageSize,
	})
	if errors.Is(err, queries.ErrInvalidFilter) {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listMachinesOutput{Body: list}, nil
}

type machineIDInput struct {
	ID string `path:"id" format:"uuid" doc:"The machine's id, as listed."`
}

type getMachineOutput struct {
	Body contract.MachineDetail
}

func (s *Server) getMachine(ctx context.Context, in *machineIDInput) (*getMachineOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	id, err := uuid.Parse(in.ID)
	if err != nil {
		return nil, fail(logging.From(ctx), queries.ErrNotFound)
	}
	detail, err := queries.Machine(ctx, s.deps.DB, principal, id)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &getMachineOutput{Body: detail}, nil
}

func (s *Server) forgetMachine(ctx context.Context, in *machineIDInput) (*struct{}, error) {
	principal, _ := PrincipalFrom(ctx)
	id, err := uuid.Parse(in.ID)
	if err != nil {
		return nil, fail(logging.From(ctx), queries.ErrNotFound)
	}
	if err := commands.ForgetMachine(ctx, s.deps.DB, principal, id); err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &struct{}{}, nil
}
