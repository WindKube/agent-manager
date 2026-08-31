package api

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

// The Scanner screen's operations (US4, T062-T066).
//
// The three reads are open to any authenticated identity; the two decisions are
// not. That asymmetry is the whole authorisation model of this screen: seeing what
// is quarantined is what a governance tool is for, and accepting a risk on the
// organisation's behalf is an act with a named person behind it (FR-028, FR-126).

// The filter vocabularies, lowercase and canonical. The design's chips say "Open"
// and "High"; an API that took those would have made a rendering decision for
// every client.
const (
	stateOpen     = "open"
	stateApproved = "approved"
	stateRejected = "rejected"

	severityLow    = "low"
	severityMedium = "medium"
	severityHigh   = "high"
)

// ---- GET /v1/scanner/summary -------------------------------------------------

type scannerSummaryInput struct {
	Days int `query:"days" minimum:"1" maximum:"365" default:"30" doc:"The window the scanned count and the median are computed over. The design's card says 30 days; the parameter is what keeps that caption a value rather than a constant (FR-121)."`
}

type scannerSummaryOutput struct {
	Body contract.ScannerSummary
}

func (s *Server) scannerSummary(ctx context.Context, in *scannerSummaryInput) (*scannerSummaryOutput, error) {
	summary, err := queries.ScannerSummary(ctx, s.deps.DB, in.Days)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &scannerSummaryOutput{Body: summary}, nil
}

// ---- GET /v1/findings --------------------------------------------------------

type listFindingsInput struct {
	State    string `query:"state" enum:"all,open,approved,rejected" default:"all" doc:"Mutually exclusive single selection. Defaults to all: the screen's open-only view says so by passing it, rather than the API applying a filter the caller cannot see."`
	Severity string `query:"severity" enum:"all,low,medium,high" default:"all" doc:"Mutually exclusive single selection."`
	Page     int    `query:"page" minimum:"1" default:"1" doc:"Clamped into range: a page past the end returns the last one."`
	PageSize int    `query:"pageSize" minimum:"1" maximum:"100" default:"20"`
}

type listFindingsOutput struct {
	Body contract.FindingsPage
}

func (s *Server) listFindings(ctx context.Context, in *listFindingsInput) (*listFindingsOutput, error) {
	page, err := queries.Findings(ctx, s.deps.DB, queries.FindingFilter{
		State:    findingState(in.State),
		Severity: findingSeverity(in.Severity),
		Page:     in.Page,
		PageSize: in.PageSize,
	})
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listFindingsOutput{Body: page}, nil
}

func findingState(state string) models.FindingState {
	switch state {
	case stateOpen:
		return models.FindingStateOpen
	case stateApproved:
		return models.FindingStateApproved
	case stateRejected:
		return models.FindingStateRejected
	default:
		return ""
	}
}

func findingSeverity(severity string) models.FindingSeverity {
	switch severity {
	case severityLow:
		return models.FindingSeverityLow
	case severityMedium:
		return models.FindingSeverityMedium
	case severityHigh:
		return models.FindingSeverityHigh
	default:
		return ""
	}
}

// ---- GET /v1/findings/{id} ---------------------------------------------------

type findingInput struct {
	ID string `path:"id" format:"uuid" doc:"The finding's identifier, as the findings list returns it."`
}

// findingID parses the path parameter.
//
// A malformed uuid is a 422 and not a 404, and the difference is worth keeping: a
// 404 would say "no such finding", which is a claim about the data, and this is a
// request that never named a finding at all. huma's `format:"uuid"` annotation
// documents the shape but does not validate it, so the parse is here.
func findingID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, huma.Error422UnprocessableEntity("the finding id is not a uuid")
	}
	return id, nil
}

type findingOutput struct {
	Body contract.FindingDetail
}

func (s *Server) getFinding(ctx context.Context, in *findingInput) (*findingOutput, error) {
	id, err := findingID(in.ID)
	if err != nil {
		return nil, err
	}
	detail, err := queries.Finding(ctx, s.deps.DB, id)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &findingOutput{Body: detail}, nil
}

// ---- POST /v1/findings/{id}/accept and .../reject ----------------------------

type acceptFindingInput struct {
	ID   string `path:"id" format:"uuid"`
	Body contract.FindingApproval
}

type rejectFindingInput struct {
	ID   string `path:"id" format:"uuid"`
	Body contract.FindingRejection
}

type decisionOutput struct {
	Body contract.FindingDecision
}

func (s *Server) acceptFinding(ctx context.Context, in *acceptFindingInput) (*decisionOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "accept a scanner finding", scannerDecisionRoles...); err != nil {
		return nil, err
	}
	id, err := findingID(in.ID)
	if err != nil {
		return nil, err
	}

	decision, err := commands.AcceptFinding(ctx, s.deps.DB, principal, commands.Decision{
		FindingID: id,
		Note:      in.Body.Note,
		Days:      in.Body.ExpiresInDays,
	})
	if err != nil {
		return nil, decisionFailure(ctx, err)
	}
	return &decisionOutput{Body: decision}, nil
}

func (s *Server) rejectFinding(ctx context.Context, in *rejectFindingInput) (*decisionOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "reject a scanner finding", scannerDecisionRoles...); err != nil {
		return nil, err
	}
	id, err := findingID(in.ID)
	if err != nil {
		return nil, err
	}

	decision, err := commands.RejectFinding(ctx, s.deps.DB, principal, commands.Decision{
		FindingID: id,
		Note:      in.Body.Note,
	})
	if err != nil {
		return nil, decisionFailure(ctx, err)
	}
	return &decisionOutput{Body: decision}, nil
}

// decisionFailure maps the two commands' refusals onto the wire.
//
// A rejected finding is a 409 and not a 422: the request is well formed and the
// caller is permitted; it is the resource's state that refuses, and it will refuse
// the same request for ever. That is the same reading registerPackage's
// immutability conflict already uses.
//
// commands.ErrNoReviewer falls to the default and becomes a 500 deliberately. A
// session that resolved but carries no identity row is a hub in a state no
// browser sign-in produces, so it is not the caller's mistake to report back.
func decisionFailure(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, commands.ErrFindingNotFound):
		return huma.Error404NotFound("no such finding")
	case errors.Is(err, commands.ErrFindingRejected):
		return huma.Error409Conflict("this finding was rejected, which is terminal")
	case errors.Is(err, commands.ErrDecisionIncomplete):
		return huma.Error422UnprocessableEntity(err.Error())
	default:
		return fail(logging.From(ctx), err)
	}
}
