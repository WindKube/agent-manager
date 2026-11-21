package api

import (
	"bufio"
	"context"
	"encoding/json"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

// AuditFilterInput is shared by the page and the export, so the export is
// always the page's full current scope.
type AuditFilterInput struct {
	SubjectKind string `query:"subjectKind" enum:"package,version,finding,profile,revision,category,mapping,policy,identity,device,service-token,machine,webhook" doc:"Only rows about this kind of subject. package also matches the rows about its versions and findings."`
	SubjectID   string `query:"subjectId" maxLength:"200" doc:"Only rows about this subject id; pair it with subjectKind."`
	Namespace   string `query:"namespace" maxLength:"200" doc:"Only rows whose subject is in this package namespace."`
}

// Resolve refuses a bare subjectId: no index serves it, and an id means
// nothing without its kind.
func (f *AuditFilterInput) Resolve(huma.Context) []error {
	if f.SubjectID != "" && f.SubjectKind == "" {
		return []error{&huma.ErrorDetail{Location: "query.subjectId", Message: "subjectId needs subjectKind", Value: f.SubjectID}}
	}
	return nil
}

func (f AuditFilterInput) filter() queries.AuditFilter {
	return queries.AuditFilter{SubjectKind: f.SubjectKind, SubjectID: f.SubjectID, Namespace: f.Namespace}
}

type listAuditInput struct {
	AuditFilterInput
	Page     int `query:"page" minimum:"1" default:"1" doc:"Clamped into range: a page past the end returns the last one."`
	PageSize int `query:"pageSize" minimum:"1" maximum:"200" default:"50"`
}

type listAuditOutput struct {
	Body contract.AuditPage
}

func (s *Server) listAudit(ctx context.Context, in *listAuditInput) (*listAuditOutput, error) {
	page, err := queries.Audit(ctx, s.deps.DB, in.filter(), in.Page, in.PageSize)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listAuditOutput{Body: page}, nil
}

// auditExportMediaType is NDJSON rather than CSV: row text quotes publisher-chosen
// names, so CSV would expose spreadsheet formula injection, and each line being a
// complete document lets consumers process the export as it streams.
const auditExportMediaType = "application/x-ndjson"

// exportAudit streams the whole log rather than holding it in memory. Headers are
// sent before the first row, so a mid-stream failure cannot change the status; the
// final line is a completeness sentinel and its absence marks a truncated export.
func (s *Server) exportAudit(ctx context.Context, in *AuditFilterInput) (*huma.StreamResponse, error) {
	filter := in.filter()
	log := logging.From(ctx)

	return &huma.StreamResponse{Body: func(hctx huma.Context) {
		hctx.SetHeader("Content-Type", auditExportMediaType)
		hctx.SetHeader("Content-Disposition", `attachment; filename="audit-log.ndjson"`)

		out := bufio.NewWriterSize(hctx.BodyWriter(), 32*1024)
		encoder := json.NewEncoder(out)

		written, err := queries.AuditExport(hctx.Context(), s.deps.DB, filter, func(entry contract.AuditEntry) error {
			return encoder.Encode(entry)
		})
		if err != nil {
			// No trailer: its absence signals truncation, and the rows already written are still flushed.
			_ = out.Flush()
			log.Error().Err(err).Int("rows", written).Msg("audit export truncated")
			return
		}

		if err := encoder.Encode(contract.AuditExportTrailer{Complete: true, Rows: written}); err != nil {
			log.Error().Err(err).Int("rows", written).Msg("audit export trailer could not be written")
		}
		if err := out.Flush(); err != nil {
			log.Error().Err(err).Int("rows", written).Msg("audit export could not be flushed")
		}
	}}, nil
}

// auditExportResponse is declared by hand because a StreamResponse has no body type
// for huma to infer from. The body is a sequence of documents, which a single
// response schema cannot describe, so the row and trailer shapes are stated in prose.
func auditExportResponse() *huma.Response {
	return &huma.Response{
		Description: "The whole audit log, newline-delimited JSON, one row per line, most recent " +
			"first. The final line is a completeness sentinel: a stream that ends without it was " +
			"truncated and the export is incomplete.",
		Headers: map[string]*huma.Param{
			"Content-Disposition": {
				Description: "Names the download.",
				Schema:      &huma.Schema{Type: huma.TypeString},
			},
		},
		Content: map[string]*huma.MediaType{
			auditExportMediaType: {Schema: &huma.Schema{Type: huma.TypeString, Format: "binary"}},
		},
	}
}
