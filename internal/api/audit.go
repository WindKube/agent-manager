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

// The audit log's operations (US4, T067-T068, 001 FR-050..FR-052).

// ---- GET /v1/audit -----------------------------------------------------------

type listAuditInput struct {
	Page     int `query:"page" minimum:"1" default:"1" doc:"Clamped into range: a page past the end returns the last one."`
	PageSize int `query:"pageSize" minimum:"1" maximum:"200" default:"50"`
}

type listAuditOutput struct {
	Body contract.AuditPage
}

func (s *Server) listAudit(ctx context.Context, in *listAuditInput) (*listAuditOutput, error) {
	page, err := queries.Audit(ctx, s.deps.DB, in.Page, in.PageSize)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listAuditOutput{Body: page}, nil
}

// ---- GET /v1/audit/export ----------------------------------------------------

// auditExportMediaType is newline-delimited JSON, one audit row per line.
//
// NDJSON and not CSV, and the reason is not taste. An audit row's `text` quotes
// package, profile and host names that a publisher chose, so a cell beginning `=`
// or `+` is reachable by anyone who can register a package — and a spreadsheet
// evaluates that on open. Escaping formula injection correctly in CSV means
// prefixing such cells, which then corrupts the value for every non-spreadsheet
// consumer. JSON has no evaluated syntax, and it is already the shape every other
// operation here answers in.
//
// It is also what makes streaming honest: each line is a complete document, so a
// consumer can process the export as it arrives rather than after it lands.
const auditExportMediaType = "application/x-ndjson"

// exportAudit streams the whole log (FR-051).
//
// A huma.StreamResponse rather than a body huma marshals, and that is the point
// of the task: a `[]contract.AuditEntry` on this one operation would hold the
// entire audit log — the one table designed to grow without bound — in the api's
// heap before the first byte left. Nothing here accumulates: the query hands over
// one row at a time, the encoder writes it, and the buffered writer is flushed as
// it fills.
//
// The cost is that this response cannot fail. The status line and headers are
// written before the first row is read, so a statement that dies halfway through
// leaves a 200 that simply stops — there is no status code left to change. That is
// why the last line is a completeness sentinel: every other line is a valid JSON
// object, so truncation is otherwise invisible, and a consumer that reaches
// end-of-stream without the trailer has an incomplete export. The failure is also
// logged with the request's correlation id, which is what joins the operator's
// truncated file to the cause.
func (s *Server) exportAudit(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	log := logging.From(ctx)

	return &huma.StreamResponse{Body: func(hctx huma.Context) {
		hctx.SetHeader("Content-Type", auditExportMediaType)
		// Named so a browser's download lands as a file rather than as a page of
		// text. No timestamp in the name: it would be the api container's clock, and
		// an operator's file manager already stamps what it saved.
		hctx.SetHeader("Content-Disposition", `attachment; filename="audit-log.ndjson"`)

		// A buffer, not a write per row: an audit row is a couple of hundred bytes
		// and one syscall each would dominate the export. It is NOT accumulation —
		// bufio flushes when full, so the memory held is one buffer whatever the
		// log's size.
		out := bufio.NewWriterSize(hctx.BodyWriter(), 32*1024)
		encoder := json.NewEncoder(out)

		written, err := queries.AuditExport(hctx.Context(), s.deps.DB, func(entry contract.AuditEntry) error {
			return encoder.Encode(entry)
		})
		if err != nil {
			// No trailer. Its absence is the signal, and the flush below still sends
			// the rows that did come out — a partial export an operator knows is
			// partial is more use than none.
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

// auditExportResponse documents the stream. It is declared by hand because huma
// infers a response schema from the handler's body type and a StreamResponse has
// none — an undeclared 200 would leave a generated client with no typed field for
// it at all.
//
// The body's schema is `string`/`binary` and not a row type, because the body is a
// SEQUENCE of documents and an OpenAPI response schema describes one. Each line is
// a contract.AuditEntry except the last, which is a contract.AuditExportTrailer,
// and that is stated in prose because it cannot be stated in the schema: huma
// PRUNES unreferenced component schemas when it marshals the document (see
// OpenAPI.MarshalJSON), so registering the trailer beside this response does not
// emit it, and the only way to reference it here would be a `oneOf` claiming the
// body is one of the two — which it is not. Measured, not assumed.
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
