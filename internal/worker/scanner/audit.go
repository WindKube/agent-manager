package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker/scanner/checks"
)

const (
	auditActor  = RoleName
	auditSource = "system"
)

// writeScanAudit takes the transaction rather than a pool so the audit row
// commits or rolls back together with the verdict.
func writeScanAudit(ctx context.Context, tx bun.IDB, job Job, stamp string, result analysis, verdict models.Verdict) error {
	event, err := audit.New(audit.Entry{
		Kind:      models.AuditKindScan,
		Action:    "scanned",
		Actor:     auditActor,
		ActorKind: models.ActorKindSystem,
		Text:      scanText(job, stamp, result, verdict),
		Source:    auditSource,
		Subject:   audit.Version(job.Namespace, job.Name, job.Semver),
		Data: map[string]any{
			"verdict":   string(verdict),
			"analyzers": stamp,
			"ruleIds":   ruleIDs(result.findings),
			"timedOut":  result.timedOut,
		},
	})
	if err != nil {
		return err
	}
	// am_scanner holds INSERT-only on audit_event — no SELECT — and bun appends
	// RETURNING for OccurredAt's `default:` tag unless told not to.
	if _, err := tx.NewInsert().Model(event).Returning("NULL").Exec(ctx); err != nil {
		return fmt.Errorf("write the scan audit row: %w", err)
	}
	return nil
}

func scanText(job Job, stamp string, result analysis, verdict models.Verdict) string {
	switch {
	case result.timedOut:
		return fmt.Sprintf("scan of %s timed out under analyzers %s; verdict unchanged", job, stamp)
	case verdict == models.VerdictFlagged:
		return fmt.Sprintf("flagged %s — %s (analyzers %s)", job, strings.Join(ruleIDs(result.findings), ", "), stamp)
	default:
		return fmt.Sprintf("cleared %s — %d checks, no findings (analyzers %s)", job, len(result.checks), stamp)
	}
}

func ruleIDs(findings []checks.Finding) []string {
	seen := make(map[string]struct{}, len(findings))
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		if _, dup := seen[finding.RuleID]; dup {
			continue
		}
		seen[finding.RuleID] = struct{}{}
		out = append(out, finding.RuleID)
	}
	sort.Strings(out)
	return out
}
