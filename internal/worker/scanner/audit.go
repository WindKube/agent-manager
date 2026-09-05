package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"agent-manager/internal/store/models"
	"agent-manager/internal/worker/scanner/checks"
)

// auditActor and auditSource are what a background role writes into the
// audit log: actor_kind `system` separates a role's action from a person's.
const (
	auditActor  = RoleName
	auditSource = "system"
)

// writeScanAudit inserts the one audit row a verdict is accountable for. It
// takes the transaction rather than a pool, so the record cannot survive a
// rolled back scan or go missing after a committed one.
func writeScanAudit(ctx context.Context, tx bun.IDB, text string) error {
	event := &models.AuditEvent{
		ID:        models.NewID(),
		Actor:     auditActor,
		ActorKind: models.ActorKindSystem,
		Kind:      models.AuditKindScan,
		Text:      text,
		Source:    auditSource,
	}
	// am_scanner holds INSERT-only on audit_event — no SELECT — and bun appends
	// RETURNING for OccurredAt's `default:` tag unless told not to.
	if _, err := tx.NewInsert().Model(event).Returning("NULL").Exec(ctx); err != nil {
		return fmt.Errorf("write the scan audit row: %w", err)
	}
	return nil
}

// scanText is the audit line: what was scanned, under which rules, and what
// came of it.
func scanText(job Job, packVersion string, result analysis, verdict models.Verdict) string {
	switch {
	case result.timedOut:
		return fmt.Sprintf("scan of %s timed out under rule pack %s; verdict unchanged", job, packVersion)
	case verdict == models.VerdictFlagged:
		return fmt.Sprintf("flagged %s — %s (rule pack %s)", job, strings.Join(ruleIDs(result.findings), ", "), packVersion)
	default:
		return fmt.Sprintf("cleared %s — %d checks, no findings (rule pack %s)", job, len(result.checks), packVersion)
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
