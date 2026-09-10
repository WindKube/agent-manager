package web

import (
	"errors"
	"time"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// loadScan fills the package detail screen's security section (the owner's
// "collapsible section, default hidden, showing the security scan result
// and approval and comment"): the latest visible version's scan, its
// findings and any reviewer decision.
//
// Read independently of everything loadFiles and the rest of packageDetail
// load, following the same precedent: a deployment can answer the rest of
// the page while this one read is unavailable, and the two must fail on
// their own terms.
func (s *Server) loadScan(c *gin.Context, detail *view.Package, namespace, name string) {
	if s.deps.PackageScan == nil {
		return
	}

	scan, err := s.deps.PackageScan.PackageScan(session(c), namespace, name)
	switch {
	case err == nil:
		detail.ScanDetail = packageScanScreen(scan, time.Now().UTC())
	case errors.Is(err, view.ErrNotFound):
		// The package existed a moment ago, for the read that rendered the
		// rest of this page — a race rather than a state this screen has
		// copy for, so it collapses into Unavailable like any other failed read.
		detail.ScanDetail.Unavailable = true
	default:
		logFrom(c).Error().Err(err).Msg("load package scan")
		detail.ScanDetail.Unavailable = true
	}
}

// packageScanScreen maps the hub's answer onto the screen's model. Every
// finding goes through findingDetail (scanner.go) unchanged: this section
// and the Scanner screen must render one finding one way.
func packageScanScreen(from hub.PackageScanDetail, now time.Time) view.PackageScan {
	if from.Rejected {
		return view.PackageScan{Rejected: true}
	}

	out := view.PackageScan{
		Scanned: from.Scanned,
		Scan: view.ScanMeta{
			PackVersion: from.Scan.PackVersion,
			Started:     view.Timestamp(from.Scan.StartedAt),
			Verdict:     view.Verdict(from.Scan.Verdict),
			TimedOut:    from.Scan.TimedOut,
		},
	}
	if from.Scan.FinishedAt != nil {
		out.Scan.Finished = view.Timestamp(*from.Scan.FinishedAt)
	}
	out.Verdict = out.Scan.Verdict

	for _, check := range from.Checks {
		out.Checks = append(out.Checks, view.Check{
			ID: check.ID, Engine: check.Engine, Label: check.Label,
			Result: view.CheckResult(check.Result), WarnCount: check.WarnCount,
		})
	}
	for i := range from.Findings {
		out.Findings = append(out.Findings, findingDetail(from.Findings[i], now))
	}
	return out
}
