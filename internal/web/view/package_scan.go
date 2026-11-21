package view

// PackageScan is the package detail's security section. It reuses the Scanner screen's types so the two
// cannot disagree about what a finding is.
type PackageScan struct {
	// Scanned distinguishes a clean scan from no scan; both have empty Findings.
	Scanned bool
	// Rejected is not a read failure; Unavailable is.
	Rejected    bool
	Unavailable bool

	Verdict  Verdict
	Scan     ScanMeta
	Checks   []Check
	Findings []FindingDetail
}

// Summary is the collapsed header's one line.
func (s PackageScan) Summary() string {
	switch {
	case s.Rejected:
		return "rejected — not served"
	case s.Unavailable:
		return "could not be read"
	case !s.Scanned:
		return "not scanned yet"
	case len(s.Findings) == 0:
		return s.Verdict.Label()
	default:
		return s.Verdict.Label() + " · " + plural(len(s.Findings), "finding")
	}
}
