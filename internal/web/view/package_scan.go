package view

// PackageScan is the package detail screen's security section (the owner's
// "collapsible section... scan result and approval and comment"): what the
// latest visible version's scan found, and what a reviewer decided about
// each finding.
//
// It reuses the Scanner screen's own FindingDetail, ScanMeta and Check
// (scanner.go) rather than a second shape for the same rows: this section
// and the Scanner screen must not be able to disagree about what a finding is.
type PackageScan struct {
	// Scanned distinguishes a version scanned clean from one never scanned:
	// Capabilities.Scanned's own distinction (package.go), repeated here
	// because both states produce an empty Findings slice.
	Scanned bool
	// Rejected and Unavailable follow the Files panel's own split: a
	// rejected version is not a read failure, and neither is read as the
	// other's reason.
	Rejected    bool
	Unavailable bool

	Verdict  Verdict
	Scan     ScanMeta
	Checks   []Check
	Findings []FindingDetail
}

// Summary is the collapsed header's one line: enough to decide whether to
// expand it without paying a round trip to find out.
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
