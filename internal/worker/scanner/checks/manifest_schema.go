package checks

// ManifestSchema validates the root manifest against the published schema its
// own `$schema` names. It runs at scan time even though ingestion already
// validated the same bytes: the schemas this build holds may have moved since
// publication, and a version whose manifest no longer conforms is what a
// rescan is for. It reads the manifest out of the bundle, not `version.manifest`,
// because the bytes are the evidence and the row is a copy.
func ManifestSchema() Check {
	return ruleCheck{id: "manifest-schema", label: "Manifest schema"}
}
