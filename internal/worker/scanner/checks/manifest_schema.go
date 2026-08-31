package checks

// ManifestSchema validates the root manifest against the published schema its own
// `$schema` names (FR-004, FR-022).
//
// It runs at scan time even though the ingestion path already validated the same
// bytes, and the duplication is deliberate: the schemas this build holds may have
// moved since the version was published, and a version whose manifest no longer
// conforms is exactly what a rescan is for. It reads the manifest out of the
// BUNDLE rather than out of `version.manifest`, because the bytes are the
// evidence and the row is a copy.
func ManifestSchema() Check {
	return ruleCheck{id: "manifest-schema", label: "Manifest schema"}
}
