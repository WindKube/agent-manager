package checks

// ManifestSchema validates the root manifest against the schema its own
// `$schema` names, read out of the bundle rather than `version.manifest`
// since the bytes are the evidence.
func ManifestSchema() Check {
	return ruleCheck{id: "manifest-schema", label: "Manifest schema"}
}
