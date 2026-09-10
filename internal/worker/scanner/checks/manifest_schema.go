package checks

// ManifestSchema validates the root manifest against its own declared schema.
func ManifestSchema() Check {
	return ruleCheck{
		id:    "manifest-schema",
		label: "Manifest schema",
		explain: "Validates the package's root manifest against the schema its own `$schema` " +
			"names, read out of the bundle rather than the catalog's stored copy. Every other " +
			"check reads the package kind, the expected capability set and the component list " +
			"off this document, so a manifest the validator rejects means those readings are " +
			"not to be trusted either.",
	}
}
