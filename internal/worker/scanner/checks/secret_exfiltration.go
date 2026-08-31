package checks

// SecretExfiltration looks for the credential, key and token locations a package
// has no business reading (FR-022).
//
// It is separate from the filesystem scope check even though both judge paths,
// because the two answer different questions for a reviewer: "this writes outside
// its own directory" is a scope decision, and "this reads ~/.aws/credentials" is
// not a scope decision at all. Merging them would put one severity and one piece
// of prose on both.
func SecretExfiltration() Check {
	return ruleCheck{id: "secret-exfiltration", label: "Secret exfiltration"}
}
