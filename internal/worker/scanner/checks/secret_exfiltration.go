package checks

// SecretExfiltration looks for the credential, key and token locations a
// package has no business reading. It is separate from the filesystem scope
// check even though both judge paths: "writes outside its own directory" is a
// scope decision, and "reads ~/.aws/credentials" is not a scope decision at
// all.
func SecretExfiltration() Check {
	return ruleCheck{id: "secret-exfiltration", label: "Secret exfiltration"}
}
