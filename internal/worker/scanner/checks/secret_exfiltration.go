package checks

// SecretExfiltration looks for credential, key and token locations a package
// has no business reading — distinct from filesystem scope's "outside its
// own directory".
func SecretExfiltration() Check {
	return ruleCheck{id: "secret-exfiltration", label: "Secret exfiltration"}
}
