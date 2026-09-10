package checks

// SecretExfiltration looks for credential, key and token locations a package
// has no business reading.
func SecretExfiltration() Check {
	return ruleCheck{
		id:    "secret-exfiltration",
		label: "Secret exfiltration",
		explain: "Flags a script or instruction file naming a path that holds credentials — " +
			"an SSH private key, a cloud credential file, a `.netrc`, `.npmrc`, `.pgpass`, a " +
			"Docker or kube config, or a `.env` file. It matches the PATH, not the word: prose " +
			"telling a reader to keep a token in a password manager does not trip it.",
	}
}
