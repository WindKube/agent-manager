package checks

// PromptInjection looks for instruction text written to redirect the agent
// that reads it rather than to inform it.
func PromptInjection() Check {
	return ruleCheck{
		id:    "prompt-injection",
		label: "Prompt injection patterns",
		explain: "Scans instruction files (`.md`, `.txt`, `.rst`) for language telling the " +
			"agent reading them to ignore, disregard, forget or override what it was told " +
			"before — a sentence with no legitimate use in a skill description, since " +
			"describing what a skill does never requires countermanding the operator.",
	}
}
