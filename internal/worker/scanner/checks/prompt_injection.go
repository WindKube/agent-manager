package checks

// PromptInjection looks for instruction text written to redirect the agent
// that reads it rather than to inform it.
func PromptInjection() Check {
	return ruleCheck{id: "prompt-injection", label: "Prompt injection patterns"}
}
