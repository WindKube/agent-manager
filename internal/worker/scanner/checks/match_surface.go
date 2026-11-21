package checks

import (
	"encoding/json"
	"strings"

	"agent-manager/internal/domain/capability"
	"agent-manager/internal/worker/scanner/rules"
)

// matchSurface is the `plugin-surface` matcher over hooks, MCP servers and tool
// grants, each located at its `file#/pointer`.
func matchSurface(b *Bundle, rule rules.Rule) []hit {
	if b.Surfaces == nil {
		return nil
	}
	var hits []hit
	add := func(location string, line int, quote, value string) {
		if !rule.Match.InScope(location) || !judge(b, rule, value) {
			return
		}
		hits = append(hits, hit{path: location, line: line, quote: quote, value: value})
	}

	switch rule.Match.Extract {
	case rules.ExtractURLArgument:
		for i := range b.Surfaces.Servers {
			server := &b.Surfaces.Servers[i]
			if server.URL == "" {
				continue
			}
			add(server.Location(), 0, server.Name+": "+server.URL, server.Host())
		}

	case rules.ExtractHookTrigger:
		for _, hook := range b.Surfaces.Hooks {
			quote := hook.Event + " matcher=" + hook.Matcher
			if hook.Command != "" {
				quote += ": " + hook.Command
			}
			add(hook.Location(), 0, quote, hook.Event+":"+strings.TrimSpace(hook.Matcher))
		}

	case rules.ExtractGrantedTool:
		for _, prompt := range b.Surfaces.Prompts {
			for _, tool := range prompt.Tools {
				add(prompt.Path, lineOf(b, prompt.Path, tool), lineTextOf(b, prompt.Path, tool), tool)
			}
		}

	default:
		// Unreachable: rules.Load refuses any other extract under this kind.
	}
	return hits
}

// declaredHosts returns the manifest's homepage and repository hosts, including subdomains.
func (b *Bundle) declaredHosts() []string {
	if len(b.Manifest) == 0 {
		return nil
	}
	var manifest struct {
		Homepage   string          `json:"homepage"`
		Repository json.RawMessage `json:"repository"`
	}
	if json.Unmarshal(b.Manifest, &manifest) != nil {
		return nil
	}
	urls := []string{manifest.Homepage}
	var repository string
	var repositoryObject struct {
		URL string `json:"url"`
	}
	switch {
	case json.Unmarshal(manifest.Repository, &repository) == nil:
		urls = append(urls, repository)
	case json.Unmarshal(manifest.Repository, &repositoryObject) == nil:
		urls = append(urls, repositoryObject.URL)
	}

	var out []string
	for _, raw := range urls {
		host := capability.HostOf(strings.TrimSpace(raw))
		if host == "" || capability.Indefinite(host) {
			continue
		}
		host = strings.ToLower(host)
		out = append(out, host, "."+host)
	}
	return out
}
