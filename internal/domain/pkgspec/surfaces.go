package pkgspec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"agent-manager/internal/bundle"
)

// Claude Code's plugin surfaces — hooks, agents, commands and its own
// `.mcp.json` — have no place in the closed Agent Plugins layout, so they are
// read from the client-extension directory and from the namespace object of
// the same name in plugin.json, the only conformant homes for them. Parsing is
// lenient: a malformed file is reported in Unreadable, never an ingestion
// failure, because the spec assigns these files no semantics.

// ClaudeCodeNamespace is the client-extension namespace Claude Code reads.
const ClaudeCodeNamespace = "com.anthropic.claude-code"

// Hook is one hook entry: what runs, and on which event and tool matcher.
type Hook struct {
	Event   string
	Matcher string
	Type    string
	Command string
	// File and Pointer locate the hook entry; Location joins them.
	File    string
	Pointer string
}

func (h Hook) Location() string { return h.File + "#" + h.Pointer }

// Server is one MCP server from any of the three places one can be declared.
type Server struct {
	Name      string
	Type      string
	Transport string
	Command   string
	Args      []string
	URL       string
	File      string
	Pointer   string
}

func (s Server) Location() string { return s.File + "#" + s.Pointer }

// CommandLine is the stdio command and its arguments as one shell line.
func (s Server) CommandLine() string {
	if s.Command == "" {
		return ""
	}
	words := make([]string, 0, 1+len(s.Args))
	words = append(words, shellQuote(s.Command))
	for _, arg := range s.Args {
		words = append(words, shellQuote(arg))
	}
	return strings.Join(words, " ")
}

// Host is the remote server's URL host, empty for stdio or an unreadable URL.
func (s Server) Host() string {
	if s.URL == "" {
		return ""
	}
	parsed, err := url.Parse(s.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// Prompt is a skill, agent or command file and the tools its frontmatter
// pre-approves.
type Prompt struct {
	Kind        ComponentKind
	Name        string
	Path        string
	Description string
	Tools       []string
}

// Surfaces is everything in a package tree that a client executes or loads
// beyond its skills' bodies.
type Surfaces struct {
	Hooks   []Hook
	Servers []Server
	Prompts []Prompt
	// Unreadable names files that should declare surfaces but did not parse.
	Unreadable []string
}

// MCP transports, as components report them.
const (
	TransportStdio = "stdio"
	TransportHTTP  = "http"
	TransportSSE   = "sse"
)

// ReadSurfaces reads a filtered package tree's surfaces.
func ReadSurfaces(files *bundle.Bundle) *Surfaces {
	out := &Surfaces{}
	if files == nil {
		return out
	}
	r := surfaceReader{files: files, out: out, seen: map[string]struct{}{}}

	if file, ok := files.Lookup(MCPConfigFile); ok {
		r.serversFile(file)
	}

	ext := claudeCodeExtension(files)
	if ext != nil {
		pointer := "/extensions/" + escapePointer(ClaudeCodeNamespace)
		r.hooksValue(ext.Hooks, PluginManifest, pointer+"/hooks")
		r.serversValue(ext.MCPServers, PluginManifest, pointer+"/mcpServers")
	}
	if file, ok := files.Lookup(ClaudeCodeNamespace + "/hooks/hooks.json"); ok {
		r.hooksFile(file)
	}
	if file, ok := files.Lookup(ClaudeCodeNamespace + "/.mcp.json"); ok {
		r.serversFile(file)
	}

	r.skills()
	agentDirs, commandDirs := []string{"agents"}, []string{"commands"}
	if ext != nil {
		agentDirs = append(agentDirs, pathList(ext.Agents)...)
		commandDirs = append(commandDirs, pathList(ext.Commands)...)
	}
	r.prompts(ComponentAgent, agentDirs)
	r.prompts(ComponentCommand, commandDirs)

	sort.Strings(out.Unreadable)
	return out
}

type claudeCodeObject struct {
	Hooks      json.RawMessage `json:"hooks"`
	MCPServers json.RawMessage `json:"mcpServers"`
	Agents     json.RawMessage `json:"agents"`
	Commands   json.RawMessage `json:"commands"`
}

func claudeCodeExtension(files *bundle.Bundle) *claudeCodeObject {
	manifest, ok := files.Lookup(PluginManifest)
	if !ok {
		return nil
	}
	var probe struct {
		Extensions map[string]claudeCodeObject `json:"extensions"`
	}
	if json.Unmarshal(manifest.Data, &probe) != nil {
		return nil
	}
	ext, ok := probe.Extensions[ClaudeCodeNamespace]
	if !ok {
		return nil
	}
	return &ext
}

type surfaceReader struct {
	files *bundle.Bundle
	out   *Surfaces
	seen  map[string]struct{}
}

func (r *surfaceReader) unreadable(filePath string) {
	if _, dup := r.seen["!"+filePath]; dup {
		return
	}
	r.seen["!"+filePath] = struct{}{}
	r.out.Unreadable = append(r.out.Unreadable, filePath)
}

// resolve turns a path declared in the Claude Code namespace into a tree
// path; one that escapes the namespace directory resolves to nothing.
func resolve(declared string) (string, bool) {
	declared = strings.TrimPrefix(strings.TrimSpace(declared), "${CLAUDE_PLUGIN_ROOT}")
	clean := path.Clean("/" + strings.TrimPrefix(declared, "./"))
	if clean == "/" {
		return "", false
	}
	return ClaudeCodeNamespace + clean, true
}

// pathList reads a manifest value that is one path or a list of them.
func pathList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

// hooksValue is plugin.json's `hooks`: an inline object, or paths to files.
func (r *surfaceReader) hooksValue(raw json.RawMessage, filePath, pointer string) {
	if len(raw) == 0 {
		return
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		r.hookEvents(raw, filePath, pointer)
		return
	}
	for _, declared := range pathList(raw) {
		target, ok := resolve(declared)
		if !ok {
			continue
		}
		if file, found := r.files.Lookup(target); found {
			r.hooksFile(file)
		}
	}
}

func (r *surfaceReader) hooksFile(file bundle.File) {
	if _, dup := r.seen[file.Path]; dup {
		return
	}
	r.seen[file.Path] = struct{}{}

	var document map[string]json.RawMessage
	if json.Unmarshal(file.Data, &document) != nil {
		r.unreadable(file.Path)
		return
	}
	// Claude Code wraps the event map in `hooks`; a bare event map is read too.
	if wrapped, ok := document["hooks"]; ok && bytes.HasPrefix(bytes.TrimSpace(wrapped), []byte("{")) {
		r.hookEvents(wrapped, file.Path, "/hooks")
		return
	}
	r.hookEventMap(document, file.Path, "")
}

func (r *surfaceReader) hookEvents(raw json.RawMessage, filePath, pointer string) {
	var events map[string]json.RawMessage
	if json.Unmarshal(raw, &events) != nil {
		r.unreadable(filePath)
		return
	}
	r.hookEventMap(events, filePath, pointer)
}

type hookGroup struct {
	Matcher *string `json:"matcher"`
	Hooks   []struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	} `json:"hooks"`
}

func (r *surfaceReader) hookEventMap(events map[string]json.RawMessage, filePath, pointer string) {
	names := make([]string, 0, len(events))
	for name := range events {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, event := range names {
		if event == "description" {
			continue
		}
		var groups []hookGroup
		if json.Unmarshal(events[event], &groups) != nil {
			r.unreadable(filePath)
			continue
		}
		for i, group := range groups {
			matcher := ""
			if group.Matcher != nil {
				matcher = *group.Matcher
			}
			for j, hook := range group.Hooks {
				r.out.Hooks = append(r.out.Hooks, Hook{
					Event:   event,
					Matcher: matcher,
					Type:    hook.Type,
					Command: hook.Command,
					File:    filePath,
					Pointer: fmt.Sprintf("%s/%s/%d/hooks/%d", pointer, escapePointer(event), i, j),
				})
			}
		}
	}
}

// serversValue is plugin.json's `mcpServers`: an inline map, or paths.
func (r *surfaceReader) serversValue(raw json.RawMessage, filePath, pointer string) {
	if len(raw) == 0 {
		return
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		r.serverMap(raw, filePath, pointer)
		return
	}
	for _, declared := range pathList(raw) {
		target, ok := resolve(declared)
		if !ok {
			continue
		}
		if file, found := r.files.Lookup(target); found {
			r.serversFile(file)
		}
	}
}

func (r *surfaceReader) serversFile(file bundle.File) {
	if _, dup := r.seen[file.Path]; dup {
		return
	}
	r.seen[file.Path] = struct{}{}

	var document struct {
		MCPServers json.RawMessage `json:"mcpServers"`
	}
	if json.Unmarshal(file.Data, &document) != nil {
		r.unreadable(file.Path)
		return
	}
	r.serverMap(document.MCPServers, file.Path, "/mcpServers")
}

func (r *surfaceReader) serverMap(raw json.RawMessage, filePath, pointer string) {
	if len(raw) == 0 {
		return
	}
	var servers map[string]struct {
		Type    string   `json:"type"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
		URL     string   `json:"url"`
	}
	if json.Unmarshal(raw, &servers) != nil {
		r.unreadable(filePath)
		return
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		server := servers[name]
		r.out.Servers = append(r.out.Servers, Server{
			Name:      name,
			Type:      server.Type,
			Transport: transportOf(server.Type, server.Command),
			Command:   server.Command,
			Args:      server.Args,
			URL:       server.URL,
			File:      filePath,
			Pointer:   pointer + "/" + escapePointer(name),
		})
	}
}

func transportOf(declared, command string) string {
	switch strings.ToLower(declared) {
	case MCPTypeStdio:
		return TransportStdio
	case MCPTypeStreamableHTTP, "http":
		return TransportHTTP
	case MCPTypeSSE:
		return TransportSSE
	case "":
		if command != "" {
			return TransportStdio
		}
		return TransportHTTP
	default:
		return ""
	}
}

func (r *surfaceReader) skills() {
	for _, filePath := range r.files.Paths() {
		segments := splitPath(filePath)
		isSkill := filePath == SkillManifest ||
			(len(segments) == 3 && segments[0] == SkillsDir && segments[2] == SkillManifest)
		if !isSkill {
			continue
		}
		front, ok := r.frontmatter(filePath)
		if !ok {
			continue
		}
		r.out.Prompts = append(r.out.Prompts, Prompt{
			Kind: ComponentSkill, Name: front.Name, Path: filePath,
			Description: front.Description, Tools: front.tools(),
		})
	}
}

// prompts reads the Markdown files directly under each declared directory,
// or a declared Markdown file itself.
func (r *surfaceReader) prompts(kind ComponentKind, declared []string) {
	for _, entry := range declared {
		target, ok := resolve(entry)
		if !ok {
			continue
		}
		for _, filePath := range r.files.Paths() {
			if path.Ext(filePath) != ".md" {
				continue
			}
			if filePath != target && path.Dir(filePath) != target {
				continue
			}
			if _, dup := r.seen[filePath]; dup {
				continue
			}
			r.seen[filePath] = struct{}{}

			name := strings.TrimSuffix(path.Base(filePath), ".md")
			front, _ := r.frontmatter(filePath)
			if kind == ComponentAgent && front.Name != "" {
				name = front.Name
			}
			r.out.Prompts = append(r.out.Prompts, Prompt{
				Kind: kind, Name: name, Path: filePath,
				Description: front.Description, Tools: front.tools(),
			})
		}
	}
}

type promptFrontmatter struct {
	Name         string `yaml:"name"`
	Description  string `yaml:"description"`
	Tools        any    `yaml:"tools"`
	AllowedTools any    `yaml:"allowed-tools"`
}

func (f promptFrontmatter) tools() []string {
	return append(toolList(f.AllowedTools), toolList(f.Tools)...)
}

// frontmatter reads a Markdown file's frontmatter leniently. A file with no
// frontmatter has none to read and is not unreadable.
func (r *surfaceReader) frontmatter(filePath string) (promptFrontmatter, bool) {
	var out promptFrontmatter
	file, ok := r.files.Lookup(filePath)
	if !ok {
		return out, false
	}
	block, err := splitFrontmatter(file.Data)
	if err != nil {
		return out, false
	}
	if yaml.Unmarshal(block, &out) != nil {
		r.unreadable(filePath)
		return promptFrontmatter{}, false
	}
	return out, true
}

// toolList reads a tool grant written as a YAML list or as one string,
// comma- or space-separated, without splitting inside `Bash(git status:*)`.
func toolList(value any) []string {
	switch typed := value.(type) {
	case string:
		return splitTools(typed)
	case []any:
		var out []string
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, splitTools(text)...)
			}
		}
		return out
	default:
		return nil
	}
}

func splitTools(text string) []string {
	var out []string
	var current strings.Builder
	depth := 0
	flush := func() {
		if token := strings.TrimSpace(current.String()); token != "" {
			out = append(out, token)
		}
		current.Reset()
	}
	for _, r := range text {
		switch {
		case r == '(':
			depth++
		case r == ')' && depth > 0:
			depth--
		case depth == 0 && (r == ',' || r == ' ' || r == '\t' || r == '\n'):
			flush()
			continue
		}
		current.WriteRune(r)
	}
	flush()
	return out
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func shellQuote(word string) string {
	if shellSafe.MatchString(word) {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}
