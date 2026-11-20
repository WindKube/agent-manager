// Package pluginparts reads an Agent Plugins bundle into the components a
// client installs one by one: skills, MCP servers, and the Claude Code
// agents, commands and hooks that live in the com.anthropic.claude-code
// extension directory or namespace object. Reading is lenient below the
// manifest: a component file that does not parse is named in Problems.
package pluginparts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	ManifestFile        = "plugin.json"
	MCPConfigFile       = "mcp.json"
	SkillsDir           = "skills"
	SkillFile           = "SKILL.md"
	ClaudeCodeNamespace = "com.anthropic.claude-code"

	// PluginRootVar is only substituted by Claude Code inside an installed
	// plugin; a component naming it cannot work once decomposed.
	PluginRootVar = "CLAUDE_PLUGIN_ROOT"
)

// ErrNotPlugin marks a tree with no readable plugin.json at its root.
var ErrNotPlugin = errors.New("not an agent plugin")

// Kind is one installable component kind.
type Kind string

const (
	KindSkill     Kind = "skill"
	KindMCPServer Kind = "mcp-server"
	KindAgent     Kind = "agent"
	KindCommand   Kind = "command"
	KindHook      Kind = "hook"
)

// Transport is how a client reaches an MCP server.
type Transport string

const (
	TransportStdio Transport = "stdio"
	TransportHTTP  Transport = "http"
	TransportSSE   Transport = "sse"
)

// Plugin is every component of one plugin, each list sorted by name.
type Plugin struct {
	Name     string
	Skills   []Skill
	Servers  []Server
	Agents   []Prompt
	Commands []Prompt
	Hooks    []Hook
	Problems []string
}

// Skill is `skills/<Name>/` and every regular file under it.
type Skill struct {
	Name           string
	Dir            string
	Files          []string // Dir-relative, slash-separated, sorted
	UsesPluginRoot bool
}

// Server is one MCP server, normalised across the three shapes it may be declared in.
type Server struct {
	Name      string
	Source    string // file#/json-pointer
	Transport Transport
	Command   string
	Args      []string
	Env       map[string]string
	Cwd       string
	URL       string
	Headers   map[string]string

	UsesPluginRoot bool
}

// Prompt is an agent or command Markdown file, kept byte for byte.
type Prompt struct {
	Name        string
	Path        string
	Data        []byte
	Description string

	UsesPluginRoot bool
}

// HookEntry is one handler inside a hook group.
type HookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// Hook is one matcher group under one event, kept verbatim as Group.
type Hook struct {
	Event   string
	Matcher string
	Group   json.RawMessage
	Entries []HookEntry
	Source  string // file#/json-pointer of the group

	UsesPluginRoot bool
}

// Read decomposes the plugin rooted at fsys.
func Read(fsys fs.FS) (*Plugin, error) {
	raw, err := fs.ReadFile(fsys, ManifestFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotPlugin, err)
	}
	var manifest struct {
		Name       string                     `json:"name"`
		Extensions map[string]json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNotPlugin, ManifestFile, err)
	}

	r := &reader{fsys: fsys, out: &Plugin{Name: manifest.Name}, seen: map[string]bool{}}
	var ext claudeCodeObject
	if obj, ok := manifest.Extensions[ClaudeCodeNamespace]; ok {
		if json.Unmarshal(obj, &ext) != nil {
			r.problem(ManifestFile + ": extensions." + ClaudeCodeNamespace + " is not an object")
		}
	}

	if data, ok := r.read(MCPConfigFile); ok {
		r.serversFile(MCPConfigFile, data)
	}
	pointer := "/extensions/" + escapePointer(ClaudeCodeNamespace)
	r.hooksValue(ext.Hooks, ManifestFile, pointer+"/hooks")
	r.serversValue(ext.MCPServers, ManifestFile, pointer+"/mcpServers")
	if data, ok := r.read(ClaudeCodeNamespace + "/hooks/hooks.json"); ok {
		r.hooksFile(ClaudeCodeNamespace+"/hooks/hooks.json", data)
	}
	if data, ok := r.read(ClaudeCodeNamespace + "/.mcp.json"); ok {
		r.serversFile(ClaudeCodeNamespace+"/.mcp.json", data)
	}

	if err := r.skills(); err != nil {
		return nil, err
	}
	r.out.Agents = r.prompts(KindAgent, append([]string{"agents"}, pathList(ext.Agents)...))
	r.out.Commands = r.prompts(KindCommand, append([]string{"commands"}, pathList(ext.Commands)...))

	sortByName(r.out.Servers, func(s Server) string { return s.Name })
	sortByName(r.out.Agents, func(p Prompt) string { return p.Name })
	sortByName(r.out.Commands, func(p Prompt) string { return p.Name })
	slices.Sort(r.out.Problems)
	return r.out, nil
}

type claudeCodeObject struct {
	Hooks      json.RawMessage `json:"hooks"`
	MCPServers json.RawMessage `json:"mcpServers"`
	Agents     json.RawMessage `json:"agents"`
	Commands   json.RawMessage `json:"commands"`
}

type reader struct {
	fsys fs.FS
	out  *Plugin
	seen map[string]bool
}

func (r *reader) problem(msg string) { r.out.Problems = append(r.out.Problems, msg) }

func (r *reader) read(name string) ([]byte, bool) {
	data, err := fs.ReadFile(r.fsys, name)
	if err != nil {
		return nil, false
	}
	return data, true
}

// resolve maps a path declared in the Claude Code namespace onto the tree;
// one that escapes the namespace directory resolves to nothing.
func resolve(declared string) (string, bool) {
	declared = strings.TrimSpace(declared)
	declared = strings.TrimPrefix(declared, "${"+PluginRootVar+"}")
	clean := path.Clean("/" + strings.TrimPrefix(declared, "./"))
	if clean == "/" {
		return "", false
	}
	return ClaudeCodeNamespace + clean, true
}

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

func isObject(raw json.RawMessage) bool { return bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) }

func (r *reader) hooksValue(raw json.RawMessage, file, pointer string) {
	if len(raw) == 0 {
		return
	}
	if isObject(raw) {
		r.hookEvents(raw, file, pointer)
		return
	}
	for _, declared := range pathList(raw) {
		if target, ok := resolve(declared); ok {
			if data, found := r.read(target); found {
				r.hooksFile(target, data)
			}
		}
	}
}

func (r *reader) hooksFile(file string, data []byte) {
	if r.seen[file] {
		return
	}
	r.seen[file] = true
	var document map[string]json.RawMessage
	if json.Unmarshal(data, &document) != nil {
		r.problem(file + ": not a JSON object")
		return
	}
	if wrapped, ok := document["hooks"]; ok && isObject(wrapped) {
		r.hookEvents(wrapped, file, "/hooks")
		return
	}
	r.hookEventMap(document, file, "")
}

func (r *reader) hookEvents(raw json.RawMessage, file, pointer string) {
	var events map[string]json.RawMessage
	if json.Unmarshal(raw, &events) != nil {
		r.problem(file + "#" + pointer + ": hooks is not an object")
		return
	}
	r.hookEventMap(events, file, pointer)
}

func (r *reader) hookEventMap(events map[string]json.RawMessage, file, pointer string) {
	names := make([]string, 0, len(events))
	for name := range events {
		if name != "description" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, event := range names {
		var groups []json.RawMessage
		if json.Unmarshal(events[event], &groups) != nil {
			r.problem(fmt.Sprintf("%s#%s/%s: not an array of hook groups", file, pointer, escapePointer(event)))
			continue
		}
		for i, raw := range groups {
			source := fmt.Sprintf("%s#%s/%s/%d", file, pointer, escapePointer(event), i)
			var group struct {
				Matcher *string     `json:"matcher"`
				Hooks   []HookEntry `json:"hooks"`
			}
			if json.Unmarshal(raw, &group) != nil {
				r.problem(source + ": not a hook group")
				continue
			}
			h := Hook{Event: event, Group: compact(raw), Entries: group.Hooks, Source: source}
			if group.Matcher != nil {
				h.Matcher = *group.Matcher
			}
			h.UsesPluginRoot = bytes.Contains(raw, []byte(PluginRootVar))
			r.out.Hooks = append(r.out.Hooks, h)
		}
	}
}

func compact(raw json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	if json.Compact(&buf, raw) != nil {
		return raw
	}
	return buf.Bytes()
}

func (r *reader) serversValue(raw json.RawMessage, file, pointer string) {
	if len(raw) == 0 {
		return
	}
	if isObject(raw) {
		r.serverMap(raw, file, pointer)
		return
	}
	for _, declared := range pathList(raw) {
		if target, ok := resolve(declared); ok {
			if data, found := r.read(target); found {
				r.serversFile(target, data)
			}
		}
	}
}

func (r *reader) serversFile(file string, data []byte) {
	if r.seen[file] {
		return
	}
	r.seen[file] = true
	var document struct {
		MCPServers json.RawMessage `json:"mcpServers"`
	}
	if json.Unmarshal(data, &document) != nil {
		r.problem(file + ": not a JSON object")
		return
	}
	r.serverMap(document.MCPServers, file, "/mcpServers")
}

type serverDecl struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	Cwd     string            `json:"cwd"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

func (r *reader) serverMap(raw json.RawMessage, file, pointer string) {
	if len(raw) == 0 {
		return
	}
	var servers map[string]json.RawMessage
	if json.Unmarshal(raw, &servers) != nil {
		r.problem(file + "#" + pointer + ": mcpServers is not an object")
		return
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		source := file + "#" + pointer + "/" + escapePointer(name)
		var d serverDecl
		if json.Unmarshal(servers[name], &d) != nil {
			r.problem(source + ": not an MCP server object")
			continue
		}
		transport, ok := transportOf(d.Type, d.Command)
		if !ok {
			r.problem(fmt.Sprintf("%s: unknown MCP server type %q", source, d.Type))
			continue
		}
		if r.hasServer(name) {
			r.problem(fmt.Sprintf("%s: a server named %q is already declared; the first one is kept", source, name))
			continue
		}
		r.out.Servers = append(r.out.Servers, Server{
			Name: name, Source: source, Transport: transport,
			Command: d.Command, Args: d.Args, Env: d.Env, Cwd: d.Cwd, URL: d.URL, Headers: d.Headers,
			UsesPluginRoot: bytes.Contains(servers[name], []byte(PluginRootVar)),
		})
	}
}

func (r *reader) hasServer(name string) bool {
	return slices.ContainsFunc(r.out.Servers, func(s Server) bool { return s.Name == name })
}

// transportOf accepts both the Agent Plugins `type` values and Claude Code's.
func transportOf(declared, command string) (Transport, bool) {
	switch strings.ToLower(declared) {
	case "stdio":
		return TransportStdio, true
	case "streamable-http", "http":
		return TransportHTTP, true
	case "sse":
		return TransportSSE, true
	case "":
		if command != "" {
			return TransportStdio, true
		}
		return TransportHTTP, true
	default:
		return "", false
	}
}

func (r *reader) skills() error {
	entries, err := fs.ReadDir(r.fsys, SkillsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", SkillsDir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := path.Join(SkillsDir, entry.Name())
		if _, ok := r.read(path.Join(dir, SkillFile)); !ok {
			r.problem(dir + ": no " + SkillFile)
			continue
		}
		skill := Skill{Name: entry.Name(), Dir: dir}
		walkErr := fs.WalkDir(r.fsys, dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel := strings.TrimPrefix(p, dir+"/")
			skill.Files = append(skill.Files, rel)
			if data, ok := r.read(p); ok && bytes.Contains(data, []byte(PluginRootVar)) {
				skill.UsesPluginRoot = true
			}
			return nil
		})
		if walkErr != nil {
			return fmt.Errorf("read %s: %w", dir, walkErr)
		}
		slices.Sort(skill.Files)
		r.out.Skills = append(r.out.Skills, skill)
	}
	return nil
}

// prompts reads the Markdown files directly under each declared directory,
// or a declared Markdown file itself.
func (r *reader) prompts(kind Kind, declared []string) []Prompt {
	var out []Prompt
	for _, entry := range declared {
		target, ok := resolve(entry)
		if !ok {
			continue
		}
		var files []string
		if path.Ext(target) == ".md" {
			files = []string{target}
		} else if entries, err := fs.ReadDir(r.fsys, target); err == nil {
			for _, e := range entries {
				if e.Type().IsRegular() && path.Ext(e.Name()) == ".md" {
					files = append(files, path.Join(target, e.Name()))
				}
			}
		}
		for _, file := range files {
			if r.seen[file] {
				continue
			}
			data, found := r.read(file)
			if !found {
				continue
			}
			r.seen[file] = true
			p := Prompt{Name: strings.TrimSuffix(path.Base(file), ".md"), Path: file, Data: data}
			front, _, err := SplitFrontmatter(data)
			if err != nil {
				r.problem(file + ": " + err.Error())
			}
			if kind == KindAgent && front.Name != "" {
				p.Name = front.Name
			}
			p.Description = front.Description
			p.UsesPluginRoot = bytes.Contains(data, []byte(PluginRootVar))
			out = append(out, p)
		}
	}
	return out
}

// Frontmatter is the part of a prompt's YAML header this package reads.
type Frontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Model       string `yaml:"model"`
}

// SplitFrontmatter returns a Markdown file's parsed header and its body; a
// file with no `---` fence has an empty header and is all body.
func SplitFrontmatter(data []byte) (Frontmatter, []byte, error) {
	block, body, ok := cutFrontmatter(data)
	if !ok {
		return Frontmatter{}, data, nil
	}
	var front Frontmatter
	var loose map[string]any
	if err := yaml.Unmarshal(block, &loose); err != nil {
		return Frontmatter{}, body, fmt.Errorf("frontmatter is not YAML: %w", err)
	}
	front.Name, _ = loose["name"].(string)
	front.Description, _ = loose["description"].(string)
	front.Model, _ = loose["model"].(string)
	return front, body, nil
}

// cutFrontmatter splits `---\n<block>\n---\n<body>`; block excludes both fences.
func cutFrontmatter(data []byte) (block, body []byte, ok bool) {
	rest, found := bytes.CutPrefix(data, []byte("---\n"))
	if !found {
		if rest, found = bytes.CutPrefix(data, []byte("---\r\n")); !found {
			return nil, data, false
		}
	}
	if bytes.HasPrefix(rest, []byte("---\n")) {
		return nil, rest[len("---\n"):], true
	}
	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 {
		return nil, data, false
	}
	after := rest[end+len("\n---"):]
	switch {
	case len(after) == 0:
	case after[0] == '\n':
		after = after[1:]
	case bytes.HasPrefix(after, []byte("\r\n")):
		after = after[2:]
	default:
		return nil, data, false
	}
	return rest[:end+1], after, true
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func sortByName[T any](items []T, name func(T) string) {
	slices.SortStableFunc(items, func(a, b T) int { return strings.Compare(name(a), name(b)) })
}
