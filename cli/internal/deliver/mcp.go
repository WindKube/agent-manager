package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/record"
	"github.com/WindKube/agent-manager/cli/pluginparts"
)

// Reasons an MCP server is not configured for a target.
const (
	SkipNoClaudeCLI     = "the claude CLI is not on PATH; amctl adds MCP servers to Claude Code only through it"
	SkipSSEOnCodex      = "codex does not connect to SSE MCP servers"
	SkipEnvExpansion    = "uses ${VAR} expansion, which this agent's MCP config does not do"
	SkipWorkingDir      = "sets a working directory, which this agent's MCP config cannot express"
	SkipNameCollision   = "its entry name collides with another server of this plugin:"
	SkipOpenCodeV2Shape = "the opencode config lists MCP servers under mcp.servers, a shape amctl does not edit"
)

// ClaudeCLI runs `claude <args...>`; Deliverer.Claude is nil when there is no
// claude on PATH.
type ClaudeCLI func(ctx context.Context, args ...string) error

var openCodeConfigFiles = []string{"opencode.json", "opencode.jsonc"}

// mcpEntryName is the deterministic, sanitized name amctl gives a server's
// entry: `<plugin>-<server>`, keeping only letters, digits, '-' and '_'.
func mcpEntryName(plugin, server string) string {
	var b strings.Builder
	name := plugin + "-" + server
	for i := 0; i < len(name); i++ {
		if c := name[i]; bareKeyChar(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func (p *placer) mcpSlots() []slot {
	var out []slot
	seen := map[string]string{}
	for i := range p.plugin.Servers {
		s := &p.plugin.Servers[i]
		key := mcpEntryName(p.pkg.Name, s.Name)
		if reason := p.mcpSkip(s, key); reason != "" {
			p.skip(record.ComponentMCPServer, s.Name, reason)
			continue
		}
		if first, dup := seen[key]; dup {
			p.skip(record.ComponentMCPServer, s.Name, SkipNameCollision+" "+first)
			continue
		}
		seen[key] = s.Name
		sl, err := p.mcpSlot(s, key)
		if err != nil {
			p.skip(record.ComponentMCPServer, s.Name, err.Error())
			continue
		}
		if sl != nil {
			out = append(out, sl)
		}
	}
	return out
}

func (p *placer) mcpSkip(s *pluginparts.Server, key string) string {
	switch {
	case s.UsesPluginRoot:
		return SkipPluginRoot
	case key == "" || strings.Trim(key, "_") == "":
		return SkipUnusableName
	}
	switch p.change.Target {
	case record.TargetClaudeCode:
		if p.d.Claude == nil {
			return SkipNoClaudeCLI
		}
		if s.Cwd != "" {
			return SkipWorkingDir
		}
	case record.TargetCodex:
		if s.Transport == pluginparts.TransportSSE {
			return SkipSSEOnCodex
		}
		if expands(s) {
			return SkipEnvExpansion
		}
	case record.TargetOpenCode:
		if s.Cwd != "" {
			return SkipWorkingDir
		}
		if expands(s) {
			return SkipEnvExpansion
		}
	}
	return ""
}

func expands(s *pluginparts.Server) bool {
	vals := append([]string{s.Command, s.URL, s.Cwd}, s.Args...)
	for _, v := range s.Env {
		vals = append(vals, v)
	}
	for _, v := range s.Headers {
		vals = append(vals, v)
	}
	for _, v := range vals {
		if strings.Contains(v, "${") {
			return true
		}
	}
	return false
}

func (p *placer) mcpSlot(s *pluginparts.Server, key string) (slot, error) {
	comp := record.Component{Kind: record.ComponentMCPServer, Name: s.Name, Key: key}
	switch p.change.Target {
	case record.TargetClaudeCode:
		comp.Path = p.target.Components().MCPConfig
		sl := &claudeMCPSlot{d: p.d, comp: comp, entry: claudeEntry(s)}
		if err := sl.fingerprint(); err != nil {
			return nil, err
		}
		return sl, nil
	case record.TargetCodex:
		comp.Path = p.target.Components().MCPConfig
		sl := &codexMCPSlot{d: p.d, comp: comp, block: codexBlock(s, key)}
		if err := sl.fingerprint(); err != nil {
			return nil, err
		}
		return sl, nil
	case record.TargetOpenCode:
		path, err := p.d.openCodeConfig(p.target.Components().ConfigDir)
		if err != nil {
			return nil, err
		}
		comp.Path = path
		sl := &openCodeMCPSlot{d: p.d, comp: comp, entry: openCodeEntry(s)}
		if err := sl.fingerprint(); err != nil {
			return nil, err
		}
		return sl, nil
	}
	return nil, fmt.Errorf("internal: no MCP config for target %s", p.change.Target)
}

func (d *Deliverer) mcpSlotOf(target record.Target, c record.Component) (slot, error) {
	switch target {
	case record.TargetClaudeCode:
		return &claudeMCPSlot{d: d, comp: c}, nil
	case record.TargetCodex:
		return &codexMCPSlot{d: d, comp: c}, nil
	case record.TargetOpenCode:
		return &openCodeMCPSlot{d: d, comp: c}, nil
	}
	return nil, fmt.Errorf("internal: no MCP config for target %s", target)
}

// openCodeConfig picks the file amctl edits: opencode.json, else
// opencode.jsonc, else a new opencode.json.
func (d *Deliverer) openCodeConfig(dir string) (string, error) {
	for _, name := range openCodeConfigFiles {
		p := filepath.Join(dir, name)
		if _, err := d.contained(p); err != nil {
			return "", err
		}
		if _, err := os.Stat(p); err == nil {
			doc, rerr := d.readConfig(p)
			if rerr != nil {
				return "", rerr
			}
			if v, _ := jsoncGet(doc, "mcp", "servers"); v != nil {
				return "", errors.New(SkipOpenCodeV2Shape)
			}
			return p, nil
		}
	}
	return filepath.Join(dir, openCodeConfigFiles[0]), nil
}

func claudeEntry(s *pluginparts.Server) map[string]any {
	e := map[string]any{"type": string(s.Transport)}
	if s.Transport == pluginparts.TransportStdio {
		e["command"] = s.Command
		if len(s.Args) > 0 {
			e["args"] = s.Args
		}
		if len(s.Env) > 0 {
			e["env"] = s.Env
		}
		return e
	}
	e["url"] = s.URL
	if len(s.Headers) > 0 {
		e["headers"] = s.Headers
	}
	return e
}

func openCodeEntry(s *pluginparts.Server) map[string]any {
	if s.Transport == pluginparts.TransportStdio {
		e := map[string]any{"type": "local", "command": append([]string{s.Command}, s.Args...), "enabled": true}
		if len(s.Env) > 0 {
			e["environment"] = s.Env
		}
		return e
	}
	e := map[string]any{"type": "remote", "url": s.URL, "enabled": true}
	if len(s.Headers) > 0 {
		e["headers"] = s.Headers
	}
	return e
}

func codexBlock(s *pluginparts.Server, key string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s.%s]\n", codexServersTable, key)
	if s.Transport == pluginparts.TransportStdio {
		fmt.Fprintf(&b, "command = %s\n", tomlString(s.Command))
		if len(s.Args) > 0 {
			fmt.Fprintf(&b, "args = %s\n", tomlStringArray(s.Args))
		}
		if s.Cwd != "" {
			fmt.Fprintf(&b, "cwd = %s\n", tomlString(s.Cwd))
		}
		if len(s.Env) > 0 {
			fmt.Fprintf(&b, "env = %s\n", tomlInlineTable(s.Env))
		}
		return []byte(b.String())
	}
	fmt.Fprintf(&b, "url = %s\n", tomlString(s.URL))
	if len(s.Headers) > 0 {
		fmt.Fprintf(&b, "http_headers = %s\n", tomlInlineTable(s.Headers))
	}
	return []byte(b.String())
}

// claudeMCPSlot is a user-scope server in Claude Code's own config file,
// changed only through `claude mcp`: that file is Claude Code's live state.
type claudeMCPSlot struct {
	d     *Deliverer
	comp  record.Component
	entry map[string]any
}

func (s *claudeMCPSlot) ref() record.Component { return s.comp }

func (s *claudeMCPSlot) fingerprint() error {
	fp, err := canonical(roundTrip(s.entry))
	s.comp.SHA256 = fp
	return err
}

func (s *claudeMCPSlot) current(string) (string, error) {
	doc, err := s.d.readConfig(s.comp.Path)
	if err != nil || doc == nil {
		return "", err
	}
	var cfg struct {
		MCPServers map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return "", fmt.Errorf("read %s: %w", s.comp.Path, err)
	}
	v, ok := cfg.MCPServers[s.comp.Key]
	if !ok {
		return "", nil
	}
	return canonical(v)
}

func (s *claudeMCPSlot) cli() (ClaudeCLI, error) {
	if s.d.Claude == nil {
		return nil, errors.New("the claude CLI is not on PATH")
	}
	return s.d.Claude, nil
}

func (s *claudeMCPSlot) write(ctx context.Context, have string) (string, error) {
	run, err := s.cli()
	if err != nil {
		return "", err
	}
	if rerr := s.recheck(have); rerr != nil {
		return "", rerr
	}
	if have != "" {
		if rmErr := run(ctx, "mcp", "remove", s.comp.Key, "--scope", "user"); rmErr != nil {
			return "", rmErr
		}
	}
	b, err := marshalJSON(s.entry)
	if err != nil {
		return "", err
	}
	if addErr := run(ctx, "mcp", "add-json", s.comp.Key, string(b), "--scope", "user"); addErr != nil {
		return "", addErr
	}
	got, err := s.current("")
	if err != nil {
		return "", err
	}
	if got != s.comp.SHA256 && s.d.Log != nil {
		s.d.Log.Warnf("claude stored MCP server %s differently from what amctl gave it", s.comp.Key)
	}
	return got, nil
}

func (s *claudeMCPSlot) remove(ctx context.Context, have string) error {
	run, err := s.cli()
	if err != nil {
		return err
	}
	if err := s.recheck(have); err != nil {
		return err
	}
	return run(ctx, "mcp", "remove", s.comp.Key, "--scope", "user")
}

func (s *claudeMCPSlot) recheck(have string) error {
	now, err := s.current("")
	if err != nil {
		return err
	}
	if now != have {
		return fmt.Errorf("%s (%s) changed while amctl was syncing", s.comp.Path, s.comp.Key)
	}
	return nil
}

// codexMCPSlot is one [mcp_servers.<key>] table in $CODEX_HOME/config.toml.
type codexMCPSlot struct {
	d     *Deliverer
	comp  record.Component
	block []byte
}

func (s *codexMCPSlot) ref() record.Component { return s.comp }

func (s *codexMCPSlot) fingerprint() error {
	m, err := parseTOML(s.block)
	if err != nil {
		return fmt.Errorf("internal: %w", err)
	}
	s.comp.SHA256, err = canonical(tomlTable(m, s.comp.Key))
	return err
}

func (s *codexMCPSlot) current(string) (string, error) {
	_, fp, err := s.read()
	return fp, err
}

func (s *codexMCPSlot) read() (doc []byte, fp string, err error) {
	doc, err = s.d.readConfig(s.comp.Path)
	if err != nil || doc == nil {
		return doc, "", err
	}
	m, err := parseTOML(doc)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", s.comp.Path, err)
	}
	v := tomlTable(m, s.comp.Key)
	if v == nil {
		return doc, "", nil
	}
	fp, err = canonical(v)
	return doc, fp, err
}

func (s *codexMCPSlot) write(_ context.Context, have string) (string, error) {
	return s.edit(have, func(doc []byte) ([]byte, error) { return tomlSetTable(doc, s.comp.Key, s.block) })
}

func (s *codexMCPSlot) remove(_ context.Context, have string) error {
	_, err := s.edit(have, func(doc []byte) ([]byte, error) { return tomlRemoveTable(doc, s.comp.Key) })
	return err
}

func (s *codexMCPSlot) edit(have string, change func([]byte) ([]byte, error)) (string, error) {
	doc, now, err := s.read()
	if err != nil {
		return "", err
	}
	if now != have {
		return "", fmt.Errorf("%s (%s) changed while amctl was syncing", s.comp.Path, s.comp.Key)
	}
	out, err := change(doc)
	if err != nil {
		return "", fmt.Errorf("%s: %w", s.comp.Path, err)
	}
	if err := s.d.writeConfig(s.comp.Path, out); err != nil {
		return "", err
	}
	return s.current("")
}

// openCodeMCPSlot is one mcp.<key> member of opencode.json(c).
type openCodeMCPSlot struct {
	d     *Deliverer
	comp  record.Component
	entry map[string]any
}

func (s *openCodeMCPSlot) ref() record.Component { return s.comp }

func (s *openCodeMCPSlot) fingerprint() error {
	fp, err := canonical(roundTrip(s.entry))
	s.comp.SHA256 = fp
	return err
}

func (s *openCodeMCPSlot) current(string) (string, error) {
	_, fp, err := s.read()
	return fp, err
}

func (s *openCodeMCPSlot) read() (doc []byte, fp string, err error) {
	doc, err = s.d.readConfig(s.comp.Path)
	if err != nil || doc == nil {
		return doc, "", err
	}
	v, err := jsoncGet(doc, "mcp", s.comp.Key)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", s.comp.Path, err)
	}
	if v == nil {
		return doc, "", nil
	}
	fp, err = canonical(v)
	return doc, fp, err
}

func (s *openCodeMCPSlot) write(_ context.Context, have string) (string, error) {
	return s.edit(have, func(doc []byte) ([]byte, error) { return jsoncSet(doc, s.entry, "mcp", s.comp.Key) })
}

func (s *openCodeMCPSlot) remove(_ context.Context, have string) error {
	_, err := s.edit(have, func(doc []byte) ([]byte, error) { return jsoncRemove(doc, "mcp", s.comp.Key) })
	return err
}

func (s *openCodeMCPSlot) edit(have string, change func([]byte) ([]byte, error)) (string, error) {
	doc, now, err := s.read()
	if err != nil {
		return "", err
	}
	if now != have {
		return "", fmt.Errorf("%s (%s) changed while amctl was syncing", s.comp.Path, s.comp.Key)
	}
	out, err := change(doc)
	if err != nil {
		return "", fmt.Errorf("%s: %w", s.comp.Path, err)
	}
	if doc == nil && len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	if err := s.d.writeConfig(s.comp.Path, out); err != nil {
		return "", err
	}
	return s.current("")
}
