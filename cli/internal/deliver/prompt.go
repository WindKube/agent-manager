package deliver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/record"
	"github.com/WindKube/agent-manager/cli/pluginparts"
)

// Reasons an agent or command file is not placed for a target.
const (
	SkipCodexCommands     = "codex has no command files (its custom prompts are deprecated)"
	SkipPositionalArgs    = "uses positional arguments ($1, $ARGUMENTS[0]), which only Claude Code expands"
	SkipModelAlias        = "names a Claude model alias, which this agent cannot resolve"
	SkipNoFrontmatter     = "its frontmatter is unreadable"
	SkipCodexNoDescriptor = "has no description, which a codex agent requires"
)

var positionalArg = regexp.MustCompile(`\$\d|\$ARGUMENTS\[`)

func (p *placer) agentSlots() []slot {
	var out []slot
	for i := range p.plugin.Agents {
		a := &p.plugin.Agents[i]
		if a.UsesPluginRoot {
			p.skip(record.ComponentAgent, a.Name, SkipPluginRoot)
			continue
		}
		front, body, err := pluginparts.SplitFrontmatter(a.Data)
		if err != nil {
			p.skip(record.ComponentAgent, a.Name, SkipNoFrontmatter+": "+err.Error())
			continue
		}
		var file string
		var data []byte
		switch p.change.Target {
		case record.TargetClaudeCode:
			file, data = a.Name+".md", a.Data
		case record.TargetOpenCode:
			file = a.Name + ".md"
			data, err = openCodeAgent(front, body)
		case record.TargetCodex:
			if strings.TrimSpace(front.Description) == "" {
				p.skip(record.ComponentAgent, a.Name, SkipCodexNoDescriptor)
				continue
			}
			file, data = a.Name+".toml", codexAgent(a.Name, front.Description, body)
		}
		if err != nil {
			p.skip(record.ComponentAgent, a.Name, err.Error())
			continue
		}
		if sl := p.fileSlot(record.ComponentAgent, a.Name, p.target.Components().Agents, file, data); sl != nil {
			out = append(out, sl)
		}
	}
	return out
}

func (p *placer) commandSlots() []slot {
	var out []slot
	for i := range p.plugin.Commands {
		c := &p.plugin.Commands[i]
		switch {
		case c.UsesPluginRoot:
			p.skip(record.ComponentCommand, c.Name, SkipPluginRoot)
			continue
		case p.target.Components().Commands == "":
			p.skip(record.ComponentCommand, c.Name, SkipCodexCommands)
			continue
		}
		if p.change.Target != record.TargetClaudeCode {
			front, body, err := pluginparts.SplitFrontmatter(c.Data)
			switch {
			case err != nil:
				p.skip(record.ComponentCommand, c.Name, SkipNoFrontmatter+": "+err.Error())
				continue
			case positionalArg.Match(body):
				p.skip(record.ComponentCommand, c.Name, SkipPositionalArgs)
				continue
			case front.Model != "" && !strings.Contains(front.Model, "/"):
				p.skip(record.ComponentCommand, c.Name, SkipModelAlias)
				continue
			}
		}
		if sl := p.fileSlot(record.ComponentCommand, c.Name, p.target.Components().Commands, c.Name+".md", c.Data); sl != nil {
			out = append(out, sl)
		}
	}
	return out
}

func (p *placer) fileSlot(kind record.ComponentKind, name, dir, file string, data []byte) slot {
	if err := layout.ValidateDirName(file); err != nil {
		p.skip(kind, name, SkipUnusableName+": "+err.Error())
		return nil
	}
	return &fileSlot{d: p.d, comp: record.Component{Kind: kind, Name: name, Path: filepath.Join(dir, file), SHA256: sum(data)}, data: data}
}

// openCodeAgent rewrites a Claude Code agent's frontmatter for OpenCode,
// which names an agent by its file and reads `mode`; Claude's `tools` and a
// bare model alias mean nothing there and are dropped. The body is kept.
func openCodeAgent(front pluginparts.Frontmatter, body []byte) ([]byte, error) {
	header := struct {
		Description string `yaml:"description,omitempty"`
		Mode        string `yaml:"mode"`
		Model       string `yaml:"model,omitempty"`
	}{Description: front.Description, Mode: "subagent"}
	if strings.Contains(front.Model, "/") {
		header.Model = front.Model
	}
	y, err := yaml.Marshal(header)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("---\n")
	b.Write(y)
	b.WriteString("---\n")
	b.Write(body)
	return b.Bytes(), nil
}

// codexAgent is a Codex agent file: the Claude agent's body becomes its
// developer instructions.
func codexAgent(name, description string, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "name = %s\n", tomlString(name))
	fmt.Fprintf(&b, "description = %s\n", tomlString(description))
	fmt.Fprintf(&b, "developer_instructions = %s\n", tomlMultiline(string(body)))
	return []byte(b.String())
}

// tomlMultiline is a multi-line literal string when the text allows one, so
// the instructions stay readable in the file.
func tomlMultiline(s string) string {
	if strings.Contains(s, "'''") || strings.ContainsFunc(s, func(r rune) bool {
		return (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f
	}) || strings.HasSuffix(s, "'") {
		return tomlString(s)
	}
	return "'''\n" + s + "'''"
}

type fileSlot struct {
	d    *Deliverer
	comp record.Component
	data []byte
}

func (s *fileSlot) ref() record.Component { return s.comp }

func (s *fileSlot) current(string) (string, error) {
	if _, err := s.d.contained(s.comp.Path); err != nil {
		return "", err
	}
	info, err := os.Lstat(s.comp.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return sum([]byte("not a file: " + info.Mode().String())), nil
	}
	return fileSum(s.comp.Path)
}

func (s *fileSlot) write(context.Context, string) (string, error) {
	if err := s.d.writeFile(s.comp.Path, s.data, 0o644); err != nil {
		return "", err
	}
	return s.current("")
}

func (s *fileSlot) remove(context.Context, string) error {
	if _, err := s.d.contained(s.comp.Path); err != nil {
		return err
	}
	err := os.Remove(s.comp.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
