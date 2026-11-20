package deliver

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// SkipHooksClaudeOnly is why a hook is placed for Claude Code alone.
const SkipHooksClaudeOnly = "only Claude Code runs Claude Code hooks"

const claudeSettingsFile = "settings.json"

func (p *placer) hookSlots() []slot {
	var out []slot
	for i := range p.plugin.Hooks {
		h := &p.plugin.Hooks[i]
		switch {
		case p.change.Target != record.TargetClaudeCode:
			p.skip(record.ComponentHook, h.Source, SkipHooksClaudeOnly)
			continue
		case h.UsesPluginRoot:
			p.skip(record.ComponentHook, h.Source, SkipPluginRoot)
			continue
		}
		var group any
		if err := json.Unmarshal(h.Group, &group); err != nil {
			p.skip(record.ComponentHook, h.Source, "unreadable: "+err.Error())
			continue
		}
		fp, err := canonical(group)
		if err != nil {
			p.skip(record.ComponentHook, h.Source, "unreadable: "+err.Error())
			continue
		}
		out = append(out, &hookSlot{d: p.d, group: group, comp: record.Component{
			Kind: record.ComponentHook, Name: h.Source, Key: h.Event, SHA256: fp,
			Path: filepath.Join(p.target.Components().ConfigDir, claudeSettingsFile),
		}})
	}
	return out
}

// hookSlot is one matcher group in settings.json's hooks.<Event> array.
// A group carries no name, so it is found by its content: an edited group no
// longer matches and is left alone, never rewritten or removed.
type hookSlot struct {
	d     *Deliverer
	comp  record.Component
	group any
}

func (s *hookSlot) ref() record.Component { return s.comp }

func (s *hookSlot) current(want string) (string, error) {
	_, i, err := s.find(want)
	if err != nil || i < 0 {
		return "", err
	}
	return want, nil
}

func (s *hookSlot) find(fp string) (doc []byte, index int, err error) {
	doc, err = s.d.readConfig(s.comp.Path)
	if err != nil || doc == nil || fp == "" {
		return doc, -1, err
	}
	v, err := jsoncGet(doc, "hooks", s.comp.Key)
	if err != nil {
		return nil, -1, fmt.Errorf("read %s: %w", s.comp.Path, err)
	}
	list, _ := v.([]any)
	for i, g := range list {
		if c, cerr := canonical(g); cerr == nil && c == fp {
			return doc, i, nil
		}
	}
	return doc, -1, nil
}

func (s *hookSlot) write(_ context.Context, have string) (string, error) {
	doc, i, err := s.find(have)
	if err != nil {
		return "", err
	}
	var out []byte
	switch {
	case have != "" && i < 0:
		return "", fmt.Errorf("%s (hooks.%s) changed while amctl was syncing", s.comp.Path, s.comp.Key)
	case i >= 0:
		out, err = jsoncSetElem(doc, i, s.group, "hooks", s.comp.Key)
	default:
		out, err = jsoncAppend(doc, s.group, "hooks", s.comp.Key)
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", s.comp.Path, err)
	}
	if err := s.d.writeConfig(s.comp.Path, out); err != nil {
		return "", err
	}
	return s.current(s.comp.SHA256)
}

func (s *hookSlot) remove(_ context.Context, have string) error {
	doc, i, err := s.find(have)
	if err != nil || i < 0 {
		return err
	}
	out, err := jsoncRemoveElem(doc, i, "hooks", s.comp.Key)
	if err != nil {
		return fmt.Errorf("%s: %w", s.comp.Path, err)
	}
	return s.d.writeConfig(s.comp.Path, out)
}
