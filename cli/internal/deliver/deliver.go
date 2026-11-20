// Package deliver places a plugin's components into each agent's own
// locations: skill directories, agent and command files, MCP server entries
// and hooks. Every place it writes is recorded with a fingerprint of what it
// wrote, and nothing is overwritten or removed unless it still matches that
// fingerprint (or --force says so, by name).
package deliver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
	"github.com/WindKube/agent-manager/cli/pluginparts"
)

// Reasons a component is not placed for a target.
const (
	SkipPluginRoot      = "uses ${CLAUDE_PLUGIN_ROOT}, which only an installed Claude Code plugin expands"
	SkipServedBy        = "served by"
	SkipUnusableName    = "name is not usable as a file or directory name"
	SkipNoAgentLocation = "this agent has no location for it"
)

// Deliverer implements apply.Components for every target this build writes.
type Deliverer struct {
	Targets map[record.Target]layout.Target
	Home    *apply.Home
	Force   bool
	Log     apply.Logger
	Claude  ClaudeCLI

	// ProfileTargets is every target each profile writes in this run, which
	// decides whether opencode already sees a skill through another target.
	ProfileTargets map[string][]record.Target
}

var _ apply.Components = (*Deliverer)(nil)

// slot is one place a component lives. Fingerprints are hex SHA-256 strings;
// "" means nothing is there.
type slot interface {
	ref() record.Component // SHA256 is the fingerprint this run would write, "" for a pure removal
	current(want string) (string, error)
	write(ctx context.Context, have string) (string, error)
	remove(ctx context.Context, have string) error
}

type opKind int

const (
	opKeep opKind = iota
	opWrite
	opRemove
)

type op struct {
	kind opKind
	slot slot
	have string            // what is there now
	prev *record.Component // what the record owned here, if anything
}

type delivery struct {
	ops   []op
	skips []apply.ComponentSkip
}

func (d *delivery) Skipped() []apply.ComponentSkip { return d.skips }

// Apply runs removals first, then writes. On failure it still returns every
// component this entry owns at that moment, so the record never loses one.
func (d *delivery) Apply(ctx context.Context) ([]record.Component, error) {
	owned := map[string]record.Component{}
	order := []string{}
	own := func(c record.Component) {
		if _, ok := owned[c.Identity()]; !ok {
			order = append(order, c.Identity())
		}
		owned[c.Identity()] = c
	}
	for _, o := range d.ops {
		if o.prev != nil {
			own(*o.prev)
		}
	}

	ops := slices.Clone(d.ops)
	slices.SortStableFunc(ops, func(a, b op) int {
		return boolInt(a.kind != opRemove) - boolInt(b.kind != opRemove)
	})
	for _, o := range ops {
		if err := ctx.Err(); err != nil {
			return collect(owned, order), err
		}
		ref := o.slot.ref()
		switch o.kind {
		case opKeep:
			own(ref)
		case opRemove:
			if err := o.slot.remove(ctx, o.have); err != nil {
				return collect(owned, order), fmt.Errorf("remove %s %s: %w", ref.Kind, ref.Name, err)
			}
			delete(owned, ref.Identity())
		case opWrite:
			fp, err := o.slot.write(ctx, o.have)
			if err != nil {
				return collect(owned, order), fmt.Errorf("place %s %s: %w", ref.Kind, ref.Name, err)
			}
			ref.SHA256 = fp
			own(ref)
		}
	}
	return collect(owned, order), nil
}

func collect(owned map[string]record.Component, order []string) []record.Component {
	out := make([]record.Component, 0, len(owned))
	for _, id := range order {
		if c, ok := owned[id]; ok {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b record.Component) int { return strings.Compare(a.Identity(), b.Identity()) })
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Prepare reads the staged plugin, works out every component's place for
// c.Target and checks each one against disk; it writes nothing.
func (d *Deliverer) Prepare(ctx context.Context, c plan.Change, stagedDir string, prev, others []record.Component) (apply.Delivery, error) {
	t, ok := d.Targets[c.Target]
	if !ok {
		return nil, fmt.Errorf("internal: no layout for target %s", c.Target)
	}
	plugin, err := pluginparts.Read(os.DirFS(stagedDir))
	if err != nil {
		return nil, fmt.Errorf("plugin %s: %w", c.ID, err)
	}
	for _, p := range plugin.Problems {
		d.logf("%s: %s", c.ID, p)
	}
	pkg, err := layout.ParsePackageID(c.ID)
	if err != nil {
		return nil, err
	}

	pl := &placer{d: d, target: t, change: c, pkg: pkg, plugin: plugin, stagedDir: stagedDir}
	slots := pl.slots()
	return d.guard(ctx, c, slots, pl.skips, prev, others)
}

func (d *Deliverer) logf(format string, args ...any) {
	if d.Log != nil {
		d.Log.Warnf(format, args...)
	}
}

func (d *Deliverer) guard(_ context.Context, c plan.Change, slots []slot, skips []apply.ComponentSkip,
	prev, others []record.Component,
) (*delivery, error) {
	prevByID := map[string]*record.Component{}
	for i := range prev {
		prevByID[prev[i].Identity()] = &prev[i]
	}
	othersBySlot := map[string]record.Component{}
	for _, o := range others {
		if o.Kind != record.ComponentHook {
			othersBySlot[o.Slot()] = o
		}
	}

	out := &delivery{skips: skips}
	var refusals []error
	wanted := map[string]bool{}
	for _, s := range slots {
		ref := s.ref()
		wanted[ref.Identity()] = true
		p := prevByID[ref.Identity()]
		if o, taken := othersBySlot[ref.Slot()]; taken && p == nil {
			refusals = append(refusals, fmt.Errorf("%w: %s %s would be placed at %s, which another package's %s %s owns",
				apply.ErrComponentConflict, ref.Kind, ref.Name, where(ref), o.Kind, o.Name))
			continue
		}
		o, err := d.decide(c, s, p)
		if err != nil {
			refusals = append(refusals, err)
			continue
		}
		out.ops = append(out.ops, o)
	}

	for i := range prev {
		p := &prev[i]
		if wanted[p.Identity()] {
			continue
		}
		s, err := d.slotOf(c.Target, *p)
		if err != nil {
			refusals = append(refusals, err)
			continue
		}
		have, err := s.current(p.SHA256)
		if err != nil {
			refusals = append(refusals, err)
			continue
		}
		switch {
		case have == "":
			d.logf("%s: %s %s at %s is already gone", c.ID, p.Kind, p.Name, where(*p))
		case have == p.SHA256:
			out.ops = append(out.ops, op{kind: opRemove, slot: s, have: have, prev: p})
		case d.Force:
			d.logf("%s: --force is removing %s %s at %s, which was modified since amctl placed it",
				c.ID, p.Kind, p.Name, where(*p))
			out.ops = append(out.ops, op{kind: opRemove, slot: s, have: have, prev: p})
		default:
			refusals = append(refusals, fmt.Errorf("%w: %s %s at %s is no longer in %s and was modified since amctl "+
				"placed it; re-run with --force to remove it", apply.ErrModified, p.Kind, p.Name, where(*p), c.ID))
		}
	}
	if len(refusals) > 0 {
		return nil, errors.Join(refusals...)
	}
	return out, nil
}

// decide is the one rule every component follows: write over nothing or over
// exactly what amctl wrote; keep what already matches; refuse anything else
// unless forced.
func (d *Deliverer) decide(c plan.Change, s slot, p *record.Component) (op, error) {
	ref := s.ref()
	want := ref.SHA256
	look := want
	if p != nil {
		look = p.SHA256
	}
	have, err := s.current(look)
	if err != nil {
		return op{}, err
	}
	if have == "" && look != want {
		if again, cerr := s.current(want); cerr == nil && again == want {
			have = want
		}
	}
	switch {
	case have == want:
		return op{kind: opKeep, slot: s, have: have, prev: p}, nil
	case have == "":
		if p != nil {
			d.logf("%s: %s %s at %s was recorded but is gone; placing it again", c.ID, ref.Kind, ref.Name, where(ref))
		}
		return op{kind: opWrite, slot: s, prev: p}, nil
	case p != nil && have == p.SHA256:
		return op{kind: opWrite, slot: s, have: have, prev: p}, nil
	case d.Force:
		d.logf("%s: --force is overwriting %s %s at %s", c.ID, ref.Kind, ref.Name, where(ref))
		return op{kind: opWrite, slot: s, have: have, prev: p}, nil
	case p != nil:
		return op{}, fmt.Errorf("%w: %s %s at %s was modified since amctl placed it; re-run with --force to overwrite it",
			apply.ErrModified, ref.Kind, ref.Name, where(ref))
	default:
		return op{}, fmt.Errorf("%w: %s %s: %s already exists and amctl did not write it; re-run with --force to overwrite it",
			apply.ErrUnrecorded, ref.Kind, ref.Name, where(ref))
	}
}

// Remove deletes each recorded component that still matches what amctl wrote.
func (d *Deliverer) Remove(ctx context.Context, target record.Target, comps []record.Component) ([]record.Component, error) {
	var kept []record.Component
	var errs []error
	for _, c := range comps {
		if err := d.removeOne(ctx, target, c); err != nil {
			kept = append(kept, c)
			errs = append(errs, err)
		}
	}
	return kept, errors.Join(errs...)
}

func (d *Deliverer) removeOne(ctx context.Context, target record.Target, c record.Component) error {
	s, err := d.slotOf(target, c)
	if err != nil {
		return err
	}
	have, err := s.current(c.SHA256)
	if err != nil {
		return err
	}
	switch {
	case have == "":
		return nil
	case have != c.SHA256 && !d.Force:
		return fmt.Errorf("%w: %s %s at %s was modified since amctl placed it; re-run with --force to remove it",
			apply.ErrModified, c.Kind, c.Name, where(c))
	case have != c.SHA256:
		d.logf("--force is removing %s %s at %s, which was modified since amctl placed it", c.Kind, c.Name, where(c))
	}
	return s.remove(ctx, have)
}

// slotOf rebuilds the slot a recorded component lives in, for removal.
func (d *Deliverer) slotOf(target record.Target, c record.Component) (slot, error) {
	switch c.Kind {
	case record.ComponentSkill:
		return &dirSlot{d: d, comp: c}, nil
	case record.ComponentMCPServer:
		return d.mcpSlotOf(target, c)
	default:
		return nil, fmt.Errorf("%s %s for target %s: this build cannot remove a %s it recorded", c.Kind, c.Name, target, c.Kind)
	}
}

func where(c record.Component) string {
	if c.Key == "" {
		return c.Path
	}
	return c.Path + " (" + c.Key + ")"
}

// placer works out where each of one plugin's components goes for one target.
type placer struct {
	d         *Deliverer
	target    layout.Target
	change    plan.Change
	pkg       layout.Package
	plugin    *pluginparts.Plugin
	stagedDir string
	skips     []apply.ComponentSkip
}

func (p *placer) skip(kind record.ComponentKind, name, reason string) {
	p.skips = append(p.skips, apply.ComponentSkip{Kind: kind, Name: name, Reason: reason})
}

func (p *placer) slots() []slot {
	for _, a := range p.plugin.Agents {
		p.skip(record.ComponentAgent, a.Name, skipNotYet)
	}
	for _, c := range p.plugin.Commands {
		p.skip(record.ComponentCommand, c.Name, skipNotYet)
	}
	for _, h := range p.plugin.Hooks {
		p.skip(record.ComponentHook, hookName(h), skipNotYet)
	}
	return append(p.skillSlots(), p.mcpSlots()...)
}

const skipNotYet = "this build does not place this kind of component"

func hookName(h pluginparts.Hook) string { return h.Source }
