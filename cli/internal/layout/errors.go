package layout

import "errors"

// ErrR2Unresolved marks a target whose on-disk layout research gate R2 could not
// settle. Every constructor for such a target returns an error wrapping this, so
// the registry can refuse the target by CLASS rather than by string match, and a
// `sync` for a profile naming it fails loudly instead of writing somewhere hopeful.
//
// Failing loudly is the entire point. A target that installs nothing while the
// command exits 0 is the worst failure this tool has, because it reports success —
// which is why R2 exists and why warn-and-continue is not an option here.
//
// `agents-md` used to be the second target wrapping this. It is gone from the
// contract entirely rather than shipped as a constructor that always fails: the
// convention documents only a repository-root AGENTS.md and no per-user location,
// and one shared markdown file cannot be installed per package, marked with a
// package and version, given a distinct directory per publisher, swapped
// atomically or pruned by path. A gated target is one awaiting a measurement;
// that one was awaiting a design.
var ErrR2Unresolved = errors.New("target layout unresolved by research gate R2")
