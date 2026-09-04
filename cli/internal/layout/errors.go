package layout

import "errors"

// ErrR2Unresolved marks a target whose on-disk layout could not be settled by
// research. Every constructor for such a target returns an error wrapping this,
// so the registry refuses the target by class rather than by string match: a
// sync for a profile naming it fails loudly instead of writing somewhere
// hopeful and reporting success on an install of nothing.
var ErrR2Unresolved = errors.New("target layout unresolved by research gate R2")
