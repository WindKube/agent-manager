package layout

import "errors"

// ErrR2Unresolved marks a target with no settled on-disk layout, refused so a sync fails loudly
// instead of reporting success on an install of nothing.
var ErrR2Unresolved = errors.New("target layout unresolved by research gate R2")
