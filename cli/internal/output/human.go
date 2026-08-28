package output

import "io"

// HumanRenderer writes prose for a person at a terminal.
//
// Its wording is deliberately not a contract: anything that needs to be parsed
// must use FormatJSON. That is why nothing here is column-aligned across
// results or padded to a fixed width — a stable-looking layout invites awk.
type HumanRenderer struct{}

// Render implements Renderer.
func (HumanRenderer) Render(w io.Writer, r Result) error {
	if r == nil {
		return nil
	}
	return r.Human(w)
}
