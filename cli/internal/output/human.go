package output

import "io"

// HumanRenderer writes prose for a person at a terminal. Its wording is not a
// contract; anything that needs parsing must use FormatJSON.
type HumanRenderer struct{}

func (HumanRenderer) Render(w io.Writer, r Result) error {
	if r == nil {
		return nil
	}
	return r.Human(w)
}
