package worker

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// definitions is the one list. It is the ONLY thing that changes when a role is
// added: not the cobra command, not Build, not the Dockerfile (principle VII).
//
// The two roles the spec calls for arrive with their own layers:
//
//	fetcher.Definition(), // T035 — Needs{DB: AccessReadWrite, Blob: AccessReadWrite, Outbound: true}
//	scanner.Definition(), // T060 — Needs{DB: AccessReadWrite, Blob: AccessRead,      Outbound: false}
var definitions = []Definition{}

// Definitions returns the registered roles in registration order.
func Definitions() []Definition { return slices.Clone(definitions) }

// Names returns the registered role names, which are the arguments
// `agent-manager worker run` accepts.
func Names() []string {
	out := make([]string, 0, len(definitions))
	for _, def := range definitions {
		out = append(out, def.Name)
	}
	return out
}

// Lookup finds a role by the name `worker run <name>` was given.
func Lookup(name string) (Definition, error) {
	for _, def := range definitions {
		if def.Name == name {
			return def, nil
		}
	}
	if len(definitions) == 0 {
		return Definition{}, fmt.Errorf("unknown worker %q: no workers are registered yet", name)
	}
	return Definition{}, fmt.Errorf("unknown worker %q: registered workers are %s", name, strings.Join(Names(), ", "))
}

// List writes the registry for `agent-manager worker list`.
func List(w io.Writer) error {
	if len(definitions) == 0 {
		_, err := fmt.Fprintln(w, "no workers registered yet")
		return err
	}
	for _, def := range definitions {
		queues := make([]string, 0, len(def.Queues))
		for name, concurrency := range def.Queues {
			queues = append(queues, fmt.Sprintf("%s=%d", name, concurrency))
		}
		slices.Sort(queues)

		if _, err := fmt.Fprintf(w, "%s\tdb=%s blob=%s outbound=%t queues=%s\n",
			def.Name, def.Needs.DB, def.Needs.Blob, def.Needs.Outbound, strings.Join(queues, ",")); err != nil {
			return err
		}
	}
	return nil
}
