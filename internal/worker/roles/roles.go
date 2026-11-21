// Package roles is the worker registry: the one list of background roles. It
// lives outside internal/worker because role packages import internal/worker,
// so listing them there would be an import cycle.
package roles

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"agent-manager/internal/worker"
	"agent-manager/internal/worker/fetcher"
	"agent-manager/internal/worker/notifier"
	"agent-manager/internal/worker/scanner"
)

// definitions shows the credential split side by side: only the fetcher may
// write bundle bytes, the scanner has no network, and the notifier holds no
// object-store credential.
var definitions = []worker.Definition{
	fetcher.Definition(),  // Needs{DB: AccessReadWrite, Blob: AccessReadWrite, Outbound: true}
	scanner.Definition(),  // Needs{DB: AccessReadWrite, Blob: AccessRead,      Outbound: false}
	notifier.Definition(), // Needs{DB: AccessReadWrite, Blob: AccessNone,      Outbound: true}
}

// Definitions returns the registered roles in registration order.
func Definitions() []worker.Definition { return slices.Clone(definitions) }

// Names returns the registered role names accepted by `worker run`.
func Names() []string {
	out := make([]string, 0, len(definitions))
	for _, def := range definitions {
		out = append(out, def.Name)
	}
	return out
}

// Lookup finds a role by the name `worker run <name>` was given.
func Lookup(name string) (worker.Definition, error) {
	for _, def := range definitions {
		if def.Name == name {
			return def, nil
		}
	}
	if len(definitions) == 0 {
		return worker.Definition{}, fmt.Errorf("unknown worker %q: no workers are registered yet", name)
	}
	return worker.Definition{}, fmt.Errorf("unknown worker %q: registered workers are %s", name, strings.Join(Names(), ", "))
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
