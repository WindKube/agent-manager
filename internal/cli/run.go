package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// The role entry points land in later layers of this stack. Each is replaced by
// a real bootstrap in the layer that owns it; until then a role starts, reports
// itself and exits 0 so the compose topology can be wired ahead of the code.

func runAPI(context.Context) error { return notYet("serve api") }
func runWeb(context.Context) error { return notYet("serve web") }

func runWorker(_ context.Context, name string) error {
	return notYet("worker run " + name)
}

func listWorkers(w io.Writer) error {
	_, err := fmt.Fprintln(w, "no workers registered yet")
	return err
}

func runMigrateQueue(context.Context) error { return notYet("migrate queue") }
func runSeed(context.Context) error         { return notYet("seed") }

// runHealthcheck is real from the start: containers need it before any role is
// implemented, and it depends on nothing.
func runHealthcheck(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("probe %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe %s: status %d", url, resp.StatusCode)
	}
	return nil
}

func notYet(role string) error {
	fmt.Printf("agent-manager: %s is not implemented in this layer yet\n", role)
	return nil
}
