// Package worker is the background-role framework: a role is a Definition
// declaring what it needs, and the bootstrap hands it exactly that. Adding a
// worker means writing one Definition and appending it to registry.go.
package worker

import (
	"time"

	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/fetch"
	"agent-manager/internal/signing"
)

// Definition is the complete description of a background role.
type Definition struct {
	Name     string         // matches `agent-manager worker run <name>`
	Queues   map[string]int // queue name -> max concurrent
	Needs    Needs          // what the bootstrap is permitted to construct
	Register func(Deps, *river.Workers) error
	Periodic func(Config) ([]PeriodicJob, error)
}

// PeriodicJob is a job a role inserts every Interval. Roles schedule their own
// because River's PeriodicJobs run only on the queue database's single elected
// leader, so other roles' schedules would never fire.
type PeriodicJob struct {
	Interval   time.Duration
	Args       river.JobArgs
	RunOnStart bool
}

// Access is how much of a datastore a role may be handed.
type Access int

const (
	AccessNone Access = iota
	AccessRead
	AccessReadWrite
)

func (a Access) String() string {
	switch a {
	case AccessNone:
		return "none"
	case AccessRead:
		return "read"
	case AccessReadWrite:
		return "read-write"
	default:
		return "unknown"
	}
}

// Needs is what a role may be handed; anything undeclared is never constructed.
type Needs struct {
	DB       Access // AccessNone | AccessRead | AccessReadWrite
	Blob     Access
	Outbound bool // may construct the SSRF-hardened client
}

// Deps is what a worker receives; any field the role did not declare is nil.
// Needs.DB only selects the DSN: bun.IDB can always write, so the database's
// own grants are what enforce read-only access.
type Deps struct {
	DB        bun.IDB
	BlobRead  blob.Reader
	BlobWrite blob.Writer  // nil unless Needs.Blob == AccessReadWrite
	Fetch     fetch.Client // nil unless Needs.Outbound
	// GitHubToken authenticates GitHub API calls; empty means anonymous (60 requests an hour).
	GitHubToken string
	// Signatures verifies Sigstore bundles; nil unless Needs.Outbound.
	Signatures *signing.Verifier
	Log        zerolog.Logger
}
