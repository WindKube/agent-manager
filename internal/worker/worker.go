// Package worker is the background-role framework: a background role is a
// value, not a subclass. It declares what it needs, and the bootstrap hands
// it exactly that and nothing else. Adding a worker means writing one
// Definition and appending it to the list in registry.go — not touching the
// cobra tree, this bootstrap, or the Dockerfile.
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
	// Periodic builds the jobs this role schedules, from the role's config.
	Periodic func(Config) ([]PeriodicJob, error)
}

// PeriodicJob is a job a role inserts every Interval. The role schedules it
// itself rather than through River's PeriodicJobs, which only the one client
// elected leader of the whole queue database runs: with several roles sharing
// it, every other role's schedule silently never fired.
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

// Needs is machine-checkable: a role that does not declare BlobWrite is never
// handed a writer, so it cannot acquire one by accident three refactors from
// now.
type Needs struct {
	DB       Access // AccessNone | AccessRead | AccessReadWrite
	Blob     Access
	Outbound bool // may construct the SSRF-hardened client
}

// Deps is what a worker receives. Every field is an interface, and any field
// the role did not declare is nil — a startup failure in tests rather than a
// silent privilege escalation in production.
//
// Needs.DB selects which DSN the bootstrap uses, not how much the handle can
// write: bun.IDB exposes NewUpdate() unconditionally, so read-only access
// through the ORM is not expressible in Go, and the database's own grants are
// what actually stop the write.
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
