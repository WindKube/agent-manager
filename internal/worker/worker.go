// Package worker is the background-role framework from
// specs/001-agent-manager-hub/contracts/worker.md.
//
// Constitution principle VII: a background role is a value, not a subclass. It
// declares what it needs, and the bootstrap hands it exactly that and nothing
// else. Adding a worker means writing one Definition and appending it to the list
// in registry.go — not touching the cobra tree, this bootstrap, or the Dockerfile.
package worker

import (
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/fetch"
)

// Definition is the complete description of a background role.
type Definition struct {
	Name     string              // matches `agent-manager worker run <name>`
	Queues   map[string]int      // queue name -> max concurrent
	Needs    Needs               // what the bootstrap is permitted to construct
	Periodic []river.PeriodicJob // cron-ish jobs this role owns
	Register func(Deps, *river.Workers) error
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

// Needs is the machine-checkable half of principle II. A role that does not
// declare BlobWrite is never handed a writer, so it cannot acquire one by accident
// three refactors from now.
type Needs struct {
	DB       Access // AccessNone | AccessRead | AccessReadWrite
	Blob     Access
	Outbound bool // may construct the SSRF-hardened client
}

// Deps is what a worker receives. Every field is an interface, and any field the
// role did not declare is nil — a startup failure in tests rather than a silent
// privilege escalation in production.
//
// Note what Needs.DB does NOT do: it selects which DSN the bootstrap uses, not
// how much the handle can write. bun.IDB exposes NewUpdate() unconditionally, so
// read-only access through the ORM is not expressible in Go; the grants in
// data-model.md are what actually stop the write (contracts/worker.md's boundary
// table).
type Deps struct {
	DB        bun.IDB
	BlobRead  blob.Reader
	BlobWrite blob.Writer  // nil unless Needs.Blob == AccessReadWrite
	Fetch     fetch.Client // nil unless Needs.Outbound
	Log       zerolog.Logger
}
