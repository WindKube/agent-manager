# Contract — Background Roles, Checks and Sources

**Read this before adding a worker.** Constitution principle VII.

Three registries share one pattern: a plugin is a value, not a subclass; it declares what
it needs; the runtime hands it exactly that and nothing else.

---

## 1. Worker roles

```go
// internal/worker/worker.go

// Definition is the complete description of a background role. Adding a worker means
// writing one of these and appending it to the list in registry.go. Nothing else in the
// tree changes — not the cobra command, not the bootstrap, not the Dockerfile.
type Definition struct {
    Name     string              // matches `agent-manager worker run <name>`
    Queues   map[string]int      // queue name -> max concurrent
    Needs    Needs               // what the bootstrap is permitted to construct
    Periodic []river.PeriodicJob // cron-ish jobs this role owns
    Register func(Deps, *river.Workers) error
}

// Needs is the machine-checkable half of principle II. A role that does not declare
// BlobWrite is never handed a writer, so it cannot acquire one by accident three
// refactors from now.
type Needs struct {
    DB       Access // AccessNone | AccessRead | AccessReadWrite
    Blob     Access
    Outbound bool   // may construct the SSRF-hardened client
}

// Deps is what a worker receives. Every field is an interface, and any field the role
// did not declare is nil — a startup failure in tests rather than a silent privilege
// escalation in production.
type Deps struct {
    DB        bun.IDB
    BlobRead  blob.Reader
    BlobWrite blob.Writer  // nil unless Needs.Blob == AccessReadWrite
    Fetch     fetch.Client // nil unless Needs.Outbound
    Audit     audit.Writer
    Log       zerolog.Logger
}
```

`registry.go` is the only file that changes when a role is added:

```go
var definitions = []Definition{
    fetcher.Definition(), // Needs{DB: ReadWrite, Blob: ReadWrite, Outbound: true}
    scanner.Definition(), // Needs{DB: ReadWrite, Blob: Read,      Outbound: false}
}
```

### Which boundary is enforced by what

This distinction matters and is easy to get wrong:

| Boundary | Enforced by | Why not the other way |
| --- | --- | --- |
| Scanner cannot write bundle bytes | **Go type system** — `Deps.BlobWrite` is nil and `blob.Reader` has no write method to assert back to | Expressible as an interface, so it should be |
| Web role cannot reach the database | **Absence of a DSN** — `am_web` has no grant and no connection string | Not a Go boundary at all; the role never links the code |
| Scanner cannot write `digest` / `object_key` | **Postgres grants** (`am_scanner`) | `bun.IDB` exposes `NewUpdate()` unconditionally; Go cannot express column-level read-only over an ORM |

Do not assume `Needs.DB: AccessRead` produces a read-only handle. It selects which DSN the
bootstrap uses. The grants in `data-model.md` are what actually stop the write.

### Rules

1. A worker declares the narrowest `Needs` that works. Widening one is a code-review
   subject, not a detail.
2. Handlers are **idempotent** — delivery is at-least-once (principle IX). Re-running a
   fetch for a version with committed bytes, or a scan at an already-recorded
   `pack_version`, is a no-op.
3. A worker never enqueues by calling River. It writes to the outbox inside its
   transaction.
4. Every handler takes a `context.Context` and honours cancellation; a scan that exceeds
   its budget records `timed_out` and returns (FR-031).

---

## 2. Scanner checks

```go
// internal/scan/checks/check.go
type Check interface {
    ID() string    // "network-allowlist" — stable, stored on scan_check
    Label() string // "Network allowlist" — rendered in the design's checks-run matrix
    Run(ctx context.Context, b *Bundle, rules RuleSet) (Result, []Finding, error)
}
```

The runner iterates the registry and writes one `scan_check` row per registered check —
**including passes** — so FR-025 holds automatically and a new check appears in the UI with
no renderer change.

A `Check` receives an already-extracted, already-capped `*Bundle`. It **never** touches the
network, the filesystem outside the bundle, or a subprocess. A check that needs to execute
something is not a check (principle III).

Shipped: `manifest-schema`, `network-allowlist`, `shell-audit`, `secret-exfiltration`,
`prompt-injection`, `filesystem-scope`, `dependency-pinning`.

---

## 3. Fetch sources

```go
// internal/fetch/source.go
type Source interface {
    Name() string
    Handles(SourceRef) bool
    Fetch(ctx context.Context, ref SourceRef) (Tree, error)
}
```

Shipped: `upload` (multipart archive), `git` (repository URL + ref + subdirectory),
`archive-url` (direct `.zip`/`.tar.gz` URL). An OCI-registry or GitLab source later is a
new file plus a registry line.

Every `Source` that touches the network uses `Deps.Fetch`. Constructing an `http.Client`
inside a `Source` is a defect (principle III).

---

## 4. Adding a worker — the whole checklist

1. New package under `internal/worker/<name>/` exporting `Definition()`.
2. Append it to `definitions` in `registry.go`.
3. If it needs a new job type, define the River args struct and its outbox `job_kind`.
4. Add a compose service reusing the same image with `command: ["worker", "run", "<name>"]`
   and **only** the env vars its `Needs` implies.
5. Add a Postgres role in the migration if its grants differ from an existing role.
6. Table-driven test for the handler, plus a redelivery test proving idempotency.

No step touches an existing worker, the cobra tree, the bootstrap, or the Dockerfile.
