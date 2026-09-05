# Agent Manager Constitution

Agent Manager is a self-hosted registry for AI agent plugins and skills: it fetches
sources, unpacks them into immutable versions, statically scans them for hostile
behaviour, and lets people assemble versioned profiles that a CLI syncs onto their
machines.

Everything below is a constraint on *how* that gets built. Product behaviour lives in
`specs/`, not here.

## Core Principles

### I. One Module, One Image, Roles as Subcommands

The whole system is a single Go module producing a single binary and a single container
image. Deployable units are selected at run time by a cobra subcommand — `serve api`,
`serve web`, `worker fetcher`, `worker scanner` — never by a separate build.

This is the pattern already proven by `technologia` (`worker run ai`) and `arc-ui` in
this monorepo. It buys process isolation, independent scaling and per-role credentials
without paying for a second toolchain, a second CI pipeline, or drifting shared types.

A new deployable unit is a new subcommand. Anyone proposing a second module or a second
image must justify it against this principle in the plan.

### II. Least Privilege Between Roles (NON-NEGOTIABLE)

Each role gets exactly the credentials its job needs, and the compose file and
deployment manifests must make that visible:

- `serve web` holds **no** database credential and **no** object-store credential. It
  reaches data only through `serve api` over HTTP, carrying the end user's identity.
- `worker fetcher` is the **only** role with object-store *write* access.
- `worker scanner` gets object-store *read* and may write scan verdicts and findings.
  It never writes bundle bytes and never gets a publish credential.
- `serve api` owns the relational schema and mediates every mutation.

A change that widens a role's credentials is a change to this constitution, not an
implementation detail.

### III. Untrusted Input Is the Default Assumption

Every package that enters the system is hostile until proven otherwise. Concretely:

- Any URL supplied by a user and fetched by the server goes through
  the project's single sanctioned SSRF-hardened client, which refuses private, loopback
  and link-local destinations on every redirect hop and every resolved address. A bare
  `http.Client` pointed at user input is a defect, not a style preference.
- Archive extraction is written and owned by this project, with explicit caps on entry
  count, per-entry size, total decompressed size, and path depth. Absolute paths,
  `..` traversal, symlinks and hardlinks are rejected, not sanitised.
- The scanner performs **static analysis only**. It never executes, sources, imports or
  evaluates anything from a bundle. No `exec`, no interpreter, no container escape
  hatch "just to run the postinstall".
- Content rendered from a manifest, a `SKILL.md` or a scan evidence snippet is escaped
  at the template layer. `templ.Raw` on package-derived content is forbidden.

### IV. Immutability and Provenance

A published version is write-once. Its object key, its `sha256` digest and its scan
verdict are recorded together and never mutated. Re-publishing the same
`publisher/name@version` with different bytes is rejected, not overwritten.

Every state change that a human or a system actor causes — fetch, scan verdict, publish,
approve, override, share, sync, login — writes an audit row naming the actor, the
subject, and the source (`web`, `cli / <host>`, `system`). If an action is worth doing,
it is worth being accountable for; a code path that mutates state without an audit write
is incomplete.

### V. Contract-First, Generated, Never Hand-Copied

The HTTP contract is declared once as typed huma operations and emitted as OpenAPI 3.1.
The `serve web` client and any future CLI are **generated** from that document.

Hand-written duplicates of a request or response type across roles are prohibited — they
are how the api/web split rots. If a type must cross a role boundary, it crosses through
generated code or through the shared domain package, never through a copy-paste.

### VI. It Runs With One Command

`docker compose up` from the project directory brings up a working system — database,
object store, identity provider, api, web, both workers — seeded with representative
data, with no manual step, no cloud account, and no credential the reader has to invent.

A feature that only works against real S3, real Okta or a hand-run migration is not
done. Local substitutes (MinIO, Dex) are first-class configuration, not a dev hack.

"One image" governs code this project writes. Third-party images the stack composes —
Postgres, MinIO, Dex, the Atlas migration runner — are infrastructure, not a second build,
and adding one does not engage principle I.

### VII. Background Roles Are Plugins, and They Declare What They Need

A background role is a `worker.Definition` value: a name, its queues and concurrency, its
periodic jobs, a registration function, and — the load-bearing part — a `Needs` declaration
of which clients the bootstrap may construct for it.

Adding a worker means writing one `Definition` and adding it to a single list. It must not
require touching the cobra command, the bootstrap, or any existing worker. The same
registry pattern governs the two other things that grow by accretion: scanner **checks**
and fetch **sources**.

A role receives its dependencies as narrow interfaces, and anything it did not declare is
nil. This is principle II made checkable: the scanner is handed a blob *reader* and there
is no writer in scope to assert back to. Where the type system cannot express the boundary
— read-only access through an ORM — it is enforced by distinct database roles and grants
instead, and the plan says which mechanism covers which boundary.

### VIII. Commands and Queries Are Separated in Code, Not in Infrastructure

Mutations and reads live in different packages with different rules. A command runs domain
logic inside one transaction and writes its audit row there; a query is read-only and free
to use purpose-built SQL rather than the object mapper's relation loading.

This project deliberately stops short of CQRS as an architecture. There is no separate read
database, no event sourcing, no command bus, and eventual consistency is not a general
property of the system. Exactly one denormalised projection is sanctioned — the catalog
entry — and it is maintained under a stated rule: **synchronous on structural change,
asynchronous on verdict change**. A package must appear in the catalog the instant it is
registered; a scan verdict may lag, because the design already renders `Scanning` as a
visible intermediate state.

A second projection is a constitutional amendment, not an optimisation.

### IX. The Queue Is a Separate Database, and Enqueue Is Transactional Anyway

The job queue lives in its own PostgreSQL database with its own connection URL, its own
pool and its own migration tool. Nothing in the application schema references it and no
tool that manages one may see the other.

That isolation costs the queue library's transactional-enqueue guarantee, so the guarantee
is rebuilt rather than abandoned: a mutation writes its jobs to an **outbox** table inside
its own transaction, and a relay moves them to the queue. A commit therefore either
publishes both the state change and its jobs, or neither.

Two consequences are binding. Delivery is **at-least-once**, so every job handler must be
idempotent — re-running a fetch or a scan for a version that already has one is a no-op,
not a duplicate. And no code path may enqueue a job by calling the queue directly from a
request handler; it goes through the outbox, or it is a defect.

## Technology Constraints

The stack is fixed for the initial build. Deviations require a documented justification
in the feature's `plan.md` Complexity Tracking table.

| Concern | Choice |
| --- | --- |
| Language | Go (matching the monorepo's pinned toolchain) |
| HTTP + contract | `gin` router, `danielgtaylor/huma/v2` operations, OpenAPI 3.1 out |
| Generated client | `oapi-codegen/v2` |
| Persistence | PostgreSQL via `jackc/pgx/v5`; object mapping, relations and fixtures via `uptrace/bun` (`pgdialect`, `dbfixture`) over a shared `pgxpool` |
| Schema migrations | **Atlas** — Bun models are the source of truth, `ariga.io/atlas-provider-bun` loads them, `atlas migrate diff` generates versioned SQL. Applied by an init container (`arigaio/atlas:latest-community-alpine`), never at application boot. Atlas is pointed at the application database only; River migrates its own with its own tool. |
| Job queue | `riverqueue/river` on its **own PostgreSQL database**, addressed by a separate connection URL (`AGENT_MANAGER_RIVER_DATABASE_URL`) and its own pool. It shares no schema, no pool and no migration tool with the application database. |
| Job hand-off | A transactional **outbox** table in the application database, written inside the same transaction as the mutation and drained into River by a relay on `LISTEN/NOTIFY`. Every job handler is idempotent. |
| Object storage | `gocloud.dev/blob` (`s3blob` against MinIO/S3, `memblob` and `fileblob` in tests and dev); `bucket.As()` for the raw S3 client the Storage screen's bucket-settings report needs |
| Bundles | `archive/tar`, `archive/zip`, `klauspost/compress/zstd`, `crypto/sha256` |
| Web UI | `a-h/templ` components, `starfederation/datastar-go` for reactivity, Tailwind standalone binary. **No Node.js in any image.** |
| Identity | `coreos/go-oidc/v3` + `golang.org/x/oauth2`, RFC 8628 device flow; locally **Dex in front of glauth**. The directory is not optional: Dex's static-password connector emits no `groups` claim, and that claim is the sole input to the group-to-role map (003 R1) |
| Scanner analysis | `santhosh-tekuri/jsonschema/v6`, `goccy/go-yaml`, `mvdan.cc/sh/v3/syntax`, stdlib `regexp` (RE2) |
| Config / CLI / logs | `caarlos0/env/v11`, `spf13/cobra`, `rs/zerolog` |
| Tests | `stretchr/testify`, `testcontainers-go` |

This project takes **no dependency on the monorepo's `go-modules`**. It is self-contained:
`internal/fetch`, a project-owned SSRF-hardened client, for outbound fetches of
user-supplied URLs, `google/go-github` for repository access, and a project-owned parser
for repository URLs. The trade is deliberate — independence over reuse — and the cost is
that the SSRF and URL-parsing behaviour must be proven by this project's own tests rather
than inherited.

Monorepo build rules apply: the Docker build context is the repository root, the project
directory must be admitted in the root `.dockerignore` allowlist, and the project must
appear in the `project-name` choices of `.github/workflows/build-image.yaml`. Omitting
either produces a misleading "file not found" build failure.

## Development Workflow

**Scanner rules are data.** Detection rules (`SH-NET-002`, `SH-INJ-011`, `SH-DEP-004`,
`SH-FS-007`, …) live in a versioned rule pack, not in Go control flow. Adding or tuning a
rule must not require a code change or a deploy. Every rule ships with a fixture bundle
that must trip it and a fixture bundle that must not.

**Tests before merge, at the layer that can actually fail.** Pure logic (version
resolution, manifest validation, shell AST rules, extractor limits) gets table-driven
unit tests. Anything crossing Postgres, MinIO or the OIDC provider gets a
`testcontainers-go` integration test. Screen-level behaviour that the design specifies —
facet counts, sort order, gate policy outcomes — gets a test asserting the specified
outcome, not the current one.

**Security-relevant code carries its reasoning.** The extractor, `safeurl` call sites,
the scanner sandbox boundary and the credential split each explain *why* in a comment.
Elsewhere, comments are sparse: the monorepo's house style is code that reads without
narration.

**Observability is not optional.** Structured logs via zerolog with a request/job
correlation id; `/v1/health` on serving roles plus a `healthcheck` subcommand the
container can invoke without a shell; Prometheus metrics for queue depth, scan duration
and fetch outcomes.

## Governance

This constitution outranks convenience, precedent and personal preference. Where it
conflicts with a habit from another project in the monorepo, this document wins for this
project.

Every `plan.md` records a Constitution Check before design and again after. A violation
that survives must appear in that plan's Complexity Tracking table with the simpler
alternative that was rejected and why. An unjustified violation blocks the work.

Amendments are made by editing this file with a version bump and a note in the amendment
record below. Principles marked NON-NEGOTIABLE require an explicit decision from the
project owner to change.

Versioning is semantic: MAJOR for removing or redefining a principle, MINOR for adding a
principle or a materially new constraint, PATCH for wording and clarification.

**Version**: 1.3.2 | **Ratified**: 2026-08-27 | **Last Amended**: 2026-09-04

### Amendment record

- **1.3.2** (2026-09-04) — No principle changed. The Technology Constraints table named
  `doyensec/safeurl` as the sanctioned SSRF client, but R10 rejected it before feature 001
  shipped: its check runs per connect attempt, and a name that answers with both a public
  and a private address gets the private attempt refused and then connects over the public
  one anyway. `internal/fetch` has been the actual client since then, proven by its own
  six-case suite rather than inherited. The table is corrected to name it.
- **1.3.1** (2026-08-31) — No principle changed. Recorded, because the repository spent a
  feature out of step with this document and nothing said so: principle VI and the Technology
  Constraints table both name **Dex** as the local identity substitute, and feature 001's
  research R6 overrode that with Keycloak on a measurement — Dex's static-password connector
  emits no `groups` claim, and the claim is the sole input to the group-to-role map. The
  override was correct on its evidence and was never brought here, so for one feature the
  constitution named one provider and the stack ran another. Feature 003 restores the letter
  of this document by measurement in the other direction: R6's finding still reproduces, but
  it was a property of one connector rather than of the provider, and Dex in front of a
  directory (glauth) does emit a per-user claim — at 268 MB against 730 MB and under a second
  against nine. Two infrastructure images now stand where one did, which principle VI's final
  clause already excludes from principle I. The lesson this entry exists to record is
  procedural, not technical: an override of a named constraint belongs in this record when it
  is taken, whether or not it is later reversed.
- **1.3.0** (2026-08-27) — Added principle IX: the job queue moves to its own PostgreSQL
  database with a separate connection URL, and the transactional-enqueue guarantee lost to
  that split is rebuilt with an outbox table and a relay. Delivery becomes explicitly
  at-least-once; handler idempotency becomes mandatory.
- **1.2.0** (2026-08-27) — Added principle VII (background roles are declarative plugins
  carrying a capability declaration) and principle VIII (command/query separation in code,
  with exactly one sanctioned projection and CQRS-as-architecture explicitly rejected).
  Replaced `bun/migrate` with Atlas versioned migrations applied by an init container.
  Clarified under principle VI that third-party infrastructure images do not engage
  principle I.
- **1.1.0** (2026-08-27) — Technology Constraints amended: dropped the `go-modules`
  dependency in favour of a self-contained module (`doyensec/safeurl`,
  `google/go-github`, own URL parser); replaced `sqlc` + `pressly/goose` with
  `uptrace/bun` for object mapping, migrations and fixtures; replaced the direct
  `aws-sdk-go-v2/service/s3` data path with `gocloud.dev/blob`. No principle changed.
