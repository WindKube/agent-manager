# Implementation Plan: Agent Manager — self-hosted plugin & skill registry

**Branch**: `001-agent-manager-hub` | **Date**: 2026-08-27 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-agent-manager-hub/spec.md`

## Summary

Build the ten screens of `docs/design/agent-manager.dc.html` as one Go module producing
one binary and one container image, run as four roles — `serve api`, `serve web`,
`worker fetcher`, `worker scanner` — over PostgreSQL, MinIO and Keycloak, all started by a
single `docker compose up`. (Keycloak rather than Dex: see R6, resolved by measurement.)

The spine is fetch → freeze → scan. A user-supplied source is pulled through an
SSRF-hardened client, extracted under hard caps, validated against the package schema,
written once to object storage with a digest, then statically analysed by a rule pack
that parses shell scripts into an AST rather than grepping them. Everything else —
catalog facets, profile resolution, the gate policy, the device flow, the audit trail —
hangs off versions produced by that spine.

The role split follows the credential boundaries the design itself drew: the web role
holds no datastore credential and reaches data only through the api role over a generated
HTTP client; the fetcher is the only role that can write bundle bytes; the scanner reads
bytes and writes verdicts.

## Technical Context

**Language/Version**: Go 1.26.5 (matching the monorepo's pinned toolchain)

**Primary Dependencies**:
`gin` + `danielgtaylor/huma/v2` (REST with OpenAPI 3.1 emission) ·
`oapi-codegen/v2` (web→api client) ·
`a-h/templ` + `starfederation/datastar-go` + Tailwind standalone (UI, no Node) ·
`jackc/pgx/v5` + `uptrace/bun` (object mapping, relations, fixtures) ·
**Atlas** + `ariga.io/atlas-provider-bun` (versioned migrations diffed from the Bun models) ·
`riverqueue/river` (Postgres-backed jobs) ·
`gocloud.dev/blob` + `klauspost/compress/zstd` (bundles) ·
`coreos/go-oidc/v3` + `golang.org/x/oauth2` (identity, RFC 8628) ·
`santhosh-tekuri/jsonschema/v6` + `goccy/go-yaml` + `mvdan.cc/sh/v3/syntax` (scanning) ·
`caarlos0/env/v11` + `spf13/cobra` + `rs/zerolog` + `samber/lo` (house standard) ·
`Masterminds/semver/v3` (resolution).
`doyensec/safeurl` (SSRF-hardened outbound client) + `google/go-github/v66` (repository
access). **No dependency on the monorepo's `go-modules`** — this module is self-contained.

**Storage**: two PostgreSQL 16 databases. The application database holds the relational
model and the outbox, reached through one `pgxpool` that Bun rides via
`stdlib.OpenDBFromPool`. The queue database holds River alone, on its own pool and its own
connection URL. S3-compatible object
storage (MinIO locally) for immutable bundles, manifests, scan reports and profile
lockfiles, behind `gocloud.dev/blob` so tests can run against `memblob` with no container.

**Testing**: `stretchr/testify` for table-driven unit tests; `testcontainers-go` for
anything crossing Postgres, MinIO or the OIDC provider; a fixture corpus of hostile and
benign bundles as the scanner's regression suite.

**Target Platform**: Linux containers, `linux/amd64` and `linux/arm64`, distroless or
debian-slim per the monorepo's existing Dockerfiles.

**Project Type**: Multi-role web service — one module, one image, four run-time roles.

**Performance Goals**: catalog query p95 < 300 ms at 10k packages / 50k versions; median
fetch-to-verdict < 60 s; a 25 MB archive extracted and digested in < 10 s.

**Constraints**: no Node.js in any image; the scanner never executes bundle content; the
web role holds no datastore credential; `docker compose up` must be the only setup step.

**Scale/Scope**: single organisation; thousands of packages; ten screens; four roles.

## Constitution Check

*GATE: evaluated before Phase 0 and re-evaluated after Phase 1 design.*

| Principle | Pre-design | Notes |
| --- | --- | --- |
| I. One module, one image, roles as subcommands | PASS | One `module agent-manager`; `cmd/agent-manager` with `serve api`, `serve web`, `worker fetcher`, `worker scanner`, `seed`, `healthcheck`. No second module, no second image. |
| II. Least privilege between roles | PASS | Four distinct env-var credential sets in `compose.yaml`; the web service is given no `DATABASE_URL` and no S3 keys; the scanner is given read-only S3 credentials. Enforced by a test that boots each role with only its own environment. |
| III. Untrusted input is the default | PASS | `safeurl` at every user-URL call site, proven by this project's own rebinding and redirect tests (Phase 0 item 10); a project-owned extractor with explicit caps; static-only analysis; `templ` auto-escaping with a lint rule banning `templ.Raw` on package-derived content. |
| IV. Immutability and provenance | PASS | Unique constraint on `(package_id, version)`; content-addressed keys; a commit-last visibility rule; an audit write in the same transaction as every mutation. |
| V. Contract-first, generated | PASS | huma operations emit OpenAPI 3.1; the web role's client is generated by `oapi-codegen` in `task gen`; CI fails if generated output is stale. |
| VI. It runs with one command | PASS | `compose.yaml` brings up postgres, minio (+ bucket init), keycloak, two chained migration init containers, api, web, fetcher, scanner, then `seed` as a one-shot. The Atlas image is third-party infrastructure and does not engage principle I. |
| VII. Workers are declarative plugins | PASS | `worker.Definition` + a single `registry.go` list; `Needs` drives what the bootstrap constructs; the scanner receives `blob.Reader` with no writer in scope. Same registry pattern for scanner checks and fetch sources. |
| VIII. Command/query separation | PASS | `internal/api/commands/` and `internal/api/queries/`; exactly one projection (`catalog_entry`), synchronous on structural change and asynchronous on verdict change. No read replica, no event sourcing, no command bus. |

**Post-design re-check (completed 2026-08-27, after Phase 1):**

| Principle | Post-design | Evidence |
| --- | --- | --- |
| I | PASS | One module; roles are subcommands. The Atlas init container is third-party infrastructure (principle VI clause). |
| II | PASS | Now enforced at three layers, not one: Go types (`Deps.BlobWrite` nil for the scanner), Postgres grants (`am_scanner` cannot write `digest`/`object_key`), and absent environment (`am_web` has no DSN). `contracts/worker.md` states which layer covers which boundary so nobody assumes more safety than exists. |
| III | PASS, with an owed proof | R10 makes `safeurl` adoption conditional on a six-case test suite this project owns, with a stated fallback. Extraction caps are numbered with reasons in R3. |
| IV | PASS | `unique (package_id, semver)`; `visible` commit-last flag; `audit_event` append-only by revoked grant rather than convention. |
| V | PASS | `contracts/openapi.yaml` is explicitly scoped to the frozen machine-facing surface, with a CI check that the generated document stays a superset. Web schemas are not duplicated. |
| VI | PASS | `quickstart.md` is one command; two chained migration init containers; Keycloak gives a working login offline, with a `groups` claim that differs per user (R6). |
| VII | PASS | `contracts/worker.md` fixes `Definition`/`Needs`/`Deps` plus the `Check` and `Source` registries. Adding a worker touches one list. |
| VIII | PASS, strengthened | R12 makes the single sanctioned projection **conditional on measurement** — if base-table indexes hold SC-003, it is not built and the allowance stays unspent. |
| IX | PASS | Two databases, two URLs, `outbox` table with a relay in `api`; idempotency keys named in R5 and enforced by `unique (version_id, pack_version)`. |

No violations. The Complexity Tracking table below is intentionally empty.

**One requirement change came out of Phase 0**, not out of design pressure: research R1
found that neither package spec defines a permissions model, so the capability model
inverted from *declared* to *inferred*. `spec.md` FR-004, FR-016–FR-019, FR-027 and FR-048
are amended accordingly, with FR-018a and FR-048a added.

## Project Structure

### Documentation (this feature)

```text
specs/001-agent-manager-hub/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0 output — decisions and rejected alternatives
├── data-model.md        # Phase 1 output — entities, relations, constraints
├── quickstart.md        # Phase 1 output — from clone to running stack
├── contracts/           # Phase 1 output — OpenAPI, rule-pack schema, lockfile schema
│   ├── openapi.yaml
│   ├── rulepack.schema.json
│   └── lockfile.schema.json
└── tasks.md             # Phase 2 output — /speckit-tasks, not created here
```

### Source Code (repository root)

```text
agent-manager/
├── cmd/agent-manager/           # main + cobra root; every role is a subcommand
├── internal/
│   ├── config/                  # caarlos0/env structs, one per role
│   ├── logging/                 # zerolog setup, correlation ids
│   ├── domain/                  # entities and pure rules, no I/O
│   │   ├── pkgspec/             # Agent Plugins 1.0.0 + Agent Skills manifest models
│   │   ├── resolve/             # semver policy + gate application -> lockfile
│   │   └── capability/          # manifest -> declared capability levels
│   ├── store/
│   │   ├── models/              # bun structs + relations — the schema source of truth
│   │   ├── migrations/          # Atlas-generated versioned SQL + atlas.sum
│   │   ├── fixtures/            # bun/dbfixture YAML — the design's dataset
│   │   └── projection/          # the one sanctioned read model: catalog_entry
│   ├── blob/                    # gocloud.dev/blob; owns key layout, digest, commit-last
│   ├── bundle/                  # SECURITY: archive extraction under caps; tar.zst pack
│   ├── fetch/                   # URL + repo + upload sources, all via safeurl
│   ├── repourl/                 # project-owned repository URL parser
│   ├── scan/
│   │   ├── rules/               # the rule pack loader
│   │   ├── rulepack/            # the shipped rules, as data
│   │   ├── checks/              # schema, network, shellast, secrets, injection, fs, deps
│   │   └── fixtures/            # hostile + benign corpus, one dir per rule
│   ├── worker/                  # Definition, Needs, Deps, registry.go — the plugin seam
│   │   ├── fetcher/             # Needs{DB: RW, Blob: RW, Outbound: true}
│   │   └── scanner/             # Needs{DB: RW, Blob: Read, Outbound: false}
│   ├── audit/                   # append-only event writer
│   ├── auth/                    # OIDC, group->role mapping, device flow, sessions
│   ├── api/
│   │   ├── commands/            # mutations: domain -> one transaction -> audit row
│   │   └── queries/             # read-only; purpose-built SQL, may bypass the mapper
│   ├── apiclient/               # oapi-codegen output, consumed by web/
│   ├── web/
│   │   ├── views/               # templ components, one package per screen
│   │   ├── static/              # generated app.css
│   │   └── handlers/            # datastar SSE handlers
│   └── seed/                    # the design's dataset
├── assets/input.css             # Tailwind entry; design tokens as CSS variables
├── specs/                       # spec-kit artefacts (this directory)
├── docs/design/                 # imported design source of truth
├── atlas.hcl                    # external_schema loader + the `bun` env
├── Dockerfile
├── compose.yaml
├── Taskfile.yaml
└── go.mod                       # module agent-manager — no replace directives
```

**Structure Decision**: single Go module rooted at `agent-manager/`, matching
`technologia` and `arc-ui`. Roles are cobra subcommands under `cmd/agent-manager`, not
separate binaries or directories — Constitution principle I. `internal/api` is the only
package permitted to import `internal/store` and `internal/blob`; `internal/web` may
import only `internal/apiclient` and `internal/domain`. That import rule is the compiled
expression of the credential boundary and is enforced by a lint check, because an env-var
boundary alone erodes the first time someone "just needs one query".

Two monorepo-level edits are part of this feature, not follow-up chores: adding
`!agent-manager/` to the root `.dockerignore` allowlist, and adding `agent-manager` to the
`project-name` choices in `.github/workflows/build-image.yaml`. Omitting either makes the
image build fail with a misleading "file not found".

## Phase 0 — Research

Open questions to settle in `research.md` before any design work. Each gets a decision, a
rationale, and the alternatives rejected.

1. **Agent Plugins 1.0.0 and Agent Skills schemas.** Locate the authoritative published
   schemas. Reconcile them against the design's illustrative manifests — the design shows
   both an `agentPluginsVersion`/`components` shape and an `openplugin/v1`/`entry` shape,
   which cannot both be current. Decide which is normative and adjust the seed fixtures.
2. **Rule-pack format.** The declarative schema for a rule: identifier, severity, the
   check it drives, its matcher (AST predicate vs. regex vs. schema path), its evidence
   extraction, and its fixture references. Must express all four seeded rules
   (`SH-NET-002`, `SH-INJ-011`, `SH-DEP-004`, `SH-FS-007`) without escaping into Go.
3. **Extraction caps.** Concrete numbers for entry count, per-entry size, total
   decompressed size, path depth and compression ratio, with the reasoning for each. These
   are security parameters; they get chosen deliberately, not guessed.
4. **Catalog query shape.** Whether facet counts and the filtered page come from one
   round trip or two, and the index set (GIN on the tag array, tsvector for search) that
   holds the p95 at target scale. Validate with a generated 10k/50k dataset.
5. **Outbox relay design.** River lives in its own database, so transactional enqueue is
   gone and is rebuilt with an outbox. Settle: the relay's delivery loop (`LISTEN/NOTIFY`
   plus a periodic sweep for missed notifications), its at-least-once semantics, where the
   idempotency key lives so a redelivered fetch or scan is a no-op, and which role runs the
   relay. Confirm River's periodic jobs still cover the rescan policy from a database that
   holds no application state.
6. **Local IdP device-flow parity.** Verify the local IdP implements the device
   authorisation grant and emits a groups claim, so the local stack exercises the same code
   path as Okta. **Resolved**: Dex does not emit `groups` for a static user; the local IdP is
   Keycloak. See R6.
7. **Datastar interaction budget.** Prototype the hardest interaction on the catalog
   screen — the typeahead-filtered multi-select facet with live counts — and confirm it is
   comfortable in datastar before committing every screen to it. This is the one place the
   chosen frontend approach could bite; find out in Phase 0, not in week three.
8. **Usage counting.** How "42 uses" and "184 installs" are derived from profile
   membership and sync events without a write on every read.
9. **Signature policy without verification.** Exactly what `require signed bundles`
   enforces in this phase, and the shape of the record so real Sigstore verification can
   land later without a schema migration.
10. **`safeurl` behavioural parity.** Prove, with this project's own tests, that the chosen
    client refuses: a public hostname that redirects to `127.0.0.1` mid-chain, a hostname
    resolving to both a public and a private address, and a redirect to a link-local
    metadata endpoint. If any case passes through, fall back to an owned
    `net.Dialer{Control: ...}` implementation. This is the one capability the project used
    to inherit and must now prove for itself.
11. **Atlas isolation.** With River in a separate database the drop-the-queue-tables hazard
    is structural rather than configured, but verify it: run `atlas migrate diff` with River
    fully migrated and assert the generated migration is empty.
12. **Projection consistency rule.** Validate that `catalog_entry` can be updated inside the
    registration transaction without lock contention against a concurrent scan backlog, and
    measure whether it is actually needed at 10k/50k — if base-table indexes hold SC-003's
    300 ms p95 on their own, the projection is dropped rather than kept "for later".
13. **`gocloud.dev/blob` escape hatches.** Confirm `bucket.As()` yields the raw S3 client
    needed for the Storage screen's bucket-settings report (object lock, SSE-KMS,
    versioning, retention), and that `memblob` is faithful enough to keep the bundle
    pipeline's unit tests container-free.

## Phase 1 — Design

Produced after Phase 0 research is settled:

- **`data-model.md`** — every entity from the spec as tables with keys, constraints and
  indexes. The load-bearing constraints: unique `(package_id, version)`; append-only
  audit enforced by a revoked `UPDATE`/`DELETE` grant, not by convention; sequential
  per-profile revision numbers allocated so two racing publishes get two revisions with no
  gap; a partial index for open findings.
- **`contracts/openapi.yaml`** — emitted from the huma operation definitions, not
  hand-written. Covers the web role's needs and the frozen CLI-facing surface: device
  authorisation, profile list, revision resolution, bundle download.
- **`contracts/rulepack.schema.json`** — the rule-pack format from research item 2, so a
  rule pack can be validated in CI.
- **`contracts/lockfile.schema.json`** — the resolved revision written to
  `profiles/<slug>/r<N>.json`, including the skip-reason entries required by FR-036.
- **`quickstart.md`** — clone to running stack, the seeded tour matching the design, and
  the `curl` walkthrough of the device flow.
- **`contracts/worker.md`** — the `Definition` / `Needs` / `Deps` contract, plus the `Check`
  and `Source` interfaces, written as the thing a future contributor reads before adding a
  worker. It states which boundaries the type system enforces (blob access) and which are
  enforced by database grants instead (read-only DB access), because that distinction is
  where someone will otherwise assume more safety than exists.

Design work is done when the post-design Constitution Check above is filled in and the
role import rule is expressible as a lint check.

## Phase 2 — Tasks

Not produced here. `/speckit-tasks` will decompose against the spec's eight user stories,
in priority order, with the P1 stories forming the MVP: register a source (US1), browse
the catalog (US2), inspect a package (US3), triage a finding (US4). Each story must be
independently demonstrable on the seeded stack.

## Complexity Tracking

> One deviation from the Technology Constraints table, taken on the evidence R10 demanded.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| The outbound SSRF client is owned by this project (`internal/fetch`, `net.Dialer.Control`) rather than `doyensec/safeurl`, which the constitution's Technology Constraints table names. | R10 made adoption conditional on a six-case suite this project owns, and safeurl **fails case 2**. Its only control is a `Dialer.Control` hook that fires per connect attempt, so a name answering with both a public and a private address has the private attempt refused and then connects over the public one — probed against v0.2.5 with a real resolver, debug log captured in the T009 commit message. It also cannot express "permit exactly this one loopback origin", so cases 2 and 4 could not be tested hermetically against it at all. | Adopting safeurl anyway was rejected because an SSRF control that does not fire looks identical to one that does — that is precisely why R10 required the proof rather than the README. `tasks.md` already carried this outcome: "T008/T009 (R10) — Build the owned `Dialer.Control` client." The owned client refuses the whole address set when any member is non-public, re-resolves at connect time, and keeps `Control` as defence in depth; all six cases pass and each was mutation-tested to prove it can fail. |

**Consequence for the constitution**: the Technology Constraints table's `doyensec/safeurl` entry is
now stale for this project. It should read "a project-owned SSRF-hardened client, proven by
`internal/fetch/safe_test.go`" at the next amendment. The dependency is dropped from `go.mod`.
