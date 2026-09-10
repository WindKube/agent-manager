# Feature 004 Plan: Second Scan Engine

## Shape

The scanner grows a second analyzer behind an interface it already almost has. Today
`Worker.analyse` calls one thing: `checks.Registry.Run`. After this feature it walks a
list of analyzers, both producing the same `[]checks.CheckRun` and `[]checks.Finding`, and
everything downstream — grading, the record transaction, the verdict, the API, the UI —
sees the vocabulary it already sees.

```
Worker.analyse
  ├── rulepack analyzer   (existing registry, unchanged)   -> checks.CheckRun/Finding
  └── engine analyzer     (new)                            -> checks.CheckRun/Finding
        └── engine.Client -> HTTP -> skill-scanner-api sidecar
```

`checks` keeps the shared vocabulary and gains no import. The engine package imports
`checks`; nothing imports the engine package but the scanner. That is the whole dependency
story.

## Why an interface rather than two calls in `analyse`

Two calls in `analyse` is fewer lines today and an edit to `analyse` for every engine
after. The interface costs one small type and makes the third engine a registration.
Principle VII already mandates this shape for the two other things that grow by
accretion — scanner checks and fetch sources — so this is the house pattern, not a new
abstraction.

The subject passed to an analyzer carries the in-memory tree and a lazily-built zip. Lazy
matters: with no engine configured, no zip is ever built and the rule-pack path allocates
exactly what it allocates today.

## Constitutional review

Two principles are engaged. Both are argued here rather than quietly stretched.

### Principle III — "The scanner performs static analysis only. No `exec`, no interpreter"

**Substance is preserved; wording needs a clarification.** The clause exists to forbid
running bundle content. Every analyzer this feature enables is static — Cisco's own
documentation states no analyzer executes skill code, and the `behavioral_analyzer` is AST
dataflow, not a sandbox. Nothing from a bundle is executed by us or by the engine.

The literal words "no interpreter" would nonetheless forbid an engine written in Python.
The constitution's amendment is therefore to name what the clause protects:

> The scanner never executes, sources, imports or evaluates anything **from a bundle**.
> A pinned, third-party, static-analysis engine may read an extracted tree, provided it is
> reached over a documented interface, its analyzer set is fixed in code, and no analyzer
> that executes bundle content or reaches a network is enabled.

Enforced in code, not prose: the request builder sends every network-reaching analyzer
toggle explicitly false, and `engine.New` refuses to start if configuration asks for one.

### Principle I — "One module, one image"

**Not engaged.** Principle VI settles it: "'One image' governs code this project writes.
Third-party images the stack composes — Postgres, MinIO, Dex, the Atlas migration
runner — are infrastructure, not a second build."

The engine image contains no code this project writes. Its Dockerfile is a pinned pip
install of an Apache 2.0 package and the tool's own entrypoint. It is the Atlas runner
case: infrastructure the stack composes.

The rejected alternative was adding Python to the scanner's own image and running the CLI
as a subprocess. It is simpler by a service and an HTTP hop, and it was rejected on
principle II, which is non-negotiable:

- It replaces the scanner's distroless base with a Python one, in the one role that reads
  hostile bytes.
- Cisco's static analyzer uses YARA, a C extension, to parse attacker-controlled input.
  A memory-safety bug there would land in a process holding the database credential and
  the object-store read key.
- Under a sidecar, that same bug lands in a process holding no credential, on a network
  with no egress, reachable only from the scanner.

The sidecar is more moving parts and strictly better least privilege. Principle II wins.

## Work

Ordered so each layer is reviewable and the stack rebases cleanly.

### 1. Engine client — `internal/worker/scanner/engine`

| File | Contents |
| --- | --- |
| `engine.go` | `Client` interface, `Options`, `New`, the analyzer-toggle guard |
| `cisco.go` | HTTP calls to `/health` and `/scan-upload`; timeouts, one retry-free attempt per job attempt |
| `report.go` | The response types, parsed defensively: unknown fields ignored, `findings_count`/`is_safe` cross-check (R11) |
| `mapping.go` | Report to `[]checks.CheckRun` and `[]checks.Finding`; severity map (R7), report threshold (R8) |
| `zip.go` | `bundle.Bundle` to zip bytes; non-executable modes, zeroed mtimes |

`bundle.Pack` is not reused: it emits tar.zst and its output is a published version's
identity. A zip for an external tool has no digest contract and must not share that code
path.

The client is an interface so the scanner's tests run against a stub and the integration
test runs against the pinned image.

### 2. Analyzer seam — `internal/worker/scanner`

- `analyzer` interface, `subject` with the lazy zip.
- `rulepackAnalyzer` wrapping the existing registry. No behaviour change.
- `engineAnalyzer` wrapping `engine.Client`, including the R9 `ENG-UNAVAILABLE` finding.
- `analyse` walks the list; the fingerprint (R15) joins each analyzer's own.
- `Needs.Engine` on `worker.Needs`, `Deps.Engine` on `worker.Deps`, constructed by
  `worker.Build` — the role declares it, per principle VII, and a role that did not
  declare it gets nil.

### 3. Schema and surface

- Bun models gain `Engine` on `Finding` and `ScanCheck`; `atlas migrate diff` generates
  the SQL. Default `rulepack` backfills existing rows.
- `am_scanner` needs no new grant: it already holds `insert, update` on both tables.
- huma contract gains `engine` on the finding and check-row types; `task gen` regenerates
  OpenAPI and both clients.
- Findings list and check matrix group by engine.

### 4. Compose and image

- `deploy/local/skill-scanner/Dockerfile` — pinned pip install, `skill-scanner-api` on
  localhost inside its container.
- `compose.yaml` — the `skill-scanner` service on an internal network shared only with
  `scanner`; no credentials in its environment; `/health` as its healthcheck.
- `scanner` gains `AGENT_MANAGER_SCAN_ENGINE_URL` and depends on it being healthy.

## Tests

| Layer | What it proves |
| --- | --- |
| `engine` unit | Severity map, report threshold, the R11 cross-check, zip determinism and non-executable modes |
| `engine` unit | A configuration asking for an LLM or VirusTotal analyzer fails `New` |
| `scanner` unit | Two analyzers merge; an engine error on the last attempt records `ENG-UNAVAILABLE`; with `Required` false it records a warning instead |
| `scanner` unit | The fingerprint changes when the engine version changes and not otherwise |
| `scanner` integration | Against the pinned engine image: a base64-obfuscated payload the rule pack passes is flagged and attributed |
| `scanner` integration | The engine container cannot reach Postgres, MinIO or the internet |

The obfuscated-payload fixture is the acceptance test for the whole feature. Without it
this is a refactor that added a network call.

## Complexity Tracking

| Deviation | Justification | Cheaper alternative rejected because |
| --- | --- | --- |
| A fourth service in compose | R2 isolation; principle VI exempts third-party images from principle I | Python in the scanner image puts a C-extension parser of hostile input next to the database credential |
| An HTTP hop inside a scan | The engine's only documented machine interfaces are its CLI and its REST server | The CLI needs an interpreter in our image, which is the same deviation with worse isolation |
| `Needs.Engine` widens the worker framework | Principle VII: a role declares what it needs and the bootstrap constructs exactly that | Reading the URL from config inside the role hides a capability from the declaration that principle II is checked against |
| Response shape parsed against partly undocumented JSON | Pinned engine version, plus the R11 cross-check degrading rather than passing on mismatch | Trusting the shape silently records `clean` when the engine changes a field name |

## Risks

- **The engine's finding-object shape is not fully documented.** Mitigated by pinning the
  version, ignoring unknown fields, and R11. An engine bump is a deliberate change with a
  test to run, not a dependabot merge.
- **Rescan load.** R16 re-fingerprints every version at once. The sweep already exists and
  is rate-limited by scanner concurrency; the operator sees it as queue depth.
- **The engine is unauthenticated by design** and its own docs say not to expose it beyond
  localhost. Here "localhost" is an internal compose network with one peer and no egress.
  Any deployment that puts it on a shared network is a misconfiguration this plan does not
  cover.
