# Tasks: Agent Manager — self-hosted plugin & skill registry

**Input**: `/specs/001-agent-manager-hub/` — spec.md, plan.md, research.md, data-model.md, contracts/

**Tests**: Included. The constitution mandates them (Development Workflow), and SC-005/006/008
are only meaningful as executable assertions.

## Format: `[ID] [P?] [Story] Description`

- **[P]** — parallelisable: different files, no dependency on another unstarted task
- **[Story]** — the user story this serves; `—` for shared infrastructure

Paths are relative to `agent-manager/`.

**MVP = Phases 1–3 plus US1–US4.** That is a registry that ingests, freezes, scans,
adjudicates and is browsable. US5–US8 are increments on top.

---

## Phase 1: Setup

- [ ] T001 `go mod init agent-manager`; Go 1.26.5; **no `replace` directives**. Add `.golangci.yml` matching monorepo style.
- [ ] T002 [P] Cobra root in `cmd/agent-manager/` with `serve api`, `serve web`, `worker run <name>`, `migrate queue`, `seed`, `healthcheck`, `version`. Every subcommand a stub that exits 0.
- [ ] T003 [P] `internal/config/` — one `caarlos0/env` struct per role. A role's struct MUST NOT contain a field it has no business reading (`web` has no `DatabaseURL` field at all, not an unused one).
- [ ] T004 [P] `internal/logging/` — zerolog, JSON/console by env, request and job correlation ids.
- [ ] T005 [P] `Taskfile.yaml` — `gen`, `gen:templ`, `gen:css`, `gen:client`, `migrate:diff`, `migrate:apply`, `test`, `test:integration`, `lint`, `build`. Tailwind standalone downloaded to `.bin/` (arc-ui pattern).
- [ ] T006 Add `!agent-manager/` to the **root** `.dockerignore` allowlist and `agent-manager` to the `project-name` choices in `.github/workflows/build-image.yaml`. **Do this now** — omitting it fails the build later with a misleading "file not found".
- [ ] T007 Multi-stage `Dockerfile`. Note: with no `replace` directive the local build context can be the project directory, but CI passes the repo root — keep the `COPY` paths repo-root-relative so both work.

---

## Phase 2: Foundational — blocks every user story

**⚠️ No story work starts until this phase is green.**

### Security primitives (do these first; everything untrusted flows through them)

- [ ] T008 **[R10 GATE]** `internal/fetch/safe_test.go` — the six-case suite from research R10: redirect-to-loopback, dual public/private A-records, link-local metadata, DNS rebinding, non-HTTP scheme, and a legitimate public host that MUST pass. Write the tests **before** choosing the client.
- [ ] T009 `internal/fetch/` — adopt `doyensec/safeurl` behind a `fetch.Client` interface. If T008 fails on any of cases 1–5, implement the `net.Dialer.Control` fallback instead. Ship whichever passes.
- [ ] T010 `internal/bundle/extract.go` — **SECURITY**. Extraction under the R3 caps: 25 MB compressed, 250 MB decompressed, 100:1 ratio checked *while streaming*, 10k entries, 25 MB per entry, depth 32, path 1024 B, 60 s wall clock. Reject absolute paths, `..` after cleaning, symlinks, hardlinks, devices, FIFOs, duplicate paths.
- [ ] T011 [P] `internal/bundle/extract_test.go` — table-driven, one case per cap and per rejected member kind, plus a real zip bomb and a tar with a symlink escape.
- [ ] T012 [P] `internal/repourl/` — project-owned parser (owner, repo, ref, subdirectory) with a table test over the messy shapes: bare `owner/repo`, scp-style, `.git` suffix, `?query`, `#fragment`, `www.` host.

### Persistence

- [ ] T013 `internal/store/models/` — Bun structs for every table in data-model.md, with relations. Enums as Postgres enum types.
- [ ] T014 `atlas.hcl` + `ariga.io/atlas-provider-bun` loader (`--dialect postgres`), `tools.go` pin. Generate the initial migration; commit SQL **and** `atlas.sum`.
- [ ] T015 Migration for the constraints that carry meaning, not just shape: `unique (package_id, semver)`, `unique (version_id, pack_version)`, `unique (profile_id, seq)`, `check (id = 1)` on `org_policy`, `check (mode <> 'pinned' or pinned_version_id is not null)`.
- [ ] T016 Migration creating roles `am_api`, `am_fetcher`, `am_scanner`, `am_migrate` with the grants in data-model.md. **Revoke `UPDATE`/`DELETE` on `audit_event` from every role** — this is how FR-052 is enforced.
- [ ] T017 [P] Indexes: GIN on tags, GIN on tsvector, partial `(verdict) where visible`, partial `(version_id) where state='open'`, partial `(created_at) where state='pending'` on outbox, `(occurred_at desc)` on audit.
- [ ] T018 `internal/store/db.go` — one `pgxpool` for `agent_manager`, Bun via `stdlib.OpenDBFromPool`; a **separate** pool for `river`. Two URLs, never one.
- [ ] T019 [P] `internal/store/store_test.go` — testcontainers Postgres; assert `unique (package_id, semver)` rejects a differing-bytes republish, and that `UPDATE audit_event` fails as the app role.

### Blob

- [ ] T020 `internal/blob/` — `gocloud.dev/blob`; `Reader` and `Writer` as **separate interfaces**. The key layout from the design, sha256-on-write, and **commit-last**: staging prefix, then `index.json` written last.
- [ ] T021 [P] `internal/blob/blob_test.go` — against `memblob`. Assert a version is invisible until `index.json` names it, and that an interrupted write leaves nothing readable.

### Queue and hand-off

- [ ] T022 `internal/outbox/` — writer (inside caller's transaction) and relay (`LISTEN outbox_new` + 10 s sweep, `FOR UPDATE SKIP LOCKED`, prune at 24 h). Relay hosted in `api`.
- [ ] T023 [P] `internal/outbox/relay_test.go` — a rolled-back transaction enqueues nothing; a committed one always delivers; a redelivered row is a no-op.
- [ ] T024 `agent-manager migrate queue` — River's own migrator against `RIVER_DATABASE_URL`.
- [ ] T025 **[R11 GATE]** Test: migrate River fully, run `atlas migrate diff`, assert the generated migration is **empty**. Catches anyone later collapsing the two URLs onto one database.

### Worker framework

- [ ] T026 `internal/worker/` — `Definition`, `Needs`, `Access`, `Deps`, `Build()`, `registry.go`, exactly as `contracts/worker.md` specifies. `Build` returns nil for undeclared capabilities.
- [ ] T027 [P] `internal/worker/worker_test.go` — a Definition declaring `Blob: AccessRead` gets a nil `BlobWrite`; `Build` fails fast when config lacks a declared credential.

### API and web skeletons

- [ ] T028 `internal/api/` — gin + huma, OpenAPI 3.1 at `/v1/openapi.json`, `/v1/health`, error shape, correlation-id middleware. Split `commands/` and `queries/` from the first handler (principle VIII).
- [ ] T029 `internal/auth/` — OIDC discovery, ID-token verification, `groups` → role mapping, opaque Postgres sessions (token hashed at rest).
- [ ] T030 [P] `internal/apiclient/` — `oapi-codegen` wired into `task gen:client`; CI fails on stale output.
- [ ] T031 `internal/web/` — templ + datastar skeleton, `assets/input.css` carrying the design's CSS-variable palette as Tailwind tokens, light/dark from `data-sm-theme`, shell + sidebar nav.
- [ ] T032 **[R7 GATE]** Spike the catalog's typeahead-filtered multi-select facet with live counts in datastar. Exit criterion: instant typing at 50 options, table update < 300 ms. **If it fails, stop and adopt the Alpine.js fallback before building any other screen.**
- [ ] T033 [P] Lint rule enforcing the role import boundary: only `internal/api` may import `internal/store` or `internal/blob`; `internal/web` may import only `internal/apiclient` and `internal/domain`.
- [ ] T034 `compose.yaml` — postgres (two databases), minio + bucket init, dex (2 users, 2 groups, device grant), `migrate-schema` → `migrate-queue` chained on `service_completed_successfully`, api, web, fetcher, scanner, seed one-shot, `queue-ui` profile. Env per the quickstart table; `web` gets **no** DSN and **no** blob URL.
- [ ] T035 [P] Test booting each role with **only** its own environment — proves SC-006 and that no role silently depends on a credential it should not have.

**Checkpoint**: `docker compose up` starts everything, all health checks green, no screens yet.

---

## Phase 3: US1 — Register a source, get a scanned immutable version (P1) 🎯 MVP

**Goal**: URL or archive in → immutable, digested, scanned version out.
**Independent test**: register from both paths; see a digest, an object key and a verdict.

- [ ] T036 [P] [US1] `internal/domain/pkgspec/` — Agent Plugins manifest model (the **ten** real fields, `additionalProperties: false`) and Agent Skills frontmatter (`name`, `description`, `license`, `allowed-tools`, `metadata`, `compatibility`). Embed both published schemas.
- [ ] T037 [P] [US1] Manifest validation via `santhosh-tekuri/jsonschema/v6`, dispatching on the `$schema` `$id`. Errors report the failing schema path (US1 scenario 3).
- [ ] T038 [US1] Component derivation **from the file tree** — `skills/*/SKILL.md`, `mcp.json`, reverse-domain dirs. No manifest field lists components (R1).
- [ ] T039 [P] [US1] `internal/fetch/source_*.go` — the three `Source` implementations (upload, git, archive-url) behind the registry from `contracts/worker.md`.
- [ ] T040 [US1] Spec-layout filter: keep `plugin.json`, `skills/`, `mcp.json`, reverse-domain dirs; drop everything else and **report what was dropped** (FR-005, US1 scenario 2).
- [ ] T041 [US1] `POST /v1/packages/preview` — pre-submit entry list with per-entry validation marks, matching the design's archive-contents panel.
- [ ] T042 [US1] `POST /v1/packages` command — validate, create package/version rows, write the outbox `fetch` job, write the audit row. **All in one transaction.**
- [ ] T043 [US1] `internal/worker/fetcher/` — `Definition()` with `Needs{DB: RW, Blob: RW, Outbound: true}`; fetch → extract → pack `tar.zst` → digest → commit-last write → flip `visible` → outbox a `scan` job.
- [ ] T044 [P] [US1] Immutability: translate the `unique (package_id, semver)` violation into the FR-007 error. Test that stored bytes are untouched after a rejected republish.
- [ ] T045 [P] [US1] Fetch-error path distinct from scan-failure path, including the SSRF refusal (US1 scenario 5) — surfaced as a fetch error, never a finding.
- [ ] T046 [US1] Import modal UI: both tabs, the drop zone, the archive-contents list, category and visibility selects, the explanatory note, disabled-until-attached submit.
- [ ] T047 [P] [US1] Integration test: register from a local git fixture and from an archive; assert digest, object key, `visible`, audit row with actor `fetcher`, and a queued scan job.

**Checkpoint**: US1 independently demonstrable.

---

## Phase 4: US2 — Browse and narrow the catalog (P1) 🎯 MVP

- [ ] T048 [US2] `internal/api/queries/catalog.go` — the R4 two-query shape: filtered page and facet counts issued concurrently. Facet counts computed with that facet's own filter removed.
- [ ] T049 [P] [US2] Search across name, id, publisher, tags — substring, case-insensitive (FR-010).
- [ ] T050 [P] [US2] Kind and status filters. `Verified` = verified publisher **AND** clean verdict (US2 scenario 3).
- [ ] T051 [US2] Facets: multi-select, per-option counts, typeahead filtering, Clear. **Tags AND, categories OR** (FR-013) — the asymmetry is deliberate and needs its own test.
- [ ] T052 [P] [US2] Sorting: name, uses, updated; desc then asc; arrow on the active column only.
- [ ] T053 [US2] Catalog screen in templ + datastar: table, chips, both facet menus, result count, empty state, reset control.
- [ ] T054 [P] [US2] Test asserting the exact result set and count for each seeded filter combination (SC-004).
- [ ] T055 **[R12 GATE]** [US2] Generate 10k packages / 50k versions; measure p95 against base tables. **If < 300 ms, do not build `catalog_entry`** and record that principle VIII's allowance is unspent. Only if it fails: build the projection with the sync-on-structural / async-on-verdict rule.

**Checkpoint**: catalog fully navigable over seeded data.

---

## Phase 5: US3 — Inspect a package (P1) 🎯 MVP

- [ ] T056 [P] [US3] `internal/domain/capability/` — **inference** from the scan: hosts from the shell AST and instruction URLs, filesystem scope from read/write targets, shell from commands present. Levels `scoped`/`allowlisted`/`review`; shell never below `review`.
- [ ] T057 [P] [US3] Read the *expected* capability set from `extensions["dev.agent-manager"]` (FR-018a) and store it as `capability` rows with `source = 'expected'`.
- [ ] T058 [US3] `GET /v1/packages/{id}` — description, origin line, tags, manifest, capabilities, versions with key + digest, dependent profiles.
- [ ] T059 [US3] Detail screen: plugin variant (tree + components) vs skill variant (no contents section, frontmatter as manifest, origin naming the parent plugin).
- [ ] T060 [P] [US3] Capabilities panel presenting **inferred vs expected** clearly. It must not read as an enforced permission grant — the specs define no such thing (R1).
- [ ] T061 [P] [US3] Versions panel: semver, dist tag (`pinned by N` derived, not stored), date, full object key, sha256.
- [ ] T062 [P] [US3] Test both variants render correctly for every seeded package.

---

## Phase 6: US4 — Triage a finding (P1) 🎯 MVP

- [ ] T063 [US4] `internal/scan/rules/` — rule-pack loader validating each YAML against `contracts/rulepack.schema.json`; `packVersion` recorded on every scan.
- [ ] T064 [US4] `internal/scan/checks/` — the `Check` interface and registry. Runner writes one `scan_check` row per registered check **including passes** (FR-025).
- [ ] T065 [P] [US4] `manifest-schema` check.
- [ ] T066 [US4] `shell-audit` check on `mvdan.cc/sh/v3/syntax` — walk the AST, extract command names, arguments and URL targets. This is the load-bearing one; `SH-NET-002` and `SH-DEP-004` both depend on it.
- [ ] T067 [P] [US4] `network-allowlist` check — discovered hosts vs the **expected** set (FR-027). No expected set ⇒ surface every host for review, do not pass silently.
- [ ] T068 [P] [US4] `secret-exfiltration` and `prompt-injection` checks — RE2 rule pack over instruction files.
- [ ] T069 [P] [US4] `filesystem-scope` and `dependency-pinning` checks (package.json, go.mod, requirements.txt).
- [ ] T070 [US4] Ship the four seeded rules as YAML, each with its `trips` and `clean` fixture bundle. CI fails a rule missing either.
- [ ] T071 [US4] `internal/worker/scanner/` — `Definition()` with `Needs{DB: RW, Blob: Read, Outbound: false}`. Time budget; a timeout records `timed_out` and retries with backoff, **never** resolves to clean (FR-031).
- [ ] T072 [P] [US4] Idempotency: `unique (version_id, pack_version)` makes a redelivered scan a no-op. Test the redelivery explicitly.
- [ ] T073 [US4] Scanner screen: four stats, findings list, detail pane with severity, rule id, subject, prose, evidence block, checks-run matrix.
- [ ] T074 [US4] Approve-with-note and reject commands: override row with reviewer/note/expiry, audit row, and a rejected version unresolvable by any profile regardless of gate (FR-029).
- [ ] T075 [P] [US4] Rescan-on-new-version: River periodic job → `rescan-sweep` → outbox fan-out. A new finding on an approved version reopens it (FR-030).
- [ ] T076 **[SC-005]** [US4] The hostile/benign corpus: undeclared egress, credential reads in instructions, unpinned postinstall, over-broad write scope, path traversal, symlink escape, zip bomb — **zero false negatives**; benign corpus — **zero false positives**.

**🎯 MVP COMPLETE** — ingests, freezes, scans, adjudicates, browsable.

---

## Phase 7: US5 — Profiles (P2)

- [ ] T077 [P] [US5] `internal/domain/resolve/` — semver policy (floating-latest, pinned, range) via `Masterminds/semver/v3`. Pure, no I/O.
- [ ] T078 [US5] Gate application: `block` → last clean version; `approval` → exclude unapproved; `warn-with-override` → include and record. Every exclusion produces a `skipped` entry with a reason (FR-036).
- [ ] T079 [P] [US5] Table test over the full matrix: 3 gates × 3 policies × {clean, flagged, rejected, no-clean-available, stale-pin}.
- [ ] T080 [US5] Profiles list screen: cards, visibility filter, counts.
- [ ] T081 [US5] Profile detail: entries with latest↔pinned toggle and resolved version, scan badge, policy note.
- [ ] T082 [US5] Publish revision: allocate `seq` under `SELECT ... FOR UPDATE` on the profile row, write the lockfile to `profiles/<slug>/r<N>.json` conforming to `contracts/lockfile.schema.json`, audit row.
- [ ] T083 [P] [US5] Concurrency test: two racing publishes produce `r15` and `r16` — **no gap, no overwrite**.
- [ ] T084 [P] [US5] Sharing: members and groups, four roles, union of permissions across groups.
- [ ] T085 [P] [US5] Share link and fork. A fork must have **no** mechanism to receive upstream revisions (FR-038).
- [ ] T086 [P] [US5] Sync-target toggles; server state unaffected.
- [ ] T087 [P] [US5] Revisions panel.

---

## Phase 8: US6 — Device authorisation and resolution (P2)

- [ ] T088 [US6] `POST /v1/device/authorize` — Crockford base32 user code (ambiguous glyphs excluded), device code **hashed at rest**, host bound, expiry.
- [ ] T089 [US6] `POST /v1/device/token` — RFC 8628 polling with `authorization_pending` / `slow_down` / `expired_token`. Single-use via the `pending → approved → consumed` transition in one transaction.
- [ ] T090 [US6] Browser approval flow through Dex, `login` audit row naming the host.
- [ ] T091 [P] [US6] Refusal tests: expired code, replayed code, approval by a different identity than the requester (FR-042).
- [ ] T092 [P] [US6] `GET /v1/profiles` — exactly the readable set, enumerated not filtered (FR-044).
- [ ] T093 [P] [US6] `GET /v1/profiles/{slug}/revisions/{revision}` and `GET /v1/bundles/...` with the `Digest` header.
- [ ] T094 [P] [US6] `POST /v1/sync` → `sync_event` + audit row.
- [ ] T095 [US6] Connect-the-CLI screen: three steps, live device code with countdown, profile selection, sync-result panel.
- [ ] T096 [P] [US6] Group-loss test: takes effect at next token refresh, not next login (FR-045).
- [ ] T097 [P] [US6] CI check that the generated OpenAPI remains a superset of `contracts/openapi.yaml`.

---

## Phase 9: US7 — Organisation (P3)

- [ ] T098 [P] [US7] IdP settings screen; secret rotation without revealing the current value; test-connection action.
- [ ] T099 [P] [US7] Group→role mapping CRUD.
- [ ] T100 [US7] Policy toggles wired to real behaviour: gate change affects the next resolution; signed-bundles refuses a version with no signature ref **and states it is unverified** (FR-048a); community-needs-review routes to a queue; rescan toggles the periodic job.
- [ ] T101 [P] [US7] Category admin with counts; tags stay manifest-derived and non-editable.
- [ ] T102 [P] [US7] Test each toggle changes downstream behaviour, not just its own row.

---

## Phase 10: US8 — Audit and storage (P3)

- [ ] T103 [P] [US8] Audit log screen: kind badges, actor, source, paging.
- [ ] T104 [P] [US8] CSV export of the **full current scope**, streamed, not the visible page (FR-051).
- [ ] T105 **[SC-008]** [US8] Exercise every mutating endpoint and assert the audit row count delta is exactly one.
- [ ] T106 [P] [US8] Storage screen: stats, key layout for `skills/` and `profiles/`, bucket settings via `bucket.As(&s3Client)`, recent fetches with outcome dots.

---

## Phase 11: Polish

- [ ] T107 [P] `agent-manager seed` — the design's dataset with **conformant** manifests, timestamps relative to seed time (SC-004).
- [ ] T108 [P] `healthcheck` subcommand — self-probing, usable by a shell-less container.
- [ ] T109 [P] Prometheus metrics: queue depth, scan duration histogram, fetch outcomes, outbox lag.
- [ ] T110 [P] **[SC-009]** WCAG AA contrast audit across all ten screens in both themes.
- [ ] T111 [P] **[FR-055]** Assert every manifest-, instruction- and evidence-derived string is escaped. Lint rule banning `templ.Raw` on package-derived content.
- [ ] T112 [P] **[SC-010]** Prove a new rule can be added, tested and take effect with no code change and no rebuild.
- [ ] T113 [P] `README.md` and `docs/` — the role/credential table, the worker-adding checklist, and the R1 finding (why the seeded manifests differ from the design).

---

## Dependencies

```
Phase 1 ──> Phase 2 ──> US1 ──> US2 ──> US3
                         │       │       │
                         └──────>US4<────┘      (needs versions + a bundle to scan)
                                 │
                    US5 ─────────┘  (gate application needs verdicts)
                     │
                    US6              (resolution needs profiles)
              US7, US8               (independent once Phase 2 lands)
```

**Gates that can change the plan** — do not defer these:

| Task | If it fails |
| --- | --- |
| T008/T009 (R10) | Build the owned `Dialer.Control` client. Blocks all fetching. |
| T025 (R11) | The two database URLs have been collapsed. Fix before any migration ships. |
| T032 (R7) | Adopt the Alpine.js fallback **before** building nine more screens. |
| T055 (R12) | Build the projection. Otherwise leave the allowance unspent. |

## Parallelisation

- Phase 1: T002–T005 together.
- Phase 2: security (T008–T012), persistence (T013–T019), blob (T020–T021) are three independent tracks.
- US2, US3 are largely parallel once US1 lands. US7 and US8 need only Phase 2.
- Within US4, checks T065–T069 are one file each.

## Traceability

Every functional requirement FR-001…FR-059 (incl. FR-018a, FR-048a) and every success
criterion SC-001…SC-010 is claimed by at least one task above. SC-005 → T076,
SC-006 → T035, SC-008 → T105, SC-009 → T110, SC-010 → T112.
