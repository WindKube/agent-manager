# Tasks: `amctl` — the Agent Manager CLI

**Input**: `/specs/002-agent-manager-cli/` — spec.md, plan.md

**Tests**: Included. The constitution mandates them, and SC-002 through SC-010 are only
meaningful as executable assertions — every one of them is a property no amount of manual
checking establishes.

## Format: `[ID] [P?] [Story] Description`

- **[P]** — parallelisable: different files, no dependency on another unstarted task
- **[Story]** — the user story this serves; `—` for shared infrastructure

Paths are relative to `cli/` unless they begin with `../`.

**MVP = Phases 1–3 plus US1 and US2.** That is a machine that can authenticate and receive
packages. US3–US7 are increments on top, and US4 (prune) is what makes the result *governed*
rather than merely convenient — treat it as the first increment, not the last.

---

## Phase 1: Setup

- [ ] T001 `cli/go.mod` — `module github.com/WindKube/agent-manager/cli`, Go 1.26.6, **no `replace` directives**. A `replace` back to the hub module would make `go install` from the public repo fail, which is the one thing this module exists to support.
- [ ] T002 [P] Cobra root in `main.go` + `internal/cmd/root.go`: `login`, `logout`, `sync`, `status`, `version`. Global flags `--hub`, `--output {human,json}`, `--offline`, `-v`. Every verb a stub exiting 0.
- [ ] T003 [P] `cli/Taskfile.yaml` — `build`, `test`, `lint`, `gen:client`, `release:snapshot`. Reachable from the root Taskfile as `cli:<task>` so one command still runs everything.
- [ ] T004 [P] `.golangci.yml` for the module, matching the hub's ruleset. Local import prefix `github.com/WindKube/agent-manager/cli`.
- [ ] T005 Extend `.github/workflows/ci.yaml` with the CLI module: build matrix over the five target platforms, unit tests, lint. **The hub's jobs must keep passing unchanged** — a second module in the repo must not make `go build ./...` at the root ambiguous.
- [ ] T006 [P] `internal/output/` — one result type per verb, a human renderer and a json renderer over it (FR-035). Results on stdout, diagnostics on stderr, from the first commit: retrofitting this after the verbs exist means touching every verb.
- [ ] T007 [P] `internal/cmd/exit.go` — the four exit codes of FR-036 as named constants, each with a comment saying which caller distinguishes it. A bare `os.Exit(1)` anywhere else is a lint failure.

---

## Phase 2: Foundational — blocks every user story

**⚠️ No story work starts until this phase is green.**

### The gates that must run before the code they govern

- [ ] T008 **[R1 GATE]** Build for `darwin/arm64` with `CGO_ENABLED=0` and `=1`; at run time, report which `99designs/keyring` backends are compiled in. Assert the static build **loses** the macOS keychain. Record the result in plan.md. This is known to be true and must be *proved* before the credential code is written, because it decides the release matrix.
- [ ] T009 **[R1]** `internal/credentials/backends_test.go` — assert the compiled-in backend set for the current platform is the expected one, so a future `CGO_ENABLED` regression fails CI rather than silently downgrading every macOS user to a file. The negative control: force the tags the other way and confirm the test fails.
- [ ] T010 **[R2 GATE]** [P] For each of `claude-code`, `agents-md`, `codex` (`agents-md` was dropped from the contract as a result of this gate): find that agent's own documentation for where it loads skills and plugins from, write the layout into `internal/layout/<target>.go` as a doc comment **citing the source** (FR-021), and note whether it was verified by running the agent or only read. A target that cannot be verified is marked unshipped and its constructor returns an error naming R2. **Do not guess a path.**
- [ ] T011 **[R3 GATE]** [P] `internal/apply/swap_test.go` — the rename-aside-rename-in sequence on linux and darwin, with an induced failure at each step, asserting the result is always wholly the old or wholly the new version (FR-024).
- [ ] T012 **[R4 GATE]** [P] Measure the three modification-detection candidates against the largest design profile; choose on correctness first, speed second, and record the numbers. A false "unmodified" destroys a person's edit, so a fast wrong answer loses.

### Shared primitives

- [ ] T013 `internal/archive/` — **SECURITY**. Extraction under caps: entry count, per-entry size, total size, compression ratio checked *while streaming*, path depth, path length, wall clock. Reject absolute paths, `..` after cleaning, symlinks, hardlinks, devices, FIFOs, duplicate paths, and any resolved destination outside the entry root (FR-019). Independent of the hub's `internal/bundle` on purpose — see Complexity Tracking; the comment must say so, or someone will "deduplicate" it.
- [ ] T014 [P] `internal/archive/archive_test.go` — one case per cap and per rejected member kind, plus a real zip bomb, a symlink escape, a hardlink escape and a deep path. **[SC-005]**
- [ ] T015 [P] `internal/cache/` — digest-addressed store: `~/.agent-manager/cache/sha256-<digest>`. Re-hash on read before trusting an entry (FR-017); a mismatch discards rather than repairs. Write via temp-file-and-rename so a killed process cannot leave a truncated entry that looks whole.
- [ ] T016 [P] `internal/cache/cache_test.go` — hit, miss, corrupted-entry-discarded, concurrent writers, and a killed write leaving no visible entry.
- [ ] T017 `internal/record/` — the installation record of plan.md's state model: read, write, schema version, per-hub path, and the exact revision installed per profile so a later run can tell drift from change (FR-013). Written **after** the swap, and the doc comment must say why that ordering is the recoverable one.
- [ ] T018 [P] `internal/record/record_test.go` — round trip, unknown schema version refused with a message rather than a panic, absent file is an empty record and not an error, and a record for hub A is refused against hub B.
- [ ] T019 `internal/hub/` — generate the client from the hub's **emitted** document (not the frozen contract, which is the machine-facing subset). Wire `gen:client` into the Taskfile and a `gen:check`-style CI gate so a stale client fails the build.
- [ ] T020 `internal/hub/hub.go` — bearer injection, and error classification into unreachable / unauthorised / forbidden / not-found (FR-040). TLS required; a plaintext hub needs an explicit flag (FR-041).
- [ ] T021 [P] `internal/hub/hub_test.go` — each of the four error classes is distinguishable, the token is sent on hub calls and **never** on a redirect target (FR-016), and a plaintext URL is refused without the flag.
- [ ] T022 `internal/hub/fake/` — **[R5]** the fake hub as a reusable `httptest` server: the six endpoints, plus the awkward paths (`slow_down`, expiry, 307, digest mismatch, mid-sync 403). Every behavioural test runs against this; T060 runs the same suite against the real stack.
- [ ] T023 [P] `internal/cmd/home.go` — resolve and validate the home directory before any network call; refuse unset or unwritable, naming the variable (FR-039). Also the per-hub directory naming: a hub URL becomes a directory name without ever producing `..` or an absolute path.
- [ ] T024 [P] `internal/cmd/lock.go` — a per-home lock so two syncs refuse rather than interleave (FR-038). A stale lock from a killed process must not wedge the machine forever; say in a comment how that is decided.

---

## Phase 3: User Story 1 — Authenticate a new machine (P1) 🎯 MVP

- [ ] T025 [US1] `internal/device/` — RFC 8628: authorise, then poll at the hub's interval, honouring `slow_down` and the expiry (FR-001, FR-002). Pure state machine over a clock and a transport, so the timing is testable without sleeping.
- [ ] T026 [P] [US1] `internal/device/device_test.go` — approval, denial, expiry, `slow_down` increasing the interval, and an assertion that the CLI **never polls faster than told**. A fake clock; no real sleeps.
- [ ] T027 [US1] `internal/credentials/` — store selection over `99designs/keyring`, per hub (FR-006), with the owner-only file fallback and a **stderr warning naming why it fell back** (FR-003). Refuse a fallback file whose mode is wider than owner-only (FR-004).
- [ ] T028 [P] [US1] `internal/credentials/credentials_test.go` — round trip per backend available on the test platform, the file fallback's mode enforced both ways (0600 accepted, 0644 refused), two hubs coexisting, and the warning present when the fallback is used.
- [ ] T029 [US1] `internal/credentials/env.go` — a token from the environment takes precedence and is never persisted (FR-005). Test that no store is even opened when it is set.
- [ ] T030 [US1] `internal/cmd/login.go` — wire it up: print the user code and verification URL, poll, store, report the identity and hub.
- [ ] T031 [P] [US1] `internal/cmd/logout.go` — remove the credential for one hub; touch nothing installed (FR-008).
- [ ] T032 [P] [US1] **[SC-010]** A test that scans **all** captured output of the suite for the known test token and fails if it appears anywhere (FR-007). Negative control: deliberately log it once and confirm the test catches it.
- [ ] T033 [US1] `internal/cmd/login_test.go` against the fake hub: the full flow, plus the no-TTY path failing with the flag that answers it (FR-037).

**Checkpoint**: `login` works, `whoami`/`status` names the identity, and nothing else is needed to prove it.

---

## Phase 4: User Story 2 — Sync a profile onto the machine (P1) 🎯 MVP

- [ ] T034 [US2] `internal/layout/` — the `Target` interface and registry; per-target path derivation from the R2 findings. **PURE**: string in, paths out, no filesystem. Distinct directories for colliding names across publishers (FR-023), and an on-disk marker identifying package and version without the hub (FR-022).
- [ ] T035 [P] [US2] `internal/layout/layout_test.go` — per target, the expected paths for a plugin and for a standalone skill; two publishers with the same package name landing in different directories; a package id that is not two segments refused (edge case).
- [ ] T036 [US2] `internal/plan/` — **PURE**. `(lockfile, record, targets) -> Plan{Add, Upgrade, Downgrade, Remove, Conflicts, Skipped}`. This is the query half of principle VIII and the thing `--dry-run` prints. No I/O whatsoever.
- [ ] T037 [P] [US2] `internal/plan/plan_test.go` — table-driven over every transition: absent→installed, version change in both directions, unchanged, left-the-profile, target-disabled, and the two-profiles-one-package conflict (FR-012).
- [ ] T038 [US2] `internal/hub/bundles.go` — download with the digest verified **before** anything reaches the tree (FR-014), 307 followed without the bearer token (FR-016), bytes landing in the cache first so the install reads only verified local bytes.
- [ ] T039 [P] [US2] `internal/hub/bundles_test.go` — **[SC-003]** a corrupted body writes nothing, leaves the machine unchanged for that entry and exits non-zero naming both digests (FR-015); a 307 is followed; the token is absent from the redirect request; a 403 mid-sync skips that entry and continues.
- [ ] T040 [US2] `internal/apply/stage.go` — extract a verified bundle into `staging/`, cap-enforced through T013.
- [ ] T041 [US2] `internal/apply/swap.go` — the R3 sequence, per entry, atomic (FR-024).
- [ ] T042 [US2] `internal/apply/apply.go` — execute a Plan: stage, swap, record, in that order. **The only package that mutates the tree**; a test asserts no other package imports `os.Remove`, `os.Rename` or `os.WriteFile`.
- [ ] T042a [P] [US2] **FR-020** — assert every destination path resolves inside the invoking user's home before it is opened, and a test that walks a completed sync confirming no path outside it was written. Symlinked agent directories make this a real question rather than a tautology: the check is on the RESOLVED path, not the requested one.
- [ ] T042b [P] [US2] **FR-009** — an import-graph test asserting the CLI holds no version-resolution logic: `Masterminds/semver` may be imported only by the plan's reporting code, never by anything that chooses a version. The hub resolves; a second implementation here would be a second answer, and the two would eventually disagree. Same shape as the hub's `internal/archcheck`.
- [ ] T043 [US2] `internal/cmd/sync.go` — `--profile` (repeatable), `--revision` accepting `head` or an exact number so a machine can be pinned to a known state (FR-010), wire plan→apply→record, report skips with the hub's reasons (FR-011).
- [ ] T044 [US2] `internal/hub/sync_report.go` — report the sync exactly once (FR-032); a failed report warns on stderr and does not fail the sync (FR-033). **[R6]** confirm server-side idempotence first, or a retry breaks hub SC-008.
- [ ] T045 [P] [US2] **[SC-002]** Idempotence (FR-025): sync twice against an unchanged fake hub and assert **zero** filesystem modifications on the second run, by mtime across the whole tree — not by the CLI's own report of what it did.
- [ ] T046 [P] [US2] **[SC-008]** Interruption: kill the process at staging, at swap, and between swap and record; re-run; assert the tree matches the lockfile exactly in all three cases.
- [ ] T047 [P] [US2] `internal/cmd/sync_test.go` — targets honoured and no other agent directory touched (FR-039); the symlinked-agent-directory edge case; HOME unset refused before any request.

**Checkpoint**: a machine can be authenticated and populated. This is the MVP.

---

## Phase 5: User Story 4 — Reconcile drift and removals (P2)

Deliberately before US3: this is what makes the tool governed rather than convenient, and
`--dry-run` is far more useful once there is something destructive to preview.

- [ ] T048 [US4] `internal/apply/prune.go` — remove entries the record claims and no lockfile does, or whose version the hub now refuses (FR-027). **Only paths in the record** (FR-028); never a glob over a directory the CLI does not own.
- [ ] T049 [US4] `internal/record/fingerprint.go` — the R4 mechanism; detect a managed path modified since install (FR-029).
- [ ] T050 [P] [US4] **[SC-004]** The property test that matters: seed every directory the CLI writes with unmanaged neighbours — a hand-written skill, a stray file, an unrelated directory — then run a full add/remove cycle and assert **every** neighbour survives byte-identical.
- [ ] T051 [P] [US4] `internal/apply/prune_test.go` — left-the-profile removes; a rejected version removes; a modified file is preserved and reported as a conflict; `--force` overrides and names each file it destroys; a disabled target's files are removed (FR-030).
- [ ] T052 [P] [US4] The partial-sync report: a sync failing at entry seven of twelve reports which five landed and which are untouched, and exits with the failure code — not a bare error (plan.md Risks).

---

## Phase 6: User Story 3 — See what will change (P2)

- [ ] T053 [US3] `internal/cmd/sync.go` — `--dry-run`: render the Plan, write nothing, send no report (FR-031). Trivial because `plan` is already pure and separate; if this task turns out to be hard, T036 was built wrong.
- [ ] T054 [P] [US3] `internal/cmd/dryrun_test.go` — snapshot the whole tree before and after `--dry-run` and assert byte-equality, including mtimes; assert no request to the report endpoint; assert a removal is listed with its reason.

---

## Phase 7: User Story 5 — Offline and cache reuse (P3)

- [ ] T055 [US5] `--offline`: complete from cache or fail naming what is missing, leaving nothing partially installed (FR-018).
- [ ] T056 [P] [US5] **[SC-006]** Assert the request count against the fake hub is zero for a second sync of versions already cached, and that `--offline` restores a deleted tree from cache alone.

---

## Phase 8: User Story 6 — Unattended operation (P3)

- [ ] T057 [US6] Audit every verb for an interactive assumption; each prompt gets a flag, and no-TTY fails naming it (FR-037).
- [ ] T058 [P] [US6] **[SC-007]** The full end-to-end in a no-TTY environment with no credential store and a token from the environment: assert success, no prompt, and that no credential store was opened.
- [ ] T059 [P] [US6] Exit-code table test: one case per code of FR-036, including no-changes distinguished from changes-applied.

---

## Phase 9: User Story 7 — Status and introspection (P3)

- [ ] T060 [US7] `internal/cmd/status.go` — hub, identity, profiles, revisions, drift (FR-034). Never-synced is a state, exits 0.
- [ ] T061 [P] [US7] `internal/cmd/status_test.go` — synced, never-synced, drifted, and a credential present but expired.

---

## Phase 10: Polish and cross-cutting

- [ ] T062 **[R5]** [P] Run the behavioural suite against the **real compose stack**, not the fake, in CI. Any case that cannot be expressed against both is a case the fake must not silently pass.
- [ ] T063 **[SC-009]** [P] For each shipped target, prove an installed skill is actually loaded by that agent. This is the task that stops the tool reporting success while doing nothing.
- [ ] T064 **[SC-001]** [P] Time the whole first-run journey — install, `login`, browser approval, `sync` — and record the human-effort figure against the two-minute budget.
- [ ] T065 [P] `goreleaser` (or equivalent) for the five platforms. Per the measured R1: **`CGO_ENABLED=1` for both darwin arches, each on a native `macos-*` runner** — R1 declines to prove cross-arch cgo on an arm64 mac, and darwin cannot be cross-compiled from linux at all — and static elsewhere. The mac artefacts are therefore **not static**; they link `libSystem` and `Security.framework`, so the runner's deployment target becomes the minimum supported macOS version and must be stated. Checksums published; the release workflow pinned by SHA like every other action in this repo.
- [ ] T066 [P] `cli/README.md` — install, the four verbs, the on-disk layout, and where the token lives on each platform. State plainly which targets are verified and which are not.
- [ ] T067 [P] Update the hub's Connect-the-CLI screen: it currently says `brew install example/tap/skillhub` and `skillhub login`, neither of which will ever be true. A hub-side change, but this feature is what makes the screen wrong, so it owns the fix.
- [ ] T068 [P] Update `specs/001-agent-manager-hub/spec.md`'s Out of Scope entry to point at this feature rather than describing the CLI as unbuilt.
- [ ] T069 [P] Mark every task above complete in this file, and record the R1–R6 outcomes in plan.md. An unmarked task set is indistinguishable from an abandoned one.

---

## Coverage

Every SC-001…SC-010 is claimed by at least one task above, and every FR-001…FR-041 is named
by at least one task or by a plan.md section. Checked mechanically, not by reading:

    SC-001 → T064 · SC-002 → T045 · SC-003 → T039 · SC-004 → T050 · SC-005 → T014
    SC-006 → T056 · SC-007 → T058 · SC-008 → T046 · SC-009 → T063 · SC-010 → T032

The four FRs that are properties of the *codebase* rather than of a run get import-graph or
whole-tree assertions rather than a unit test, because nothing else can hold them: FR-009
(T042b, no resolution logic), FR-020 (T042a, no write outside home), FR-028 (T050, prune walks
the record), FR-007 (T032, no token in any output).

---

## Dependencies & Execution Order

### Phase dependencies

- **Phase 1** blocks everything.
- **Phase 2** blocks every story. R1 and R2 in particular gate code that would otherwise be
  written against a guess.
- **US1 (Phase 3)** blocks US2: no token, no bundles.
- **US2 (Phase 4)** blocks US4, US3, US5 — all three operate on an installed tree.
- **US4 (Phase 5)** is the first increment after MVP, before US3.
- **US6, US7** depend only on the verbs existing.
- **Phase 10** last, except T067 and T068 which can land any time after Phase 1.

### Parallel opportunities

Phase 2's four gates (T008, T010, T011, T012) are independent and are the best parallel work
in the whole plan — each is a measurement, none touches shared code.

Within US2, `layout` (T034), `plan` (T036) and `bundles` (T038) are three independent
packages: pure paths, pure diffing, and network. They meet only in `apply` (T042).

Every `_test.go` marked [P] is parallelisable against its siblings.

### The tasks most likely to be got wrong

Stated explicitly, because each has a plausible wrong version that passes review:

- **T036 (`plan`)** — the temptation is to thread a `dryRun bool` through the apply path
  instead of producing a plan value. Do that and T053 becomes hard, T054 becomes untrustworthy,
  and principle VIII is violated in the one place it actually earns its keep.
- **T048 (`prune`)** — the temptation is to list a directory and remove what is not in the
  lockfile. That deletes a person's hand-written skill. Walk the record, never the directory.
- **T013 (`archive`)** — the temptation is to import the hub's extractor. Read the
  Complexity Tracking entry first; the duplication is the design.
- **T038 (digest)** — the temptation is to verify after writing, because that is easier to
  wire. FR-014 says before, and SC-003 tests it.
