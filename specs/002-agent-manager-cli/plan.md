# Implementation Plan: `amctl` — the Agent Manager CLI

**Branch**: `002-agent-manager-cli` | **Date**: 2026-08-28 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-agent-manager-cli/spec.md`

## Summary

A single static binary that turns the hub's resolved lockfile into files on a laptop, and
removes them again when the hub says so. Four verbs — `login`, `sync`, `status`, `logout` —
over the six endpoints hub `001` froze.

The spine is **resolve → verify → stage → swap → record → prune**. The hub resolves; the CLI
downloads each immutable bundle, verifies its digest before a byte reaches the tree, unpacks
into a staging directory, swaps it into place atomically, records exactly what it wrote, and
removes anything its own record still claims but the lockfile no longer does. Every design
decision below follows from two facts: **the hub is the resolver**, so the CLI never re-decides
a version or a gate; and **bundle bytes are immutable**, so a digest-addressed cache needs no
invalidation and a swap can be a rename.

It ships as a **second Go module in this repository**. That keeps the contract one `git grep`
away while keeping the CLI's dependencies — a credential store, a progress renderer, a
terminal detector — entirely out of the hub's module graph and out of the hub's image.

## Technical Context

**Language/Version**: Go 1.26.6, matching the hub. Second module at `cli/`, module path
`github.com/WindKube/agent-manager/cli` so `go install` works against the public repo.

**Primary Dependencies**:
`spf13/cobra` (verbs, matching the hub's house standard) ·
`99designs/keyring` (credential store: macOS keychain, Secret Service, KWallet, `pass`,
Windows credential manager, and an owner-only file as the sanctioned fallback) ·
`klauspost/compress/zstd` (the bundle format, same as the hub) ·
`Masterminds/semver/v3` (comparison for reporting upgrade vs downgrade — **not** for
resolution, which is the hub's) ·
`oapi-codegen/v2`-generated client from the **emitted** hub document ·
`rs/zerolog` (diagnostics on stderr) ·
`stretchr/testify` (tests).
Deliberately **not** taken: an HTTP framework (this is a client), a TUI toolkit (see
Out of Scope), a retry library (the polling and backoff rules are short and specified).

**Storage**: the user's filesystem, nothing else. Three trees, all under the invoking user's
home and all per hub:

| Tree | Holds | Why it is separate |
|---|---|---|
| Agent directories | the installed skills and plugins | owned by the agent, shared with files the CLI must never touch |
| `~/.agent-manager/<hub>/state.json` | the installation record | the authority for what may be removed (FR-026) |
| `~/.agent-manager/cache/sha256-<digest>` | bundle bytes | keyed by content, so it is shared across hubs, profiles and targets |

The cache is deliberately outside the per-hub directory: the same version fetched from two
hubs is the same bytes, and keying it by hub would double the disk for no gain.

**Testing**: `testify`, table-driven. The whole CLI is exercised against a **fake hub** — an
`httptest` server serving the frozen contract's shapes — because the interesting failures are
a corrupt digest, a 307, a `slow_down`, an expired code and a 403 mid-sync, all of which are
trivial to produce against a fake and awkward against a real one. One integration suite runs
against the real compose stack to prove the fake does not lie. Filesystem behaviour is tested
against a temporary HOME, never the developer's own.

**Target Platform**: `linux/amd64`, `linux/arm64`, `darwin/arm64`, `darwin/amd64`,
`windows/amd64`. Static where possible — see R1, which says macOS cannot be.

**Project Type**: single-binary command-line client.

**Performance Goals**: a no-change `sync` completes in under a second against a warm cache;
a first sync is bounded by download, not by the CLI. Ten entries is the design's largest
profile, so nothing here needs to scale beyond tens.

**Constraints**: no daemon; no background process; no writes outside the user's home; no
network call before the home directory is known good; every command works with no TTY.

## Constitution Check

The hub's constitution governs this repository, so it governs this module. Most of it binds;
two principles need a stated reading.

| Principle | How it applies here |
|---|---|
| **I. One module, one image, roles as subcommands** | **Reading required.** The principle is about the *hub*: one deployable, roles as subcommands, no microservice sprawl. A client binary is not a role of the hub — it runs on a laptop, ships on a different cadence, and cannot be redeployed with the server. A second module is therefore not a violation but the thing that keeps the hub's module and image single-purpose. Recorded in Complexity Tracking below. |
| **II. Least privilege between roles** | Holds, and this is the least-privileged participant of all: the CLI holds a short-lived bearer token, no datastore credential, and no write access to anything server-side except one sync report. |
| **III. Untrusted input is the default assumption** | Binds hardest here. The CLI is the **last hop** before a developer's disk: bundles are re-validated, digests re-verified, and archive members re-checked even though the hub already did all three. Defence in depth is the point — the hub could be wrong, or compromised, or a redirect could be poisoned. |
| **IV. Immutability and provenance** | Depended upon rather than implemented: the digest-addressed cache is only correct because a version's bytes never change. The installation record keeps provenance on the machine — package, version, digest — so a laptop can answer "where did this come from" offline. |
| **V. Contract-first, generated, never hand-copied** | Holds. The client is generated from the hub's **emitted** document. No hand-written request structs, no copied types. |
| **VI. It runs with one command** | Adapted: for a client, this is `go install` or a downloaded binary, then `amctl login`. No configuration file is required to reach a working state. |
| **VII. Background roles are plugins that declare what they need** | Not applicable — no background roles. |
| **VIII. Commands and queries separated in code** | Holds and is load-bearing: `--dry-run` is exactly the query half of `sync`, and it is only trustworthy if planning and applying are genuinely separate code paths rather than one path with a boolean threaded through it. The plan is a value; applying it is a function of that value. |
| **IX. The queue is a separate database** | Not applicable. |

**Comment discipline** (house rule, from the global instructions and reinforced by this
build): comment where the reasoning is non-obvious, and above all state **what the code does
not do and why**. The security-relevant sites here are the extractor, the digest check, the
redirect handling, the credential store selection and the prune. Each must carry a short note
saying what it refuses.

## Project Structure

### Documentation (this feature)

```
specs/002-agent-manager-cli/
├── spec.md              this feature's requirements
├── plan.md              this file
└── tasks.md             T001.. with story tags
```

### Source Code

```
cli/
├── go.mod                        module github.com/WindKube/agent-manager/cli
├── main.go                       thin: cobra wiring only
├── Taskfile.yaml                 build, test, lint, release-snapshot
└── internal/
    ├── cmd/                      one file per verb; parsing and output only
    │   ├── root.go               global flags: --hub, --output, --offline, -v
    │   ├── login.go  logout.go
    │   ├── sync.go               --profile, --revision, --dry-run, --force, --yes
    │   └── status.go
    ├── hub/                      the generated client plus the thin wrapper
    │   ├── client.gen.go         GENERATED from the hub's emitted document
    │   ├── hub.go                bearer injection, error classification (FR-040)
    │   └── bundles.go            download, 307 handling, digest verification
    ├── device/                   RFC 8628: authorise, poll, slow_down, expiry
    ├── credentials/              store selection, keyring backends, file fallback
    ├── plan/                     PURE. lockfile + record -> Plan{add,upgrade,remove}
    ├── apply/                    the only package that touches the filesystem
    │   ├── stage.go              extract to staging, cap-enforced
    │   ├── swap.go               atomic per-entry replace
    │   └── prune.go              remove only what the record claims
    ├── layout/                   PURE. target -> paths. One file per target.
    │   ├── claude_code.go  agents_md.go  codex.go
    │   └── layout.go             the Target interface and the registry
    ├── record/                   the installation record: read, write, fingerprint
    ├── cache/                    digest-addressed bundle bytes
    ├── archive/                  hostile-archive extraction with caps
    └── output/                   human and json renderers over one result type
```

Three packages are **pure** — `plan`, `layout` and most of `archive`'s validation — and that
is where the interesting logic lives, so most of the test suite needs no filesystem and no
network. `apply` is the only package permitted to mutate the disk, which makes "did we write
outside the home directory" a question about one package rather than about the codebase.

## Research gates

Same discipline the hub used: each of these is settled by **measurement before
implementation**, because each has a plausible-but-wrong answer that would survive review.

**R1 — Does the credential store work in a static build? (blocks US1)**
Already partly answered, and the answer is uncomfortable: `99designs/keyring`'s macOS
keychain backend is compiled behind `//go:build darwin && cgo`. Built with `CGO_ENABLED=0`
on darwin, it **silently disappears** and the library selects a different backend — the file
one — while the CLI still believes it stored a token in the keychain. That is precisely the
silent fallback FR-003 forbids.

Resolve by: building for darwin both ways and asserting which backend is selected at run
time. Expected outcome — macOS release builds set `CGO_ENABLED=1` on a macOS runner (no
cross-compile), Linux and Windows stay static. **A test must assert the compiled-in backend
set**, so a build-flag regression fails CI instead of quietly downgrading every Mac user's
token storage.

**R2 — What is each target's real on-disk layout? (blocks US2, gates SC-009)**
The contract enumerates `claude-code`, `agents-md` and `codex`; none of them tells us where
those agents actually look. Writing to a path an agent does not read is the worst failure
this tool has, because it reports success. Resolve by reading each agent's own published
documentation, writing the layout down per target with the source cited, and — where the
agent is installable here — proving a synced skill is actually picked up. **Until R2 is
resolved for a target, that target does not ship.** Shipping two verified targets beats
shipping three where one silently does nothing.

**R3 — Atomic swap across platforms.**
`os.Rename` over an existing directory fails on Windows and is not atomic for directories on
any platform. The intended shape is: extract to `staging/<digest>`, then swap by renaming the
old aside and the new in, removing the old only after the new is in place. Resolve by testing
the sequence on all three platforms, including the interrupted cases, and confirming that a
crash at each step leaves either the old or the new version — never a mixture (FR-024).

**R4 — Modification detection.**
FR-029 needs "changed since install" without hashing a large tree on every run. Candidates:
per-file sha256 at install (accurate, slowest), size+mtime (fast, misses same-size edits),
or a per-entry manifest hash. Resolve by measuring against the largest design profile.
Correctness wins ties here — a false "unmodified" silently destroys a person's edit.

**R5 — Fake-hub fidelity.**
The suite leans on an `httptest` fake. A fake that diverges from the real hub gives green
tests and a broken binary. Resolve by running the same behavioural suite against both the
fake and the compose stack, with the real run in CI. If a case cannot be expressed against
both, it is a case the fake must not silently pass.

**R6 — Does `reportSync` need to be best-effort?**
FR-033 says a failed report must not fail the sync. Confirm the hub agrees: check whether a
duplicate report is idempotent server-side, since a retry after a timeout is otherwise a
second audit row for one sync — which would break hub SC-008's exactly-one-row property.

## On-disk state model

The installation record is the only new persistent structure this feature introduces, and it
is the entire basis for safe pruning. Shape, per hub:

- **schema version** — so a future format change is a migration rather than a crash.
- **hub** — canonical URL, so a record cannot be applied to the wrong hub.
- **per profile**: slug, revision installed, when, and the targets in force at that time.
- **per entry**: package id, version, digest, kind, the target it was installed for, the
  absolute destination path, and the fingerprint from R4.

Two properties matter more than the field list. **It records paths, not patterns** — pruning
walks a list of things the CLI wrote, never a glob over a directory it does not own, which is
what makes FR-028 true by construction rather than by care. And **it is written after the
swap, not before**: a record claiming an entry that is not there causes a spurious removal
attempt, whereas an entry present without a record is merely re-installed next run. Both
orderings can be wrong; this one is wrong in the recoverable direction.

## Complexity Tracking

| Deviation | Why it is needed | What was rejected |
|---|---|---|
| A second Go module in the repository | The CLI needs a credential store and a terminal renderer; the hub's image must not carry them. Separate `go.mod` is the only way to keep the hub's graph clean while keeping the contract adjacent. | **One module, `cmd/amctl`** — simplest, but every CLI dependency lands in the hub's `go.mod` and its supply-chain surface. **Separate repository** — cleanest release story, but the breaking-change gate would no longer see both sides of the contract in one diff. |
| Extraction logic that resembles `internal/bundle` in the hub | Deliberate duplication, not a missed abstraction: the CLI is the last hop and must not trust the hub's extraction. Sharing the code would mean a shared module and a shared bug. The caps are the same numbers; the code is independent on purpose. | Extracting `internal/bundle` into a shared module — couples the hub's release to the CLI's and defeats the defence-in-depth reading of principle III. |
| `Masterminds/semver` present in a client that does not resolve | Only for *reporting* upgrade versus downgrade in the plan output. A comment at the import must say so, or someone will reach for it to resolve a range. | Comparing version strings by hand — wrong for prerelease ordering. |

## Risks

- **R2 is the schedule risk.** If a target's layout cannot be verified, the honest move is to
  ship fewer targets, and the spec is written so that is possible without rework.
- **The design's copy will be wrong.** The Connect-the-CLI screen says
  `brew install example/tap/skillhub` and `skillhub login`. Those strings are hub-side and
  need a follow-up change; this feature should not silently leave the screen lying.
- **`--force` is a footgun by construction.** It exists because FR-029 would otherwise make a
  legitimate re-install impossible. Its output must name every file it is about to destroy.
- **A partially applied multi-profile sync.** Entries are atomic individually (FR-024), but a
  sync of twelve entries that fails at the seventh leaves five installed. That is accepted:
  the alternative is a whole-tree transaction, and the next `sync` converges. It must be
  *reported* as partial rather than as failure with no detail.
