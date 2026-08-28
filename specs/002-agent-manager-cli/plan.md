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
a first sync is bounded by download, not by the CLI. Twelve entries is the design's largest
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
R1–R4 have been measured and are recorded below as what was measured, what it showed, what the
implementation must now do, and what the measurement did **not** settle. R5 and R6 are still
open, and each names the task that closes it.

**R1 — Does the credential store work in a static build? (blocks US1)**
`99designs/keyring`'s macOS keychain backend is compiled behind `//go:build darwin && cgo`.
Does a `CGO_ENABLED=0` darwin build silently select a different backend while the CLI still
believes it stored a token in the keychain — the silent fallback FR-003 forbids?

**Resolved.** Confirmed, and the fallback is not the one this plan originally recorded — it said
the file backend. `keychain.go` is the only cgo-gated file in keyring v1.2.2, so a static darwin
build does not contain it, and `keyring.Open` walks its own `backendOrder` to the next backend
that opens — which is **`pass`, not the file**, because `pass.go` is `!windows` and precedes
`FileBackend` in that order. A Mac
developer with `pass` on `$PATH` gets their token written into their GPG password store; one
without gets a file. Nothing in the library reports either: a missing backend file is not an
error at any layer, only a shorter list. Linux and Windows are CGO-invariant — `secret-service`,
`kwallet`, `keyctl` and `wincred` are pure Go — so only the macOS builds pay for cgo.

**Evidence.** `GOOS=darwin GOARCH=arm64 CGO_ENABLED=n go list -json github.com/99designs/keyring`
moves `keychain.go` between `IgnoredGoFiles` and `GoFiles` on that one flag. `go tool nm` on a
probe cross-built `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0` — a real `Mach-O 64-bit arm64
executable` — finds exactly two backend itabs, `fileKeyring` and `passKeyring`, and zero
`keychain` symbols, against a positive control of 16 `github.com/99designs/keyring.*` symbols in
the same binary. Backends per platform, derived mechanically from `GoFiles` ∩ the
`supportedBackends` registration sites and ordered by keyring's own `backendOrder`, first entry
being what `Open` picks:

| Target | `CGO_ENABLED=0` | `CGO_ENABLED=1` |
|---|---|---|
| `linux/amd64`, `linux/arm64` | `secret-service kwallet keyctl pass file` | *identical* |
| `darwin/arm64`, `darwin/amd64` | **`pass file`** — keychain lost | `keychain pass file` |
| `windows/amd64` | `wincred file` | *identical* |

The linux row was cross-checked against a real run — `keyring.AvailableBackends()` on native
linux/arm64 prints exactly `[secret-service kwallet keyctl pass file]` — which validates the
derivation method on the one platform where both are possible. The guard is
`cli/internal/credentials/backends.go`, and its negative control has been *seen* to fail: with
`required["linux"]` forced to `keychain`, `TestVerifyCurrentAcceptsThisBuild` reports `keyring
backend "keychain" is not compiled into this linux build (available: [secret-service kwallet
keyctl pass file]): the platform credential store is missing, most likely built with
CGO_ENABLED=0`.

**Consequence.** The release matrix carries `CGO_ENABLED` per platform, not one global value:

| Target | `CGO_ENABLED` | Runner | Why |
|---|---|---|---|
| `darwin/arm64` | **1** | macOS | keychain is `darwin && cgo`; static loses it silently |
| `darwin/amd64` | **1** | macOS | same |
| `linux/amd64` | 0 (static) | linux | Linux backends are pure Go — measured CGO-invariant |
| `linux/arm64` | 0 (static) | linux | same |
| `windows/amd64` | 0 (static) | linux or windows | `wincred` is pure Go — measured CGO-invariant |

darwin cannot be cross-compiled for a shippable build: `CGO_ENABLED=1 GOOS=darwin` from linux
fails with `cgo: C compiler "clang" not found`, and the host `gcc` rejects Apple's `-arch`. The
release workflow therefore requires a `macos-*` runner for both darwin arches, and T003's
`release:snapshot` and T065 must both encode the per-platform flag. The macOS artefacts are
**not static** — they link `libSystem`/Security.framework, which is fine but kills any "one
static binary everywhere" claim for them, and makes the runner's macOS deployment target the
minimum supported macOS version. T005: the unit suite must run **on each target OS**.
`TestCompiledInBackendSetIsTheOneThisPlatformShouldHave` only sees the darwin regression when it
runs on darwin, so pinning it to a linux runner makes it a gate that can never fire for the case
it was written for. T027 must not infer the backend from `runtime.GOOS` — ask
`credentials.Available()` / `credentials.VerifyCurrent()` — and FR-003's stderr report must name
the backend **actually chosen**: on static darwin the first fallback is `pass`, so a message
hard-coding "falling back to a file" would be a lie. FR-004's owner-only permission check
applies only when the chosen backend really is the file one. `github.com/99designs/keyring
v1.2.2` (the latest published version) is now a direct requirement; it drags in
`golang.org/x/sys v0.3.0`, `golang.org/x/term v0.3.0` and `github.com/godbus/dbus` on the
pre-v5 import path — nothing needs bumping for correctness, but a dependency audit will flag
them, and the hub's module graph is untouched, which is why the CLI is a second module.

**Not established.** The guard has never been *run* on darwin — no macOS machine was available.
Its darwin behaviour rests on the toolchain's own file list, `nm` on a cross-built darwin binary
and test binary, and `go list -deps`; that is deduction from measurement, not observation. The
first macOS CI run is what converts it, and should be treated as the closing step of this gate
rather than as routine CI. `CGO_ENABLED=1 GOOS=darwin` was never built at all; the substitute
discriminator was whether the cgo-only C wrapper `github.com/99designs/go-keychain` enters the
dependency graph, which it does for darwin+cgo and for nothing else. Also unproven: that
`darwin/amd64` can be cross-*arch* built on an arm64 mac. And the guard reads keyring's own
registry rather than a mirror of its build tags kept in this tree — deliberate, so the guard
cannot end up guarding a copy that drifted on upgrade, but it means compiled-in is what is
asserted, never reachable-at-run-time.

**R2 — What is each target's real on-disk layout? (blocks US2, gates SC-009)**
The contract enumerates `claude-code`, `agents-md` and `codex`; none of them tells us where
those agents actually look. Writing to a path an agent does not read is the worst failure this
tool has, because it reports success.

**Resolved.** One target ships: **`claude-code`, skills only**. Its layout is user
`$CLAUDE_CONFIG_DIR/skills/<dir>/SKILL.md` (default `~/.claude/skills/`) and project
`<project>/.claude/skills/<dir>/SKILL.md`, verified by observation against Claude Code 2.1.248.
`codex` is documented but unobserved, and its user path moved within the last nine months
(`~/.codex/skills` → `$HOME/.agents/skills`), so it stays gated on one measurement. `agents-md`
is not merely unverified but **unresolvable as specified**: the convention documents only a
repository-root `AGENTS.md`, there is no per-user location, and one shared file cannot satisfy
FR-020, FR-022, FR-023 or FR-024/028/029.

**Evidence.** Three different strengths, and they are not interchangeable.

1. *Observed* (`claude-code`). A skill was planted on disk and a headless
   `claude -p 'List the exact names of every skill available to you via the Skill tool, one per
   line, nothing else.'` session was asked what it could see — what appears in that list is
   loaded by definition. `<cwd>/.claude/skills/amctl-probe/SKILL.md` → `amctl-probe` listed;
   `CLAUDE_CONFIG_DIR=$dir` with `$dir/skills/amctl-user-probe/SKILL.md` → listed. Three
   negative controls, each a path a reasonable implementer would have guessed wrong and each
   failing silently: a skill at `.claude/skills/synced/` **did not load** (reserved name — the
   claude.ai skills-sync root, and the agent's own guard says it "would never load"); neither
   `$XDG_CONFIG_HOME/claude/skills` nor `$XDG_CONFIG_HOME/skills` was read at all, despite 30
   `XDG_CONFIG_HOME` references in the binary; and two directories with identical
   `name: pdf-tools` frontmatter both loaded, each under its own **directory** name. A marker
   dotfile beside `SKILL.md` (`.agent-manager.json`) was also confirmed to load normally, which
   is what settles FR-022 for this target.
2. *Documented, unobserved* (`codex`). https://learn.chatgpt.com/docs/build-skills gives
   `$HOME/.agents/skills` for the USER scope; the REPO rows are project trees outside the home
   (FR-020) and the ADMIN row `/etc/codex/skills` needs root. Two independent December-2025
   accounts still give `~/.codex/skills` with no deprecation note. `which codex` is empty here
   and neither `~/.codex` nor `~/.agents` exists, so nothing could be run. Corroborating
   first-hand artefact for the `.agents/` root: the superpowers 6.3.0 plugin cache on this
   machine ships both `.codex-plugin/plugin.json` and `.agents/plugins/marketplace.json`.
3. *Documented, and the documentation is the problem* (`agents-md`). https://agents.md/
   documents a repository-root file plus nested per-package copies, nearest wins, and mentions
   no user-level location; agentsmd/agents.md#91, still **open**, proposes standardising
   `~/.config/agents/AGENTS.md` precisely because every tool uses a different global path
   (`~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.factory/AGENTS.md`, `~/.config/AGENTS.md`).
   An open proposal to standardise a path is proof there is no standard path.

**Consequence.** The release matrix ships one target. `sync` for a profile naming `agents-md` or
`codex` must **fail loudly**: both constructors return an error wrapping `ErrR2Unresolved` so
the registry refuses by class rather than by string match. Warn-and-continue is exactly the
failure this gate exists to stop — a target that installs nothing while the command exits 0.
T034's registry must therefore tolerate a target that cannot be constructed: registration is
fallible, not a package-level `init()` map. Path resolution reads `CLAUDE_CONFIG_DIR` and
nothing else; an XDG-first resolver, the obvious thing to write for Linux, installs to a
directory the agent never opens. `ValidateClaudeCodeSkillDirName` must run before any write, or
a package legitimately named `synced` installs, reports success and does nothing. FR-023 is
satisfiable for this target by directory naming alone, with no bundle rewriting, because the
directory name is the skill's identity — but keep the disambiguation separator conservative,
since Codex may enforce the naming rules claude-code ignores. FR-022's marker is
`.agent-manager.json`, a dotfile beside `SKILL.md`; the extractor must refuse a bundle
containing `.claude-plugin/`, `agents/`, `output-styles/`, `themes/`, `hooks/`, `monitors/` or
`workflows/` at a skill root, because those change the entry's kind from skill to plugin
(lifecycle hooks, monitors, MCP servers). `SKILL.md` is **never** edited to stamp provenance,
tempting though the spec's `metadata` map is: that would rewrite bytes just verified by digest
and break R4's install fingerprint. The marker is provenance, not authority — `state.json`
remains the only thing pruning consults. Plugins are out of scope for every target and
structurally so: claude-code plugins live in agent-owned `installed_plugins.json` and Codex MCP
servers in user-owned `~/.codex/config.toml`, and neither can be swapped by rename (FR-024) or
pruned without touching keys the CLI did not write (FR-028). The frozen contract keeps all three
enum values; a target the CLI refuses is a client-side decision and needs no OpenAPI change.

**Not established.** SC-009 is met for `claude-code` on **linux only**. darwin and windows are
the same code path (`CLAUDE_CONFIG_DIR`, else OS home + `.claude`) with no XDG or `%APPDATA%`
indirection found for the skills root, but the observation is owed on both and belongs on the
release-matrix runners (T063). `codex` needs ten minutes on a machine with Codex signed in:
plant `~/.agents/skills/amctl-probe/SKILL.md` plus the marker, confirm Codex lists the skill,
then repeat against `~/.codex/skills` to learn whether the old root is still live, recording the
Codex version with both answers. Two sub-questions must be settled in the same sitting because
each is a silent-failure candidate — scan depth (the December accounts say exactly one level,
non-recursive; OpenAI's current page is silent) and whether Codex accepts YAML frontmatter (the
spec and OpenAI's page require it, while Claude Code's own Codex importer asserts Codex treats
`SKILL.md` as plain text, so one of the two is stale). `agents-md` needs a **spec decision, not
more research**: either name one per-user location and define how N packages compose into one
file as delimited, individually prunable regions, or drop it from the contract enum. Reading
more documentation cannot fix it. Also outstanding: `internal/layout/*_test.go` does not exist —
the three findings that need regression tests are that `synced` is refused, that
`XDG_CONFIG_HOME` is not consulted, and that the plugin-adopting subdirectory set is refused.

**R3 — Atomic swap across platforms.**
`os.Rename` over an existing directory fails on Windows and is not atomic for directories on any
platform. Does the intended shape — extract to `staging/<digest>`, rename the old aside, rename
the new in, remove the old only after the new is in place — leave either the old or the new
version at every interruption point (FR-024)?

**Resolved.** Passes on linux/arm64. Formalised as five steps, the sequence leaves the
destination absent, wholly old or wholly new after an interruption at every one of them — never
a mixture — and a re-run always converges on the new version leaving no `.amctl-old` behind. The
question's framing was wrong on a load-bearing detail: through Go's `os` package, `os.Rename`
refuses **any** existing directory destination on **every** platform, empty or not. The
rename-aside step is therefore not a Windows workaround but the only way `os.Rename` installs
over anything at all.

**Evidence.** `cli/internal/apply/swap_test.go` — 26 subtests, all passing, none skipped:
`go test ./internal/apply/... -v`, and `CGO_ENABLED=1 go test -race -shuffle=on -count=2
./internal/apply/...` → `ok github.com/WindKube/agent-manager/cli/internal/apply`.
`TestR3InterruptionAtEveryStepLeavesOldOrNew` asserts the state after a crash at each step and
that the re-run converges leaving no aside. The measurement that contradicted the plan, on
linux/arm64, go1.26.6:

| call | result |
|---|---|
| `os.Rename(dir, ABSENT)` | `nil` — the only usable form |
| `os.Rename(dir, EMPTY dir)` | `EEXIST` |
| `os.Rename(dir, NON-EMPTY dir)` | `EEXIST` |
| `os.Rename(dir, SYMLINK→dir)` | `ENOTDIR` |
| `syscall.Rename(dir, EMPTY dir)` | `nil` — POSIX is *more* permissive; this is the trap |
| `syscall.Rename(dir, NON-EMPTY dir)` | `ENOTEMPTY` |

Root cause, read from `$GOROOT/src/os/file_unix.go`: `rename()` `Lstat`s the destination and
returns `EEXIST` for any directory *without ever reaching* `syscall.Rename`. Anyone hitting
`EEXIST` will reach for `syscall.Rename` or `unix.Renameat` because it "works" — it does, for
empty destinations only, then gives `ENOTEMPTY` at the first real upgrade, and has no Windows
equivalent. `TestR3NaiveRenameOverAnExistingDestination` pins these measurements in four
subtests, so that shortcut fails a test instead of passing review. On Windows, from source: `os.Rename` is
`MoveFileEx(from, to, MOVEFILE_REPLACE_EXISTING)`, documented as unusable when either name is a
directory, and `MOVEFILE_COPY_ALLOWED` is not passed, so a cross-volume move gives
`ERROR_NOT_SAME_DEVICE` (17) rather than `EXDEV` — and `syscall.EXDEV` on Windows is an
`APPLICATION_ERROR`-range constant no real Windows error ever equals. Cross-device was
constructed for real, `/dev/shm` (tmpfs, device 29) against the home filesystem (64769), and
`TestR3CrossDeviceStagingCollapsesTheWholeScheme` genuinely runs rather than skips.

**Consequence.** The sequence T041 implements, with `aside := dest + ".amctl-old"`:

1. Reclaim or discard a leftover aside — if `aside` exists and `dest` is absent,
   `rename(aside → dest)`; if `dest` exists, `RemoveAll(aside)`. Fatal on error.
2. `rename(dest → aside)`. `ENOENT` tolerated, not an error. Fatal otherwise.
3. `rename(staging → dest)`. Fatal **with rollback**: if `dest` is absent, `rename(aside → dest)`
   first, then return the original error.
4. `fsync` the parent directory of `dest`. Non-fatal.
5. `RemoveAll(aside)`. Non-fatal.

The record is written after step 5, unchanged. The one window in which `dest` is absent is
between steps 2 and 3 — a single rename wide — which FR-024 explicitly permits. The aside name
must be **deterministic and a sibling** of the destination: deterministic because the record
stores destination paths, so the set of paths the CLI may ever remove is exactly
`{dest, dest+".amctl-old"}` per entry and FR-028 holds by construction rather than by care (a
random token forces a glob, and a glob is how you delete somebody's hand-written skill); a
sibling because a central trash directory makes step 3's rollback fail with `EXDEV` exactly when
it is needed. Do not `Stat`-then-branch on whether `dest` exists — two code paths and a TOCTOU
window; tolerating `ENOENT` at step 2 makes the no-old-version case the same code path. Do
**not** add an `EXDEV` recursive-copy fallback: a copy is not atomic, so the fallback silently
inverts the one requirement this gate exists for. Detect cross-device and fail the entry naming
both paths. Steps 4 and 5 stay non-fatal, and a failed step 5 is surfaced as a leftover to clean
next run — on Windows an open handle in the old tree (editor, indexer, antivirus) makes
`RemoveAll` fail routinely, and failing the entry there reports a broken install for a working
one. `internal/layout` must guarantee no package installs to a path ending in `.amctl-old`.

Two things the plan left open are settled by this gate. **Staging is a sibling of the
destination** — `<dest-parent>/.amctl-staging/<digest>`, not a central
`~/.agent-manager/staging/<digest>`. Agent directories are often symlinks into a dotfiles repo,
which may be another mount, an encrypted volume, a network share or a tmpfs, and same-filesystem
staging is the only thing that makes step 3 a rename at all. That is a constraint on T040, not
only T041. And **T040 must `fsync` every extracted file** before handing the tree to the swap:
fsyncing the parent makes the directory *entry* durable, not the *content*, so on a
delayed-allocation filesystem a power loss just after the swap can leave `dest` present and full
of zero-length files — a mixture no care in `swap.go` can prevent. Content durability is
staging's, directory-entry durability is the swap's; split it explicitly or neither owns it.

A symlink at an entry destination is by definition not something the CLI wrote — extraction
refuses symlink members (FR-019) — so T042 must refuse the entry under FR-028/FR-029 unless
`--force` is given, and `--force` must name the link it will destroy. `swap.go` is unconditional
by design and **replaces** a destination symlink rather than following it: following one is
precisely how the CLI would write outside the home without ever constructing a path outside it
(`~/.claude/skills/x → /etc/whatever`), which is FR-020. A symlinked *parent* is fine and needs
nothing — the kernel resolves it during the rename. Rejected and recorded so they are not
re-proposed: `renameat2(RENAME_EXCHANGE)` and `renamex_np(RENAME_SWAP)`, both genuine
single-step atomic directory swaps but single-platform, leaving the other platforms on a second
and then untested code path. The release matrix is unaffected: R3 imposes no build-flag or
platform-drop decision.

**Not established.** The suite was **executed on linux/arm64 only**. It cross-compiles clean for
darwin/amd64, darwin/arm64 and windows/amd64 (`go vet` per GOOS), platform expectations are
explicit via a `runtime.GOOS` switch rather than hidden, and on the unmeasured platforms the
errno assertions log rather than assert. The highest-value unverified items: the Windows
`ERROR_ACCESS_DENIED` errno for rename-onto-a-directory, the `ERROR_NOT_SAME_DEVICE` (17) branch
of the cross-device check (entirely unexercised), and the symlink subtests on Windows, where
unprivileged `os.Symlink` needs Developer Mode. Cross-device is verified on linux only — neither
darwin nor windows has a dependable unprivileged second filesystem here. Crash consistency under
a **real power loss** is not verified anywhere and cannot be by a unit test: the gate proves the
sequence against process death at every step, not the filesystem's durability behaviour, which
needs a crash-consistency harness (`dm-log-writes`, or a VM force-reset loop). That is the
residual risk behind the T040 fsync requirement. `swap.go` itself does not exist yet — the gate
drives the sequence through a helper local to the test file, so T041 must assert that
`swap.go`'s own aside-suffix constant equals the gate's, or the two drift apart silently.
Closing the platform gap costs one line of CI: `cli-test` is pinned to `ubuntu-latest` while
`cli-build` already runs on `macos-latest`, `macos-15-intel` and `windows-latest` with
`shell: bash` and `setup-go` on `cli/go.mod`. Running `cli-test` over
`[ubuntu-latest, macos-latest, windows-latest]` with `fail-fast: false` converts the whole
unverified column above into measurements — Windows without `-race` (it needs cgo, and gcc is
not guaranteed on `PATH` there; these assertions are filesystem semantics, not data races), and
the coverage upload kept on the ubuntu leg only or the three legs collide on the artifact name.

**R4 — Modification detection.**
FR-029 needs "changed since install" without hashing a large tree on every run. Candidates:
per-file sha256 at install (accurate, slowest), size+mtime (fast, misses same-size edits), or a
per-entry manifest hash. Correctness wins ties: a false "unmodified" silently destroys a
person's edit.

**Resolved.** Per-file **sha256 + permission bits + entry kind + a recorded directory set**, as
a closed set over the entry root. It is the only candidate measured with **zero work-destroying
misses** — 15/15 on a fifteen-mutation matrix — and the speed argument for size+mtime is worth
nothing: on the design's largest profile (12 entries, 287 files, 15.86 MiB) the full content
check costs **8.8 ms warm / 21.6 ms cold**, 0.9%–2.2% of the one-second no-change-sync budget.
Size+mtime is 19× faster, saves 8 ms, and buys six work-destroying misses, two of which need no
adversary at all.

**Evidence.** A throwaway harness outside `cli/`, run against a synthetic tree that keeps the
seed catalogue's shape and scales the counts to the hub's own extraction caps (250 MB
decompressed, 10,000 entries, 25 MB single member, depth 32), so nothing generated is an input
the extractor would refuse. Correctness matrix, counted mechanically out of the run log —
`miss` = said unmodified when the correct answer is modified, the direction that destroys work;
`fp` = said modified when the correct answer is unmodified:

| candidate | misses | false positives |
|---|---|---|
| per-file sha256 + mode + kind | 2 (`M10`, `M12` — directories) | 0 |
| per-file sha256, content only | 6 | 0 |
| size + mtime | 6 | 2 |
| size + mtime on a 1 s-granularity filesystem | 7 | 1 |
| one manifest hash over content | 2 | 0 |
| one manifest hash over metadata | 4 | 2 |
| **recommended: sha256 + mode + kind + a recorded directory set** | **0** | **0** |

Every `MISS` was produced by running the mutation, not by argument, and the negative control is
proved alive: `./r4bench mutate | grep -c "NEGATIVE CONTROL FAILED"` → `0`, while
`R4BENCH_NEGCTL=1 ./r4bench mutate | grep -c "NEGATIVE CONTROL FAILED"` → `15`. Three findings
decide it.

- **A same-size edit with nothing forged.** This kernel is `CONFIG_HZ=1000`, so inode timestamps
  advance one jiffy at a time: 200 consecutive writes on ext4 produced **5 distinct stored
  mtimes**, smallest non-zero delta exactly 1,000,000 ns. Over 2,000 trials per row across three
  runs, a real same-size edit made immediately after the install write is byte-identical in
  mtime — and reported unmodified — **99.0–99.2%** of the time (0.7–0.9% at ≥100 µs, 0.1% at
  ≥1 ms, 0% at ≥5 ms). That ~1 ms window is exactly what a post-sync hook or a
  `sync && sed -i` one-liner lands in. The mtime forge-back (`tar -x`, `rsync -a`, `cp -p`, any
  backup restore) has no window at all.
- **A permission-only change and a symlink swap.** `chmod 0755 → 0644` moves no bytes and moves
  *ctime*, not mtime, so both size+mtime and content-only hashing miss it. A file replaced by a
  symlink whose target-path length and `lstat` mtime are both matched is missed by both too; the
  recommended shape reports `kind changed scripts/helper.sh: regular -> symlink`. That one is
  security-relevant rather than bookkeeping: a `--force` overwrite of a path the CLI believes is
  a regular file writes *through* the link, which is what FR-020 exists to prevent.
- **`size + mtime + ctime` is not merely inadvisable but impossible.** Rejected by compiling
  rather than by assuming: `GOOS=windows` → `undefined: syscall.Stat_t`; `GOOS=darwin` →
  `st.Ctim undefined (type *syscall.Stat_t has no field or method Ctim)`.

**Consequence.** T049 stores `{algo, files: {path → {sha256, size, mode, kind}}, dirs: {path →
mode}}`, keys entry-root-relative and `filepath.ToSlash`'d so a record written on Windows reads
on Linux. That is ~146 B per file — 3,764 B per entry, 45 KB for the whole largest profile — so
**T017's `state.json` field must be an object, not a scalar**: this document's on-disk state
model line "the fingerprint from R4" means a per-file map. `Mode` and `Kind` MUST come from
`lstat` on the file as actually written, never from the archive header — under `umask 0027` a
requested 0755 lands as 0750, so recording the header's mode makes the very next `sync` report a
mode conflict on every executable file for anyone whose umask is not 022. A kind change is
reported *instead of* opening the path. Nothing time-based goes in: no mtime, no ctime, no inode
number, since an atomic swap changes the inode every time by design. `Files` and `Dirs` together
are a **closed set over the entry root**, because prune removes an entry by removing the root it
created, recursively — so an unrecorded file inside that root is work a legitimate prune will
delete. That scope applies **only** to a directory the CLI created for this entry: for a
single-file target the root is the file, `Dirs` is empty, and unmanaged neighbours in the parent
are none of the CLI's business. Getting that backwards turns SC-004 into a false-conflict
generator. `Algo` is the migration seam — a known older algorithm is verified with that
algorithm's own verifier, while an unrecognised one must refuse, naming `--force` with FR-036's
"refusal the user can fix" exit code, because assuming unmodified on an unknown fingerprint is
the direction that deletes work. Conflicts are reported **per file**, naming what changed about
each; this is what rules out the 66-byte-per-entry manifest hash, whose verdict is literally
"entry manifest hash differs (cannot say which file)" and which therefore cannot serve FR-029,
FR-034, or the Risks requirement that `--force` name every file it is about to destroy —
recovering the detail by re-extracting from the cache does not save it, because the cache can be
cleared at any time and FR-029 has to keep working when it has been. Compute the content hashes
during extraction from the staged tree, where the extractor already holds every byte, then read
modes and kinds back with `lstat` after the swap; the record is still written after the swap. No
optimisation is needed now, and one specific optimisation must not be added later: a metadata
prefilter can only ever conclude "definitely changed", never "unchanged", so it cannot skip the
hash on the idempotent path — the only path where the cost is paid. If the 242 MiB ceiling entry
ever matters, the answer is parallel hashing (1.05 s → 384 ms measured, same 15/15 matrix), not
a weaker check. The release matrix is unaffected: the recommendation stores no timestamp and no
ctime, so it needs no per-GOOS plumbing at all.

**Not established.** The tree is **synthetic**. The seeded catalogue is 40 files totalling
34,887 bytes — too small to benchmark anything, so the shape was kept and the counts scaled;
the numbers are therefore a fair stand-in rather than a measurement of real bundles. darwin and
windows are unmeasured: the HFS+ 1-second and exFAT 2-second mtime granularities are documented
claims, and the 1-second matrix row models them by truncating stored mtimes rather than by
running on such a volume. They *strengthen* the rejection of size+mtime; what *establishes* it
is the measured ext4/`CONFIG_HZ` finding. The one reported budget breach — ceiling entry, cold
cache, no SHA-2 acceleration, 1.05 s — is a **modelled** worst case: 386.87 MB/s is
`GODEBUG=cpu.sha2=off` on an ARM core standing in for an x86-64 without SHA-NI, not a
measurement of one. Cold-cache figures come from `posix_fadvise(POSIX_FADV_DONTNEED)`, which
drops the guest page cache only: exact for the ext4 trees measured, a lower bound for anyone
re-running against a virtiofs mount. No test in `cli/` exists yet — the harness is scratch and
must not ship. The fifteen-row matrix is the durable form of this gate and belongs in
`cli/internal/record/fingerprint_test.go`, one subtest per mutation named after the behaviour,
with its negative control; the same-size edit inside the clock tick, the matched symlink swap,
the permission-only change, the added file, the added empty directory and the directory chmod
are the six cases that would otherwise have shipped broken.

**R5 — Fake-hub fidelity.** *Open.*
The suite leans on an `httptest` fake. A fake that diverges from the real hub gives green tests
and a broken binary. Resolve by running the same behavioural suite against both the fake and the
compose stack, with the real run in CI. If a case cannot be expressed against both, it is a case
the fake must not silently pass.
Settled by **T022** (the fake as a reusable `httptest` server covering the six endpoints and the
awkward paths) and **T062** (the same behavioural suite run against the real compose stack in
CI). Pending, not forgotten.

**R6 — Does `reportSync` need to be best-effort?** *Open.*
FR-033 says a failed report must not fail the sync. Confirm the hub agrees: check whether a
duplicate report is idempotent server-side, since a retry after a timeout is otherwise a second
audit row for one sync — which would break hub SC-008's exactly-one-row property.
Settled by **T044**, which must confirm server-side idempotence before implementing the retry.
Pending, not forgotten.

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

- **R2 was the schedule risk, and it landed.** Of the three targets the contract enumerates,
  **one ships**: `claude-code`, skills only. `codex` is documented but unobserved and its user
  skills path moved within the last nine months, so it stays unshipped pending one measurement;
  `agents-md` cannot be shipped as an install target at all as specified — a repository-root
  shared markdown file with no per-user location satisfies neither FR-020 nor FR-022/023 nor
  FR-024/028/029, and closing it is a spec decision rather than more research. Both constructors
  return an error wrapping `ErrR2Unresolved` and `sync` refuses the profile rather than exiting 0
  having installed nothing. The spec was written so this costs no rework, and it does not — but
  it is a reduction in scope, not a deferral, and T066's README must say plainly which targets
  are verified.
- **The design's copy will be wrong.** The Connect-the-CLI screen says
  `brew install example/tap/skillhub` and `skillhub login`. Those strings are hub-side and
  need a follow-up change; this feature should not silently leave the screen lying.
- **`--force` is a footgun by construction.** It exists because FR-029 would otherwise make a
  legitimate re-install impossible. Its output must name every file it is about to destroy.
- **A partially applied multi-profile sync.** Entries are atomic individually (FR-024), but a
  sync of twelve entries that fails at the seventh leaves five installed. That is accepted:
  the alternative is a whole-tree transaction, and the next `sync` converges. It must be
  *reported* as partial rather than as failure with no detail.
