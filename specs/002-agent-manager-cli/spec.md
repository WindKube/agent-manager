# Feature Specification: `amctl` — the Agent Manager CLI

**Feature Branch**: `002-agent-manager-cli`

**Created**: 2026-08-28

**Status**: Draft

**Input**: The hub's phase-2 companion. Hub spec `001-agent-manager-hub` lists "the CLI
binary" under Out of Scope and freezes the six endpoints it needs; the Connect-the-CLI
screen presents `login` and `sync` as documentation for a binary that does not exist. This
feature is that binary.

> **Numbering.** `FR-` and `SC-` numbers in this document are local to this feature.
> Requirements of the hub are cited as **hub FR-041**, **hub SC-007** and so on.

---

## Why this exists

The hub can freeze bytes, analyse them and resolve a profile into a lockfile. Nothing
currently puts those bytes on a laptop. Until something does, the whole governance chain
ends at a web page: a platform team can approve a package and still have no idea whether
any machine is running it, and a developer's only route to a skill is to copy it out of a
browser — which is exactly the ungoverned path the hub was built to replace.

`amctl` closes the chain. It is the only sanctioned way packages reach a machine, and the
only thing that reports back that they did.

---

## User Scenarios & Testing

### User Story 1 — Authenticate a new machine (Priority: P1)

An engineer on a new laptop runs `amctl login --hub hub.example.dev`. The CLI opens a
device authorisation, prints a short user code and the verification URL, and polls. The
engineer types the code in a browser and approves through the organisation's identity
provider. The CLI receives a short-lived token, stores it in the platform credential store,
and prints who it is now acting as.

**Why this priority**: nothing else in the CLI works unauthenticated. Every other endpoint
requires a bearer token, and hub FR-044 scopes what the machine can see to the identity
behind it.

**Independent Test**: run `login` against a hub with a seeded identity provider; assert a
usable credential exists afterwards and that `amctl whoami` names the right identity. No
sync required.

**Acceptance Scenarios**:

1. **Given** no stored credential, **When** `login` runs, **Then** a user code and
   verification URL are printed, the code is bound to this host's name, and the command
   blocks on polling at the interval the hub returned — never faster.
2. **Given** a pending authorisation, **When** a human approves it, **Then** the next poll
   returns a token, the token is written to the credential store, and the command exits 0
   naming the authenticated identity and the hub.
3. **Given** a pending authorisation, **When** it expires unapproved, **Then** the command
   exits non-zero saying the code expired, and no credential is written.
4. **Given** a pending authorisation, **When** the hub answers `slow_down`, **Then** the
   poll interval increases and the CLI does not treat it as a failure.
5. **Given** a platform with no reachable credential store, **When** `login` succeeds,
   **Then** the token is written to a file readable only by its owner, and the CLI says on
   stderr that it fell back and why.
6. **Given** a stored credential for a different hub, **When** `login --hub other` runs,
   **Then** both are retained: a credential is per hub, and logging into one must not sign
   the machine out of another.

---

### User Story 2 — Sync a profile onto the machine (Priority: P1)

The engineer runs `amctl sync --profile platform-engineer`. The CLI fetches the profile's
head revision as a lockfile, downloads each entry's bundle, verifies every digest before
anything is written, unpacks each into the agent directories the profile's targets name, and
reports what it installed and what the hub told it to skip.

**Why this priority**: this is the product. US1 exists to enable it.

**Independent Test**: against a seeded hub, sync a profile into a temporary HOME and assert
the resulting tree, file by file, against the lockfile.

**Acceptance Scenarios**:

1. **Given** an authenticated machine and a readable profile, **When** `sync` runs, **Then**
   every entry in the lockfile is installed at its exact locked version and the command
   exits 0.
2. **Given** a bundle whose bytes do not match the `Digest` header, **When** `sync` runs,
   **Then** nothing from that bundle is written anywhere, the command exits non-zero, and
   the failure names the package and both digests.
3. **Given** a lockfile with a `skipped` array, **When** `sync` completes, **Then** each
   skipped entry is reported with the hub's reason and the version it would have resolved
   to — a skip is never silently omitted (hub FR-036).
4. **Given** a profile enabling only some targets, **When** `sync` runs, **Then** only those
   targets' directories are written, and no other agent directory is touched (hub FR-039).
5. **Given** a successful sync, **When** it finishes, **Then** exactly one sync report is
   sent to the hub naming the profile, the revision, this host and the targets written.
6. **Given** an interrupted sync, **When** it is run again, **Then** it completes without
   manual cleanup and the resulting tree is identical to an uninterrupted run.
7. **Given** two profiles naming the same package at different versions, **When** both are
   synced, **Then** the conflict is refused before anything is written, naming both
   profiles and both versions.

---

### User Story 3 — See what will change before it changes (Priority: P2)

Before letting it touch the machine, the engineer runs `amctl sync --dry-run`. The CLI
resolves and reports exactly what it would add, upgrade, downgrade and remove, and writes
nothing.

**Why this priority**: this command deletes files. A person's first use of a tool that
deletes files should be able to be a question rather than an action. It also makes the
reconciliation logic assertable without a filesystem.

**Independent Test**: run `--dry-run` against a machine in a known state, diff the report
against the tree afterwards, and assert the tree is byte-identical.

**Acceptance Scenarios**:

1. **Given** any machine state, **When** `sync --dry-run` runs, **Then** no file is created,
   modified or removed, and no sync report is sent to the hub.
2. **Given** a package that would be removed, **When** `--dry-run` runs, **Then** it is
   listed as a removal with the reason — left the profile, version rejected, or gate.
3. **Given** a machine already in the target state, **When** `--dry-run` runs, **Then** it
   reports no changes, and a subsequent real `sync` writes nothing.

---

### User Story 4 — Reconcile drift and removals (Priority: P2)

A package is removed from the profile, or the hub rejects a version already installed. The
next `sync` removes it from the machine. The CLI removes only what it installed and never
touches a file a person put there.

**Why this priority**: without it, a rejected package stays on the laptop and the hub's
verdict means nothing. It is what makes the registry governed rather than advisory.

**Independent Test**: install, then change the profile server-side, then sync again and
assert both the removal and the survival of unmanaged neighbours.

**Acceptance Scenarios**:

1. **Given** a package installed by a previous sync, **When** it leaves the profile,
   **Then** the next sync removes its directory and the lockfile entry.
2. **Given** an installed version the hub has since rejected, **When** sync runs, **Then**
   the version is removed from the machine, not merely reported.
3. **Given** a skill directory the engineer created by hand, **When** sync runs, **Then** it
   is left exactly as it is — the CLI's record of what it installed is the only thing it
   will remove.
4. **Given** a managed file modified since install, **When** sync would remove or overwrite
   it, **Then** it is preserved and reported as a conflict, unless `--force` is passed.
5. **Given** a target disabled since the last sync, **When** sync runs, **Then** what the
   CLI wrote under that target is removed.

---

### User Story 5 — Work on a slow or absent network (Priority: P3)

Bundle bytes are immutable and addressed by digest, so a machine that has seen a version
never needs to download it again. On an aeroplane, `amctl sync --offline` reinstalls from
cache or fails honestly.

**Why this priority**: it is nearly free — immutability makes the cache trivially correct —
and it turns the second sync on a machine from a download into a copy.

**Independent Test**: sync, clear the tree but keep the cache, sync again with the network
blocked, and assert the tree is restored.

**Acceptance Scenarios**:

1. **Given** a cached bundle whose digest matches the lockfile, **When** sync runs, **Then**
   it is not downloaded again.
2. **Given** `--offline` and a lockfile entry absent from the cache, **When** sync runs,
   **Then** the command exits non-zero naming what is missing, and the machine is left
   unchanged.
3. **Given** a cache entry whose bytes no longer match its digest, **When** sync runs,
   **Then** it is discarded and re-downloaded rather than trusted.

---

### User Story 6 — Run unattended (Priority: P3)

A provisioning script or CI job syncs a machine with no human present and no browser.

**Why this priority**: it is how the tool reaches machines at scale, and it constrains
earlier design — every prompt needs a non-interactive path from the start rather than a
retrofit.

**Independent Test**: run `sync` in an environment with no TTY, no credential store and a
token supplied by the environment; assert success and no prompt.

**Acceptance Scenarios**:

1. **Given** a token in the environment, **When** any command runs, **Then** it is used, no
   credential store is opened, and nothing is written to it.
2. **Given** no TTY, **When** a command would prompt, **Then** it fails with a message
   naming the flag that answers the question instead of blocking.
3. **Given** `--output json`, **When** a command runs, **Then** every result is machine
   readable on stdout, every diagnostic is on stderr, and the exit code distinguishes
   "nothing to do" from "changes applied" from "failed".

---

### User Story 7 — Know what this machine has (Priority: P3)

`amctl status` reports which hub, which identity, which profiles, which revisions, and
whether the tree matches. `amctl logout` removes the credential.

**Why this priority**: a governed machine whose state nobody can read is not much better
than an ungoverned one, and every support conversation starts here.

**Acceptance Scenarios**:

1. **Given** a synced machine, **When** `status` runs, **Then** it names the hub, the
   identity, each profile with its revision, and any drift from the recorded state.
2. **Given** a machine that has never synced, **When** `status` runs, **Then** it says so
   and exits 0 — an empty state is a state, not an error.
3. **Given** a stored credential, **When** `logout` runs, **Then** it is removed and
   nothing installed is touched.

---

### Edge Cases

- **The lockfile names a version the hub will not serve.** A version rejected between
  publication and sync answers 403. The entry is reported and skipped; the sync does not
  abort, because one poisoned package must not block the other eleven.
- **A pre-signed redirect.** `GET /v1/bundles/...` may answer 307 to object storage. The
  redirect is followed, but the bearer token is not sent to the redirect target, and the
  digest is still verified against the `Digest` header from the hub's own response.
- **A bundle expands to more than the machine can hold.** Extraction is capped the same way
  the hub caps ingestion; the disk is not the cap.
- **A malicious bundle path.** The hub extracts and re-packs, but the CLI is the last hop
  and treats every archive as hostile anyway: no absolute paths, no `..`, no symlinks, no
  writes outside the entry's own directory.
- **Two hubs.** Credentials, cache and installed state are per hub. A machine may be
  synced from two hubs without either seeing the other's state.
- **The agent directory is a symlink** — a dotfiles repository often makes it one. It is
  followed if it resolves inside the user's home, refused otherwise.
- **A package id that is not two path segments.** It cannot address a bundle and cannot name
  a directory; it is refused before any request is made.
- **Clock skew.** A token that appears expired but is accepted, or vice versa, is decided by
  the hub. The CLI does not pre-emptively refuse a token on local time alone.
- **`sync` while another `sync` runs.** The second refuses rather than interleaving writes.
- **The hub is unreachable.** Distinguished from "unauthorised" and from "no such profile" in
  both the message and the exit code.
- **HOME is unset or not writable.** Refused before any network call, naming the variable.

---

## Requirements

### Functional Requirements

**Identity and credentials**

- **FR-001**: The CLI MUST authenticate through the hub's RFC 8628 device authorisation
  flow, binding the request to this machine's hostname so the approving human sees what
  they are approving (hub FR-041).
- **FR-002**: The CLI MUST poll no faster than the interval the hub returns, and MUST honour
  `slow_down` by increasing it.
- **FR-003**: The CLI MUST store the issued token in the platform credential store where one
  is reachable, and MUST fall back to a file readable and writable only by its owner where
  none is — reporting the fallback on stderr, never silently.
- **FR-004**: The CLI MUST refuse a fallback credential file whose permissions are wider than
  owner-only rather than reading it.
- **FR-005**: A token supplied by the environment MUST take precedence over stored
  credentials, and MUST NOT be persisted anywhere.
- **FR-006**: Credentials MUST be scoped per hub. Logging in to one hub MUST NOT affect a
  credential for another.
- **FR-007**: The CLI MUST NOT write a token, device code or user code to any log, report or
  error message.
- **FR-008**: `logout` MUST remove the credential for a hub and MUST NOT alter anything
  installed.

**Resolution**

- **FR-009**: The CLI MUST obtain what to install from the hub's resolved revision lockfile.
  It MUST NOT resolve versions, ranges or gate decisions itself — those belong to the hub,
  and a second implementation of them is a second answer.
- **FR-010**: The CLI MUST support syncing a named revision as well as `head`, so a machine
  can be pinned to a known state.
- **FR-011**: The CLI MUST report every entry in the lockfile's `skipped` array with the
  hub's reason and the version it would have resolved to (hub FR-036).
- **FR-012**: The CLI MUST refuse, before writing anything, a set of profiles that resolve
  the same package to two different versions, naming both profiles and both versions.
- **FR-013**: The CLI MUST record the exact revision it installed, per profile, so a later
  run can tell drift from change.

**Download and verification**

- **FR-014**: The CLI MUST verify each bundle's sha256 against the digest the hub supplied
  **before** any byte of it reaches the installation tree.
- **FR-015**: A digest mismatch MUST abort that entry, leave the machine unchanged for it,
  and exit non-zero.
- **FR-016**: The CLI MUST NOT send its bearer token to a redirect target when following a
  pre-signed object-store redirect.
- **FR-017**: The CLI MUST cache bundle bytes by digest and MUST reuse a cache entry only
  after confirming its bytes still hash to that digest.
- **FR-018**: `--offline` MUST complete from cache alone or fail naming what is missing,
  and MUST NOT leave a partially installed tree.
- **FR-019**: The CLI MUST treat every archive as hostile: no absolute paths, no `..` after
  cleaning, no symlinks, no hardlinks, no device nodes, no duplicate paths, and no write
  outside the entry's own destination directory. Extraction MUST be capped on entry count,
  entry size, total size, compression ratio and path depth.

**Installation and layout**

- **FR-020**: The CLI MUST install into the per-user agent directories that the profile's
  enabled targets name, under the invoking user's home, and MUST NOT write outside it.
- **FR-021**: Each target's on-disk layout MUST be verified against that agent's own
  documented convention before release. A sync that writes to a path the agent does not read
  reports success and does nothing, which is the worst failure this tool can have.
- **FR-022**: An installed entry MUST be identifiable on disk as belonging to a specific
  package and version without consulting the hub.
- **FR-023**: Two packages whose names collide across publishers MUST install to distinct
  directories.
- **FR-024**: Installation MUST be atomic per entry: an entry is either fully present at the
  locked version or absent, never half-written.
- **FR-025**: `sync` MUST be idempotent. A second run against an unchanged hub MUST make no
  filesystem modification.

**Reconciliation**

- **FR-026**: The CLI MUST maintain a record of what it installed — package, version, digest,
  target and paths — as the authority for what it may later remove.
- **FR-027**: The CLI MUST remove an installed entry that is no longer in any synced
  profile's lockfile, or whose version the hub now refuses to serve.
- **FR-028**: The CLI MUST NOT remove or overwrite any path absent from its own record.
- **FR-029**: The CLI MUST detect a managed path modified since installation, preserve it,
  and report it as a conflict unless `--force` is given.
- **FR-030**: Disabling a target MUST remove what the CLI wrote under it.
- **FR-031**: `--dry-run` MUST report the full add/upgrade/downgrade/remove set, write
  nothing, and send no sync report.

**Reporting and observability**

- **FR-032**: After a successful sync the CLI MUST report it to the hub — profile, revision,
  host, targets written and entries skipped locally — exactly once.
- **FR-033**: A failed sync report MUST NOT fail the sync, and MUST be reported on stderr.
  The bytes are already on disk; refusing to admit it would be the wrong correction.
- **FR-034**: `status` MUST report the hub, identity, profiles, revisions and any drift
  between the record and the tree.
- **FR-035**: `--output json` MUST put results on stdout and diagnostics on stderr, so the
  CLI is scriptable without parsing prose.
- **FR-036**: Exit codes MUST distinguish success-with-changes, success-with-no-changes,
  a refusal the user can fix, and an unexpected failure.
- **FR-037**: Every command MUST run without a TTY, or fail naming the flag that supplies
  what it would have asked for.

**Safety and concurrency**

- **FR-038**: Concurrent syncs against the same home MUST be refused, not interleaved.
- **FR-039**: The CLI MUST refuse to run where the home directory is unset or unwritable,
  before making any network request.
- **FR-040**: Every error MUST distinguish unreachable, unauthorised, forbidden and
  not-found. "Something went wrong" is not an acceptable diagnosis for any of the four.
- **FR-041**: The CLI MUST verify it is talking to a hub over TLS, and MUST require an
  explicit flag to accept anything else, so a local-development shortcut cannot be the
  default.

### Key Entities

- **Installation record** — the CLI's own account of what it put on this machine, per hub:
  each entry's package id, version, digest, target, destination path and a content
  fingerprint taken at install. It is the authority for removal (FR-026) and the reason the
  CLI can prune safely without owning the whole directory.
- **Bundle cache** — immutable bundle bytes addressed by digest, shared across profiles,
  hubs and targets. Correct by construction because a version's bytes never change.
- **Credential** — one short-lived token per hub, with the identity it belongs to and its
  expiry, in the platform store or an owner-only file.
- **Target** — one agent's directory convention (`claude-code`, `agents-md`, `codex`), which
  the profile enables and the CLI writes. Advisory from the hub's side: it stores nothing per
  target (hub FR-039).
- **Resolved revision** — the hub's lockfile, consumed and never recomputed.

---

## Success Criteria

- **SC-001**: A machine goes from nothing installed to a synced profile in under two minutes
  of human effort, browser approval included (mirrors hub SC-007).
- **SC-002**: `sync` is idempotent: a second run against an unchanged hub performs zero
  filesystem modifications, asserted by comparing modification times across the tree.
- **SC-003**: Every installed byte is digest-verified before it is written. Tested by
  corrupting a bundle in transit and asserting nothing lands on disk.
- **SC-004**: Reconciliation removes exactly what the CLI installed and nothing else, proven
  against a tree seeded with unmanaged neighbours in every directory the CLI writes.
- **SC-005**: A hostile-bundle corpus — absolute paths, traversal, symlink escape, hardlink,
  duplicate entries, a zip bomb, a deep path — is refused with zero escapes outside the
  destination directory.
- **SC-006**: A second sync of a version already seen performs no download, measured by the
  request count against the hub.
- **SC-007**: Every command completes with no TTY and no interactive prompt, in an
  environment with no credential store, given a token from the environment.
- **SC-008**: The install tree matches the lockfile exactly after a sync interrupted at any
  point and re-run — verified by killing the process at several stages.
- **SC-009**: For every enabled target, an installed skill is actually loaded by that agent —
  verified against the agent's own documented path, not against this CLI's assumption
  (FR-021).
- **SC-010**: No token appears in any output stream, log line or error message, asserted by
  scanning all captured output of the full test suite for the known test token.

---

## Assumptions

- **The hub is the resolver.** Every gate decision, version resolution and readability check
  already happened server-side. The CLI's job is bytes and files. This is what keeps two
  implementations of the gate from disagreeing.
- **Installation is per user, not per project.** One machine-wide set of agent directories
  under the invoking user's home. A per-project scope is a plausible later addition and is
  deliberately not in this feature.
- **Bundle bytes are immutable**, so a digest-addressed cache needs no invalidation. This is
  hub FR-007 and the CLI depends on it.
- **Tokens are short-lived** (hub FR-043), which is what bounds the exposure of the
  file-based credential fallback.
- **The six frozen endpoints are sufficient** and will not change shape: device authorize,
  device token, list profiles, get revision, get bundle, report sync.
- **Targets are the three the contract enumerates.** A fourth is a change to the hub's enum
  first, and to this CLI second.
- **The design's `skillhub` name is not used.** The product is Agent Manager; the binary is
  `amctl`. The Connect-the-CLI screen's copy will need updating to match, which is a hub
  change and not this feature's.

---

## Out of Scope

- **Per-project installation** and a committable project lockfile.
- **Publishing from the CLI.** Registration stays a hub concern; there is no `amctl publish`.
- **Editing profiles.** The CLI reads profiles; it does not create or modify them.
- **Signature verification.** Deferred in the hub (hub FR-048a) and therefore here. The CLI
  carries the signature reference through to its record and never renders unverified as a
  pass.
- **A background daemon or scheduled sync.** `sync` is a command a person or a provisioner
  runs.
- **Package distribution of the CLI itself** — Homebrew, apt, winget. Release artefacts and a
  container image are in scope; third-party package repositories are not.
- **Interactive profile selection TUI.** The design's Connect-the-CLI screen shows a picker;
  `--profile` flags and a plain list are enough for this feature.
