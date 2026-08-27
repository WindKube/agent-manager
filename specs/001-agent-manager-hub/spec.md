# Feature Specification: Agent Manager — self-hosted plugin & skill registry

**Feature Branch**: `001-agent-manager-hub`

**Created**: 2026-08-27

**Status**: Draft

**Input**: Implement the Claude Design project `Agent Manager.dc.html`
(claude.ai/design/p/4f533038-5662-4716-8ebf-0c128d64568f) as a Go system, runnable via
`docker compose up`, split into api / web / worker roles with the security scanner as a
separate worker.

**Design source of truth**: `docs/design/agent-manager.dc.html` (imported verbatim from
the Claude Design project). Where this spec and the design disagree on a label, count,
badge or interaction, the design wins and this spec is wrong. `docs/design/support.js`
is the design canvas runtime and carries no product meaning.

---

## Context

Teams accumulate agent plugins and skills from internal groups and from the public
internet. Those artefacts are directories of instructions, scripts and MCP server
declarations that an agent will read and act on. Installing one from an untrusted
publisher is closer to installing a browser extension than to adding a library: it can
tell the agent to read `~/.aws/credentials`, or shell out to `curl` against a host
nobody declared.

Agent Manager is the governed place those artefacts live. It fetches a source, freezes it
as an immutable version, statically analyses it, and only then lets it appear in a
profile that people's machines sync from.

### Terminology

- **Package** — the unit registered in the catalog. Either a **plugin** (a portable
  multi-component package conforming to Agent Plugins 1.0.0, with `plugin.json` at its
  root) or a standalone **skill** (a directory whose entry point is `SKILL.md` with YAML
  frontmatter, per the Agent Skills spec). A skill may also be *distributed inside* a
  plugin, in which case the catalog shows both and links them.
- **Version** — an immutable snapshot of a package's file tree, addressed by
  `publisher/name@semver`, stored once with a `sha256` digest.
- **Profile** — a named, shareable set of packages with a version-resolution policy and
  a set of sync targets. Publishing a profile produces a numbered **revision** (`r14`)
  that is a resolved lockfile.
- **Finding** — one rule violation the scanner raised against one version.
- **Verdict** — a version's overall scan state: `scanning`, `clean`, or `flagged`.
- **Gate** — the org policy deciding what a `flagged` verdict does to distribution:
  `block`, `approval`, or `warn-with-override`.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Register a source and get a scanned, immutable version (Priority: P1)

A platform engineer has a plugin repository. They open the catalog, click **Add source**,
paste the repository URL with a ref and an optional subdirectory (or instead upload a
`.zip`/`.tar.gz` of the tree), choose a category and a visibility, and submit. The system
fetches the tree, validates the manifest, unpacks and freezes it as a version in object
storage, then scans it. The catalog row shows `Scanning`, then `Clean` or `Flagged`.

**Why this priority**: Nothing else exists without it. Fetch → freeze → scan is the
spine; the catalog, the scanner queue, the storage view and the audit log are all
downstream of a version existing.

**Independent Test**: With only this story implemented, a user can register a package
from a URL or an archive and see it land in the catalog with a digest, an object key and
a verdict. That alone is a usable registry.

**Acceptance Scenarios**:

1. **Given** an empty catalog, **When** a user registers `https://github.com/org/plugin`
   at ref `v1.3.0` with subdirectory `plugins/platform-toolkit`, **Then** a version
   `1.3.0` is created, its bytes are written once to
   `skills/<publisher>/<name>/1.3.0/bundle.tar.zst`, its `sha256` is recorded, and a scan
   job is enqueued.
2. **Given** an archive whose root contains `plugin.json`, `skills/`, `mcp.json`,
   `com.anthropic.claude-code/hooks/`, `.github/` and `README.md`, **When** it is
   uploaded, **Then** the pre-submit preview lists every entry with a validation mark,
   marks `.github/` and `README.md` as *outside spec, dropped*, and the stored tree
   excludes them.
3. **Given** a `plugin.json` that fails the Agent Plugins 1.0.0 schema, **When** it is
   submitted, **Then** no version is created, the failure is reported against the
   specific schema path, and nothing is written to object storage.
4. **Given** `example/platform-toolkit@1.3.0` already exists, **When** the same
   `publisher/name@version` is registered with different bytes, **Then** the request is
   rejected as an immutability violation and the stored version is untouched.
5. **Given** a registration whose URL resolves to a private, loopback or link-local
   address, **When** the fetch is attempted, **Then** it is refused before any connection
   completes and the failure is recorded as a fetch error, not a scan finding.
6. **Given** any successful fetch, **When** it completes, **Then** an audit row is
   written with actor `fetcher`, source `system`, and text naming the stored version.

---

### User Story 2 — Browse and narrow the catalog (Priority: P1)

Someone looking for a capability opens the catalog and narrows a mixed list of plugins
and standalone skills by free-text search, by kind, by trust status, by one or more
categories, and by one or more tags — then sorts by name, usage or recency.

**Why this priority**: A registry nobody can search is a bucket. This is the screen the
design spends the most surface on, and it is the entry point to every other screen.

**Independent Test**: Seed the catalog with the design's ten packages and drive every
filter, facet and sort control, asserting the result set and the result count.

**Acceptance Scenarios**:

1. **Given** the seeded catalog, **When** the user types a query, **Then** rows are
   matched against name, id, publisher and tags (substring, case-insensitive), and the
   result count reads `N results` (or `1 result`).
2. **Given** the kind filter, **When** `Plugins` is selected, **Then** only packages of
   kind plugin remain; `Skills` shows only standalone and plugin-distributed skills;
   `All` shows both.
3. **Given** the status filter, **When** `Verified` is selected, **Then** only packages
   from a verified publisher **and** with a `clean` verdict remain; `Flagged` shows every
   package whose verdict is not `clean`; `Community` shows non-verified publishers.
4. **Given** the Category facet, **When** it is opened, **Then** it lists every category
   with the count of matching packages, supports typing to fuzzy-filter the option list,
   supports multi-select, shows `Any` / the single name / `N selected` as its summary,
   and offers Clear.
5. **Given** the Tag facet, **When** two tags are selected, **Then** only packages
   carrying **both** tags remain (AND, not OR).
6. **Given** any sortable column, **When** its header is clicked, **Then** it sorts
   descending, and clicking the same header again sorts ascending, with the direction
   arrow shown on the active column only.
7. **Given** a filter combination with no matches, **When** it is applied, **Then** the
   table shows the empty state instead of an empty grid, and a reset control appears
   whenever any category or tag is selected.

---

### User Story 3 — Inspect a package before trusting it (Priority: P1)

Before adding something to a profile, a reviewer opens its detail page: what it is, where
it came from, what it contains, what its manifest declares, what capabilities it is
asking for, what versions exist with what digests, and who already depends on it.

**Why this priority**: This is the screen that turns "a package exists" into "a human can
make a decision about it". It is also where the capability model becomes visible, which
everything in the scanner depends on.

**Independent Test**: Open each seeded package and assert the detail page renders the
correct manifest form, capability levels, version list and dependants.

**Acceptance Scenarios**:

1. **Given** a plugin, **When** its detail page is opened, **Then** it shows the package
   file tree, the component list (each marked `skill`, `mcp` or `ext`), the raw
   `plugin.json`, and an origin line stating the spec version and the count of skills and
   MCP servers it contains.
2. **Given** a standalone skill, **When** its detail page is opened, **Then** the package
   contents section is absent, the manifest section shows the `SKILL.md` frontmatter, and
   the origin line states whether it is standalone or distributed inside a named plugin
   version.
3. **Given** any package, **When** its detail page is opened, **Then** declared
   capabilities are listed with a name, a human note and a level of `Scoped`,
   `Allowlisted` or `Review`, where a shell capability is always at least `Review`.
4. **Given** any package, **When** its versions are listed, **Then** each row shows the
   semver, its tag (`latest`, `pinned by N`, or `archived`), its date, its full object
   key and its `sha256` digest.
5. **Given** a package used by profiles, **When** its detail page is opened, **Then** it
   names each profile and how that profile resolves it (`latest` or a pinned version),
   and summarises the number of people and profiles affected.

---

### User Story 4 — Triage a scanner finding and decide (Priority: P1)

A security reviewer opens the Scanner screen, sees quarantine counts and open findings,
selects one, reads the rule, the explanation, the file-and-line evidence and the full
matrix of checks that ran, then either rejects the version or approves it with a note.

**Why this priority**: The scanner is the reason this system exists rather than a shared
folder. A registry that ingests but cannot adjudicate provides governance theatre.

**Independent Test**: Seed the four design findings, drive selection, and assert that
approve and reject each change the version's distribution state and write audit rows.

**Acceptance Scenarios**:

1. **Given** the Scanner screen, **When** it loads, **Then** it shows versions scanned in
   the last 30 days, the quarantined count, the count of active overrides with the
   nearest expiry, and the median fetch-to-verdict duration.
2. **Given** the findings list, **When** a finding is selected, **Then** the detail pane
   shows its severity, its rule identifier, its subject as `publisher/name@version`, a
   prose explanation, an evidence block quoting the offending file and line, and every
   check that ran with a pass / fail / warn-count result.
3. **Given** a flagged version, **When** a reviewer approves it with a note, **Then** an
   override is recorded with the reviewer's identity, the note and an expiry; the version
   becomes distributable subject to the gate; and an audit row is written with kind
   `approve`.
4. **Given** a flagged version, **When** a reviewer rejects it, **Then** the version stays
   quarantined, cannot be resolved by any profile regardless of gate, and an audit row is
   written.
5. **Given** the org policy *rescan on every new version*, **When** a new version of any
   package is published, **Then** already-approved versions of that package are
   re-enqueued for scanning and a new finding on an approved version reopens it.

---

### User Story 5 — Assemble, pin and publish a profile (Priority: P2)

A profile owner curates a named set of packages, chooses per package whether it floats to
`latest` or is pinned to a specific version, sees each one's scan state and how the org
gate affects it, shares the profile with people and groups, picks which agent directories
it writes to, and publishes a numbered revision.

**Why this priority**: Profiles are how the catalog reaches a machine, but a catalog with
a scanner is already independently useful. This depends on stories 1–4 existing.

**Independent Test**: Build a profile from seeded packages, toggle pins, publish, and
assert the resulting revision lockfile resolves exactly as the UI displayed.

**Acceptance Scenarios**:

1. **Given** a profile skill row, **When** its resolution is toggled from `latest` to
   `pinned`, **Then** the displayed resolved version changes from the floating latest to
   the pinned version, and the change is not durable until a revision is published.
2. **Given** the gate is `block` and a profile contains a flagged package, **When** the
   profile resolves, **Then** that package resolves to its most recent clean version, and
   the screen states this in the policy note.
3. **Given** the gate is `approval`, **When** a profile containing an unapproved flagged
   version resolves, **Then** that package is excluded and reported as requiring a named
   reviewer approval.
4. **Given** the gate is `warn-with-override` and an active override exists, **Then** the
   flagged version resolves with a warning and the override is visible in the audit log.
5. **Given** a curated profile, **When** a revision is published, **Then** a new
   sequential revision (`r15`) is written as an immutable resolved lockfile naming every
   package at an exact version and digest, the previous revision remains readable, and an
   audit row of kind `profile` records the change summary.
6. **Given** a profile, **When** sharing is configured, **Then** individual members and
   identity-provider groups can each hold `Owner`, `Maintainer`, `Reviewer` or `Consumer`,
   and a share link exists whose forks do not inherit future revisions.
7. **Given** a profile, **When** sync targets are configured, **Then** each of
   `~/.claude/skills/`, `<repo>/AGENTS.md` and `~/.codex/prompts/` can be independently
   enabled, and targets affect only what a client writes — never what the server stores.

---

### User Story 6 — Authorise a machine and resolve a profile for it (Priority: P2)

An engineer on a new laptop runs the CLI. It requests a device authorisation; the hub
shows a short user code bound to the requesting host; the engineer approves it in the
browser through the org identity provider; the CLI receives a short-lived token, lists
the profiles that identity may read, and fetches resolved revisions and bundles.

**Why this priority**: This is the distribution edge. The **server side** is in scope; the
CLI binary itself is explicitly phase 2 (see Out of Scope).

**Independent Test**: Drive the device flow end to end against the local identity
provider with `curl`, then fetch a resolved revision and a bundle with the issued token.

**Acceptance Scenarios**:

1. **Given** an unauthenticated client, **When** it requests device authorisation,
   **Then** the hub returns a device code, a short human-typable user code, a
   verification URI and an expiry, and binds the request to the requesting host.
2. **Given** a pending device authorisation, **When** the user approves it via the
   identity provider, **Then** the CLI's next poll returns a short-lived access token and
   an audit row of kind `login` is written naming the host.
3. **Given** an expired or already-consumed device code, **When** it is polled or
   approved, **Then** it is refused and no token is issued.
4. **Given** an authenticated client, **When** it lists profiles, **Then** it sees exactly
   the profiles that identity may read via direct membership or group mapping, each with
   its package count — and no others.
5. **Given** an authenticated client, **When** it fetches a resolved revision, **Then** it
   receives the lockfile with every package at an exact version, digest and download
   reference, with gate-excluded packages listed as skipped and the reason given.

---

### User Story 7 — Configure the organisation (Priority: P3)

An admin connects the identity provider, maps provider groups to roles, sets the policies
every profile inherits, and curates the category vocabulary publishers pick from.

**Why this priority**: The system ships with working defaults; this makes them
adjustable. Real value, but every other story functions without the screen.

**Independent Test**: Change each policy and each mapping and assert the behaviour
downstream changes accordingly.

**Acceptance Scenarios**:

1. **Given** identity provider settings, **When** they are viewed, **Then** provider,
   issuer, client id, scopes and device endpoint are shown, the connection can be tested,
   and the secret can be rotated without exposing the current value.
2. **Given** a group-to-role mapping, **When** a user authenticates carrying that group,
   **Then** they hold that role, and a user carrying several mapped groups holds the union
   of their permissions.
3. **Given** the policy *require signed bundles*, **When** it is enabled and an unsigned
   version is submitted, **Then** publication is refused.
4. **Given** the policy *community sources need review*, **When** it is enabled and a
   non-verified publisher registers a source, **Then** the version enters a review queue
   rather than becoming immediately distributable.
5. **Given** categories, **When** an admin edits the vocabulary, **Then** publishers
   choose from it at registration, each category shows its item count, and tags remain
   free-form values read from the manifest — never admin-curated.

---

### User Story 8 — Read the audit trail and the storage state (Priority: P3)

A compliance reviewer reads a chronological log of who fetched, approved, published,
shared, synced or logged in, from which source, and exports it. An operator reads the
object store's key layout, its settings and its recent fetches.

**Why this priority**: Required for the governance story to be credible, but not on any
critical path.

**Independent Test**: Perform one action of each kind and assert exactly one
correspondingly-typed audit row appears with the right actor and source.

**Acceptance Scenarios**:

1. **Given** any state-changing action, **When** it completes, **Then** exactly one audit
   row exists naming the actor (a person's identity, or `fetcher`/`scanner` for system
   actors), the event kind, human-readable text, and the source (`web`, `system`, or
   `cli / <hostname>`).
2. **Given** the audit log, **When** CSV export is requested, **Then** every row currently
   in scope is exported, not just the visible page.
3. **Given** the storage screen, **When** it loads, **Then** it shows object count, total
   size after compression, bucket region and CLI read cache hit rate; the key layout for
   both `skills/` and `profiles/`; the bucket's versioning, object-lock, encryption,
   write-access and retention settings; and the most recent fetches with an outcome
   indicator.

---

### Edge Cases

**Ingestion**
- An archive containing a member with an absolute path, a `..` component, a symlink or a
  hardlink is rejected outright — not sanitised, not skipped silently.
- An archive that decompresses to far more than its packed size (a zip bomb) is aborted
  once the cumulative decompressed-size cap is hit, and reported as a malformed archive.
- An archive over the 25 MB upload limit, with too many entries, or nested too deeply is
  rejected before extraction begins.
- A repository URL whose ref does not exist, whose subdirectory is absent, or that
  requires credentials the hub does not hold, fails as a fetch error with the reason
  distinguishable from a scan failure.
- A public hostname that resolves to a private address, or redirects to one mid-chain, is
  refused at the connect for **every** hop and every address in a rotation.
- A `plugin.json` declaring components that do not exist on disk (`skills/` missing) is a
  manifest validation failure, not a scan finding.

**Versioning and resolution**
- A package whose only versions are all flagged, under a `block` gate, resolves to
  nothing and is reported as unresolvable rather than silently omitted.
- A pinned version that is later archived, rejected or deleted keeps the profile
  resolving to the pin until the pin is changed; the profile screen surfaces that the pin
  is stale.
- A non-semver version string from an upstream tag is normalised or rejected at
  registration, never stored in a form that breaks ordering.
- Two versions claiming the same semver from different refs collide on the immutability
  rule; the second is refused.

**Scanning**
- A scan that exceeds its time budget leaves the version in `scanning` with a recorded
  timeout and is retried with backoff; it never silently becomes `clean`.
- A rule pack update that would newly flag an already-approved version reopens it rather
  than mutating history.
- A bundle containing no analysable files still produces a verdict with the checks that
  ran and their trivial results.

**Authorisation and sharing**
- A user losing a mapped group loses access at their next token refresh, not at their next
  login.
- A forked profile whose upstream publishes a new revision does not receive it.
- A device code approved by a different identity than the one that requested it is
  refused.

**Concurrency**
- Two publishes of the same profile racing produce two sequential revisions, never one
  overwritten revision or a gap in the sequence.
- A fetch retried after a partial write must not leave a readable half-written version;
  a version becomes visible only when its bytes, digest and metadata are all committed.

---

## Requirements *(mandatory)*

### Functional Requirements

**Ingestion and immutability**

- **FR-001**: The system MUST accept a package source as either an uploaded archive
  (`.zip` or `.tar.gz`, at most 25 MB) or a fetchable URL with an optional ref and an
  optional subdirectory.
- **FR-002**: The system MUST fetch every user-supplied URL through an outbound client
  that refuses private, loopback, link-local and other non-public addresses, re-checking
  on every redirect hop and every resolved address.
- **FR-003**: The system MUST extract archives under explicit caps on entry count, per-
  entry size, total decompressed size and path depth, and MUST reject absolute paths,
  parent-directory traversal, symlinks and hardlinks.
- **FR-004**: The system MUST validate a plugin's `plugin.json` against the published Agent
  Plugins schema identified by its `$schema` field (`$id`
  `https://agent-plugins.org/schemas/<ver>/plugin.schema.json`, ten permitted top-level
  fields, `additionalProperties: false`), and a skill's `SKILL.md` frontmatter against the
  published Agent Skills key set, before any version is created. Non-conformant manifests
  are rejected; the schemas are not locally relaxed to admit extra fields.
- **FR-005**: The system MUST discard files outside the spec layout and MUST report which
  paths were discarded before the user commits to registration.
- **FR-006**: The system MUST store each version's tree exactly once at
  `skills/<publisher>/<name>/<version>/bundle.tar.zst`, alongside its manifest, its scan
  report and its signature, with a per-package `index.json` carrying the version list and
  the latest pointer.
- **FR-007**: The system MUST record a `sha256` digest for every stored version and MUST
  refuse to republish an existing `publisher/name@version` with different bytes.
- **FR-008**: A version MUST become visible only when its bytes, digest and metadata are
  all committed; a partial write MUST NOT be readable.

**Catalog**

- **FR-009**: The catalog MUST present plugins and standalone skills in one list, each row
  showing name, id, kind, category, version, scan verdict, usage count and recency.
- **FR-010**: The catalog MUST support free-text search across name, id, publisher and
  tags, case-insensitively, matching on substring.
- **FR-011**: The catalog MUST support a kind filter (All / Plugins / Skills) and a status
  filter (All / Verified / Community / Flagged) as mutually exclusive single selections.
- **FR-012**: The catalog MUST support multi-select category and tag facets, each option
  showing the count of matching packages, each menu typeable to fuzzy-filter its options,
  each independently clearable.
- **FR-013**: Multiple selected tags MUST narrow conjunctively; multiple selected
  categories MUST narrow disjunctively.
- **FR-014**: The catalog MUST support sorting by name, usage and recency, toggling
  descending then ascending, with the active column and direction indicated.
- **FR-015**: The catalog MUST show a live result count and a distinct empty state when a
  filter combination matches nothing.

**Package detail**

- **FR-016**: A package detail view MUST show its description, origin, tags, manifest,
  declared capabilities, version history and dependent profiles.
- **FR-017**: For a plugin the view MUST additionally show the package file tree and each
  contained component classified as a skill, an MCP server or a client extension.
- **FR-018**: Capabilities MUST be **inferred by the scanner** from static analysis — hosts
  from the shell AST and from URLs in instruction files, filesystem scope from read and
  write targets, shell capability from the commands present. Neither package spec defines a
  permissions model, so a conformant manifest cannot declare one. Inferred capabilities MUST
  be presented with a level of `Scoped`, `Allowlisted` or `Review`, and a shell capability
  is never below `Review`.
- **FR-018a**: A publisher or reviewer MAY record an **expected** capability set for a
  package. It MUST be stored under this project's reverse-domain key in the spec-sanctioned
  `extensions` object (`extensions["dev.agent-manager"]`), which is the only conformant
  place for it, and MUST be presented as an expectation rather than as an enforced
  permission.
- **FR-019**: Each version row MUST expose its semver, its distribution tag, its date, its
  full object key and its digest.

**Scanning**

- **FR-020**: Every version MUST be statically scanned before it can be distributed, and
  MUST carry a verdict of `scanning`, `clean` or `flagged`.
- **FR-021**: The scanner MUST NOT execute, source, import or evaluate any content from a
  bundle under any circumstance.
- **FR-022**: The scanner MUST run at minimum: manifest schema validation, network
  allowlist conformance, shell command audit, secret-exfiltration detection, prompt-
  injection pattern detection, filesystem scope review, and dependency pinning.
- **FR-023**: Detection rules MUST be defined in a versioned rule pack loaded as data;
  adding or tuning a rule MUST NOT require changing program code.
- **FR-024**: Each finding MUST carry a stable rule identifier, a severity, the subject
  version, a prose explanation, and evidence quoting the offending file and line.
- **FR-025**: Each scan MUST record every check that ran and its result, including checks
  that passed, so the absence of a finding is distinguishable from the absence of a check.
- **FR-026**: The shell command audit MUST analyse shell scripts by parsing them, not by
  matching text, so that command names, arguments and target hosts are extracted
  structurally.
- **FR-027**: The network check MUST compare hosts discovered in scripts and instructions
  against the package's **expected** capability set (FR-018a) and flag any host outside it.
  Where no expected set has been recorded, every discovered host MUST be surfaced for
  review rather than silently accepted.
- **FR-028**: A reviewer MUST be able to reject a version, or approve it with a recorded
  note, an identity and an expiry.
- **FR-029**: A rejected version MUST NOT be resolvable by any profile regardless of gate.
- **FR-030**: When rescan-on-new-version is enabled, publishing any version of a package
  MUST re-enqueue that package's already-approved versions, and a new finding MUST reopen
  an approved version.
- **FR-031**: A scan exceeding its time budget MUST be retried with backoff and MUST NOT
  resolve to `clean` by default.

**Profiles**

- **FR-032**: A profile MUST hold an ordered set of packages, a default version-resolution
  policy of floating-latest, pinned or range, and a per-package override of that policy.
- **FR-033**: Publishing a profile MUST produce a new sequential, immutable revision
  containing every package resolved to an exact version and digest.
- **FR-034**: Previously published revisions MUST remain readable after a new one is
  published.
- **FR-035**: Profile resolution MUST honour the org scan gate: `block` falls back to the
  most recent clean version; `approval` excludes unapproved flagged versions; `warn-with-
  override` includes them and records the override.
- **FR-036**: A resolution that excludes a package MUST report the exclusion and its
  reason rather than silently omitting it.
- **FR-037**: A profile MUST support visibility of Organisation, Shared or Private, and
  per-member and per-group roles of Owner, Maintainer, Reviewer or Consumer.
- **FR-038**: A profile MUST carry a share link, and forks made from it MUST NOT inherit
  the upstream's future revisions.
- **FR-039**: A profile MUST record which sync targets it enables; targets MUST affect only
  what a client writes locally, never what the server stores.

**Identity and access**

- **FR-040**: The system MUST authenticate people through an OpenID Connect provider and
  MUST derive roles from provider group claims via an admin-configured mapping.
- **FR-041**: The system MUST implement a device authorisation flow for machine clients,
  issuing a short human-typable user code bound to the requesting host, with an expiry.
- **FR-042**: A device code MUST be single-use, MUST expire, and MUST be refusable when
  approved by an identity other than the requester.
- **FR-043**: Tokens issued to machine clients MUST be short-lived.
- **FR-044**: A client MUST see exactly the profiles its identity may read, and no others.
- **FR-045**: Loss of a mapped group MUST take effect at the next token refresh.

**Organisation policy**

- **FR-046**: An admin MUST be able to set the scan gate to block, approval, or
  warn-with-override, and the change MUST take effect on subsequent resolutions.
- **FR-047**: An admin MUST be able to toggle: require signed bundles, community sources
  need review, rescan on every new version, allow personal profiles.
- **FR-048**: Signature material MUST be stored as registry-side metadata beside the bundle,
  not as a manifest field — neither package spec defines one. When signed bundles are
  required, a version with no signature reference MUST NOT be publishable.
- **FR-048a**: Until cryptographic verification ships, the system MUST NOT present an
  unverified signature as verified. The interface MUST state that a signature is present
  but unverified.
- **FR-049**: An admin MUST curate the category vocabulary; publishers select from it at
  registration; tags MUST remain free-form values read from the manifest.

**Audit and storage**

- **FR-050**: Every state-changing action MUST write exactly one audit row naming actor,
  event kind, human-readable text and source, where system actors are named `fetcher` and
  `scanner` and client sources identify the host.
- **FR-051**: The audit log MUST be exportable in full for the current scope, not merely
  the visible page.
- **FR-052**: Audit rows MUST be append-only.
- **FR-053**: The storage view MUST report object count, compressed size, region, CLI read
  cache hit rate, the key layout, bucket settings and recent fetch outcomes.

**Presentation**

- **FR-054**: Every screen MUST render in both light and dark themes using the design's
  token palette, with the choice persisted per viewer.
- **FR-055**: Any content originating from a package manifest, instruction file or scan
  evidence MUST be escaped when rendered; it MUST NOT be emitted as raw markup.

**Operability**

- **FR-056**: The whole system — database, object store, identity provider, api, web and
  both workers — MUST start from a single `docker compose up` with no manual step and no
  external account.
- **FR-057**: The stack MUST be seedable with the design's representative dataset so a
  fresh start resembles the design.
- **FR-058**: Serving roles MUST expose a health endpoint and a self-probing health
  subcommand usable by a container with no shell.
- **FR-059**: The system MUST emit structured logs carrying a request or job correlation
  id, and metrics for queue depth, scan duration and fetch outcomes.

### Key Entities

- **Publisher** — the owning namespace of a package (`example/platform`,
  `community/dbtools`), carrying a verified flag that drives the Verified/Community
  filter.
- **Package** — a catalog entry: id, name, kind (plugin | skill), publisher, category,
  free-form tags, visibility, and — for a skill distributed inside a plugin — the parent
  plugin.
- **Version** — an immutable snapshot: semver, object key, `sha256` digest, size,
  manifest, declared capabilities, distribution tag (latest / pinned / archived), created
  time, verdict.
- **Component** — a member of a plugin version: kind (skill | mcp | ext), name and note.
- **Capability** — a declared permission on a version: name (`filesystem.read`,
  `network`, `shell`), scope note, and level (Scoped | Allowlisted | Review).
- **Scan** — one execution of the rule pack against one version: rule pack version, start
  and end time, verdict, and the full list of checks with results.
- **Finding** — one rule violation: rule id, severity, subject version, explanation,
  evidence (file, line, quoted text), state (open | approved | rejected).
- **Override** — a reviewer's acceptance of a finding: reviewer identity, note, expiry.
- **Profile** — a named set: slug, description, visibility, owning team, default version
  policy, enabled sync targets.
- **ProfileEntry** — one package in a profile with its resolution mode and, if pinned, its
  pinned version.
- **Revision** — an immutable published resolution of a profile: sequence number, note,
  timestamp, and the resolved lockfile of package/version/digest triples with skip
  reasons.
- **Membership** — a person's or group's role on a profile: Owner, Maintainer, Reviewer or
  Consumer.
- **Category** — an admin-curated classification with a slug; distinct from tags.
- **Identity** — an authenticated person: subject, email, display name, provider groups.
- **DeviceAuthorization** — a pending machine authorisation: device code, user code,
  requesting host, expiry, state, and the approving identity once approved.
- **AuditEvent** — an append-only record: time, actor, kind, text, source.
- **OrgPolicy** — the singleton settings object: scan gate, default version policy, and
  the four policy toggles.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A person with no prior setup goes from cloning the repository to a running,
  populated system in one command and under five minutes on a laptop, with no cloud
  account and no credential they have to obtain.
- **SC-002**: Registering a package from a repository URL reaches a scan verdict in under
  60 seconds at the median, measured fetch-to-verdict.
- **SC-003**: Catalog filtering, faceting and sorting return in under 300 ms at the 95th
  percentile with 10,000 packages and 50,000 versions in the store.
- **SC-004**: Every one of the design's ten seeded packages, four profiles, four findings
  and eight audit rows renders on the corresponding screen with the values the design
  specifies.
- **SC-005**: A corpus of deliberately hostile bundles — undeclared egress, credential
  reads in instructions, unpinned postinstall dependencies, over-broad write scope, path
  traversal, symlink escape, and a zip bomb — is caught with zero false negatives, and a
  corpus of benign bundles produces zero false positives.
- **SC-006**: No role can exceed its credential boundary: with the web role's environment
  alone, no connection to the database or the object store is possible; with the scanner's
  credentials alone, no bundle byte can be written.
- **SC-007**: A machine goes from unauthenticated to holding a resolved profile lockfile
  through the device flow in under two minutes of human effort.
- **SC-008**: Every state-changing action produces exactly one audit row — verified by
  exercising each mutating endpoint and asserting the count delta is one.
- **SC-009**: Both themes pass WCAG AA contrast on text and interactive controls across
  all ten screens.
- **SC-010**: A new detection rule can be added, tested against its fixtures, and take
  effect without a code change or an image rebuild.

---

## Assumptions

- **Package specs**: verified in Phase 0 research (R1). Agent Plugins 1.0.0 permits exactly
  ten top-level `plugin.json` fields with `additionalProperties: false`, of which only
  `$schema` and `name` are required; schema 1.1.0 is identical on the plugin manifest. Agent
  Skills permits `name`, `description`, `license`, `allowed-tools` (experimental and
  explicitly non-restrictive), `metadata` and `compatibility`. **Both manifests shown in the
  design are non-conformant** — `components`, `publisher`, `signature`, `network`,
  `filesystem`, `spec: openplugin/v1`, `providers` and `entry` do not exist in either spec.
  The published schemas win: the seed fixtures are rewritten as conformant manifests and the
  capability model is inferred rather than declared.
- **A plugin's component list is derived from its file tree**, not from the manifest, since
  no manifest field enumerates components. `skills/*/SKILL.md` yields skills, `mcp.json`
  yields MCP servers, and reverse-domain directories yield client extensions.
- **Scale**: sized for an organisation — thousands of packages, tens of thousands of
  versions, hundreds of concurrent people. Not a public multi-tenant registry.
- **Single organisation per deployment.** Multi-tenancy is not modelled; `Organization` is
  a singleton settings object, not a scoping dimension.
- **Identity provider**: any OIDC provider supporting the device authorisation grant and a
  groups claim. Okta is the design's example; Dex is the local substitute. Neither is
  hard-coded.
- **Object storage**: any S3-compatible endpoint. Object lock, SSE-KMS and lifecycle
  retention are *configured and surfaced* by this system but *enforced* by the storage
  backend; the Storage screen reports what the bucket reports.
- **Usage counts** ("42 uses", "184 installs") are derived from profile membership and
  recorded sync events, not self-reported by publishers.
- **Relative dates** in the design ("2 days ago", "yesterday") are rendered from stored
  timestamps; the seed data is generated relative to seed time so the screens stay
  plausible.
- **Verified publishers** are determined by a publisher-level flag set by a catalog admin,
  not inferred from the id prefix; the design's `example/*` versus `community/*` split is
  seed data expressing that flag.
- The web role's per-request latency budget tolerates one internal hop to the api role;
  this is accepted in exchange for the credential boundary in FR/SC-006.

---

## Out of Scope

- **The CLI binary.** The device-flow endpoints, profile listing, revision resolution and
  bundle download are in scope so the Connect-the-CLI screen is truthful and the contract
  is frozen. `skillhub install` / `login` / `sync` as a shipped binary is a separate
  feature. The screen presents them as documentation.
- **Signature verification.** `Require signed bundles` is modelled, stored, surfaced and
  enforced as a *policy gate*; the cryptographic verification of a Sigstore bundle is
  deferred. Until then the policy refuses versions lacking a signature reference rather
  than validating one.
- **Multi-tenancy**, cross-organisation federation, and public anonymous browsing.
- **Editing package content in the hub.** Packages are fetched, never authored here.
- **A production Kubernetes deployment.** Compose is the delivery target; a chart may
  follow.
- **Dynamic or sandboxed execution analysis.** Static only, permanently — see FR-021.
