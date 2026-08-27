# Phase 1 Data Model — Agent Manager

**Feature**: `001-agent-manager-hub` | **Date**: 2026-08-27

Bun structs in `internal/store/models` are the source of truth; Atlas diffs them into
versioned SQL. This document is the design those structs must express — every constraint
here is load-bearing and traceable to a requirement.

Two databases. Everything below lives in **`agent_manager`** unless marked otherwise.
**`river`** holds the queue and nothing else (principle IX); no foreign key crosses between
them, by construction.

---

## Naming and shared conventions

- Primary keys: `uuid` v7 (time-ordered, so index locality is free and ids sort by creation).
- Timestamps: `timestamptz`, never `timestamp`.
- Every mutable table carries `created_at`, `updated_at`. Append-only tables carry only
  `created_at`.
- Enumerated values are Postgres `enum` types, not `text` with a check — Atlas diffs them
  cleanly and a typo becomes a migration failure rather than a runtime surprise.
- Foreign keys are **uniformly `ON DELETE NO ACTION`**, stated explicitly by the versioned
  migrations rather than left to Postgres's default. (`internal/store/schema/03-constraints.sql`
  still leans on that default for ten of the eleven hand-written keys; the resulting action
  is identical and the test below pins it, but the SQL should state the rule it follows.)
  The catalog is append-only and no role holds
  `DELETE` on any table a foreign key points at, so a delete that would cascade is a bug to
  surface, not to propagate. This is a deliberate divergence from the usual
  CASCADE/RESTRICT/SET NULL mix, which suits a design where rows get deleted; nothing here
  deletes. `TestEveryForeignKeyIsPresent` pins the action per foreign key rather than as a
  schema-wide property, because a hand-written `ON DELETE CASCADE` satisfies every other
  check in the repo — the models, the generated SQL, this document — and then deletes data.
- Every foreign key below **names its target**: `fk → <table>`. A bare `fk` is a test
  failure, not a shorthand. `override.reviewer_identity_id` points at `identity`, not at a
  `reviewer_identity` table, so no rule that infers the target from the column name survives
  contact with this schema; `TestDataModelDeclaresTheSameForeignKeys` therefore has no such
  rule and fails on any foreign key that does not spell out where it points.

---

## Catalog

### `publisher`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `slug` | text, **unique** | `example/platform`, `community/dbtools` |
| `display_name` | text | |
| `verified` | bool, default false | Drives the Verified/Community filter. Set by a catalog admin — **never** inferred from the slug prefix (spec Assumptions). |

### `category`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `name` | text, **unique** | `Infrastructure`, `Security & compliance` |
| `slug` | text, **unique** | |

Admin-curated (FR-049). Tags are *not* here — they are free-form strings on the version.

### `package`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `publisher_id` | uuid fk → publisher | |
| `name` | text | Matches the manifest `name` pattern: `^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`, ≤64 chars |
| `kind` | enum `plugin \| skill` | |
| `category_id` | uuid fk → category, nullable | |
| `visibility` | enum `organisation \| team \| private` | |
| `parent_package_id` | uuid fk → package, nullable | Set when a skill is distributed inside a plugin (FR-016 origin line) |
| `latest_version_id` | uuid fk → version, nullable | Denormalised pointer; maintained on publish |

**`unique (publisher_id, name)`** — a publisher cannot own two packages of the same name.

### `version`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `package_id` | uuid fk → package | |
| `semver` | text | Normalised at registration; rejected if unparseable (spec Edge Cases) |
| `semver_sort` | text | Zero-padded sort key, so ordering is an index scan not a Go sort |
| `object_key` | text | `skills/<publisher>/<name>/<semver>/bundle.tar.zst` |
| `digest` | bytea(32) | sha256 of the bundle |
| `size_bytes` | bigint | Compressed |
| `manifest` | jsonb | The raw conformant manifest, stored verbatim |
| `dist_tag` | enum `latest \| archived \| none` | `pinned by N` in the design is *derived*, not stored |
| `verdict` | enum `scanning \| clean \| flagged \| rejected` | |
| `visible` | bool, default false | **Commit-last (FR-008).** Flipped true only after bytes, digest and metadata all land |
| `created_at` | timestamptz | |

**`unique (package_id, semver)`** — FR-007 immutability. A republish with different bytes
hits this constraint; the handler translates it into the immutability error, it is not
caught in application logic first.

**`check (digest is not null or verdict = 'scanning')`** — no version becomes non-scanning
without bytes behind it.

Indexes: `(package_id, semver_sort desc)`, partial `(verdict) where visible`,
`(created_at desc)`.

### `version_tag`
| `version_id` uuid fk → version | `tag` text |

Free-form, read from the manifest `keywords` field. `unique (version_id, tag)`, plus a GIN
index on the materialised `tags text[]` column used by the catalog query (R4).

> **Design divergence (R1)**: the design shows tags as a package attribute. They come from
> the manifest, so they belong to the version and can change between versions. The catalog
> shows the latest version's tags.

### `component`
| Column | Type | Notes |
| --- | --- | --- |
| `version_id` | uuid fk → version | |
| `kind` | enum `skill \| mcp \| ext` | |
| `name` | text | |
| `note` | text | `SKILL.md + scripts/` |
| `path` | text | |

**Derived from the file tree, not the manifest** — no manifest field enumerates components
(spec Assumptions, R1). `skills/*/SKILL.md` → skill; `mcp.json` entries → mcp;
reverse-domain directories → ext.

### `capability`
| Column | Type | Notes |
| --- | --- | --- |
| `version_id` | uuid fk → version | |
| `name` | text | `filesystem.read`, `network`, `shell` |
| `source` | enum `inferred \| expected` | **The R1 inversion.** `inferred` written by the scanner; `expected` from `extensions["dev.agent-manager"]` |
| `detail` | jsonb | Hosts, path globs, command names |
| `level` | enum `scoped \| allowlisted \| review` | A `shell` capability is never below `review` (FR-018) |

A finding is raised where `inferred` exceeds `expected` (FR-027). Where no `expected` row
exists, every `inferred` capability is surfaced for review rather than passing silently.

### `signature`
| `version_id` uuid pk fk → version | `ref` text | `kind` enum `none \| cosign-bundle` | `verified_at` timestamptz null | `verified_by` text null | `result` enum null |

Registry-side, not a manifest field (R9). The `require signed bundles` policy checks `ref
is not null`. `verified_*` stay null until Sigstore lands — and the UI must say so
(FR-048a).

---

## Scanning

### `scan`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `version_id` | uuid fk → version | |
| `pack_version` | text | Rule-pack version (R2). Makes "rescan needed" a comparison, not a guess |
| `started_at`, `finished_at` | timestamptz | `finished_at` null ⇒ in flight; drives the median-duration stat |
| `verdict` | enum | |
| `timed_out` | bool | FR-031 — a timeout is recorded, never silently `clean` |

`unique (version_id, pack_version)` — the scan idempotency key from R5. A redelivered scan
job for the same version at the same pack version is a no-op.

### `scan_check`
| `scan_id` uuid fk → scan | `check_id` text | `label` text | `result` enum `pass \| fail \| warn` | `warn_count` int |

One row per registered check per scan, **including passes** (FR-025). Written by iterating
the check registry, so a newly registered check appears in the design's checks-run matrix
with no renderer change.

### `finding`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `scan_id` | uuid fk → scan | |
| `version_id` | uuid fk → version | Denormalised, so open findings query without a join |
| `rule_id` | text | `SH-NET-002` |
| `severity` | enum `low \| medium \| high` | |
| `title`, `detail` | text | |
| `evidence_path` | text | `scripts/digest.sh` |
| `evidence_line` | int | `41` |
| `evidence_quote` | text | Rendered escaped, always (FR-055) |
| `state` | enum `open \| approved \| rejected` | |

Partial index `(version_id) where state = 'open'`.

### `override`
| `finding_id` uuid pk fk → finding | `reviewer_identity_id` uuid fk → identity | `note` text | `expires_at` timestamptz | `created_at` |

FR-028. The "Overrides active / expires in 12 days" stat reads `expires_at`.

---

## Profiles

### `profile`
| `id` uuid pk | `slug` text **unique** | `name` | `description` | `visibility` enum `organisation \| shared \| private` | `owner_team` text | `default_policy` enum `floating-latest \| pinned \| range` | `forked_from_id` uuid fk → profile, null |

`forked_from_id` records lineage; a fork **does not** subscribe to upstream revisions
(FR-038) — there is deliberately no mechanism that could.

### `profile_entry`
| `profile_id` uuid fk → profile | `package_id` uuid fk → package | `mode` enum `latest \| pinned \| range` | `pinned_version_id` uuid fk → version, null | `range_expr` text null | `position` int |

`unique (profile_id, package_id)`.
`check (mode <> 'pinned' or pinned_version_id is not null)`.

### `revision`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `profile_id` | uuid fk → profile | |
| `seq` | int | `r14` |
| `note` | text | |
| `lockfile` | jsonb | Conforms to `contracts/lockfile.schema.json` |
| `object_key` | text | `profiles/<slug>/r<seq>.json` |
| `created_at`, `created_by` | | |

**`unique (profile_id, seq)`**, and `seq` is allocated inside the publish transaction by
`select coalesce(max(seq),0)+1 ... for update` on the parent `profile` row. Two racing
publishes therefore serialise into `r15` and `r16` — **no gap, no overwrite** (spec Edge
Cases). An application-side counter or a sequence would produce gaps on rollback.

Previous revisions are never deleted (FR-034).

### `membership`
| `profile_id` uuid fk → profile | `subject_kind` enum `user \| group` | `subject_ref` text | `role` enum `owner \| maintainer \| reviewer \| consumer` |

`unique (profile_id, subject_kind, subject_ref)`. A person in several mapped groups holds
the union of permissions (FR-042 acceptance 2) — resolved at query time, not stored.

### `sync_target`
| `profile_id` uuid fk → profile | `target` enum `claude-code \| agents-md \| codex` | `enabled` bool |

Affects only what a client writes locally, never server state (FR-039).

---

## Identity

### `identity`
| `id` uuid pk | `subject` text **unique** | `email` | `display_name` | `groups text[]` | `last_seen_at` |

`groups` refreshed on every token issue, so losing a group takes effect at the next refresh
(FR-045).

### `group_role_map`
| `group_name` text pk | `role` enum `catalog-admin \| scanner-reviewer \| profile-consumer \| read-only` |

### `device_authorization`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `device_code_hash` | bytea **unique** | **Hashed at rest.** The plaintext is a bearer credential; a database read must not yield one |
| `user_code` | text **unique** | Crockford base32, `HKQ2-9FTL` shape, ambiguous glyphs excluded |
| `requesting_host` | text | Bound at issue (FR-041) |
| `state` | enum `pending \| approved \| consumed \| expired \| denied` | |
| `approved_by_identity_id` | uuid fk → identity, nullable | |
| `expires_at` | timestamptz | |

Single-use is enforced by the `pending → approved → consumed` transition inside one
transaction, not by a boolean (FR-042).

### `session`
| `id` uuid pk | `token_hash` bytea **unique** | `identity_id` uuid fk → identity | `expires_at` |

Opaque server-side sessions for the web role. Hashed, same reasoning as above.

---

## Governance

### `org_policy` — singleton
| `id` int pk **check (id = 1)** | `scan_gate` enum `block \| approval \| warn-with-override` | `default_version_policy` enum | `require_signed_bundles` bool | `community_needs_review` bool | `rescan_on_new_version` bool | `allow_personal_profiles` bool |

The `check (id = 1)` is what makes it a singleton at the schema level rather than by
convention (spec Assumptions: single organisation per deployment).

### `audit_event` — append-only
| `id` uuid pk | `occurred_at` timestamptz | `actor` text | `actor_kind` enum `identity \| system` | `kind` enum `fetch \| scan \| approve \| profile \| share \| sync \| login` | `text` text | `source` text |

**Append-only is enforced by revoking `UPDATE` and `DELETE` from the application role**, not
by convention (FR-052, constitution principle IV). Index `(occurred_at desc)`.

### `sync_event`
| `id` uuid pk | `identity_id` uuid fk → identity | `profile_id` uuid fk → profile | `revision_id` uuid fk → revision | `host` text | `occurred_at` |

One row per sync, not per package (R8). The per-package fan-out for install counts happens
in the nightly aggregation job.

---

## Job hand-off

### `outbox`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk (v7) | Ordering is the primary key |
| `job_kind` | text | `fetch`, `scan`, `rescan-sweep` |
| `payload` | jsonb | |
| `idempotency_key` | text | `(job_kind, subject_id, subject_version)` from R5 |
| `state` | enum `pending \| delivered` | |
| `created_at`, `delivered_at` | | |

Written inside the mutation's transaction (principle IX). Drained with `for update skip
locked`; `notify outbox_new` on insert; delivered rows pruned after 24 h. Partial index
`(created_at) where state = 'pending'`.

**No code path may call River directly from a request handler.** The outbox is the only
door.

---

## `catalog_entry` — conditional (R12)

Built **only if** measurement shows the base tables miss SC-003's 300 ms p95 at 10k/50k.
Principle VIII's single projection allowance is unspent until then.

If built: `package_id` pk, plus denormalised `name`, `publisher_slug`, `verified`, `kind`,
`category`, `tags text[]`, `latest_semver`, `verdict`, `uses`, `installs`, `updated_at`,
and a `search tsvector` generated column. GIN on `tags` and `search`.

Maintained **synchronously on structural change** (a registered package appears at once)
and **asynchronously on verdict change** (`Scanning` → `Clean` may lag; the design already
renders that intermediate state).

---

## Entity coverage against the spec

| Spec entity | Table(s) |
| --- | --- |
| Publisher, Package, Version, Component, Capability | `publisher`, `package`, `version`, `version_tag`, `component`, `capability`, `signature` |
| Scan, Finding, Override | `scan`, `scan_check`, `finding`, `override` |
| Profile, ProfileEntry, Revision, Membership | `profile`, `profile_entry`, `revision`, `membership`, `sync_target` |
| Category | `category` |
| Identity, DeviceAuthorization | `identity`, `group_role_map`, `device_authorization`, `session` |
| AuditEvent | `audit_event`, `sync_event` |
| OrgPolicy | `org_policy` |

---

## Database roles and grants

The credential half of principle II — what Go interfaces cannot express (see
`contracts/worker.md`).

### How a grant gets into this table

Two rules, and the second is the one that does the work:

1. **Every grant cites its justification** — an FR, a design screen, or a named goroutine.
   A grant with nothing to cite was not derived, it was guessed.
2. **Every grant withheld from a plausible candidate is listed, with its reason**, so the
   absences are visible rather than merely true.

The asymmetry that motivates rule 2: **a missing grant fails the first time the code runs;
an excess grant produces no error anywhere, ever.** Every test still passes, the
application still works, and nothing ever surfaces it. Least privilege therefore erodes in
exactly one direction, and **no test can detect that erosion** — a test can only assert a
denial somebody already thought to write, which is the same act of judgement as not
granting it. The withheld list is doing the work a test would do if a test could, and it
turns the next person's "this table is the same class as its neighbour" sweep into a diff
against a stated decision instead of a fresh guess.

### Grants held

| Role | Grant | Cited by |
| --- | --- | --- |
| `am_api` | `SELECT`, `INSERT`, `UPDATE` on all app tables | Every write endpoint in the `contracts/openapi.yaml` inventory: registration (FR-001…FR-008), review (FR-028), profiles and revisions (FR-032, FR-033, FR-037, FR-039), org policy (FR-046, FR-047), identity and device flow (FR-040, FR-041) |
| `am_api` | `DELETE` on `outbox`, **and nowhere else** | The outbox relay (T022), a goroutine hosted in `api` (quickstart.md:43), implementing "delivered rows pruned after 24 h" above |
| `am_api` | **no `UPDATE`/`DELETE` on `audit_event`** | FR-052 |
| `am_fetcher` | `SELECT`, `INSERT`, `UPDATE` on `publisher`, `package`, `version`, `version_tag`, `component`, `signature` | The ingestion transaction: FR-006 (one stored tree), FR-007 (digest), FR-008 (commit-last), FR-048 (signature metadata) |
| `am_fetcher` | `INSERT` on `audit_event`, `outbox` | FR-050 (system actor `fetcher`) and the scan hand-off (principle IX) |
| `am_scanner` | `SELECT` on the catalog and its scan history | FR-020, FR-022 — it reads what it scans |
| `am_scanner` | `INSERT`, `UPDATE` on `scan`, `scan_check`, `finding`, `capability` | FR-025 (a row per check, passes included), FR-024 (findings), FR-018 (inferred capabilities) |
| `am_scanner` | `UPDATE (verdict)` on `version` | `contracts/worker.md`; FR-020 — the verdict is the scanner's whole output |
| `am_scanner` | `INSERT` on `audit_event` | FR-050 (system actor `scanner`) |
| `am_web` | **none — no role, no grant, no DSN** | Principle II. It reaches data only through `api` over HTTP |
| `am_migrate` | DDL owner, used only by the Atlas init container | quickstart.md's `migrate-schema` gate |

### Grants withheld

`DELETE` is granted on `outbox` and on no other table. Each row below is a table somebody
will reach for by neighbourhood, so each carries the reason it stays withheld.

| Withheld | Plausible because | Reason it stays withheld |
| --- | --- | --- |
| `DELETE` on `profile_entry` from `am_api` | Removing a package from a profile looks like a delete | FR-032 gives a profile an ordered set with a per-package policy, and the inventory's verbs are `pin / unpin / reorder` — all `UPDATE`s. "Unpin" is `mode: pinned → latest`. **Row removal is unspecified**, and the design screens carry no control for it |
| `DELETE` on `membership` from `am_api` | Unsharing a profile looks like a delete | FR-037 is about per-member and per-group *roles*; a demotion is an `UPDATE` of `role` |
| `DELETE` on `session` from `am_api` | Sign-out looks like a delete | The row carries `expires_at`. No requirement says sign-out removes it, and an expired session is one whose expiry has passed |
| `DELETE` on `device_authorization` from `am_api` | Expiring a code looks like a delete | The `state` enum already contains `expired` — expiry is a transition (FR-042), not a removal, and the row is the evidence a code was issued |
| `DELETE` on `revision` from `am_api` | Tidying old revisions looks like housekeeping | FR-034 forbids it outright |
| `DELETE`/`UPDATE`/`TRUNCATE` on `audit_event` from **every** role | `am_api` writes audit rows, so it looks like it owns them | FR-052. The revoke is the entire enforcement — no trigger, no ORM hook |
| `INSERT` on `capability` from `am_fetcher` | It parses the manifest the `expected` set comes from | The `expected` set is read out of `extensions["dev.agent-manager"]` by the API when the detail page is assembled (T057) and the `inferred` set is the scanner's. The fetcher transcribes the manifest into `version.manifest` and stops, so no role writes a capability row it did not derive itself |
| `UPDATE` on `version.digest`, `object_key`, `size_bytes`, `manifest`, `visible` from `am_scanner` | It already holds `UPDATE` on `version` | The scanner does not produce bundle bytes. The column-level grant says so as well as the Go type does, and it survives a hand-written SQL statement, which the Go type does not |
| `SELECT` on `identity`, `session`, `device_authorization`, `profile*`, `audit_event` from `am_scanner` | The grant summary above says "`SELECT` on the catalog and its scan history", which an earlier draft wrote as "SELECT broadly" | `session.token_hash` and `device_authorization.device_code_hash` are bearer credentials at rest. "Broadly" is read as the catalog and its scan history; narrowing a grant is always safe, widening one is the mistake worth avoiding |

Three independent lines of evidence back the `DELETE` half of that list, and all three were
checked rather than assumed: FR-032 / FR-037 / FR-034 make the profile endpoints
update-shaped or forbid deletion outright; the openapi inventory's verbs are
`pin / unpin / reorder`, all updates; and `docs/design/agent-manager.dc.html` contains
**zero** occurrences of remove, delete or revoke, in any case, in any button or label. No
removal affordance exists anywhere in the product being built.

If the UI later grows a "remove package" control, `DELETE` on `profile_entry` widens — as a
deliberate decision recorded here, with the FR that asked for it, and not as a bug fix.

`am_fetcher` needs `version_tag` because `version.tags` is a denormalisation of it and the
two are written in the same transaction — granting one without the other makes the
transaction unable to commit. It needs `publisher` because registering the first package
under a new publisher creates the publisher row, and `package.publisher_id` is `NOT NULL`.
Both were found by driving the whole ingestion write as `am_fetcher` in one transaction,
which is the shape a missing grant on a child table shows up in.
