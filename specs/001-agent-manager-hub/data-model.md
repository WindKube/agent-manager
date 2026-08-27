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
| `version_id` uuid fk | `tag` text |

Free-form, read from the manifest `keywords` field. `unique (version_id, tag)`, plus a GIN
index on the materialised `tags text[]` column used by the catalog query (R4).

> **Design divergence (R1)**: the design shows tags as a package attribute. They come from
> the manifest, so they belong to the version and can change between versions. The catalog
> shows the latest version's tags.

### `component`
| Column | Type | Notes |
| --- | --- | --- |
| `version_id` | uuid fk | |
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
| `version_id` | uuid fk | |
| `name` | text | `filesystem.read`, `network`, `shell` |
| `source` | enum `inferred \| expected` | **The R1 inversion.** `inferred` written by the scanner; `expected` from `extensions["dev.agent-manager"]` |
| `detail` | jsonb | Hosts, path globs, command names |
| `level` | enum `scoped \| allowlisted \| review` | A `shell` capability is never below `review` (FR-018) |

A finding is raised where `inferred` exceeds `expected` (FR-027). Where no `expected` row
exists, every `inferred` capability is surfaced for review rather than passing silently.

### `signature`
| `version_id` uuid pk fk | `ref` text | `kind` enum `none \| cosign-bundle` | `verified_at` timestamptz null | `verified_by` text null | `result` enum null |

Registry-side, not a manifest field (R9). The `require signed bundles` policy checks `ref
is not null`. `verified_*` stay null until Sigstore lands — and the UI must say so
(FR-048a).

---

## Scanning

### `scan`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `version_id` | uuid fk | |
| `pack_version` | text | Rule-pack version (R2). Makes "rescan needed" a comparison, not a guess |
| `started_at`, `finished_at` | timestamptz | `finished_at` null ⇒ in flight; drives the median-duration stat |
| `verdict` | enum | |
| `timed_out` | bool | FR-031 — a timeout is recorded, never silently `clean` |

`unique (version_id, pack_version)` — the scan idempotency key from R5. A redelivered scan
job for the same version at the same pack version is a no-op.

### `scan_check`
| `scan_id` uuid fk | `check_id` text | `label` text | `result` enum `pass \| fail \| warn` | `warn_count` int |

One row per registered check per scan, **including passes** (FR-025). Written by iterating
the check registry, so a newly registered check appears in the design's checks-run matrix
with no renderer change.

### `finding`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `scan_id` | uuid fk | |
| `version_id` | uuid fk | Denormalised, so open findings query without a join |
| `rule_id` | text | `SH-NET-002` |
| `severity` | enum `low \| medium \| high` | |
| `title`, `detail` | text | |
| `evidence_path` | text | `scripts/digest.sh` |
| `evidence_line` | int | `41` |
| `evidence_quote` | text | Rendered escaped, always (FR-055) |
| `state` | enum `open \| approved \| rejected` | |

Partial index `(version_id) where state = 'open'`.

### `override`
| `finding_id` uuid pk fk | `reviewer_identity_id` uuid fk | `note` text | `expires_at` timestamptz | `created_at` |

FR-028. The "Overrides active / expires in 12 days" stat reads `expires_at`.

---

## Profiles

### `profile`
| `id` uuid pk | `slug` text **unique** | `name` | `description` | `visibility` enum `organisation \| shared \| private` | `owner_team` text | `default_policy` enum `floating-latest \| pinned \| range` | `forked_from_id` uuid null |

`forked_from_id` records lineage; a fork **does not** subscribe to upstream revisions
(FR-038) — there is deliberately no mechanism that could.

### `profile_entry`
| `profile_id` uuid fk | `package_id` uuid fk | `mode` enum `latest \| pinned \| range` | `pinned_version_id` uuid null | `range_expr` text null | `position` int |

`unique (profile_id, package_id)`.
`check (mode <> 'pinned' or pinned_version_id is not null)`.

### `revision`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `profile_id` | uuid fk | |
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
| `profile_id` uuid fk | `subject_kind` enum `user \| group` | `subject_ref` text | `role` enum `owner \| maintainer \| reviewer \| consumer` |

`unique (profile_id, subject_kind, subject_ref)`. A person in several mapped groups holds
the union of permissions (FR-042 acceptance 2) — resolved at query time, not stored.

### `sync_target`
| `profile_id` uuid fk | `target` enum `claude-code \| agents-md \| codex` | `enabled` bool |

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
| `approved_by_identity_id` | uuid null | |
| `expires_at` | timestamptz | |

Single-use is enforced by the `pending → approved → consumed` transition inside one
transaction, not by a boolean (FR-042).

### `session`
| `id` uuid pk | `token_hash` bytea **unique** | `identity_id` uuid fk | `expires_at` |

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
| `id` uuid pk | `identity_id` uuid fk | `profile_id` uuid fk | `revision_id` uuid fk | `host` text | `occurred_at` |

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

| Role | Grants |
| --- | --- |
| `am_api` | `SELECT/INSERT/UPDATE` on all app tables; **no `UPDATE`/`DELETE` on `audit_event`**; `INSERT` on `outbox` |
| `am_fetcher` | `SELECT/INSERT/UPDATE` on `version`, `version_tag`, `component`, `signature`, `package`, `publisher`; `INSERT` on `audit_event`, `outbox` |
| `am_scanner` | `SELECT` broadly; `INSERT/UPDATE` on `scan`, `scan_check`, `finding`, `capability`; `UPDATE (verdict)` on `version`; `INSERT` on `audit_event` |
| `am_web` | **none — no grant, no connection.** The web role has no DSN at all |
| `am_migrate` | DDL owner, used only by the Atlas init container |

`am_scanner` cannot write `object_key` or `digest`: the scanner does not produce bundle
bytes, and the grant says so as well as the Go type does.

`am_fetcher` needs `version_tag` because `version.tags` is a denormalisation of it and the
two are written in the same transaction — granting one without the other makes the
transaction unable to commit. It needs `publisher` because registering the first package
under a new publisher creates the publisher row, and `package.publisher_id` is `NOT NULL`.

Nothing grants `INSERT` on `capability` to `am_fetcher`, and that is deliberate: the
`expected` set is read out of `extensions["dev.agent-manager"]` by the API when the detail
page is assembled (T057), and the `inferred` set is the scanner's. The fetcher transcribes
the manifest into `version.manifest` and stops there, so no role writes a capability row it
did not itself derive.
