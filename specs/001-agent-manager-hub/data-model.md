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
  still leans on that default for ten of the twelve hand-written keys; the resulting action
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
  rule and fails on any foreign key that does not spell out where it points. A composite key
  names its whole column tuple as well — `fk (publisher_id, namespace) → publisher`, written
  once, on the last of its columns — because two single-column declarations describe a
  different constraint from one two-column one.

---

## Catalog

### `publisher`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `slug` | text, **unique** | `example/platform`, `community/dbtools` |
| `namespace` | text, **stored generated** `split_part(slug, '/', 1)` | `example`. Not a column anybody writes: Postgres recomputes it from the slug and refuses a direct assignment |
| `display_name` | text | |
| `verified` | bool, default false | Drives the Verified/Community filter. Set by a catalog admin — **never** inferred from the slug prefix (spec Assumptions). |

**`check (slug ~ '^[^/]+/[^/]+$')`** — exactly two non-empty segments. The shape is
load-bearing rather than conventional: the first segment is the rendered package id and the
object-key prefix, so a one-segment slug produces keys with an empty namespace. The
per-segment character set is deliberately *not* restated here — registration validates it
against one pattern, and a second, looser copy in the database would be a rule that disagrees
with the real one the first time either moves.

**`unique (id, namespace)`** — not needed for its own sake, since `id` is already the primary
key. It exists because a composite foreign key can only reference a column set carrying a
unique constraint, and `package` needs to reference this one.

Three concepts, and only two of them used to have names:

| Concept | Example | What it is |
| --- | --- | --- |
| namespace | `example`, `community` | first segment; the rendered id **and** the object key |
| publisher | `example/platform` | the owning team; carries `verified` |
| name | `pii-redactor` | the package name |

They stay three rather than collapsing to two because `verified` is admin-set and never
inferred from the prefix. Collapsing publisher onto namespace would make `verified` and the
namespace one column, and `community/octoflow` could then never be verified after review —
which is the one thing the flag exists to do.

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
| `namespace` | text, fk (publisher_id, namespace) → publisher | Denormalised first segment of the owning publisher's slug. The composite key references `publisher (id, namespace)`, so it cannot disagree with its publisher — on insert or on update, with no trigger |
| `name` | text | Matches the manifest `name` pattern: `^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`, ≤64 chars |
| `kind` | enum `plugin \| skill` | |
| `category_id` | uuid fk → category, nullable | |
| `visibility` | enum `organisation \| team \| private` | |
| `parent_package_id` | uuid fk → package, nullable | Set when a skill is distributed inside a plugin (FR-016 origin line) |
| `latest_version_id` | uuid fk → version, nullable | Denormalised pointer; maintained on publish |

**`unique (namespace, name)`** — one package per name per namespace, whichever publisher owns
it.

This **replaces** `unique (publisher_id, name)`, which was wrong rather than merely weak. The
publisher-scoped key permits `example/platform` and `example/security` to each own
`pii-redactor`; both render as the id `example/pii-redactor` and both resolve to the object key
`skills/example/pii-redactor/…`, so one bundle silently overwrites the other. In a system whose
premise is immutable versions (FR-007) that is a correctness bug, not a display bug. The new
key is strictly stronger — every pair the old one rejected it also rejects — so the old one is
redundant, not merely superseded, and keeping both would mean two error messages for one
mistake.

The denormalised `namespace` is what makes that key a constraint rather than a trigger: it is
held to its publisher's by the composite foreign key above, and `publisher.namespace` is
generated from the slug, so the value under the unique index cannot be made to lie.

### `version`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `package_id` | uuid fk → package | |
| `semver` | text | Normalised at registration; rejected if unparseable (spec Edge Cases) |
| `semver_sort` | text | Zero-padded sort key, so ordering is an index scan not a Go sort |
| `object_key` | text | `skills/<namespace>/<name>/<semver>/bundle.tar.zst` — the *namespace*, not the whole publisher slug |
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
| `source` | enum `inferred \| expected` | **The R1 inversion.** Both sets are written by the scanner: `inferred` from what it finds in the bundle, `expected` transcribed from `extensions["dev.agent-manager"]` in `version.manifest` at the same time |
| `detail` | jsonb | Hosts, path globs, command names |
| `level` | enum `scoped \| allowlisted \| review` | A `shell` capability is never below `review` (FR-018) |

A finding is raised where `inferred` exceeds `expected` (FR-027). Where no `expected` row
exists, every `inferred` capability is surfaced for review rather than passing silently.

**One writer, not two.** The scanner writes the `expected` rows as well as the `inferred`
ones, in the transaction that records the scan. It holds `SELECT` on `version`, so it reads
the declaration out of `version.manifest` itself.

The fetcher is the obvious alternative — it already parses that manifest — and it is
refused on exposure, not on layering. The fetcher is the role that pulls
attacker-supplied archives over the network and unpacks them; the scanner runs offline,
holds no outbound client, and already holds `INSERT` on `capability` for the `inferred`
set. A write the most exposed role in the system can do without is a write it does not get.
`store_test.go` asserts the refusal against a live Postgres.

The consequence is that a version has no capability rows until it has been scanned, which
is correct: until then the detail screen has nothing to compare a declaration against and
says so.

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
| `evidence_path` | text | `scripts/digest.sh` — the **primary** location only |
| `evidence_line` | int | `41` |
| `evidence_quote` | text | Rendered escaped, always (FR-055) |
| `state` | enum `open \| approved \| rejected` | |

Partial index `(version_id) where state = 'open'`.

The evidence triple is a denormalised copy of the `finding_evidence` row whose role is
`primary`, kept so the findings list renders without a join. It is **not** the finding's whole
evidence.

### `finding_evidence`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `finding_id` | uuid fk → finding | |
| `path` | text | `scripts/explain-costs.sh` |
| `line` | int, nullable | Nullable because a finding can name a file without a line — which is also why the primary key is a uuid and not `(finding_id, path, line)` |
| `quote` | text | Attacker-controlled bundle content, rendered escaped, always (FR-055) |
| `role` | enum `primary \| supporting` | |

A finding legitimately has several locations (FR-024): SH-FS-007's cause is
`scripts/explain-costs.sh:9` while the writes it lets escape are on lines 28, 34 and 36. One
location per finding either drops the rest or formats them into a string — and formatting them
into a string is the option this table exists to refuse, because it defeats `line`, the number
a reader needs to find the code, and turns FR-055's escaping into a per-substring problem
inside one text column.

Index `(finding_id)` for the detail pane's read, and **`unique (finding_id) where role =
'primary'`** so that "the" primary row the triple above copies is well defined. The predicate
must stay exactly `role = 'primary'`: supporting locations are many per finding by definition.
There is deliberately no ordering column — evidence reads as `order by role, path, line`, which
is stable, and a `position` would be a second thing to keep right for no question anyone asks.

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
| `id` uuid pk | `occurred_at` timestamptz | `actor` text | `actor_kind` enum `identity \| system` | `kind` enum `fetch \| scan \| approve \| profile \| share \| sync \| login \| policy \| role \| category \| secret` | `text` text | `source` text |

**Append-only is enforced by revoking `UPDATE` and `DELETE` from the application role**, not
by convention (FR-052, constitution principle IV). Index `(occurred_at desc)`.

The last four kinds are the Organization screen's mutations, which had no representable kind
at all: `policy` for `org_policy` (the scan gate FR-046, the default version policy FR-047 and
the four booleans beside them), `role` for the group→role map (FR-040), `category` for the
admin-curated vocabulary (FR-049), and `secret` for identity-provider credential rotation.

Four values rather than one `admin` bucket, because the audit screen filters by kind and "who
changed the scan gate" and "who rotated the IdP secret" are not the same question.

Their absence was not a gap to backfill later. FR-050 requires **every** state-changing action
to write exactly one audit row; with no valid kind to write, the highest-privilege screen in
the product wrote nothing and raised nothing — leaving no row to repair and no gap to detect.
That is why the values land before the screen rather than after it.

### `fetch_attempt`
| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `occurred_at` | timestamptz | |
| `source_kind` | enum `upload \| git \| archive-url` | Mirrors `fetch.SourceKind` |
| `requested_ref` | text | The reference as submitted; credentials already redacted, rendered escaped (FR-055) |
| `outcome` | enum, below | |
| `detail` | text, nullable | The redacted error message; null when the outcome is `ok` |

FR-053 requires the storage view report recent fetch **outcomes**, and the only record of a
fetch was `version.object_key` — which a refused fetch never produces. An SSRF refusal, a
reference that names nothing, a zip bomb: none reaches a version row, so a panel whose rows
*are* object keys structurally cannot show them, and those are the outcomes an operator most
needs. The Edge Cases requirement that a failed fetch be "recorded as a fetch error, not a scan
finding" had nowhere else to be recorded.

`outcome` is one value per failure the ingestion path can actually tell apart today, so that
nothing has to be recovered by parsing `detail`:

| Value | Produced by |
| --- | --- |
| `ok` | a `fetch.Tree` was produced |
| `invalid-ref` | `repourl.ErrInvalid` or `fetch.ErrNoSource` — nothing was dialled |
| `blocked` | `fetch.ErrBlocked` — the outbound policy refused the address |
| `unreachable` | any other failure out of `fetch.Client.Do`, the client's own timeout included |
| `malformed` | `bundle.ErrMalformed` |
| `too-large` | `bundle.ErrTooLarge` |
| `rejected-member` | `bundle.ErrRejectedMember` |
| `extract-timeout` | `bundle.ErrTimeout` |

Two deliberate omissions. There is no `not-found`: a 404 is a status on a response
`fetch.Client` returns *successfully*, so nothing below the worker distinguishes it from any
other status. And a fetch-side timeout is `unreachable` rather than sharing a name with
`extract-timeout`, because one word meaning both stages is worse than a name that says which
stage produced it.

This is **not** a second audit log. `audit_event` answers "who did what" and is append-only by
revoke; this answers "what happened to the bytes" for a worker with no actor behind it. It
carries no `version_id`: the row is written before there is a version to point at, and the
successful half is already reachable through `version.object_key`. Index `(occurred_at desc)`,
which is the panel's whole query; `outcome` is not indexed because the panel shows the last N
whatever they are.

**Known limitation**: no role holds `DELETE`, retention is unspecified, and the table therefore
grows without bound. The first requirement that names a window is where a prune gets designed.

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
| Scan, Finding, Override | `scan`, `scan_check`, `finding`, `finding_evidence`, `override` |
| Profile, ProfileEntry, Revision, Membership | `profile`, `profile_entry`, `revision`, `membership`, `sync_target` |
| Category | `category` |
| Identity, DeviceAuthorization | `identity`, `group_role_map`, `device_authorization`, `session` |
| AuditEvent | `audit_event`, `sync_event` |
| OrgPolicy | `org_policy` |
| — no spec entity; FR-053's fetch outcomes | `fetch_attempt` |

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
| `am_scanner` | `SELECT`, `INSERT` on `finding_evidence` | FR-024 — the evidence rows are written by the check that raised the finding, in the same transaction as the finding |
| `am_api` | `SELECT` on `finding_evidence` | The finding detail pane, served over HTTP by `api` |
| `am_fetcher` | `INSERT` on `fetch_attempt` | FR-053 and the Edge Cases requirement that a refused fetch be recorded as a fetch error; the fetcher is what performs the fetch |
| `am_api` | `SELECT` on `fetch_attempt` | FR-053's "recent fetch outcomes" panel, served by `api` |
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
| `INSERT` on `capability` from `am_fetcher` | It parses the manifest the `expected` set comes from | Both capability sets have one writer, the scanner, which reads the declaration back out of `version.manifest` when it records the scan. The fetcher transcribes the manifest into `version.manifest` and stops. Adding a second writer here would buy nothing and cost a grant |
| `UPDATE` on `version.digest`, `object_key`, `size_bytes`, `manifest`, `visible` from `am_scanner` | It already holds `UPDATE` on `version` | The scanner does not produce bundle bytes. The column-level grant says so as well as the Go type does, and it survives a hand-written SQL statement, which the Go type does not |
| `UPDATE` on `finding_evidence` from `am_scanner` | It holds `UPDATE` on `finding`, `scan`, `scan_check` and `capability` | An evidence row quotes the bundle's bytes at the instant they were scanned. A rescan produces a new scan and new findings rather than editing old ones, so nothing needs to rewrite one — and a row that cannot be rewritten is one an operator can still trust after the fact |
| `INSERT`, `UPDATE` on `finding_evidence` from `am_api` | `am_api` otherwise holds `SELECT`/`INSERT`/`UPDATE` on every table | `api` does not run checks: findings and their evidence are the scanner's whole output (`contracts/worker.md`). The one thing a reviewer does to a finding is approve or reject it, which writes `override` and `finding.state` |
| `INSERT` on `fetch_attempt` from `am_api` | A reference that names no repository at all can be rejected in the registration handler, before any outbox row exists — so a future `api` could have a refusal to record with no fetcher involved | No such handler exists yet, so there is no statement to name, and a grant on a prediction is exactly the excess that never surfaces. The layer that writes that handler widens this deliberately |
| `SELECT` on `fetch_attempt` from `am_fetcher` | It writes every row in it | It never reads its own history, the same reason it holds only `INSERT` on `audit_event` and `outbox` |
| `UPDATE`, `DELETE` on `fetch_attempt` from **every** role | An attempt row looks like something a retention job would tidy | An attempt is a record of something that already happened. Note what this does **not** amount to: `fetch_attempt` is not covered by FR-052's revoke, which names `audit_event` and only `audit_event`, so a table owner can still grant itself back |
| `SELECT` on `identity`, `session`, `device_authorization`, `profile*`, `audit_event` from `am_scanner` | The grant summary above says "`SELECT` on the catalog and its scan history", which an earlier draft wrote as "SELECT broadly" | `session.token_hash` and `device_authorization.device_code_hash` are bearer credentials at rest. "Broadly" is read as the catalog and its scan history; narrowing a grant is always safe, widening one is the mistake worth avoiding |

Three independent lines of evidence back the `DELETE` half of that list, and all three were
checked rather than assumed: FR-032 / FR-037 / FR-034 make the profile endpoints
update-shaped or forbid deletion outright; the openapi inventory's verbs are
`pin / unpin / reorder`, all updates; and `docs/design/agent-manager.dc.html` contains
**zero** occurrences of remove, delete or revoke, in any case, in any button or label. No
removal affordance exists anywhere in the product being built.

If the UI later grows a "remove package" control, `DELETE` on `profile_entry` widens — as a
deliberate decision recorded here, with the FR that asked for it, and not as a bug fix.

Grants for `finding_evidence` and `fetch_attempt` live in the migration that creates them,
not in `20260827150200_roles_and_grants.sql` with every other grant. That migration runs first,
so its `grant … on all tables in schema public` cannot see a table a later migration creates —
naming the tables there would fail the apply, and the `all tables` form would silently grant
nothing. That file states the rule this follows: there are deliberately no default privileges,
so every migration that creates a table grants on it in the same file. This document is where
the whole map stays in one place.

`am_fetcher` needs `version_tag` because `version.tags` is a denormalisation of it and the
two are written in the same transaction — granting one without the other makes the
transaction unable to commit. It needs `publisher` because registering the first package
under a new publisher creates the publisher row, and `package.publisher_id` is `NOT NULL`.
Both were found by driving the whole ingestion write as `am_fetcher` in one transaction,
which is the shape a missing grant on a child table shows up in.
