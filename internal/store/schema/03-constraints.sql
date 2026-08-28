-- Layer 3 of the desired state (see atlas.hcl): everything a Bun struct tag
-- cannot say. Because Atlas treats the composed layers as the WHOLE desired
-- state, these belong here and not in a hand-written migration — a constraint
-- that exists only in a migration is DROPped by the next `atlas migrate diff`.

-- ---------------------------------------------------------------------------
-- The namespace, and the object-key collision it closes
-- ---------------------------------------------------------------------------
-- Three concepts, and until now the schema had names for two:
--
--   namespace  example | community    first segment; the rendered id AND the object key
--   publisher  example/platform       the owning team; carries `verified`
--   name       pii-redactor
--
-- `unique (publisher_id, name)` let example/platform and example/security each
-- own pii-redactor. Both render as example/pii-redactor and both resolve to the
-- object key skills/example/pii-redactor/..., so one bundle overwrites the other
-- — a correctness bug against FR-007, not a display bug. `unique (namespace,
-- name)` in 02-tables.sql replaces it and is strictly stronger, so the old key is
-- redundant rather than merely weaker.
--
-- Everything below exists to make that key trustworthy: a namespace that cannot
-- drift from its slug, and a package namespace that cannot disagree with its
-- publisher's.

-- A stored generated column, so publisher.namespace is not a value anybody
-- writes. Postgres recomputes it from slug on every write and refuses a direct
-- assignment, which is a guarantee no trigger and no application check can give.
-- Bun cannot express `generated always as` and 02-tables.sql is generated from the
-- models, so this is the layer it belongs in.
alter table "publisher"
  add column "namespace" text
  generated always as (split_part("slug", '/', 1)) stored not null;

-- The two-segment shape is load-bearing now: the first segment is the object-key
-- prefix, so a one-segment slug would silently produce keys with an empty
-- namespace and a second slash. It is a check rather than a comment for that
-- reason.
--
-- The per-segment character set is deliberately NOT re-stated here. Registration
-- validates each segment against one pattern; a second, looser copy in the
-- database would be a rule that disagrees with the real one the first time either
-- moves. This constraint asserts only what the object key depends on: exactly two
-- segments, neither empty.
alter table "publisher"
  add constraint "publisher_slug_is_two_segments"
  check ("slug" ~ '^[^/]+/[^/]+$');

-- Redundant against the primary key on its own, and it is not here for its own
-- sake: a composite foreign key can only reference a set of columns that carries
-- a unique constraint, and this is that set.
alter table "publisher"
  add constraint "publisher_id_namespace_key"
  unique ("id", "namespace");

-- What makes package.namespace safe to denormalise. Postgres refuses any package
-- row whose namespace is not its own publisher's, on insert and on update, with
-- no trigger and nothing for the application to remember. Without it,
-- `unique (namespace, name)` would be enforcing uniqueness over a column the
-- application is free to get wrong.
--
-- The single-column package(publisher_id) -> publisher(id) key stays. It is
-- implied by this one, but it is what the Bun belongs-to emits, and removing it
-- would mean dropping the relation.
alter table "package"
  add constraint "package_publisher_id_namespace_fkey"
  foreign key ("publisher_id", "namespace") references "publisher" ("id", "namespace")
  on update no action on delete no action;

-- ---------------------------------------------------------------------------
-- Foreign keys the Bun loader cannot emit
-- ---------------------------------------------------------------------------
-- The models declare 27 belongs-to relations; the loader emits 17 foreign keys.
-- The ten it drops are the ones whose base column is part of the primary key —
-- and data-model.md itself mandates pk-and-fk for signature.version_id and
-- override.finding_id, so they are unavoidable rather than a modelling choice.
-- package.latest_version_id is the eleventh, for a different reason (below).
--
-- ON DELETE stays NO ACTION to match every foreign key the loader does emit;
-- nothing in this schema is deleted by cascade.

alter table "capability"
  add constraint "capability_version_id_fkey"
  foreign key ("version_id") references "version" ("id")
  on update no action on delete no action;

alter table "component"
  add constraint "component_version_id_fkey"
  foreign key ("version_id") references "version" ("id")
  on update no action on delete no action;

alter table "version_tag"
  add constraint "version_tag_version_id_fkey"
  foreign key ("version_id") references "version" ("id")
  on update no action on delete no action;

alter table "signature"
  add constraint "signature_version_id_fkey"
  foreign key ("version_id") references "version" ("id")
  on update no action on delete no action;

alter table "scan_check"
  add constraint "scan_check_scan_id_fkey"
  foreign key ("scan_id") references "scan" ("id")
  on update no action on delete no action;

alter table "override"
  add constraint "override_finding_id_fkey"
  foreign key ("finding_id") references "finding" ("id")
  on update no action on delete no action;

alter table "profile_entry"
  add constraint "profile_entry_profile_id_fkey"
  foreign key ("profile_id") references "profile" ("id")
  on update no action on delete no action;

alter table "profile_entry"
  add constraint "profile_entry_package_id_fkey"
  foreign key ("package_id") references "package" ("id")
  on update no action on delete no action;

alter table "membership"
  add constraint "membership_profile_id_fkey"
  foreign key ("profile_id") references "profile" ("id")
  on update no action on delete no action;

alter table "sync_target"
  add constraint "sync_target_profile_id_fkey"
  foreign key ("profile_id") references "profile" ("id")
  on update no action on delete no action;

-- package.latest_version_id carries no bun relation at all. Adding one is not an
-- option: a second belongs-to between package and version makes the loader abort
-- with `failed to sort tables: circular dependency detected at table version`.
--
-- ON DELETE is spelled out rather than left to the default because a denormalised
-- pointer is exactly the constraint two people resolve two different ways. NO
-- ACTION: a version is immutable and never deleted (FR-007), so the only way this
-- reference can block a delete is a delete that should not be happening.
alter table "package"
  add constraint "package_latest_version_id_fkey"
  foreign key ("latest_version_id") references "version" ("id")
  on update no action on delete no action;

-- ---------------------------------------------------------------------------
-- The constraints that carry meaning (T015)
-- ---------------------------------------------------------------------------
-- The four uniques T015 names — version(package_id, semver) for FR-007,
-- scan(version_id, pack_version) for the R5 idempotency key,
-- revision(profile_id, seq), and package(namespace, name), which replaced the
-- publisher-scoped key above — are expressible as bun tags and come from layer 2.
-- The three checks are not.

-- FR-008 commit-last: no version leaves the scanning verdict without bytes
-- behind it. A publish that fails between metadata and bytes is therefore stuck
-- at 'scanning' rather than advertising a clean version with no bundle.
alter table "version"
  add constraint "version_digest_present_unless_scanning"
  check ("digest" is not null or "verdict" = 'scanning');

-- data-model.md types this column bytea(32); Postgres bytea carries no length,
-- so the width is a check. sha256 is 32 bytes and a short digest would silently
-- compare unequal against every recomputed one.
alter table "version"
  add constraint "version_digest_is_sha256"
  check ("digest" is null or octet_length("digest") = 32);

-- A pinned entry with nothing pinned is not a state the schema allows.
alter table "profile_entry"
  add constraint "profile_entry_pinned_has_version"
  check ("mode" <> 'pinned' or "pinned_version_id" is not null);

-- Singleton at the schema level, not by convention: one organisation per
-- deployment (data-model.md, spec Assumptions).
alter table "org_policy"
  add constraint "org_policy_singleton"
  check ("id" = 1);

-- ---------------------------------------------------------------------------
-- Collation
-- ---------------------------------------------------------------------------
-- semver_sort's alphabet is [0-9A-Za-z-] only, which orders identically under C
-- and under en_US.utf8. Declaring C makes `order by semver_sort desc` independent
-- of the cluster's locale, so a hub restored into a differently-configured
-- cluster cannot reorder a package's version list.
alter table "version"
  alter column "semver_sort" type text collate "C";

-- ---------------------------------------------------------------------------
-- Indexes (T017)
-- ---------------------------------------------------------------------------
-- The materialised tags column exists so the catalog's tag filter is a GIN
-- lookup instead of a join through version_tag (R4).
create index "version_tags_gin" on "version" using gin ("tags");

-- The version list for one package, newest first, as a single index scan.
create index "version_package_semver_sort_idx" on "version" ("package_id", "semver_sort" desc);

-- Catalog browse is always filtered to visible rows, so the index is too: a
-- partial index here is a fraction of the size and never has to skip the
-- invisible half-published rows.
create index "version_verdict_visible_idx" on "version" ("verdict") where "visible";

create index "version_created_at_idx" on "version" ("created_at" desc);

-- Open findings are a small minority of all findings and the only ones any
-- screen queries. The predicate must stay exactly state = 'open': widen it and
-- the planner stops using the index for the open-findings query.
create index "finding_open_version_idx" on "finding" ("version_id") where "state" = 'open';

-- The outbox relay's only query. Delivered rows are pruned after 24 h but are
-- present until then, and this keeps the drain from reading them.
create index "outbox_pending_created_at_idx" on "outbox" ("created_at") where "state" = 'pending';

create index "audit_event_occurred_at_idx" on "audit_event" ("occurred_at" desc);

-- The finding detail pane reads every location for one finding, so the child
-- table needs the parent lookup its foreign key does not give it.
create index "finding_evidence_finding_idx" on "finding_evidence" ("finding_id");

-- At most one primary location per finding. finding.evidence_path/line/quote is a
-- copy of that row, kept so the list view is a single-table read; without this
-- there could be two rows claiming to be the one it copies, and no way to say
-- which. The predicate must stay exactly role = 'primary': supporting locations
-- are many per finding by definition.
create unique index "finding_evidence_one_primary_idx"
  on "finding_evidence" ("finding_id") where "role" = 'primary';

-- FR-053 asks for RECENT fetch outcomes, so the panel's whole query is this
-- index. Nothing indexes outcome: the panel shows the last N whatever they are,
-- and a filter over a few dozen rows is not a scan worth avoiding.
create index "fetch_attempt_occurred_at_idx" on "fetch_attempt" ("occurred_at" desc);

-- T017 also asks for a GIN index on "the tsvector search column". There is no
-- such column: data-model.md names `search tsvector` only on catalog_entry, the
-- one projection principle VIII sanctions, and R12 keeps that allowance unspent
-- until measurement shows the base tables miss SC-003's 300 ms p95. Inventing a
-- tsvector on `version` would put a package-level search on a per-version row and
-- would spend the allowance without the measurement, so the index is deferred
-- with catalog_entry rather than aimed at a column that does not exist.
