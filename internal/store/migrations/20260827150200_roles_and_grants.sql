-- Roles and grants: the credential half of constitution principle II.
--
-- HAND-WRITTEN, and it stays hand-written. Atlas models neither roles nor
-- grants, so `atlas migrate diff` will neither generate nor drop anything here —
-- which is why this is the one part of the schema that does not live in
-- internal/store/schema/. Do not try to move it there; the desired-state loader
-- would report no changes and the next diff would not notice a drift.
--
-- Roles are cluster-level, not database-level, so a plain `create role` is not
-- idempotent across a re-apply on the same cluster (a second `migrate apply`
-- against a cluster that already has these roles would abort the whole
-- migration). The do-block guards on pg_roles so `migrate apply` is re-runnable.
--
-- No password is set here. A password in a migration is a credential in git; the
-- deployment sets it out of band. `login` with no password cannot connect under
-- scram or md5 authentication, so the roles are inert until it does.
--
-- There are deliberately NO default privileges (`alter default privileges`).
-- Every migration that creates a table must grant on it in the same file. That
-- makes a forgotten grant a permission-denied error against a known new table
-- rather than a silent widening of am_api onto a table nobody reviewed.
--
-- Which is why this file is NOT the whole privilege map, and cannot become it.
-- `grant ... on all tables in schema public` below binds the tables that exist
-- when this migration runs; a table created by a later migration is invisible to
-- it. finding_evidence and fetch_attempt are granted in
-- 20260828000342_namespace_audit_kinds_evidence_and_fetch_attempts.sql, beside the
-- CREATE TABLE statements that make them exist. data-model.md holds the map for
-- all of them.

do $$
declare
  role_name text;
begin
  -- am_web is absent on purpose: the web role has no role, no grant and no DSN.
  -- It reaches data only through the api over HTTP (principle II), so giving it
  -- a database role at all would make the boundary configuration rather than
  -- structure.
  foreach role_name in array array['am_api', 'am_fetcher', 'am_scanner', 'am_migrate']
  loop
    if not exists (select 1 from pg_roles where rolname = role_name) then
      execute format('create role %I login nosuperuser nocreatedb nocreaterole noreplication', role_name);
    end if;
  end loop;
end
$$;

grant usage on schema public to am_api, am_fetcher, am_scanner;

-- ---------------------------------------------------------------------------
-- am_migrate — the DDL role the Atlas init container uses
-- ---------------------------------------------------------------------------
-- Ownership of the existing objects is NOT reassigned here. Which role owns the
-- schema is a deployment decision (compose, Helm), and a migration that moves
-- ownership can lock the role that is applying it out of its own objects.
grant all on schema public to am_migrate;
grant all on all tables in schema public to am_migrate;

-- ---------------------------------------------------------------------------
-- am_api — the request path, and the outbox relay that runs beside it
-- ---------------------------------------------------------------------------
-- select/insert/update on every application table. The catalog is append-only by
-- design, so the only delete granted anywhere in this file is the one below.
grant select, insert, update on all tables in schema public to am_api;

-- The outbox relay's prune. data-model.md specifies "delivered rows pruned after
-- 24 h" and the relay is a goroutine hosted inside api (T022; quickstart.md:43),
-- not a request handler — a role's write set is the union of its handlers AND its
-- goroutines, and this half of the union is what no handler-shaped test reaches.
--
-- Claim (`for update skip locked`) and mark (`update ... set state = 'delivered'`)
-- are already covered by the grant above, so without this the relay runs,
-- delivers every job, and leaks every delivered row forever. A table that grows
-- without bound and never raises an error is the failure this line prevents.
--
-- DELETE on outbox and nowhere else. It is withheld from profile_entry,
-- membership, session, device_authorization and revision on purpose; the reason
-- for each is in the withheld-grant list in data-model.md, which is where a
-- widening gets argued before it gets granted.
grant delete on table outbox to am_api;

-- ---------------------------------------------------------------------------
-- am_fetcher — the bundle pipeline
-- ---------------------------------------------------------------------------
-- version_tag rides along with version: version.tags is a denormalisation of it and
-- both are written in one transaction, so granting version without version_tag makes
-- that transaction uncommittable. publisher is here because registering the first
-- package under a new publisher has to create the publisher row first.
--
-- capability is deliberately absent, for BOTH of its sources. am_scanner writes the
-- `inferred` rows and the `expected` ones alike -- it holds select on version, so it
-- reads the declaration back out of version.manifest when it records the scan.
--
-- The fetcher could derive `expected` itself; it already parses the manifest. It does
-- not get the grant because it is the most exposed role in this system: it is the one
-- that fetches attacker-supplied archives over the network and unpacks them. The
-- scanner runs offline, holds no outbound client, and already holds this grant. A
-- write the fetcher can do without is a write it does not get (principle II).
--
-- store_test.go asserts the refusal directly, so this is enforced rather than
-- described.
grant select, insert, update
  on table publisher, package, version, version_tag, component, signature
  to am_fetcher;
grant insert on table audit_event, outbox to am_fetcher;

-- ---------------------------------------------------------------------------
-- am_scanner — the sandbox side
-- ---------------------------------------------------------------------------
-- "select broadly" from data-model.md is read as the catalog and its scan
-- history, not literally every table: session.token_hash and
-- device_authorization.device_code_hash are bearer credentials at rest and the
-- scanner has no reason to see them, nor identities, profiles or the audit log.
-- Narrowing a grant is always safe; widening one is the mistake worth avoiding.
grant select on table
  publisher, category, package, version, version_tag, component, capability,
  signature, scan, scan_check, finding, override, org_policy
  to am_scanner;
grant insert, update on table scan, scan_check, finding, capability to am_scanner;
grant insert on table audit_event to am_scanner;

-- LOAD-BEARING (contracts/worker.md): the scanner may write only the verdict on
-- version. It does not produce bundle bytes, so it cannot write digest or
-- object_key, and a column-level grant is what says so — the Go type says the
-- same thing but a Go type does not survive a hand-written SQL statement. Adding
-- another column to this list is a decision about what the sandbox may forge.
grant update ("verdict") on table version to am_scanner;

-- ---------------------------------------------------------------------------
-- FR-052 — audit_event is append-only
-- ---------------------------------------------------------------------------
-- THIS REVOKE IS THE ENTIRE ENFORCEMENT. There is no trigger, no rule, no ORM
-- hook and no application check, and none should be added: every one of those is
-- bypassed by the first person who opens psql to fix a typo, and a rule or
-- trigger can be dropped by the same role it constrains. Postgres refusing the
-- statement is the only version of this that holds.
--
-- Caveat worth knowing rather than discovering: a table's OWNER always retains
-- the ability to grant itself back. The guarantee therefore covers the
-- application roles, and holds for the DDL owner only because that credential
-- belongs to the migration container and is never on a request path.
--
-- TRUNCATE is revoked alongside UPDATE and DELETE. It is a separate privilege,
-- it is not implied by DELETE, and `grant all` above hands it to am_migrate — so
-- without this line the audit log is one `truncate audit_event` away from empty
-- while every delete is still refused.
--
-- If you are here to "simplify" this: the two statements below are load-bearing
-- and the grants above never mention delete on audit_event for exactly this
-- reason. Do not replace them with a trigger.
revoke update, delete, truncate on table audit_event from public;
revoke update, delete, truncate on table audit_event from am_api, am_fetcher, am_scanner, am_migrate;
