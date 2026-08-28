-- Add value to enum type: "audit_kind"
ALTER TYPE "public"."audit_kind" ADD VALUE 'policy';
-- Add value to enum type: "audit_kind"
ALTER TYPE "public"."audit_kind" ADD VALUE 'role';
-- Add value to enum type: "audit_kind"
ALTER TYPE "public"."audit_kind" ADD VALUE 'category';
-- Add value to enum type: "audit_kind"
ALTER TYPE "public"."audit_kind" ADD VALUE 'secret';
-- Create enum type "evidence_role"
CREATE TYPE "public"."evidence_role" AS ENUM ('primary', 'supporting');
-- Create enum type "fetch_outcome"
CREATE TYPE "public"."fetch_outcome" AS ENUM ('ok', 'invalid-ref', 'blocked', 'unreachable', 'malformed', 'too-large', 'rejected-member', 'extract-timeout');
-- Create enum type "fetch_source_kind"
CREATE TYPE "public"."fetch_source_kind" AS ENUM ('upload', 'git', 'archive-url');
-- Create "fetch_attempt" table
CREATE TABLE "public"."fetch_attempt" (
  "id" uuid NOT NULL,
  "occurred_at" timestamptz NOT NULL DEFAULT now(),
  "source_kind" "public"."fetch_source_kind" NOT NULL,
  "requested_ref" text NOT NULL,
  "outcome" "public"."fetch_outcome" NOT NULL,
  "detail" text NULL,
  PRIMARY KEY ("id")
);
-- Create index "fetch_attempt_occurred_at_idx" to table: "fetch_attempt"
CREATE INDEX "fetch_attempt_occurred_at_idx" ON "public"."fetch_attempt" ("occurred_at" DESC);
-- Create "finding_evidence" table
CREATE TABLE "public"."finding_evidence" (
  "id" uuid NOT NULL,
  "finding_id" uuid NOT NULL,
  "path" text NOT NULL,
  "line" integer NULL,
  "quote" text NULL,
  "role" "public"."evidence_role" NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "finding_evidence_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "public"."finding" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create index "finding_evidence_finding_idx" to table: "finding_evidence"
CREATE INDEX "finding_evidence_finding_idx" ON "public"."finding_evidence" ("finding_id");
-- Create index "finding_evidence_one_primary_idx" to table: "finding_evidence"
CREATE UNIQUE INDEX "finding_evidence_one_primary_idx" ON "public"."finding_evidence" ("finding_id") WHERE (role = 'primary'::public.evidence_role);
-- Modify "publisher" table
ALTER TABLE "public"."publisher" ADD CONSTRAINT "publisher_slug_is_two_segments" CHECK (slug ~ '^[^/]+/[^/]+$'::text), ADD COLUMN "namespace" text NOT NULL GENERATED ALWAYS AS (split_part(slug, '/'::text, 1)) STORED, ADD CONSTRAINT "publisher_id_namespace_key" UNIQUE ("id", "namespace");
-- Modify "package" table
--
-- HAND-EDITED. `atlas migrate diff` emitted this as one statement ending
-- `ADD COLUMN "namespace" text NOT NULL`, which is correct against an empty table
-- and fails against every other one: Postgres has no value to put in the existing
-- rows and no default to fall back on. Split into add-nullable, backfill from the
-- owning publisher, set not null. The generated form is otherwise unchanged.
--
-- The backfill reads publisher.namespace, which is generated from the slug, so it
-- runs after the publisher statement above and cannot disagree with it.
ALTER TABLE "public"."package" DROP CONSTRAINT "package_publisher_name";
ALTER TABLE "public"."package" ADD COLUMN "namespace" text NULL;
UPDATE "public"."package" AS p
  SET "namespace" = pub."namespace"
  FROM "public"."publisher" AS pub
  WHERE pub."id" = p."publisher_id";
ALTER TABLE "public"."package" ALTER COLUMN "namespace" SET NOT NULL;
-- If two publishers in the same namespace already own a package of the same name,
-- this constraint fails and the migration aborts. That is the intended outcome:
-- those two rows resolve to one object key, so one bundle has already overwritten
-- the other, and the collision has to be resolved by a person rather than papered
-- over by a migration that widens the key back.
ALTER TABLE "public"."package" ADD CONSTRAINT "package_namespace_name" UNIQUE ("namespace", "name"), ADD
CONSTRAINT "package_publisher_id_namespace_fkey" FOREIGN KEY ("publisher_id", "namespace") REFERENCES "public"."publisher" ("id", "namespace") ON UPDATE NO ACTION ON DELETE NO ACTION;

-- ---------------------------------------------------------------------------
-- Grants for the two tables this migration creates
-- ---------------------------------------------------------------------------
-- These are HERE and not in 20260827150200_roles_and_grants.sql, which is where
-- every other grant lives, because that migration runs BEFORE this one and its
-- `grant ... on all tables in schema public` therefore cannot see a table this
-- file has not created yet. Putting them there would either fail the apply
-- outright or, for the `all tables` form, silently grant nothing. That file states
-- the rule this follows: there are deliberately no default privileges, so every
-- migration that creates a table grants on it in the same file.
--
-- Same derivation as the grants there: every grant names the statement that needs
-- it, and every grant withheld from a plausible candidate says why.

-- Ownership of these tables is a deployment decision, exactly as it is for the
-- tables in the init migration, so am_migrate is granted rather than assumed to
-- own them.
GRANT ALL ON TABLE "public"."finding_evidence", "public"."fetch_attempt" TO am_migrate;

-- finding_evidence
--
-- am_scanner INSERTs: the evidence rows are written by the check that raised the
-- finding, in the same transaction as the finding (FR-024). SELECT because a
-- rescan reads what the previous scan recorded.
--
-- UPDATE is withheld even though the scanner holds it on finding, scan, scan_check
-- and capability. An evidence row is a quote of the bundle's bytes at the instant
-- they were scanned; a rescan produces a new scan and new findings rather than
-- editing old ones, so nothing needs to rewrite one, and a row that cannot be
-- rewritten is a row an operator can still trust after the fact.
GRANT SELECT, INSERT ON TABLE "public"."finding_evidence" TO am_scanner;

-- am_api SELECTs: the finding detail pane is served over HTTP by api, which is
-- the web role's only door to this data.
--
-- INSERT and UPDATE are withheld, which narrows am_api's otherwise blanket
-- `select, insert, update on all tables`. api does not run checks — findings and
-- their evidence are the scanner's whole output (contracts/worker.md) — and the
-- one thing a reviewer does to a finding is approve or reject it, which writes
-- `override` and `finding.state`, not evidence. am_fetcher gets nothing at all: it
-- does not scan.
GRANT SELECT ON TABLE "public"."finding_evidence" TO am_api;

-- fetch_attempt
--
-- am_fetcher INSERTs, and holds nothing else, exactly as it does for audit_event
-- and outbox: it writes the record of what it did and never reads its own history.
GRANT INSERT ON TABLE "public"."fetch_attempt" TO am_fetcher;

-- am_api SELECTs: FR-053's "recent fetch outcomes" panel is served by api.
--
-- INSERT is withheld, and it is the one on this list somebody will want. A
-- reference that never names a repository at all can be rejected in the
-- registration handler, before any outbox row exists, so a future api could have a
-- refusal to record with no fetcher involved. No such handler exists yet, there is
-- no statement to name, and this file does not grant on a prediction; the layer
-- that writes that handler widens this deliberately.
--
-- UPDATE and DELETE are withheld from every role. An attempt is a record of
-- something that already happened. Note what that does NOT amount to: this table
-- is not covered by FR-052's revoke, which names audit_event and only audit_event,
-- so a table owner can still grant itself back. And with DELETE granted nowhere,
-- the table grows without bound — retention for it is unspecified, and the first
-- requirement that names a window is where a prune gets designed.
GRANT SELECT ON TABLE "public"."fetch_attempt" TO am_api;
