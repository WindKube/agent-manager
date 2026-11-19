-- Create enum type "audit_subject_kind"
CREATE TYPE "public"."audit_subject_kind" AS ENUM ('package', 'version', 'finding', 'profile', 'revision', 'category', 'mapping', 'policy', 'identity', 'device');
-- Modify "audit_event" table
ALTER TABLE "public"."audit_event" ADD COLUMN "subject_kind" "public"."audit_subject_kind" NULL, ADD COLUMN "subject_id" text NULL, ADD COLUMN "namespace" text NULL, ADD COLUMN "data" jsonb NOT NULL DEFAULT '{}';
-- Hand-edited: NOT VALID, which Atlas does not emit, so the rows written before
-- these columns existed stay legal; no backfill.
ALTER TABLE "public"."audit_event" ADD CONSTRAINT "audit_event_subject_required" CHECK ((subject_kind IS NOT NULL) AND (subject_id IS NOT NULL)) NOT VALID;
-- Create index "audit_event_subject_idx" to table: "audit_event"
CREATE INDEX "audit_event_subject_idx" ON "public"."audit_event" ("subject_kind", "subject_id", "occurred_at" DESC);
