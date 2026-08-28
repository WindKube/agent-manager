-- Create enum type "actor_kind"
CREATE TYPE "public"."actor_kind" AS ENUM ('identity', 'system');
-- Create enum type "audit_kind"
CREATE TYPE "public"."audit_kind" AS ENUM ('fetch', 'scan', 'approve', 'profile', 'share', 'sync', 'login');
-- Create enum type "capability_level"
CREATE TYPE "public"."capability_level" AS ENUM ('scoped', 'allowlisted', 'review');
-- Create enum type "capability_source"
CREATE TYPE "public"."capability_source" AS ENUM ('inferred', 'expected');
-- Create enum type "check_result"
CREATE TYPE "public"."check_result" AS ENUM ('pass', 'fail', 'warn');
-- Create enum type "component_kind"
CREATE TYPE "public"."component_kind" AS ENUM ('skill', 'mcp', 'ext');
-- Create enum type "device_auth_state"
CREATE TYPE "public"."device_auth_state" AS ENUM ('pending', 'approved', 'consumed', 'expired', 'denied');
-- Create enum type "dist_tag"
CREATE TYPE "public"."dist_tag" AS ENUM ('latest', 'archived', 'none');
-- Create enum type "entry_mode"
CREATE TYPE "public"."entry_mode" AS ENUM ('latest', 'pinned', 'range');
-- Create enum type "finding_severity"
CREATE TYPE "public"."finding_severity" AS ENUM ('low', 'medium', 'high');
-- Create enum type "finding_state"
CREATE TYPE "public"."finding_state" AS ENUM ('open', 'approved', 'rejected');
-- Create enum type "membership_role"
CREATE TYPE "public"."membership_role" AS ENUM ('owner', 'maintainer', 'reviewer', 'consumer');
-- Create enum type "org_role"
CREATE TYPE "public"."org_role" AS ENUM ('catalog-admin', 'scanner-reviewer', 'profile-consumer', 'read-only');
-- Create enum type "outbox_state"
CREATE TYPE "public"."outbox_state" AS ENUM ('pending', 'delivered');
-- Create enum type "package_kind"
CREATE TYPE "public"."package_kind" AS ENUM ('plugin', 'skill');
-- Create enum type "package_visibility"
CREATE TYPE "public"."package_visibility" AS ENUM ('organisation', 'team', 'private');
-- Create enum type "profile_visibility"
CREATE TYPE "public"."profile_visibility" AS ENUM ('organisation', 'shared', 'private');
-- Create enum type "scan_gate"
CREATE TYPE "public"."scan_gate" AS ENUM ('block', 'approval', 'warn-with-override');
-- Create enum type "signature_kind"
CREATE TYPE "public"."signature_kind" AS ENUM ('none', 'cosign-bundle');
-- Create enum type "signature_result"
CREATE TYPE "public"."signature_result" AS ENUM ('verified', 'invalid', 'error');
-- Create enum type "subject_kind"
CREATE TYPE "public"."subject_kind" AS ENUM ('user', 'group');
-- Create enum type "sync_target_kind"
CREATE TYPE "public"."sync_target_kind" AS ENUM ('claude-code', 'agents-md', 'codex');
-- Create enum type "verdict"
CREATE TYPE "public"."verdict" AS ENUM ('scanning', 'clean', 'flagged', 'rejected');
-- Create enum type "version_policy"
CREATE TYPE "public"."version_policy" AS ENUM ('floating-latest', 'pinned', 'range');
-- Create "audit_event" table
CREATE TABLE "public"."audit_event" (
  "id" uuid NOT NULL,
  "occurred_at" timestamptz NOT NULL DEFAULT now(),
  "actor" text NOT NULL,
  "actor_kind" "public"."actor_kind" NOT NULL,
  "kind" "public"."audit_kind" NOT NULL,
  "text" text NOT NULL,
  "source" text NULL,
  PRIMARY KEY ("id")
);
-- Create index "audit_event_occurred_at_idx" to table: "audit_event"
CREATE INDEX "audit_event_occurred_at_idx" ON "public"."audit_event" ("occurred_at" DESC);
-- Create "capability" table
CREATE TABLE "public"."capability" (
  "version_id" uuid NOT NULL,
  "source" "public"."capability_source" NOT NULL,
  "name" text NOT NULL,
  "detail" jsonb NULL,
  "level" "public"."capability_level" NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("version_id", "source", "name")
);
-- Create "category" table
CREATE TABLE "public"."category" (
  "id" uuid NOT NULL,
  "name" text NOT NULL,
  "slug" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "category_name_key" UNIQUE ("name"),
  CONSTRAINT "category_slug_key" UNIQUE ("slug")
);
-- Create "component" table
CREATE TABLE "public"."component" (
  "version_id" uuid NOT NULL,
  "path" text NOT NULL,
  "kind" "public"."component_kind" NOT NULL,
  "name" text NOT NULL,
  "note" text NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("version_id", "path")
);
-- Create "device_authorization" table
CREATE TABLE "public"."device_authorization" (
  "id" uuid NOT NULL,
  "device_code_hash" bytea NOT NULL,
  "user_code" text NOT NULL,
  "requesting_host" text NOT NULL,
  "state" "public"."device_auth_state" NOT NULL,
  "approved_by_identity_id" uuid NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "device_authorization_device_code_hash_key" UNIQUE ("device_code_hash"),
  CONSTRAINT "device_authorization_user_code_key" UNIQUE ("user_code")
);
-- Create "finding" table
CREATE TABLE "public"."finding" (
  "id" uuid NOT NULL,
  "scan_id" uuid NOT NULL,
  "version_id" uuid NOT NULL,
  "rule_id" text NOT NULL,
  "severity" "public"."finding_severity" NOT NULL,
  "title" text NOT NULL,
  "detail" text NULL,
  "evidence_path" text NULL,
  "evidence_line" integer NULL,
  "evidence_quote" text NULL,
  "state" "public"."finding_state" NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id")
);
-- Create index "finding_open_version_idx" to table: "finding"
CREATE INDEX "finding_open_version_idx" ON "public"."finding" ("version_id") WHERE (state = 'open'::public.finding_state);
-- Create "group_role_map" table
CREATE TABLE "public"."group_role_map" (
  "group_name" text NOT NULL,
  "role" "public"."org_role" NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("group_name")
);
-- Create "identity" table
CREATE TABLE "public"."identity" (
  "id" uuid NOT NULL,
  "subject" text NOT NULL,
  "email" text NULL,
  "display_name" text NULL,
  "groups" text[] NOT NULL DEFAULT '{}',
  "last_seen_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "identity_subject_key" UNIQUE ("subject")
);
-- Create "membership" table
CREATE TABLE "public"."membership" (
  "profile_id" uuid NOT NULL,
  "subject_kind" "public"."subject_kind" NOT NULL,
  "subject_ref" text NOT NULL,
  "role" "public"."membership_role" NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("profile_id", "subject_kind", "subject_ref")
);
-- Create "org_policy" table
CREATE TABLE "public"."org_policy" (
  "id" integer NOT NULL,
  "scan_gate" "public"."scan_gate" NOT NULL,
  "default_version_policy" "public"."version_policy" NOT NULL,
  "require_signed_bundles" boolean NOT NULL,
  "community_needs_review" boolean NOT NULL,
  "rescan_on_new_version" boolean NOT NULL,
  "allow_personal_profiles" boolean NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "org_policy_singleton" CHECK (id = 1)
);
-- Create "outbox" table
CREATE TABLE "public"."outbox" (
  "id" uuid NOT NULL,
  "job_kind" text NOT NULL,
  "payload" jsonb NOT NULL,
  "idempotency_key" text NOT NULL,
  "state" "public"."outbox_state" NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "delivered_at" timestamptz NULL,
  PRIMARY KEY ("id")
);
-- Create index "outbox_pending_created_at_idx" to table: "outbox"
CREATE INDEX "outbox_pending_created_at_idx" ON "public"."outbox" ("created_at") WHERE (state = 'pending'::public.outbox_state);
-- Create "override" table
CREATE TABLE "public"."override" (
  "finding_id" uuid NOT NULL,
  "reviewer_identity_id" uuid NOT NULL,
  "note" text NULL,
  "expires_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("finding_id")
);
-- Create "package" table
CREATE TABLE "public"."package" (
  "id" uuid NOT NULL,
  "publisher_id" uuid NOT NULL,
  "name" text NOT NULL,
  "kind" "public"."package_kind" NOT NULL,
  "category_id" uuid NULL,
  "visibility" "public"."package_visibility" NOT NULL,
  "parent_package_id" uuid NULL,
  "latest_version_id" uuid NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "package_publisher_name" UNIQUE ("publisher_id", "name"),
  CONSTRAINT "package_parent_package_id_fkey" FOREIGN KEY ("parent_package_id") REFERENCES "public"."package" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create "profile" table
CREATE TABLE "public"."profile" (
  "id" uuid NOT NULL,
  "slug" text NOT NULL,
  "name" text NOT NULL,
  "description" text NULL,
  "visibility" "public"."profile_visibility" NOT NULL,
  "owner_team" text NULL,
  "default_policy" "public"."version_policy" NOT NULL,
  "forked_from_id" uuid NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "profile_slug_key" UNIQUE ("slug"),
  CONSTRAINT "profile_forked_from_id_fkey" FOREIGN KEY ("forked_from_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create "profile_entry" table
CREATE TABLE "public"."profile_entry" (
  "profile_id" uuid NOT NULL,
  "package_id" uuid NOT NULL,
  "mode" "public"."entry_mode" NOT NULL,
  "pinned_version_id" uuid NULL,
  "range_expr" text NULL,
  "position" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("profile_id", "package_id"),
  CONSTRAINT "profile_entry_pinned_has_version" CHECK ((mode <> 'pinned'::public.entry_mode) OR (pinned_version_id IS NOT NULL))
);
-- Create "publisher" table
CREATE TABLE "public"."publisher" (
  "id" uuid NOT NULL,
  "slug" text NOT NULL,
  "display_name" text NOT NULL,
  "verified" boolean NOT NULL DEFAULT false,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "publisher_slug_key" UNIQUE ("slug")
);
-- Create "revision" table
CREATE TABLE "public"."revision" (
  "id" uuid NOT NULL,
  "profile_id" uuid NOT NULL,
  "seq" integer NOT NULL,
  "note" text NULL,
  "lockfile" jsonb NOT NULL,
  "object_key" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "created_by" text NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "revision_profile_seq" UNIQUE ("profile_id", "seq")
);
-- Create "scan" table
CREATE TABLE "public"."scan" (
  "id" uuid NOT NULL,
  "version_id" uuid NOT NULL,
  "pack_version" text NOT NULL,
  "started_at" timestamptz NOT NULL DEFAULT now(),
  "finished_at" timestamptz NULL,
  "verdict" "public"."verdict" NOT NULL,
  "timed_out" boolean NOT NULL DEFAULT false,
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "scan_version_pack_version" UNIQUE ("version_id", "pack_version")
);
-- Create "scan_check" table
CREATE TABLE "public"."scan_check" (
  "scan_id" uuid NOT NULL,
  "check_id" text NOT NULL,
  "label" text NOT NULL,
  "result" "public"."check_result" NOT NULL,
  "warn_count" integer NOT NULL DEFAULT 0,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("scan_id", "check_id")
);
-- Create "session" table
CREATE TABLE "public"."session" (
  "id" uuid NOT NULL,
  "token_hash" bytea NOT NULL,
  "identity_id" uuid NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "session_token_hash_key" UNIQUE ("token_hash")
);
-- Create "signature" table
CREATE TABLE "public"."signature" (
  "version_id" uuid NOT NULL,
  "ref" text NULL,
  "kind" "public"."signature_kind" NOT NULL,
  "verified_at" timestamptz NULL,
  "verified_by" text NULL,
  "result" "public"."signature_result" NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("version_id")
);
-- Create "sync_event" table
CREATE TABLE "public"."sync_event" (
  "id" uuid NOT NULL,
  "identity_id" uuid NOT NULL,
  "profile_id" uuid NOT NULL,
  "revision_id" uuid NOT NULL,
  "host" text NOT NULL,
  "occurred_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id")
);
-- Create "sync_target" table
CREATE TABLE "public"."sync_target" (
  "profile_id" uuid NOT NULL,
  "target" "public"."sync_target_kind" NOT NULL,
  "enabled" boolean NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("profile_id", "target")
);
-- Create "version" table
CREATE TABLE "public"."version" (
  "id" uuid NOT NULL,
  "package_id" uuid NOT NULL,
  "semver" text NOT NULL,
  "semver_sort" text NOT NULL COLLATE "C",
  "object_key" text NOT NULL,
  "digest" bytea NULL,
  "size_bytes" bigint NULL,
  "manifest" jsonb NOT NULL,
  "tags" text[] NOT NULL DEFAULT '{}',
  "dist_tag" "public"."dist_tag" NOT NULL,
  "verdict" "public"."verdict" NOT NULL,
  "visible" boolean NOT NULL DEFAULT false,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "version_package_semver" UNIQUE ("package_id", "semver"),
  CONSTRAINT "version_digest_is_sha256" CHECK ((digest IS NULL) OR (octet_length(digest) = 32)),
  CONSTRAINT "version_digest_present_unless_scanning" CHECK ((digest IS NOT NULL) OR (verdict = 'scanning'::public.verdict))
);
-- Create index "version_created_at_idx" to table: "version"
CREATE INDEX "version_created_at_idx" ON "public"."version" ("created_at" DESC);
-- Create index "version_package_semver_sort_idx" to table: "version"
CREATE INDEX "version_package_semver_sort_idx" ON "public"."version" ("package_id", "semver_sort" DESC);
-- Create index "version_tags_gin" to table: "version"
CREATE INDEX "version_tags_gin" ON "public"."version" USING gin ("tags");
-- Create index "version_verdict_visible_idx" to table: "version"
CREATE INDEX "version_verdict_visible_idx" ON "public"."version" ("verdict") WHERE visible;
-- Create "version_tag" table
CREATE TABLE "public"."version_tag" (
  "version_id" uuid NOT NULL,
  "tag" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("version_id", "tag")
);
-- Modify "capability" table
ALTER TABLE "public"."capability" ADD
CONSTRAINT "capability_version_id_fkey" FOREIGN KEY ("version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "component" table
ALTER TABLE "public"."component" ADD
CONSTRAINT "component_version_id_fkey" FOREIGN KEY ("version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "device_authorization" table
ALTER TABLE "public"."device_authorization" ADD
CONSTRAINT "device_authorization_approved_by_identity_id_fkey" FOREIGN KEY ("approved_by_identity_id") REFERENCES "public"."identity" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "finding" table
ALTER TABLE "public"."finding" ADD
CONSTRAINT "finding_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "public"."scan" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, ADD
CONSTRAINT "finding_version_id_fkey" FOREIGN KEY ("version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "membership" table
ALTER TABLE "public"."membership" ADD
CONSTRAINT "membership_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "override" table
ALTER TABLE "public"."override" ADD
CONSTRAINT "override_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "public"."finding" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, ADD
CONSTRAINT "override_reviewer_identity_id_fkey" FOREIGN KEY ("reviewer_identity_id") REFERENCES "public"."identity" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "package" table
ALTER TABLE "public"."package" ADD
CONSTRAINT "package_category_id_fkey" FOREIGN KEY ("category_id") REFERENCES "public"."category" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, ADD
CONSTRAINT "package_latest_version_id_fkey" FOREIGN KEY ("latest_version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, ADD
CONSTRAINT "package_publisher_id_fkey" FOREIGN KEY ("publisher_id") REFERENCES "public"."publisher" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "profile_entry" table
ALTER TABLE "public"."profile_entry" ADD
CONSTRAINT "profile_entry_package_id_fkey" FOREIGN KEY ("package_id") REFERENCES "public"."package" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, ADD
CONSTRAINT "profile_entry_pinned_version_id_fkey" FOREIGN KEY ("pinned_version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, ADD
CONSTRAINT "profile_entry_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "revision" table
ALTER TABLE "public"."revision" ADD
CONSTRAINT "revision_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "scan" table
ALTER TABLE "public"."scan" ADD
CONSTRAINT "scan_version_id_fkey" FOREIGN KEY ("version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "scan_check" table
ALTER TABLE "public"."scan_check" ADD
CONSTRAINT "scan_check_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "public"."scan" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "session" table
ALTER TABLE "public"."session" ADD
CONSTRAINT "session_identity_id_fkey" FOREIGN KEY ("identity_id") REFERENCES "public"."identity" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "signature" table
ALTER TABLE "public"."signature" ADD
CONSTRAINT "signature_version_id_fkey" FOREIGN KEY ("version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "sync_event" table
ALTER TABLE "public"."sync_event" ADD
CONSTRAINT "sync_event_identity_id_fkey" FOREIGN KEY ("identity_id") REFERENCES "public"."identity" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, ADD
CONSTRAINT "sync_event_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, ADD
CONSTRAINT "sync_event_revision_id_fkey" FOREIGN KEY ("revision_id") REFERENCES "public"."revision" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "sync_target" table
ALTER TABLE "public"."sync_target" ADD
CONSTRAINT "sync_target_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "version" table
ALTER TABLE "public"."version" ADD
CONSTRAINT "version_package_id_fkey" FOREIGN KEY ("package_id") REFERENCES "public"."package" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Modify "version_tag" table
ALTER TABLE "public"."version_tag" ADD
CONSTRAINT "version_tag_version_id_fkey" FOREIGN KEY ("version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
