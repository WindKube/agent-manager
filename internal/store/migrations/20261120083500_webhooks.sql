-- Add value to enum type: "audit_kind"
ALTER TYPE "public"."audit_kind" ADD VALUE 'webhook';
-- Add value to enum type: "audit_subject_kind"
ALTER TYPE "public"."audit_subject_kind" ADD VALUE 'webhook';
-- Modify "override" table
ALTER TABLE "public"."override" ADD COLUMN "expiring_notified_at" timestamptz NULL, ADD COLUMN "expired_notified_at" timestamptz NULL;
-- Create "webhook_subscription" table
CREATE TABLE "public"."webhook_subscription" (
  "id" uuid NOT NULL,
  "name" text NOT NULL,
  "url" text NOT NULL,
  "event_types" text[] NOT NULL,
  "namespaces" text[] NOT NULL DEFAULT '{}',
  "secret" bytea NOT NULL,
  "enabled" boolean NOT NULL DEFAULT true,
  "disabled_reason" text NULL,
  "created_by_identity_id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  "last_delivery_at" timestamptz NULL,
  "last_delivery_status" integer NULL,
  "last_delivery_error" text NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "webhook_subscription_created_by_identity_id_fkey" FOREIGN KEY ("created_by_identity_id") REFERENCES "public"."identity" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "webhook_subscription_has_an_event_type" CHECK (((cardinality(event_types) >= 1) AND (cardinality(event_types) <= 50)) AND (cardinality(namespaces) <= 50)),
  CONSTRAINT "webhook_subscription_name_is_bounded" CHECK ((char_length(btrim(name)) >= 1) AND (char_length(btrim(name)) <= 100)),
  CONSTRAINT "webhook_subscription_secret_is_32_bytes" CHECK (octet_length(secret) = 32),
  CONSTRAINT "webhook_subscription_url_is_https" CHECK ((url ~~ 'https://%'::text) AND (char_length(url) <= 2048))
);
-- Create "webhook_delivery" table
CREATE TABLE "public"."webhook_delivery" (
  "id" uuid NOT NULL,
  "subscription_id" uuid NOT NULL,
  "event_id" uuid NOT NULL,
  "event_type" text NOT NULL,
  "attempt" integer NOT NULL,
  "status_code" integer NULL,
  "error" text NULL,
  "response_body" text NULL,
  "duration_ms" integer NOT NULL,
  "occurred_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "webhook_delivery_subscription_id_fkey" FOREIGN KEY ("subscription_id") REFERENCES "public"."webhook_subscription" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "webhook_delivery_fields_are_bounded" CHECK ((attempt >= 1) AND (COALESCE(char_length(response_body), 0) <= 1024) AND (COALESCE(char_length(error), 0) <= 1024))
);
-- Create index "webhook_delivery_occurred_at_idx" to table: "webhook_delivery"
CREATE INDEX "webhook_delivery_occurred_at_idx" ON "public"."webhook_delivery" ("occurred_at");
-- Create index "webhook_delivery_subscription_idx" to table: "webhook_delivery"
CREATE INDEX "webhook_delivery_subscription_idx" ON "public"."webhook_delivery" ("subscription_id", "occurred_at" DESC);

-- Hand-written: the notifier role and the grants (Atlas models neither). The
-- role is created as the roles_and_grants migration creates the others, with
-- no password; the deployment sets one.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'am_notifier') then
    create role am_notifier login nosuperuser nocreatedb nocreaterole noreplication;
  end if;
end
$$;
GRANT USAGE ON SCHEMA public TO am_notifier;
GRANT ALL ON TABLE "public"."webhook_subscription", "public"."webhook_delivery" TO am_migrate;

-- am_api manages subscriptions and writes the secret, but never reads it back:
-- SELECT is granted on every column except secret. DELETE on the delivery log
-- is for deleting a subscription with it.
GRANT SELECT ("id", "name", "url", "event_types", "namespaces", "enabled", "disabled_reason",
  "created_by_identity_id", "created_at", "updated_at", "last_delivery_at", "last_delivery_status",
  "last_delivery_error") ON TABLE "public"."webhook_subscription" TO am_api;
GRANT INSERT, UPDATE, DELETE ON TABLE "public"."webhook_subscription" TO am_api;
GRANT SELECT, DELETE ON TABLE "public"."webhook_delivery" TO am_api;

-- am_notifier reads the secret to sign, may only disable a subscription and
-- record its last delivery, and owns the delivery log including its pruning.
-- It reads the audit log the events derive from and appends to it, and reads
-- the findings behind a waiver, marking only the two notice columns.
GRANT SELECT ON TABLE "public"."webhook_subscription" TO am_notifier;
GRANT UPDATE ("enabled", "disabled_reason", "updated_at", "last_delivery_at", "last_delivery_status",
  "last_delivery_error") ON TABLE "public"."webhook_subscription" TO am_notifier;
GRANT SELECT, INSERT, DELETE ON TABLE "public"."webhook_delivery" TO am_notifier;
GRANT SELECT, INSERT ON TABLE "public"."audit_event" TO am_notifier;
GRANT INSERT ON TABLE "public"."outbox" TO am_notifier;
GRANT SELECT ON TABLE "public"."override", "public"."finding", "public"."version", "public"."package" TO am_notifier;
GRANT UPDATE ("expiring_notified_at", "expired_notified_at") ON TABLE "public"."override" TO am_notifier;
