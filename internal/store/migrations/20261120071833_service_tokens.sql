-- Add value to enum type: "actor_kind"
ALTER TYPE "public"."actor_kind" ADD VALUE 'service-token';
-- Add value to enum type: "audit_kind"
ALTER TYPE "public"."audit_kind" ADD VALUE 'token';
-- Add value to enum type: "audit_subject_kind"
ALTER TYPE "public"."audit_subject_kind" ADD VALUE 'service-token';
-- Create "service_token" table
CREATE TABLE "public"."service_token" (
  "id" uuid NOT NULL,
  "name" text NOT NULL,
  "token_hash" bytea NOT NULL,
  "scopes" text[] NOT NULL,
  "created_by_identity_id" uuid NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "last_used_at" timestamptz NULL,
  "last_use_audited_at" timestamptz NULL,
  "revoked_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "service_token_token_hash_key" UNIQUE ("token_hash"),
  CONSTRAINT "service_token_created_by_identity_id_fkey" FOREIGN KEY ("created_by_identity_id") REFERENCES "public"."identity" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "service_token_expiry_is_bounded" CHECK ((expires_at > created_at) AND (expires_at <= (created_at + '1 year'::interval))),
  CONSTRAINT "service_token_has_a_scope" CHECK (cardinality(scopes) >= 1),
  CONSTRAINT "service_token_hash_is_sha256" CHECK (octet_length(token_hash) = 32),
  CONSTRAINT "service_token_name_is_bounded" CHECK ((char_length(btrim(name)) >= 1) AND (char_length(btrim(name)) <= 100))
);
-- Create index "service_token_created_by_idx" to table: "service_token"
CREATE INDEX "service_token_created_by_idx" ON "public"."service_token" ("created_by_identity_id", "created_at" DESC);
-- Modify "sync_event" table
ALTER TABLE "public"."sync_event" ADD COLUMN "service_token_id" uuid NULL, ADD
CONSTRAINT "sync_event_service_token_id_fkey" FOREIGN KEY ("service_token_id") REFERENCES "public"."service_token" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;

-- Hand-written grants (Atlas models none). service_token holds bearer-credential
-- hashes, so only am_api — the one role that authenticates requests — reads it.
-- SELECT to resolve a token, INSERT to create one, UPDATE to revoke one and to
-- record last use. DELETE is withheld from every role: a revoked or expired row
-- is the evidence that the credential existed.
GRANT ALL ON TABLE "public"."service_token" TO am_migrate;
GRANT SELECT, INSERT, UPDATE ON TABLE "public"."service_token" TO am_api;
