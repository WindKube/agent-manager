-- Modify "package" table
ALTER TABLE "public"."package" ADD COLUMN "source_kind" "public"."fetch_source_kind" NULL, ADD COLUMN "source_url" text NULL, ADD COLUMN "source_ref" text NULL, ADD COLUMN "source_subdirectory" text NULL;
-- Modify "version" table
ALTER TABLE "public"."version" ADD CONSTRAINT "version_source_commit_is_a_sha" CHECK (source_commit ~ '^[0-9a-f]{40}$'::text), ADD COLUMN "source_url" text NULL, ADD COLUMN "source_ref" text NULL, ADD COLUMN "source_commit" text NULL;
