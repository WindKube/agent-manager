-- Modify "package" table
ALTER TABLE "public"."package" ADD CONSTRAINT "package_tracks_only_git" CHECK ((NOT track_upstream) OR (source_kind = 'git'::public.fetch_source_kind)), ADD COLUMN "track_upstream" boolean NOT NULL DEFAULT false, ADD COLUMN "tag_pattern" text NOT NULL DEFAULT 'v*', ADD COLUMN "last_checked_at" timestamptz NULL, ADD COLUMN "last_check_error" text NULL;
