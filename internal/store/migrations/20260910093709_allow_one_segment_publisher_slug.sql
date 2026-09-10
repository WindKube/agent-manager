-- Modify "publisher" table
ALTER TABLE "public"."publisher" DROP CONSTRAINT "publisher_slug_is_two_segments", ADD CONSTRAINT "publisher_slug_is_one_or_two_segments" CHECK (slug ~ '^[^/]+(/[^/]+)?$'::text);
