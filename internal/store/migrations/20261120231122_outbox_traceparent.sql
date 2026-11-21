-- Modify "outbox" table
ALTER TABLE "public"."outbox" ADD COLUMN "traceparent" text NULL;
