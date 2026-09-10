-- Modify "scan_check" table
ALTER TABLE "public"."scan_check" ADD COLUMN "explain" text NOT NULL DEFAULT '';
