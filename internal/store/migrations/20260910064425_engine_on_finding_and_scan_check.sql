-- Modify "finding" table
ALTER TABLE "public"."finding" ADD COLUMN "engine" text NOT NULL DEFAULT 'rulepack';
-- Modify "scan_check" table
ALTER TABLE "public"."scan_check" ADD COLUMN "engine" text NOT NULL DEFAULT 'rulepack';
