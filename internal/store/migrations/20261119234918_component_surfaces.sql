-- Add value to enum type: "component_kind"
ALTER TYPE "public"."component_kind" ADD VALUE 'agent';
-- Add value to enum type: "component_kind"
ALTER TYPE "public"."component_kind" ADD VALUE 'command';
-- Add value to enum type: "component_kind"
ALTER TYPE "public"."component_kind" ADD VALUE 'hook';
-- Modify "component" table
ALTER TABLE "public"."component" ADD COLUMN "event" text NULL, ADD COLUMN "matcher" text NULL, ADD COLUMN "transport" text NULL, ADD COLUMN "target" text NULL;
