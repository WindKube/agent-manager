-- Modify "package" table
ALTER TABLE "public"."package" ADD COLUMN "owner_identity_id" uuid NULL, ADD
CONSTRAINT "package_owner_identity_id_fkey" FOREIGN KEY ("owner_identity_id") REFERENCES "public"."identity" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
