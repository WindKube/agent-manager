-- Add value to enum type: "audit_subject_kind"
ALTER TYPE "public"."audit_subject_kind" ADD VALUE 'machine';
-- Create "machine" table
CREATE TABLE "public"."machine" (
  "id" uuid NOT NULL,
  "hostname" text NOT NULL,
  "os" text NULL,
  "arch" text NULL,
  "amctl_version" text NULL,
  "last_identity_id" uuid NOT NULL,
  "last_service_token_id" uuid NULL,
  "last_profile_id" uuid NOT NULL,
  "last_revision_id" uuid NOT NULL,
  "first_seen_at" timestamptz NOT NULL DEFAULT now(),
  "last_seen_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "machine_last_identity_id_fkey" FOREIGN KEY ("last_identity_id") REFERENCES "public"."identity" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_last_profile_id_fkey" FOREIGN KEY ("last_profile_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_last_revision_id_fkey" FOREIGN KEY ("last_revision_id") REFERENCES "public"."revision" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_last_service_token_id_fkey" FOREIGN KEY ("last_service_token_id") REFERENCES "public"."service_token" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_fields_are_bounded" CHECK (((char_length(btrim(hostname)) >= 1) AND (char_length(btrim(hostname)) <= 255)) AND (COALESCE(char_length(os), 0) <= 32) AND (COALESCE(char_length(arch), 0) <= 32) AND (COALESCE(char_length(amctl_version), 0) <= 64))
);
-- Create index "machine_last_identity_idx" to table: "machine"
CREATE INDEX "machine_last_identity_idx" ON "public"."machine" ("last_identity_id");
-- Create "machine_install" table
CREATE TABLE "public"."machine_install" (
  "machine_id" uuid NOT NULL,
  "profile_id" uuid NOT NULL,
  "target" "public"."sync_target_kind" NOT NULL,
  "package_id" uuid NOT NULL,
  "version_id" uuid NOT NULL,
  PRIMARY KEY ("machine_id", "profile_id", "target", "package_id"),
  CONSTRAINT "machine_install_machine_id_fkey" FOREIGN KEY ("machine_id") REFERENCES "public"."machine" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_install_package_id_fkey" FOREIGN KEY ("package_id") REFERENCES "public"."package" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_install_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_install_version_id_fkey" FOREIGN KEY ("version_id") REFERENCES "public"."version" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create index "machine_install_package_version_idx" to table: "machine_install"
CREATE INDEX "machine_install_package_version_idx" ON "public"."machine_install" ("package_id", "version_id");
-- Create "machine_skip" table
CREATE TABLE "public"."machine_skip" (
  "id" uuid NOT NULL,
  "machine_id" uuid NOT NULL,
  "profile_id" uuid NOT NULL,
  "entry" text NOT NULL,
  "target" "public"."sync_target_kind" NULL,
  "component" text NULL,
  "reason" text NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "machine_skip_machine_id_fkey" FOREIGN KEY ("machine_id") REFERENCES "public"."machine" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_skip_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profile" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "machine_skip_component_is_whole" CHECK (((component IS NULL) = (reason IS NULL)) AND ((component IS NULL) = (target IS NULL)) AND ((char_length(entry) >= 1) AND (char_length(entry) <= 256)) AND (COALESCE(char_length(component), 0) <= 256) AND (COALESCE(char_length(reason), 0) <= 1024))
);
-- Create index "machine_skip_machine_profile_idx" to table: "machine_skip"
CREATE INDEX "machine_skip_machine_profile_idx" ON "public"."machine_skip" ("machine_id", "profile_id");

-- Hand-written grants (Atlas models none). The inventory is written by the
-- sync report and read by the inventory screens, both served by am_api.
-- DELETE on the two current-state tables replaces a profile's rows on every
-- report; DELETE on machine is forgetting one.
GRANT ALL ON TABLE "public"."machine", "public"."machine_install", "public"."machine_skip" TO am_migrate;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "public"."machine" TO am_api;
GRANT SELECT, INSERT, DELETE ON TABLE "public"."machine_install", "public"."machine_skip" TO am_api;
