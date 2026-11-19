-- Create index "audit_event_namespace_idx" to table: "audit_event"
CREATE INDEX "audit_event_namespace_idx" ON "public"."audit_event" ("namespace", "occurred_at" DESC);
-- Create index "audit_event_package_idx" to table: "audit_event"
CREATE INDEX "audit_event_package_idx" ON "public"."audit_event" (((data ->> 'package'::text)), "occurred_at" DESC);
