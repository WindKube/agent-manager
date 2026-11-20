-- Create "webhook_dispatch" table
CREATE TABLE "public"."webhook_dispatch" (
  "audit_event_id" uuid NOT NULL,
  "dispatched_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("audit_event_id")
);
-- Create index "webhook_dispatch_dispatched_at_idx" to table: "webhook_dispatch"
CREATE INDEX "webhook_dispatch_dispatched_at_idx" ON "public"."webhook_dispatch" ("dispatched_at");

-- Hand-written grants. The dispatch marks belong to the notifier alone: it
-- claims audit rows by inserting them and prunes them past the lookback.
GRANT ALL ON TABLE "public"."webhook_dispatch" TO am_migrate;
GRANT SELECT, INSERT, DELETE ON TABLE "public"."webhook_dispatch" TO am_notifier;
