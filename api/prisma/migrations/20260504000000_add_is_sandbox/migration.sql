-- Tag each Device and Verification with the env it was written under so
-- the dashboard's sandbox/production toggle can filter properly. Backfill
-- defaults to TRUE since every row that exists today was written via a
-- sandbox key (live keys only became writable in v2.0.0 and have not been
-- used at scale yet — verified in production prior to this migration).
ALTER TABLE "devices"       ADD COLUMN "is_sandbox" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "verifications" ADD COLUMN "is_sandbox" BOOLEAN NOT NULL DEFAULT true;

CREATE INDEX "devices_is_sandbox_idx"       ON "devices"       ("customer_id", "is_sandbox");
CREATE INDEX "verifications_is_sandbox_idx" ON "verifications" ("customer_id", "is_sandbox");
