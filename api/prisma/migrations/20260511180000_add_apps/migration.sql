-- Multi-app refactor migration. Introduces `apps` as a first-class child of
-- `customers`. Moves per-customer attestation parameters + sandbox keys onto
-- the new `apps` table. Adds `app_id` foreign keys to api_keys, devices,
-- verifications, webhook_endpoints, backfills them from each customer's new
-- "Default App", then drops the moved columns from `customers`.
--
-- The whole thing runs in a single transaction. There is no down migration —
-- the schema change is forward-only. If you need to roll back, restore from
-- a pre-migration snapshot.

BEGIN;

-- ── 1. Create `apps` table ──────────────────────────────────────────────────

CREATE TABLE "apps" (
  "id"                            TEXT PRIMARY KEY,
  "customer_id"                   TEXT NOT NULL,
  "name"                          TEXT NOT NULL,
  "slug"                          TEXT NOT NULL,
  "description"                   TEXT,
  "sandbox_write_key"             TEXT UNIQUE,
  "sandbox_read_key"              TEXT UNIQUE,
  "ios_team_id"                   TEXT,
  "ios_bundle_id"                 TEXT,
  "android_package_name"          TEXT,
  "android_signing_key_sha256"    TEXT,
  "web_sdk_enabled"               BOOLEAN NOT NULL DEFAULT false,
  "web_rp_id"                     TEXT,
  "web_allowed_origins"           TEXT[] NOT NULL DEFAULT '{}',
  "verify_min_confidence"         TEXT,
  "sign_payload_min_confidence"   TEXT,
  "context_confidence_overrides"  JSONB  NOT NULL DEFAULT '{}',
  "archived_at"                   TIMESTAMP(3),
  "created_at"                    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at"                    TIMESTAMP(3) NOT NULL,
  CONSTRAINT "apps_customer_id_fkey" FOREIGN KEY ("customer_id")
    REFERENCES "customers"("id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "apps_customer_id_slug_key"        ON "apps"("customer_id", "slug");
CREATE        INDEX "apps_customer_id_archived_at_idx" ON "apps"("customer_id", "archived_at");

-- ── 2. Add nullable app_id columns on the four child tables ─────────────────

ALTER TABLE "api_keys"          ADD COLUMN "app_id" TEXT;
ALTER TABLE "devices"           ADD COLUMN "app_id" TEXT;
ALTER TABLE "verifications"     ADD COLUMN "app_id" TEXT;
ALTER TABLE "webhook_endpoints" ADD COLUMN "app_id" TEXT;

-- ── 3. Backfill — one Default App per existing customer ────────────────────
--
-- The new app gets the customer's existing sandbox keys + attestation params.
-- We use a 24-char hex random for the ID; prefixed `app_` to match the cuid-ish
-- shape used elsewhere (`vsk_…`, `dvt_…`, `ses_…`). This is non-cryptographic
-- — it just needs to be unique, which 96 bits of randomness handles fine.

INSERT INTO "apps" (
  id, customer_id, name, slug,
  sandbox_write_key, sandbox_read_key,
  ios_team_id, ios_bundle_id, android_package_name, android_signing_key_sha256,
  sign_payload_min_confidence,
  updated_at
)
SELECT
  'app_' || encode(gen_random_bytes(12), 'hex'),
  c.id,
  'Default App',
  'default',
  c.sandbox_write_key,
  c.sandbox_read_key,
  c.ios_team_id,
  c.ios_bundle_id,
  c.android_package_name,
  c.android_signing_key_sha256,
  'high',
  CURRENT_TIMESTAMP
FROM "customers" c;

-- ── 4. Backfill app_id on each child table from the customer's Default App ─

UPDATE "api_keys" a
   SET app_id = ap.id
   FROM "apps" ap
   WHERE ap.customer_id = a.customer_id;

UPDATE "devices" d
   SET app_id = ap.id
   FROM "apps" ap
   WHERE ap.customer_id = d.customer_id;

UPDATE "verifications" v
   SET app_id = ap.id
   FROM "apps" ap
   WHERE ap.customer_id = v.customer_id;

UPDATE "webhook_endpoints" we
   SET app_id = ap.id
   FROM "apps" ap
   WHERE ap.customer_id = we.customer_id;

-- ── 5. Enforce NOT NULL + FK + index on each app_id column ─────────────────

ALTER TABLE "api_keys"          ALTER COLUMN "app_id" SET NOT NULL;
ALTER TABLE "devices"           ALTER COLUMN "app_id" SET NOT NULL;
ALTER TABLE "verifications"     ALTER COLUMN "app_id" SET NOT NULL;
ALTER TABLE "webhook_endpoints" ALTER COLUMN "app_id" SET NOT NULL;

ALTER TABLE "api_keys"
  ADD CONSTRAINT "api_keys_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "apps"("id") ON DELETE CASCADE;
ALTER TABLE "devices"
  ADD CONSTRAINT "devices_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "apps"("id") ON DELETE CASCADE;
ALTER TABLE "verifications"
  ADD CONSTRAINT "verifications_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "apps"("id") ON DELETE CASCADE;
ALTER TABLE "webhook_endpoints"
  ADD CONSTRAINT "webhook_endpoints_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "apps"("id") ON DELETE CASCADE;

CREATE INDEX "api_keys_app_id_idx"               ON "api_keys"("app_id");
CREATE INDEX "devices_app_id_is_sandbox_idx"     ON "devices"("app_id", "is_sandbox");
CREATE INDEX "verifications_app_id_is_sandbox_idx" ON "verifications"("app_id", "is_sandbox");
CREATE INDEX "webhook_endpoints_app_id_idx"      ON "webhook_endpoints"("app_id");

-- ── 6. Customer back-reference FKs (verifications + webhook_endpoints) ─────
-- These models gained `customer` relations in the Prisma schema. The columns
-- already exist; just add the FK so Prisma's generated client is happy.

ALTER TABLE "verifications"
  ADD CONSTRAINT "verifications_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "customers"("id");
ALTER TABLE "webhook_endpoints"
  ADD CONSTRAINT "webhook_endpoints_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "customers"("id");

-- ── 7. Drop now-redundant Customer columns ─────────────────────────────────
--
-- These fields lived on customers since the original schema. They've been
-- copied onto each customer's Default App in step 3 — dropping is safe.

ALTER TABLE "customers"
  DROP COLUMN "sandbox_write_key",
  DROP COLUMN "sandbox_read_key",
  DROP COLUMN "ios_team_id",
  DROP COLUMN "ios_bundle_id",
  DROP COLUMN "android_package_name",
  DROP COLUMN "android_signing_key_sha256";

COMMIT;
