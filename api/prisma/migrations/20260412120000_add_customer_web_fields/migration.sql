-- AlterTable: add web-layer fields to customers
ALTER TABLE "customers"
  ADD COLUMN "email"              TEXT,
  ADD COLUMN "sandbox_write_key"  TEXT,
  ADD COLUMN "sandbox_read_key"   TEXT,
  ADD COLUMN "webhook_secret"     TEXT,
  ADD COLUMN "org_name"           TEXT,
  ADD COLUMN "billing_email"      TEXT,
  ADD COLUMN "minimum_confidence" TEXT,
  ADD COLUMN "network_opt_in"     BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "updated_at"         TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- CreateIndex
CREATE UNIQUE INDEX "customers_email_key" ON "customers"("email");
CREATE UNIQUE INDEX "customers_sandbox_write_key_key" ON "customers"("sandbox_write_key");
CREATE UNIQUE INDEX "customers_sandbox_read_key_key" ON "customers"("sandbox_read_key");

-- AlterTable: add events array to webhook_endpoints
ALTER TABLE "webhook_endpoints"
  ADD COLUMN "events" TEXT[] NOT NULL DEFAULT '{}';
