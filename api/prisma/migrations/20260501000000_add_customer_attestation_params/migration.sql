-- AlterTable: per-customer attestation parameters for multi-tenant validation.
-- All nullable so existing customers aren't broken; the server falls back to
-- attestation_verified=false, confidence_ceiling=medium when these are unset.
ALTER TABLE "customers"
  ADD COLUMN "android_package_name"        TEXT,
  ADD COLUMN "android_signing_key_sha256"  TEXT,
  ADD COLUMN "ios_team_id"                 TEXT,
  ADD COLUMN "ios_bundle_id"               TEXT;
