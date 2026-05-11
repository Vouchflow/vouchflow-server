-- AlterTable: add WebAuthn fields to devices
-- credential_id stores the WebAuthn credential ID (base64url) for web platform devices.
-- attestation_format stores the WebAuthn attestation format name (e.g. "apple", "packed", "none").
ALTER TABLE "devices"
  ADD COLUMN "credential_id"      TEXT,
  ADD COLUMN "attestation_format" TEXT;

-- AlterTable: extend verifications for sign operations (Web SDK signPayload)
-- type distinguishes verify sessions from sign sessions (created by POST /v1/sign).
-- canonicalized_payload and payload_sha256 store the JCS-canonicalized payload for sign ops.
ALTER TABLE "verifications"
  ADD COLUMN "type"                    TEXT    NOT NULL DEFAULT 'verify',
  ADD COLUMN "canonicalized_payload"   TEXT,
  ADD COLUMN "payload_sha256"          TEXT;

-- CreateTable: signing keys for JWS assertions returned by /v1/sign
-- Ed25519 key pairs; public key exposed via /.well-known/jwks.json for customer verification.
-- Private key encrypted at rest with pgp_sym_encrypt (same approach as webhook secrets).
CREATE TABLE "signing_keys" (
    "id"                       TEXT    NOT NULL,
    "kid"                      TEXT    NOT NULL,
    "algorithm"                TEXT    NOT NULL,
    "public_key"               TEXT    NOT NULL,
    "private_jwk_encrypted"    BYTEA   NOT NULL,
    "active"                   BOOLEAN NOT NULL DEFAULT true,
    "created_at"               TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "signing_keys_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "signing_keys_kid_key" ON "signing_keys"("kid");
