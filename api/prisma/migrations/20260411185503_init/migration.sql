-- CreateExtension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- CreateEnum
CREATE TYPE "ApiScope" AS ENUM ('write', 'read');

-- CreateTable
CREATE TABLE "customers" (
    "id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "customers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "api_keys" (
    "id" TEXT NOT NULL,
    "customer_id" TEXT NOT NULL,
    "key_hash" TEXT NOT NULL,
    "scope" "ApiScope" NOT NULL,
    "deprecated" BOOLEAN NOT NULL DEFAULT false,
    "deprecated_at" TIMESTAMP(3),
    "last_used_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "api_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "devices" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "device_token" TEXT NOT NULL,
    "customer_id" TEXT NOT NULL,
    "public_key" TEXT NOT NULL,
    "key_fingerprint" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "attestation_verified" BOOLEAN NOT NULL DEFAULT false,
    "confidence_ceiling" TEXT NOT NULL DEFAULT 'high',
    "strongbox_backed" BOOLEAN,
    "enrolled_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'active',
    "network_participant" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "verifications" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "session_id" TEXT NOT NULL,
    "device_id" UUID,
    "customer_id" TEXT NOT NULL,
    "challenge" TEXT NOT NULL,
    "challenge_consumed" BOOLEAN NOT NULL DEFAULT false,
    "state" TEXT NOT NULL DEFAULT 'INITIATED',
    "context" TEXT,
    "biometric_used" BOOLEAN,
    "fallback_used" BOOLEAN NOT NULL DEFAULT false,
    "fallback_reason" TEXT,
    "confidence" TEXT,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "retry_session_id" TEXT,
    "completed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "otp_hash" TEXT,
    "otp_expires_at" TIMESTAMP(3),
    "otp_attempts" INTEGER NOT NULL DEFAULT 0,
    "otp_email_hash" TEXT,
    "otp_completed_at" TIMESTAMP(3),
    "ip_address" TEXT,
    "fallback_time_to_complete_seconds" INTEGER,

    CONSTRAINT "verifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "network_devices" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "key_fingerprint" TEXT NOT NULL,
    "first_seen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "platform" TEXT NOT NULL,
    "strongbox_backed" BOOLEAN,
    "attestation_ever_verified" BOOLEAN NOT NULL DEFAULT false,
    "total_verifications" INTEGER NOT NULL DEFAULT 0,
    "customer_count" INTEGER NOT NULL DEFAULT 0,
    "risk_score" INTEGER NOT NULL DEFAULT 0,
    "anomaly_flags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "network_joined_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "network_devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "network_events" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "network_device_id" UUID NOT NULL,
    "customer_id" TEXT NOT NULL,
    "event_type" TEXT NOT NULL,
    "confidence" TEXT,
    "biometric_used" BOOLEAN,
    "fallback_used" BOOLEAN NOT NULL DEFAULT false,
    "anomaly_score" INTEGER NOT NULL DEFAULT 0,
    "occurred_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "network_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "idempotency_records" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "response_json" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "idempotency_records_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_endpoints" (
    "id" TEXT NOT NULL,
    "customer_id" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "secret_encrypted" BYTEA NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webhook_endpoints_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_deliveries" (
    "id" TEXT NOT NULL,
    "endpoint_id" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "payload" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_attempt_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webhook_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "api_keys_key_hash_key" ON "api_keys"("key_hash");

-- CreateIndex
CREATE INDEX "api_keys_customer_id_idx" ON "api_keys"("customer_id");

-- CreateIndex
CREATE UNIQUE INDEX "devices_device_token_key" ON "devices"("device_token");

-- CreateIndex
CREATE INDEX "devices_device_token_idx" ON "devices"("device_token");

-- CreateIndex
CREATE INDEX "devices_customer_id_idx" ON "devices"("customer_id");

-- CreateIndex
CREATE INDEX "devices_key_fingerprint_idx" ON "devices"("key_fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "verifications_session_id_key" ON "verifications"("session_id");

-- CreateIndex
CREATE INDEX "verifications_session_id_idx" ON "verifications"("session_id");

-- CreateIndex
CREATE INDEX "verifications_customer_id_idx" ON "verifications"("customer_id");

-- CreateIndex
CREATE UNIQUE INDEX "network_devices_key_fingerprint_key" ON "network_devices"("key_fingerprint");

-- CreateIndex
CREATE INDEX "network_devices_key_fingerprint_idx" ON "network_devices"("key_fingerprint");

-- CreateIndex
CREATE INDEX "network_devices_risk_score_idx" ON "network_devices"("risk_score");

-- CreateIndex
CREATE INDEX "network_devices_customer_count_idx" ON "network_devices"("customer_count");

-- CreateIndex
CREATE INDEX "network_events_network_device_id_idx" ON "network_events"("network_device_id");

-- CreateIndex
CREATE INDEX "network_events_occurred_at_idx" ON "network_events"("occurred_at");

-- CreateIndex
CREATE UNIQUE INDEX "idempotency_records_key_key" ON "idempotency_records"("key");

-- CreateIndex
CREATE INDEX "idempotency_records_key_idx" ON "idempotency_records"("key");

-- CreateIndex
CREATE INDEX "webhook_endpoints_customer_id_idx" ON "webhook_endpoints"("customer_id");

-- CreateIndex
CREATE INDEX "webhook_deliveries_endpoint_id_idx" ON "webhook_deliveries"("endpoint_id");

-- CreateIndex
CREATE INDEX "webhook_deliveries_status_idx" ON "webhook_deliveries"("status");

-- AddForeignKey
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "customers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "customers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "verifications" ADD CONSTRAINT "verifications_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_events" ADD CONSTRAINT "network_events_network_device_id_fkey" FOREIGN KEY ("network_device_id") REFERENCES "network_devices"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
