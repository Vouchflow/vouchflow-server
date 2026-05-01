# Vouchflow API Server

Backend for the Vouchflow device-native verification platform. Handles device enrollment, cryptographic challenge/response verification, email OTP fallback, reputation queries, webhooks, and asynchronous anomaly scoring.

## Stack

- **Runtime**: Node.js 22, TypeScript
- **Framework**: Fastify 4
- **Database**: PostgreSQL via Prisma 5
- **Cache / rate limiting**: Redis (Upstash)
- **Queue / workers**: BullMQ
- **Email**: Resend (OTP delivery)
- **Deployment**: Fly.io (two process groups: `app` + `worker`)

## Process groups

| Process | Command | Responsibilities |
|---|---|---|
| `app` | `node dist/index.js` | HTTP API — all request handling |
| `worker` | `node dist/workers/index.js` | Anomaly scoring, webhook delivery with retries |

Both processes run in the same Fly.io app but as separate machines. They share the same Postgres database and Redis instance.

## API reference

All endpoints are prefixed `/v1` and require a `Bearer` API key.

### Authentication

Two key scopes exist. The SDK uses the write key; your server uses the read key.

| Scope | Used for |
|---|---|
| `write` | `POST` endpoints — enrollment, verification, fallback |
| `read` | `GET` endpoints — reputation queries, session status |

Every request must include:
```
Authorization: Bearer vsk_live_...
Vouchflow-API-Version: 2026-04-01
```

### Environments and base URLs

| Environment | Base URL | Key prefix |
|---|---|---|
| Sandbox | `https://sandbox.api.vouchflow.dev/v1` | `vsk_sandbox_` / `vsk_sandbox_read_` |
| Production | `https://api.vouchflow.dev/v1` | `vsk_live_` / `vsk_live_read_` |

Sandbox verifications are free, isolated from the network graph, and do not affect billing. The SDK selects the correct host automatically based on the `environment` setting in `VouchflowConfig` / `VouchflowConfig.kt`.

If a key is within its 14-day rotation window, the response includes `Vouchflow-Key-Deprecated: true`.

---

### `POST /v1/enroll`

Registers a device. Called automatically by the iOS SDK on first launch.

**Request**
```json
{
  "idempotency_key": "ik_...",
  "customer_id": "cust_...",
  "platform": "ios",
  "reason": "fresh_enrollment",
  "attestation": { "token": "...", "key_id": "...", "cert_chain": ["base64-DER-cert", "..."] },
  "public_key": "base64...",
  "device_token": null
}
```

`reason`: `fresh_enrollment` | `reinstall` | `key_invalidated` | `corrupted`  
`attestation`: nullable — omit or set to `null` when device-platform attestation isn't available (Simulator, very old KeyMaster, etc.). For iOS, populate `token` (App Attest CBOR object, base64) and `key_id` (App Attest credential ID). For Android, populate `cert_chain` (Keystore Attestation cert chain, leaf-first, each cert base64-DER).  
`device_token`: include on reinstall to preserve the token; `null` on fresh enrollment

**Response**
```json
{
  "device_token": "dvt_...",
  "enrolled_at": "2026-04-11T12:00:00Z",
  "status": "active",
  "attestation_verified": true,
  "confidence_ceiling": "high",
  "idempotency_key": "ik_..."
}
```

Idempotent within a 24-hour window — replaying the same `idempotency_key` returns the original response. Rate limit: 10 requests/minute per IP.

---

### `POST /v1/verify`

Initiates a verification session. Returns a challenge to be signed by the device's Secure Enclave key.

**Request**
```json
{
  "customer_id": "cust_...",
  "device_token": "dvt_...",
  "context": "login",
  "minimum_confidence": "high"
}
```

`context`: `signup` | `login` | `sensitive_action`  
`minimum_confidence`: optional — returns `422 verification_impossible` if the device's confidence ceiling is below this value

**Response**
```json
{
  "session_id": "ses_...",
  "challenge": "base64...",
  "expires_at": "2026-04-11T12:01:00Z",
  "session_state": "INITIATED"
}
```

Sessions expire after 60 seconds. Rate limit: 100 requests/minute per IP.

---

### `POST /v1/verify/:session_id/complete`

Submits a signed challenge to complete verification. Also used for OTP submission when the session is in `FALLBACK` state.

**Primary path request**
```json
{
  "device_token": "dvt_...",
  "signed_challenge": "base64...",
  "biometric_used": true
}
```

**Response**
```json
{
  "verified": true,
  "confidence": "high",
  "session_state": "COMPLETED",
  "device_token": "dvt_...",
  "device_age_days": 42,
  "network_verifications": 7,
  "first_seen": "2026-01-01T00:00:00Z",
  "signals": {
    "keychain_persistent": true,
    "biometric_used": true,
    "cross_app_history": false,
    "anomaly_flags": [],
    "attestation_verified": true
  },
  "fallback_used": false,
  "context": "login"
}
```

If the session has expired, returns `410` with a `retry_session_id` and `retry_challenge` — the SDK handles this transparently. Rate limit: 10 requests/minute per session.

---

### `POST /v1/verify/:session_id/fallback`

Initiates email OTP fallback when biometric verification is unavailable or fails.

**Request**
```json
{
  "device_token": "dvt_...",
  "email": "user@example.com",
  "email_hash": "sha256hexdigest",
  "reason": "biometric_failed"
}
```

`email`: plaintext — used for OTP delivery, not stored  
`email_hash`: SHA-256 hex of the email — stored for rate limiting  
`device_token`: nullable if enrollment failed

**Response**
```json
{
  "fallback_session_id": "fbs_...",
  "method": "email_otp",
  "expires_at": "2026-04-11T12:05:00Z",
  "session_state": "FALLBACK"
}
```

Pass `fallback_session_id` to `POST /v1/verify/:session_id/complete` (with `{ otp, device_token }`) to complete the fallback. Rate limits: 3 per 24h per device token, 5 per hour per email hash, 10 per hour per IP.

---

### `GET /v1/verify/:session_id`

Returns the current state of a verification session. Requires a **read-scoped** key. Intended for server-side status polling.

**Response**
```json
{
  "session_id": "ses_...",
  "session_state": "COMPLETED",
  "verified": true,
  "confidence": "high",
  "context": "login",
  "fallback_used": false,
  "expires_at": "2026-04-11T12:01:00Z",
  "created_at": "2026-04-11T12:00:00Z"
}
```

---

### `GET /v1/device/:device_token/reputation`

Returns reputation data for a device, including the most recent completed verification. Requires a **read-scoped** key. This is the primary endpoint for **server-side trust** — your server calls this after receiving a `device_token` from the SDK to independently confirm that a verification just occurred and at what confidence level.

**Server-side trust pattern**

```
Mobile                       Your server                    Vouchflow
  │  verify() succeeds           │                              │
  │  ──── {deviceToken} ────►    │                              │
  │                              │  GET /v1/device/:token/      │
  │                              │  reputation ──────────────►  │
  │                              │  ◄────── {last_verification, │
  │                              │           risk_score, ...} ──│
  │                              │                              │
  │                     check last_verification.completed_at    │
  │                     is within your freshness window (e.g.   │
  │                     30s), confidence meets your threshold,  │
  │                     and risk_score is acceptable            │
```

Never call this endpoint from mobile — it requires a read-scoped key that must stay server-side.

**Response**
```json
{
  "device_token": "dvt_...",
  "first_seen": "2026-01-01T00:00:00Z",
  "last_seen": "2026-04-11T12:00:00Z",
  "total_verifications": 12,
  "network_verifications": 12,
  "anomaly_flags": [],
  "risk_score": 0,
  "device_age_days": 100,
  "platform": "ios",
  "keychain_persistent": true,
  "network_participant": false,
  "last_verification": {
    "confidence": "high",
    "context": "login",
    "completed_at": "2026-04-11T12:00:00Z",
    "biometric_used": true,
    "fallback_used": false
  }
}
```

`last_verification`: the most recent completed biometric verification for this device, or `null` if the device has never successfully verified. Use `completed_at` to confirm freshness.  
`risk_score`: 0–100, computed asynchronously after each verification. Higher scores indicate more anomalous device behaviour.  
`anomaly_flags`: `velocity_anomaly` | `reinstall_anomaly` | `confidence_degradation`

---

### `GET /v1/webhook/test`

Fires a test `verification.test` event to your configured webhook endpoint. Requires a write-scoped key. Returns whether delivery succeeded and the HTTP status code from your endpoint.

---

### `GET /health`

Returns `{ "status": "ok" }`. Not rate-limited. Used by Fly.io health checks.

---

## Webhooks

Vouchflow POSTs a signed payload to your registered webhook endpoint after each completed verification.

### Events

| Event | Trigger |
|---|---|
| `verification.complete` | Primary (biometric) verification completed |
| `verification.fallback_complete` | Email OTP fallback completed |
| `verification.test` | `GET /v1/webhook/test` called |

### Payload

```json
{
  "event": "verification.complete",
  "session_id": "ses_...",
  "verified": true,
  "confidence": "high",
  "context": "login",
  "timestamp": "2026-04-11T12:00:00Z",
  "api_version": "2026-04-01"
}
```

`device_token` is intentionally absent from webhook payloads — use `GET /v1/device/:token/reputation` with the token returned to the SDK instead.

### Signature verification

Every webhook request includes `X-Vouchflow-Signature: t=<timestamp>,v1=<hmac>`.

```
HMAC = SHA256("<timestamp>.<json_body>", webhook_secret)
```

Verify on your server before processing the payload:

```typescript
import crypto from 'node:crypto'

function verifyWebhookSignature(
  body: string,
  header: string,
  secret: string
): boolean {
  const parts = Object.fromEntries(header.split(',').map(p => p.split('=')))
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${parts.t}.${body}`)
    .digest('hex')
  return crypto.timingSafeEqual(
    Buffer.from(parts.v1, 'hex'),
    Buffer.from(expected, 'hex')
  )
}
```

### Retry schedule

Failed deliveries are retried with exponential backoff: immediate → 5s → 30s → 2m → 10m → 1h → 6h → 24h. After 8 attempts the delivery is marked `webhook_failed`.

---

## Session state machine

```
INITIATED → COMPLETED        (biometric verification succeeded)
INITIATED → FAILED           (signature invalid)
INITIATED → EXPIRED          (60s elapsed, retry session issued)
INITIATED → FALLBACK         (fallback initiated)
FALLBACK  → FALLBACK_COMPLETE (OTP correct)
FALLBACK  → FALLBACK_EXPIRED  (OTP window elapsed)
FALLBACK  → FALLBACK_LOCKED   (max OTP attempts exceeded)
```

---

## Local development

### Prerequisites

- Node.js 22
- A PostgreSQL database
- A Redis instance (or `redis-stack` via Docker)

### Setup

```bash
cd api
npm install
```

Copy the environment variables:

```bash
cp .env.example .env   # edit with your local values
```

Generate the Prisma client and run migrations:

```bash
npm run db:generate
npx prisma migrate dev
```

Start the API server:

```bash
npm run dev
```

Start the worker (separate terminal):

```bash
npm run worker:dev
```

### Scripts

| Script | Description |
|---|---|
| `npm run dev` | Start API server with hot reload |
| `npm run worker:dev` | Start worker with hot reload |
| `npm run build` | Compile TypeScript to `dist/` |
| `npm start` | Start compiled API server |
| `npm run worker` | Start compiled worker |
| `npm run db:migrate` | Apply pending migrations (production) |
| `npm run db:generate` | Regenerate Prisma client |
| `npm run db:studio` | Open Prisma Studio |

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string — use `rediss://` (TLS) for Upstash |
| `INTERNAL_HMAC_SECRET` | Yes | 32-byte hex secret for internal signing |
| `WEBHOOK_SECRET_ENCRYPTION_KEY` | Yes | 32-byte hex key for encrypting webhook secrets at rest |
| `RESEND_API_KEY` | Yes | Resend API key for OTP email delivery |
| `APPLE_APP_ATTEST_ROOT_CA` | Yes | Apple App Attest Root CA in PEM. Public cert, [Apple's docs](https://www.apple.com/certificateauthority/private/). Single value for the whole deployment. |
| `GOOGLE_HARDWARE_ATTESTATION_ROOT_CA` | Yes | Google Hardware Attestation Root CA(s) in PEM, concatenated. Public certs, [AOSP source](https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore-engine/keystore_attestation_root.pem). |
| `APPLE_TEAM_ID`, `APPLE_BUNDLE_ID` | No | Single-tenant fallback when `Customer.iosTeamId` / `iosBundleId` is null. |
| `ANDROID_PACKAGE_NAME`, `ANDROID_SIGNING_KEY_SHA256` | No | Single-tenant fallback when `Customer.androidPackageName` / `androidSigningKeySha256` is null. |
| `NODE_ENV` | No | `development` or `production`. Default: `development` |
| `PORT` | No | HTTP port. Default: `80` |
| `API_VERSION` | No | API version header value. Default: `2026-04-01` |

Generate secrets:

```bash
openssl rand -hex 32   # INTERNAL_HMAC_SECRET
openssl rand -hex 32   # WEBHOOK_SECRET_ENCRYPTION_KEY
```

---

## Deployment (Fly.io)

The app runs on Fly.io with two process groups (`app` + `worker`) sharing a Postgres database and an Upstash Redis instance.

### First-time setup

```bash
fly secrets set \
  DATABASE_URL="postgres://..." \
  REDIS_URL="rediss://default:...@....upstash.io:6379" \
  INTERNAL_HMAC_SECRET="$(openssl rand -hex 32)" \
  WEBHOOK_SECRET_ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  RESEND_API_KEY="re_..." \
  APPLE_APP_ATTEST_ROOT_CA="-----BEGIN CERTIFICATE-----..." \
  GOOGLE_HARDWARE_ATTESTATION_ROOT_CA="-----BEGIN CERTIFICATE-----..."
```

Per-customer attestation parameters (`Customer.androidPackageName`, `androidSigningKeySha256`, `iosTeamId`, `iosBundleId`) are configured via the dashboard — no env vars needed for multi-tenant deployments.

### Deploy

```bash
fly deploy
```

Migrations run automatically via `release_command = "npx prisma migrate deploy"` before traffic is shifted to new machines.

### Logs

```bash
fly logs                          # all processes
fly logs --process-group app      # API only
fly logs --process-group worker   # worker only
```

### Database access

```bash
fly postgres connect --app vouchflow-db
```

---

## Database schema

Managed by Prisma. Migrations live in `prisma/migrations/`. The `pgcrypto` extension is required for webhook secret encryption — it must be pre-installed on the Postgres cluster by a superuser before the first migration runs:

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
```

On Fly Postgres this is done via `fly postgres connect` (which connects as the `postgres` superuser).

### Tables

| Table | Purpose |
|---|---|
| `customers` | Integrating developers with a Vouchflow account |
| `api_keys` | Write and read-scoped keys, SHA-256 hashed |
| `devices` | Enrolled devices with their public keys and confidence ceilings |
| `verifications` | Verification sessions and their state |
| `network_devices` | Cross-customer device fingerprints (network graph) |
| `network_events` | Enrollment and verification events feeding the risk model |
| `idempotency_records` | 24-hour idempotency cache for `/v1/enroll`, backed by Redis with DB fallback |
| `webhook_endpoints` | Customer webhook URLs with encrypted secrets |
| `webhook_deliveries` | Delivery log for retry tracking |
