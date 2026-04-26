# vouchflow-server

[![CI](https://github.com/vouchflow/vouchflow-server/actions/workflows/server.yml/badge.svg)](https://github.com/vouchflow/vouchflow-server/actions/workflows/server.yml)

Backend for the Vouchflow device-native verification platform. Serves the Vouchflow API, web dashboard, and marketing pages from a single Fastify process.

## Stack

- **Runtime**: Node.js 22, TypeScript
- **Framework**: Fastify 4
- **Database**: PostgreSQL via Prisma 5 (with `pgcrypto` extension)
- **Cache / rate limiting**: Redis (Upstash)
- **Queue / workers**: BullMQ
- **Email**: Resend (magic links + OTP delivery)
- **Deployment**: Fly.io

## Process groups

| Process | Command | Responsibilities |
|---|---|---|
| `app` | `node dist/index.js` | HTTP — API, web dashboard, static pages |
| `worker` | `node dist/workers/index.js` | Anomaly scoring, webhook delivery with retries |

## Project structure

```
api/
  src/
    routes/
      customers.ts     POST /v1/customers, PATCH, DELETE, live-keys
      enroll.ts        POST /v1/enroll
      verify.ts        POST /v1/verify, /verify/:id/complete, /verify/:id/fallback, GET /v1/verify/:id
      device.ts        GET /v1/device/:token/reputation
      auth.ts          GET /auth/google/callback, /auth/github/callback, POST /auth/signout
      pages.ts         HTML page routes (/, /signup, /dashboard, ...)
      web.ts           GET|PATCH|POST|DELETE /web/* — dashboard data API
    services/
      attestation.ts       Apple App Attest + Android Play Integrity
      confidence.ts        Device confidence scoring
      otp.ts               Email OTP generation and delivery
      webhooks.ts          Webhook delivery
      webhookSecrets.ts    pgcrypto encryption for webhook secrets at rest
      tokenStore.ts        Redis-backed magic link tokens
      email.ts             Resend magic link + partner inquiry delivery
      disposableEmail.ts   Disposable domain blocklist
      apiClient.ts         Internal HTTP client for web→API calls
    middleware/
      requireSession.ts    Session guard for protected routes
    lib/
      prisma.ts        Prisma client
      redis.ts         ioredis client (shared by app + BullMQ)
      queues.ts        BullMQ queue definitions
    plugins/
      apiKeyAuth.ts        Bearer key authentication for /v1/* routes
      responseHeaders.ts   Security headers
    workers/
      index.ts         Anomaly scoring + webhook retry worker
    config.ts
    app.ts
    index.ts
  prisma/
    schema.prisma
    migrations/
  public/              Static HTML pages served at /
```

## API

All `/v1` endpoints require `Authorization: Bearer <key>` and `Vouchflow-API-Version: 2026-04-01`.

### Authentication (admin key)

These endpoints require the `ADMIN_KEY` and are called by the web layer only — not exposed to SDK clients.

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/customers` | Find or create a customer by email |
| `PATCH` | `/v1/customers/:id` | Update org name, billing email, settings |
| `DELETE` | `/v1/customers/:id` | Permanently delete customer and all associated data |
| `POST` | `/v1/customers/:id/live-keys` | Generate live write+read key pair (raw keys returned once) |
| `GET` | `/v1/customers/:id/live-keys` | List active live key metadata (no raw values) |
| `GET` | `/v1/customers/:id/stats` | Verification + device overview stats |
| `GET` | `/v1/customers/:id/webhooks` | List registered webhook endpoints |
| `GET` | `/v1/customers/:id/usage` | Monthly verification count |

### SDK endpoints (write-scoped key)

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/enroll` | Enroll a device (Secure Enclave / Keystore public key + attestation) |
| `POST` | `/v1/verify` | Initiate a verification session — returns challenge |
| `POST` | `/v1/verify/:session_id/complete` | Complete verification (signed challenge or OTP fallback) |
| `POST` | `/v1/verify/:session_id/fallback` | Request email OTP fallback for a session |
| `GET` | `/v1/webhook/test` | Fire a test webhook event |
| `POST` | `/v1/webhooks` | Register a webhook endpoint |
| `DELETE` | `/v1/webhooks/:id` | Remove a webhook endpoint |
| `GET` | `/v1/verifications` | Paginated verification log |
| `GET` | `/v1/devices` | Device list |

### SDK endpoints (read-scoped key)

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/verify/:session_id` | Fetch verification session state |
| `GET` | `/v1/device/:token/reputation` | Device reputation and signal breakdown |

### Key types

| Prefix | Scope | Storage |
|---|---|---|
| `vsk_sandbox_` | Sandbox write | Plaintext in `Customer` table |
| `vsk_sandbox_read_` | Sandbox read | Plaintext in `Customer` table |
| `vsk_live_` | Live write | SHA-256 hash in `ApiKey` table |
| `vsk_live_read_` | Live read | SHA-256 hash in `ApiKey` table |

Raw live keys are returned once at generation time and never stored. Deprecated live keys remain valid for 14 days after rotation.

## Web layer

The server also hosts the Vouchflow web dashboard at `/dashboard`, `/verifications`, `/settings`, and `/onboarding`. Authentication is OAuth via Google or GitHub — no passwords.

### Auth flow

1. User clicks **Continue with Google** or **Continue with GitHub** at `/signup`
2. `GET /auth/google/callback` or `GET /auth/github/callback` — OAuth callback; creates or fetches the customer, writes session, redirects to `/onboarding` (new) or `/dashboard` (returning)
3. `POST /auth/signout` — destroys the session

Consumer email domains (gmail, yahoo, etc.) are blocked at the OAuth callback.

### Dashboard data routes

All `/web/*` routes require an active session.

| Method | Route | Description |
|---|---|---|
| `GET` | `/web/session` | Current user info and masked keys |
| `GET` | `/web/overview` | Verification + device counts and daily breakdown |
| `GET` | `/web/verifications` | Paginated verification log |
| `GET` | `/web/verifications/:sessionId` | Single verification detail |
| `GET` | `/web/devices` | Device list |
| `GET` | `/web/keys` | Masked sandbox keys and webhook secret |
| `GET` | `/web/keys/reveal` | Unmasked sandbox keys (for one-time reveal) |
| `GET` | `/web/usage` | Monthly verification count |
| `GET` | `/web/webhooks` | List webhook endpoints |
| `GET` | `/web/live-keys` | Active live key metadata (no raw values) |
| `PATCH` | `/web/account` | Update org name, billing email, settings |
| `PATCH` | `/web/onboarding` | Mark onboarding complete |
| `POST` | `/web/webhooks` | Register a webhook endpoint |
| `POST` | `/web/live-keys` | Generate live key pair (raw keys returned once) |
| `POST` | `/web/partner-inquiry` | Send a partner inquiry email |
| `DELETE` | `/web/webhooks/:webhookId` | Remove a webhook endpoint |
| `DELETE` | `/web/account` | Permanently delete account and destroy session |

## Data models

| Model | Key fields |
|---|---|
| `Customer` | id, email, sandboxWriteKey, sandboxReadKey, webhookSecret, orgName, billingEmail, minimumConfidence, networkOptIn |
| `ApiKey` | id, customerId, keyHash (SHA-256), scope (write/read), deprecated, deprecatedAt |
| `Device` | id (UUID), deviceToken, publicKey, platform, attestationVerified, confidenceCeiling, strongboxBacked |
| `Verification` | id (UUID), sessionId, deviceId, state, context, biometricUsed, fallbackUsed, confidence |
| `WebhookEndpoint` | id, customerId, url, events |
| `WebhookDelivery` | id, endpointId, payload, status, attempts |

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string (`rediss://` for Upstash TLS) |
| `INTERNAL_HMAC_SECRET` | Yes | 32-byte hex — internal signing |
| `WEBHOOK_SECRET_ENCRYPTION_KEY` | Yes | 32-byte hex — encrypts webhook secrets at rest via pgcrypto |
| `RESEND_API_KEY` | Yes | Resend API key — OTP and partner inquiry delivery |
| `SESSION_SECRET` | Yes | 32-byte hex — signs session cookies |
| `ADMIN_KEY` | Yes | 32-byte hex — authenticates web→API internal calls |
| `GOOGLE_CLIENT_ID` | Yes | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Yes | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | Yes | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | Yes | GitHub OAuth client secret |
| `APPLE_TEAM_ID` | Yes | Apple Developer Team ID for App Attest |
| `APPLE_BUNDLE_ID` | Yes | App bundle ID for App Attest |
| `GOOGLE_CLOUD_PROJECT_NUMBER` | Yes | GCP project number for Play Integrity |
| `NODE_ENV` | No | `development` or `production`. Default: `development` |
| `PORT` | No | HTTP port. Default: `80` |
| `WEB_BASE_URL` | No | Base URL for OAuth callback URLs. Default: `https://vouchflow.dev` |

## Local development

```bash
cd api
npm install
cp ../.env.example ../.env   # fill in values
npm run db:generate
npx prisma migrate dev
npm run dev
```

Worker (separate terminal):

```bash
npm run worker:dev
```

Set `NODE_ENV=development` so session cookies work over HTTP.

## Deployment

The app runs on Fly.io. Migrations run automatically before each deploy via `release_command`.

```bash
fly deploy
```

### First-time secrets

```bash
fly secrets set \
  DATABASE_URL="postgres://..." \
  REDIS_URL="rediss://..." \
  INTERNAL_HMAC_SECRET="$(openssl rand -hex 32)" \
  WEBHOOK_SECRET_ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  RESEND_API_KEY="re_..." \
  SESSION_SECRET="$(openssl rand -hex 32)" \
  ADMIN_KEY="$(openssl rand -hex 32)" \
  GOOGLE_CLIENT_ID="..." \
  GOOGLE_CLIENT_SECRET="..." \
  GITHUB_CLIENT_ID="..." \
  GITHUB_CLIENT_SECRET="..." \
  APPLE_TEAM_ID="..." \
  APPLE_BUNDLE_ID="..." \
  GOOGLE_CLOUD_PROJECT_NUMBER="..."
```

### Custom domain

```bash
flyctl certs add vouchflow.dev
flyctl certs add www.vouchflow.dev
```

Point DNS:
```
A    vouchflow.dev     → 66.241.124.3
AAAA vouchflow.dev     → 2a09:8280:1::ff:19e0:0
A    www.vouchflow.dev → 66.241.124.3
AAAA www.vouchflow.dev → 2a09:8280:1::ff:19e0:0
```

## CI / CD

| Event | Action |
|---|---|
| Pull request to `main` | TypeScript build + Prisma schema validation |
| Push to `main` | Build + deploy to **staging** (`vouchflow-server-staging.fly.dev`) |
| Push tag `server-v*` | Build + deploy to **production** |

### Required repository secrets

| Secret | Description |
|---|---|
| `FLY_STAGING_API_TOKEN` | Fly.io token scoped to `vouchflow-server-staging` |
| `FLY_API_TOKEN` | Fly.io token scoped to `vouchflow-server` |

### First-time staging setup

```bash
fly apps create vouchflow-server-staging
fly postgres create --name vouchflow-db-staging
fly secrets set -a vouchflow-server-staging \
  DATABASE_URL="postgres://..." \
  REDIS_URL="redis://..." \
  INTERNAL_HMAC_SECRET="$(openssl rand -hex 32)" \
  WEBHOOK_SECRET_ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  RESEND_API_KEY="re_..." \
  APPLE_TEAM_ID="..." \
  APPLE_BUNDLE_ID="..." \
  GOOGLE_CLOUD_PROJECT_NUMBER="..."
```

Configure GitHub Environments named `staging` and `production` to add required reviewers and deployment protection rules.
