# vouchflow-server

Backend for the Vouchflow device-native verification platform. Serves the Vouchflow API, web dashboard, and marketing pages from a single Fastify process.

## Stack

- **Runtime**: Node.js 22, TypeScript
- **Framework**: Fastify 4
- **Database**: PostgreSQL via Prisma 5
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
      enroll.ts        POST /v1/enroll
      verify.ts        POST /v1/verify, GET /v1/verify/:id, fallback
      device.ts        GET /v1/device/:token/reputation
      auth.ts          POST /auth/magic-link, GET /auth/verify, POST /auth/signout
      pages.ts         HTML page routes (/, /signup, /dashboard, ...)
      web.ts           GET|PATCH /web/* — dashboard data API
    services/
      attestation.ts   Apple App Attest + Android Play Integrity
      confidence.ts    Device confidence scoring
      otp.ts           Email OTP generation and delivery
      webhooks.ts      Webhook delivery
      webhookSecrets.ts  pgcrypto encryption for webhook secrets
      tokenStore.ts    Redis-backed magic link tokens
      email.ts         Resend magic link delivery
      disposableEmail.ts  Disposable domain blocklist
    middleware/
      requireSession.ts  Session guard for protected routes
    lib/
      prisma.ts        Prisma client
      redis.ts         ioredis client (shared by app + BullMQ)
      queues.ts        BullMQ queue definitions
    plugins/
      apiKeyAuth.ts    Bearer key authentication for /v1/* routes
      responseHeaders.ts  Security headers
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

All endpoints are prefixed `/v1` and require `Authorization: Bearer <key>` and `Vouchflow-API-Version: 2026-04-01`. See [api/README.md](api/README.md) for full API reference.

## Web layer

The server also hosts the Vouchflow web dashboard at `/dashboard`, `/verifications`, `/settings`, and `/onboarding`. Authentication is magic-link email — no passwords.

### Auth flow

1. `POST /auth/magic-link` — sends a one-time link to the submitted email
2. `GET /auth/verify?token=...` — consumes the token, creates a session, redirects to `/onboarding` (new) or `/dashboard` (returning)
3. `POST /auth/signout` — destroys the session

Consumer email domains (gmail, yahoo, etc.) are blocked. Rate limit: 3 magic links per email per hour.

### Dashboard data routes

All `/web/*` routes require an active session.

| Route | Description |
|---|---|
| `GET /web/session` | Current user info and masked keys |
| `GET /web/overview` | Verification + device counts |
| `GET /web/verifications` | Paginated verification log |
| `GET /web/verifications/:sessionId` | Single verification detail |
| `GET /web/devices` | Device list |
| `GET /web/keys` | Masked API keys and webhook secret |
| `GET /web/usage` | Monthly verification count |
| `PATCH /web/account` | Update org name, billing email, settings |
| `POST /web/webhooks` | Register a webhook endpoint |
| `DELETE /web/webhooks/:webhookId` | Remove a webhook endpoint |

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string (`rediss://` for Upstash TLS) |
| `INTERNAL_HMAC_SECRET` | Yes | 32-byte hex — internal signing |
| `WEBHOOK_SECRET_ENCRYPTION_KEY` | Yes | 32-byte hex — encrypts webhook secrets at rest |
| `RESEND_API_KEY` | Yes | Resend API key — magic links and OTP delivery |
| `SESSION_SECRET` | Yes | 32-byte hex — signs session cookies |
| `ADMIN_KEY` | Yes | 32-byte hex — reserved for admin endpoints |
| `APPLE_TEAM_ID` | Yes | Apple Developer Team ID for App Attest |
| `APPLE_BUNDLE_ID` | Yes | App bundle ID for App Attest |
| `GOOGLE_CLOUD_PROJECT_NUMBER` | Yes | GCP project number for Play Integrity |
| `NODE_ENV` | No | `development` or `production`. Default: `development` |
| `PORT` | No | HTTP port. Default: `80` |
| `WEB_BASE_URL` | No | Base URL for magic link emails. Default: `https://vouchflow.dev` |

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
