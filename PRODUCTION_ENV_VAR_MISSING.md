# Production Environment Variable Missing

## Issue

Production deployments are failing with 500 errors due to missing environment variable:

```json
{
  "statusCode": 500,
  "error": "Internal Server Error",
  "message": "Missing required environment variable: VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY"
}
```

## What This Variable Is For

`VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY` is a 32-byte hex string used to encrypt/decrypt Ed25519 private keys for JWS assertion signing (POST /v1/sign).

**Purpose:**
- Signs JWS tokens returned by POST /v1/sign
- Public keys exposed via GET /v1/.well-known/jwks.json
- Private keys encrypted using pgcrypto's pgp_sym_encrypt
- Same pattern as webhook secrets encryption

**Code Reference:** `api/src/services/signingKeys.ts`

## How to Fix

### 1. Generate the encryption key:

```bash
# Generate a 32-byte (64 hex characters) encryption key
openssl rand -hex 32
```

### 2. Set in production environment:

The exact method depends on your deployment platform:

**Fly.io:**
```bash
flyctl secrets set VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY=<64-char-hex-string>
```

**Heroku:**
```bash
heroku config:set VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY=<64-char-hex-string>
```

**Docker/K8s:**
Add to environment variables or secrets management

**Railway:**
Add to environment variables in dashboard

### 3. Redeploy

After setting the variable, redeploy the server. The signing key service will:
1. Check for an active signing key in the database
2. If none exists, generate a new Ed25519 keypair
3. Encrypt the private key using the encryption key
4. Store in the `signing_keys` table

## Repro Session

- Session ID: `ses_5a0a6da05c383cb5d719a3e1`
- Timestamp: ~12:39 mobile, 2026-05-12
- Device token: `dvt_1f181faf2585a698ce6c61cb7f9aff71`

## Future Improvement

Consider failing server boot when required env vars are missing, rather than letting it 500 at request time. This surfaces misconfiguration before the first user request.

**Suggested implementation:**
```typescript
// src/config.ts or src/index.ts
function validateRequiredEnvVars() {
  const required = [
    'DATABASE_URL',
    'REDIS_URL',
    'VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY',
    // ... other required vars
  ]
  
  const missing = required.filter(name => !process.env[name])
  
  if (missing.length > 0) {
    console.error('Missing required environment variables:', missing.join(', '))
    process.exit(1)
  }
}

validateRequiredEnvVars()
```

## Status

- ⚠️ **Action Required:** Set environment variable in production
- ⚠️ **Impact:** All POST /v1/sign calls fail with 500
- ⚠️ **Workaround:** None - env var must be set
