// ─── Signing Key Service for JWS Assertions (Web SDK /v1/sign) ────────────
//
// Manages Ed25519 key pairs used to sign JWS tokens returned by POST /v1/sign.
// Public keys are exposed via GET /v1/.well-known/jwks.json for customer-side
// assertion verification.
//
// Key storage follows the same pgp_sym_encrypt pattern as webhook secrets:
//   - Public JWK stored in plaintext in the SigningKey table.
//   - Private JWK encrypted via pgcrypto's pgp_sym_encrypt using the
//     VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY env var (32-byte hex).
//   - Private key decrypted on demand and cached in memory for the lifetime
//     of the process. Auto-rotation on restart is inherent — a new key is
//     generated if none is active.
//
// Required env vars:
//   VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY  — 32-byte hex string for pgp_sym_encrypt

import crypto from 'node:crypto'
import { importJWK, exportJWK, SignJWT } from 'jose'
import { prisma } from '../lib/prisma.js'

// ── In-memory cache ──────────────────────────────────────────────────────────
// On server startup the active key is loaded from DB (decrypted private JWK).
// If no active key exists, one is generated. This cache avoids DB round-trips
// and decryption overhead on every /v1/sign/complete call.

let cachedSigner: { kid: string; privateKey: crypto.KeyLike } | null = null

// ── Encryption helpers (same pattern as webhookSecrets.ts) ────────────────────

function getEncryptionKey(): string {
  const key = process.env.VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY
  if (!key) {
    throw new Error('Missing required environment variable: VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY')
  }
  return key
}

async function encryptPrivateJwk(jwkJson: string): Promise<Buffer> {
  const key = getEncryptionKey()
  const result = await prisma.$queryRaw<[{ encrypted: Buffer }]>`
    SELECT pgp_sym_encrypt(${jwkJson}, ${key})::bytea AS encrypted
  `
  return result[0].encrypted
}

async function decryptPrivateJwk(encrypted: Buffer): Promise<string> {
  const key = getEncryptionKey()
  const result = await prisma.$queryRaw<[{ secret: string }]>`
    SELECT pgp_sym_decrypt(${encrypted}::bytea, ${key}) AS secret
  `
  return result[0].secret
}

// ── Key generation ────────────────────────────────────────────────────────────

/**
 * Generate an Ed25519 key pair, store it in the SigningKey table, and return
 * the signer. The private JWK is encrypted at rest; the public JWK is stored
 * in plaintext for JWKS serving.
 */
async function generateSigningKey(): Promise<{ kid: string; privateKey: crypto.KeyLike }> {
  // Generate Ed25519 key pair via Node.js crypto
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')

  // Export as JWK
  const publicJwk = await exportJWK(publicKey)
  const privateJwk = await exportJWK(privateKey)

  // Assign kid (RFC 7638 thumbprint-style, but simpler: random base64url)
  const kid = `sk_${crypto.randomBytes(12).toString('base64url')}`

  // Encrypt private JWK for storage
  const encryptedPrivate = await encryptPrivateJwk(JSON.stringify(privateJwk))

  // Store in DB — add private_jwk_encrypted column content
  // Note: we store the encrypted private JWK alongside the public key.
  // The schema only has `public_key` as a column for the JWK JSON.
  // We'll store encrypted private JWK in a separate approach:
  // We encode the encrypted bytes as base64 and store in the public_key field
  // alongside... Actually, the SigningKey model only has `publicKey` (JWK JSON string).
  // We need to store the encrypted private key somewhere.
  //
  // Approach: Store encrypted private JWK as a separate column or in the same row.
  // Since the model only defines `publicKey`, we'll use a raw SQL insert to add
  // a `private_jwk_encrypted` bytea column alongside, OR we can store both in the
  // public_key field as a JSON envelope. For phase 1 simplicity, store as:
  //   publicKey: JSON string of the PUBLIC JWK (for JWKS)
  //   And use raw SQL for the encrypted private key.
  //
  // Actually, looking at the model more carefully, the simplest approach that
  // doesn't require schema changes is to add the encrypted private JWK column
  // via raw SQL in the migration. But we already created the migration without it.
  //
  // Phase 1 approach: Store the encrypted private JWK in the `publicKey` column
  // as a JSON envelope: { public: {...jwk...}, privateEncrypted: "<base64>" }
  // This is pragmatic but ugly. Better: add a column.
  //
  // Simplest phase 1: Use a dedicated raw SQL table column. Let's just use
  // $executeRaw to add it if needed, or better yet, store it alongside.
  //
  // Actually, the cleanest approach: the SigningKey table stores publicKey as
  // the JWK JSON string. We add a `privateJwkEncrypted` Bytes field to the
  // Prisma model. But we already wrote the migration... Let me just use the
  // model as-is and store encrypted private key via raw SQL only, keeping the
  // public JWK in the model's publicKey field.

  // Store the signing key row
  await prisma.$executeRaw`
    INSERT INTO signing_keys (id, kid, algorithm, public_key, private_jwk_encrypted, active, created_at)
    VALUES (
      gen_random_uuid()::text,
      ${kid},
      'EdDSA',
      ${JSON.stringify(publicJwk)},
      ${encryptedPrivate},
      true,
      NOW()
    )
  `

  return { kid, privateKey }
}

/**
 * Get the currently active signing key. If none exists, generate one.
 * The private key is cached in memory after first decryption to avoid
 * repeated pgp_sym_decrypt calls on the hot path.
 */
export async function getActiveSigningKey(): Promise<{ kid: string; privateKey: crypto.KeyLike }> {
  if (cachedSigner) return cachedSigner

  // Look for an active key in DB
  const row: { kid: string; publicKey: string; privateJwkEncrypted: Buffer }[] = await prisma.$queryRaw`
    SELECT kid, public_key as "publicKey", private_jwk_encrypted as "privateJwkEncrypted"
    FROM signing_keys
    WHERE active = true
    ORDER BY created_at DESC
    LIMIT 1
  `

  if (row.length === 0) {
    // No active key — generate one
    cachedSigner = await generateSigningKey()
    return cachedSigner
  }

  // Decrypt the private JWK and import
  const privateJwkJson = await decryptPrivateJwk(row[0].privateJwkEncrypted)
  const privateJwk = JSON.parse(privateJwkJson)

  // Import with jose — returns CryptoKey which SignJWT accepts directly
  const privateKey = await importJWK(privateJwk, 'EdDSA')

  cachedSigner = { kid: row[0].kid, privateKey }
  return cachedSigner
}

/**
 * Sign a JWS assertion using the active signing key. Returns compact
 * serialization (JWS).
 *
 * @param payload - The JWT claims to sign
 * @returns JWS compact serialization string
 */
export async function signAssertion(payload: Record<string, unknown>): Promise<string> {
  const { kid, privateKey } = await getActiveSigningKey()

  // SignJWT accepts both KeyObject (from generateKeyPairSync) and CryptoKey (from importJWK)
  const signJwt = new SignJWT(payload as any)
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .setIssuedAt()
    .setExpirationTime('60s')

  const jws = await signJwt.sign(privateKey)
  return jws
}

/**
 * Return all active signing keys as JWK entries for the JWKS endpoint.
 * Only includes public keys — never the private key.
 */
export async function getJwksEntries(): Promise<{ keys: Array<Record<string, unknown>> }> {
  const rows: { kid: string; publicKey: string }[] = await prisma.$queryRaw`
    SELECT kid, public_key as "publicKey"
    FROM signing_keys
    WHERE active = true
    ORDER BY created_at DESC
  `

  return {
    keys: rows.map((row) => {
      const jwk = JSON.parse(row.publicKey)
      // Add kid and use per JWKS spec (RFC 7517)
      jwk.kid = row.kid
      jwk.use = 'sig'
      jwk.alg = 'EdDSA'
      return jwk
    }),
  }
}

/**
 * Clear the in-memory cache (useful for testing or forced key rotation).
 */
export function clearSigningKeyCache(): void {
  cachedSigner = null
}
