import { prisma } from '../lib/prisma.js'

// Webhook secrets are encrypted at rest using pgcrypto's pgp_sym_encrypt.
// The encryption key is WEBHOOK_SECRET_ENCRYPTION_KEY (32-byte hex, stored in env).
// The raw secret is never stored in plaintext and never returned via API after creation.
//
// pgcrypto is used via raw SQL because Prisma does not support function-level
// column encryption natively. All encrypt/decrypt goes through $queryRaw.

function getEncryptionKey(): string {
  const key = process.env.WEBHOOK_SECRET_ENCRYPTION_KEY
  if (!key) throw new Error('Missing required environment variable: WEBHOOK_SECRET_ENCRYPTION_KEY')
  return key
}

export async function encryptWebhookSecret(rawSecret: string): Promise<Buffer> {
  const key = getEncryptionKey()
  const result = await prisma.$queryRaw<[{ encrypted: Buffer }]>`
    SELECT pgp_sym_encrypt(${rawSecret}, ${key})::bytea AS encrypted
  `
  return result[0].encrypted
}

export async function decryptWebhookSecret(encrypted: Buffer): Promise<string> {
  const key = getEncryptionKey()
  const result = await prisma.$queryRaw<[{ secret: string }]>`
    SELECT pgp_sym_decrypt(${encrypted}::bytea, ${key}) AS secret
  `
  return result[0].secret
}

export async function createWebhookEndpoint(customerId: string, url: string, rawSecret: string) {
  const secretEncrypted = await encryptWebhookSecret(rawSecret)
  return prisma.webhookEndpoint.create({
    data: { customerId, url, secretEncrypted },
  })
}
