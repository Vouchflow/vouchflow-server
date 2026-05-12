// /v1/customers/:id/apps/* — App management surface called by the web layer
// using $ADMIN_KEY. SDKs never hit these endpoints; they resolve their App
// from the API key via apiKeyAuth. See spec chunk 2.

import type { FastifyInstance } from 'fastify'
import crypto from 'node:crypto'
import { prisma } from '../lib/prisma.js'
import { verifyAdminKey } from '../lib/adminAuth.js'
import { encryptWebhookSecret } from '../services/webhookSecrets.js'

// Per-app webhook constants
const MAX_ENDPOINTS_PER_APP = 20
const ALLOWED_WEBHOOK_EVENTS = new Set([
  'verification.complete',
  'verification.fallback_complete',
  'sign.complete',
])

// Reserved slugs collide with dashboard URL routes (e.g. /apps/new). `default`
// is intentionally NOT reserved — the migration creates one with that slug.
const RESERVED_SLUGS = new Set(['new', 'archived'])

// Hard cap on simultaneously-active live keys per app. Bumped from 10 to
// 20 in the at-most-one-canonical-key refactor: with rotation each scope
// can have its prior key in the 14-day grace window, so transient counts
// can exceed 2. 20 leaves slack for unusual rotation patterns.
const MAX_ACTIVE_KEYS_PER_APP = 20

// ── live-key helpers (shared between create-app, generate, rotate) ──────

const hashKey = (k: string) => crypto.createHash('sha256').update(k).digest('hex')

function generateLiveKey(scope: 'write' | 'read'): { rawKey: string; hash: string } {
  const raw = scope === 'write'
    ? `vsk_live_${crypto.randomBytes(20).toString('hex')}`
    : `vsk_live_read_${crypto.randomBytes(20).toString('hex')}`
  return { rawKey: raw, hash: hashKey(raw) }
}

const CONFIDENCE_RANK: Record<string, number> = { low: 0, medium: 1, high: 2 }
const CONFIDENCE_VALUES = new Set(['low', 'medium', 'high'])

// ── slug helpers ────────────────────────────────────────────────────────────

const SLUG_RE = /^[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?$/

function isValidSlug(slug: string): boolean {
  if (slug.length < 1 || slug.length > 50) return false
  if (RESERVED_SLUGS.has(slug)) return false
  return SLUG_RE.test(slug)
}

function generateSlug(name: string, existingSlugs: Set<string>): string {
  let base = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 50)
  if (!base) base = 'app'
  if (RESERVED_SLUGS.has(base)) base = `${base}-app`
  let slug = base
  let n = 2
  while (existingSlugs.has(slug)) {
    const suffix = `-${n}`
    slug = `${base.slice(0, 50 - suffix.length)}${suffix}`
    n++
  }
  return slug
}

// ── attestation field validation (moved from customers.ts) ──────────────────

function validateAndroidPackageName(v: string): string | null {
  if (!/^[a-zA-Z][\w]*(\.[a-zA-Z][\w]*)+$/.test(v)) {
    return 'androidPackageName must be a reverse-DNS Java package name.'
  }
  return null
}
function normalizeAndroidSha256(v: string): { ok: true; value: string } | { ok: false; msg: string } {
  const normalized = v.replace(/[:\s]/g, '').toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    return { ok: false, msg: 'androidSigningKeySha256 must be 64 hex characters (colons and whitespace are stripped).' }
  }
  return { ok: true, value: normalized }
}
function validateIosTeamId(v: string): string | null {
  if (!/^[A-Z0-9]{10}$/.test(v)) return 'iosTeamId must be 10 uppercase alphanumeric characters.'
  return null
}
function validateIosBundleId(v: string): string | null {
  if (!/^[a-zA-Z][\w-]*(\.[a-zA-Z][\w-]*)+$/.test(v)) {
    return 'iosBundleId must be a reverse-DNS bundle identifier.'
  }
  return null
}
function validateWebRpId(v: string): string | null {
  // RP ID is a domain (no scheme, no path, no port). `localhost` allowed.
  if (v === 'localhost') return null
  if (!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(v)) {
    return 'webRpId must be a valid domain (e.g. "app.example.com").'
  }
  return null
}
function validateWebOrigin(v: string): string | null {
  // Must be an https:// origin (or http://localhost during development —
  // matches the WebAuthn verifier rule).
  if (/^http:\/\/localhost(:\d+)?$/.test(v)) return null
  if (!/^https:\/\/[^\s\/]+(:\d+)?$/.test(v)) {
    return `webAllowedOrigins entry "${v}" must be an https:// origin (e.g. "https://app.example.com").`
  }
  return null
}

interface ConfidencePolicyInput {
  signPayloadMinConfidence?: string | null
  verifyMinConfidence?: string | null
  contextConfidenceOverrides?: Record<string, unknown>
}

function validateConfidencePolicy(
  input: ConfidencePolicyInput,
  existing: { signPayloadMinConfidence: string | null; verifyMinConfidence: string | null },
): string | null {
  const sp = input.signPayloadMinConfidence === undefined
    ? existing.signPayloadMinConfidence ?? 'high'
    : input.signPayloadMinConfidence ?? 'high'
  if (!CONFIDENCE_VALUES.has(sp)) {
    return 'signPayloadMinConfidence must be "low", "medium", or "high".'
  }
  const vp = input.verifyMinConfidence === undefined
    ? existing.verifyMinConfidence
    : input.verifyMinConfidence
  if (vp !== null && vp !== undefined && !CONFIDENCE_VALUES.has(vp)) {
    return 'verifyMinConfidence must be "low", "medium", or "high".'
  }
  if (input.contextConfidenceOverrides !== undefined) {
    const overrides = input.contextConfidenceOverrides
    if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
      return 'contextConfidenceOverrides must be an object mapping context names to confidence levels.'
    }
    for (const [ctx, level] of Object.entries(overrides)) {
      if (typeof level !== 'string' || !CONFIDENCE_VALUES.has(level)) {
        return `contextConfidenceOverrides.${ctx} must be "low", "medium", or "high".`
      }
      // Per the signPayload RFC: a per-context override cannot weaken below
      // the default minimum. We compare against signPayloadMinConfidence as
      // the binding floor since signPayload is the higher-stakes operation.
      if (CONFIDENCE_RANK[level] < CONFIDENCE_RANK[sp]) {
        return `contextConfidenceOverrides.${ctx}: cannot weaken below signPayloadMinConfidence (${sp}).`
      }
    }
  }
  return null
}

// ── response shaping ────────────────────────────────────────────────────────

function appSummary(app: {
  id: string
  name: string
  slug: string
  description: string | null
  webSdkEnabled: boolean
  archivedAt: Date | null
  createdAt: Date
  iosTeamId?: string | null
  iosBundleId?: string | null
  androidPackageName?: string | null
  androidSigningKeySha256?: string | null
}) {
  // The list view ("/settings" Apps tab) needs enough metadata to show
  // platform-configured badges per app without a per-row API call. We
  // expose booleans only — never the raw IDs from the summary path —
  // so the list is cheap and doesn't double as a config exfiltration
  // vector for an Admin-key-leaked scenario.
  return {
    id: app.id,
    name: app.name,
    slug: app.slug,
    description: app.description,
    webSdkEnabled: app.webSdkEnabled,
    iosConfigured:     !!(app.iosTeamId && app.iosBundleId),
    androidConfigured: !!(app.androidPackageName && app.androidSigningKeySha256),
    archivedAt: app.archivedAt,
    createdAt: app.createdAt,
  }
}

function appDetail(app: any, includeRawSandbox = false) {
  const base = {
    id: app.id,
    customerId: app.customerId,
    name: app.name,
    slug: app.slug,
    description: app.description,
    iosTeamId: app.iosTeamId,
    iosBundleId: app.iosBundleId,
    androidPackageName: app.androidPackageName,
    androidSigningKeySha256: app.androidSigningKeySha256,
    webSdkEnabled: app.webSdkEnabled,
    webRpId: app.webRpId,
    webAllowedOrigins: app.webAllowedOrigins,
    verifyMinConfidence: app.verifyMinConfidence,
    signPayloadMinConfidence: app.signPayloadMinConfidence,
    contextConfidenceOverrides: app.contextConfidenceOverrides ?? {},
    sandboxWriteKeyPrefix: app.sandboxWriteKey ? app.sandboxWriteKey.slice(0, 16) + '…' : null,
    sandboxReadKeyPrefix:  app.sandboxReadKey  ? app.sandboxReadKey.slice(0, 21)  + '…' : null,
    archivedAt: app.archivedAt,
    createdAt: app.createdAt,
    updatedAt: app.updatedAt,
  }
  if (includeRawSandbox) {
    return { ...base, sandboxWriteKey: app.sandboxWriteKey, sandboxReadKey: app.sandboxReadKey }
  }
  return base
}

// ────────────────────────────────────────────────────────────────────────────

export default async function appsRoute(fastify: FastifyInstance) {

  // POST /v1/customers/:id/apps — create app (sandbox keys returned raw, ONCE)
  fastify.post<{
    Params: { id: string }
    Body: { name?: string; slug?: string; description?: string }
  }>(
    '/customers/:id/apps',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const customerId = request.params.id
      const { name, slug: rawSlug, description } = request.body ?? {}

      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return reply.code(400).send({ error: { code: 'invalid_field', message: 'name is required.' } })
      }
      if (name.length > 100) {
        return reply.code(400).send({ error: { code: 'invalid_field', message: 'name must be 100 characters or fewer.' } })
      }

      const customer = await prisma.customer.findUnique({ where: { id: customerId } })
      if (!customer) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Customer not found.' } })
      }

      const existing = await prisma.app.findMany({
        where: { customerId },
        select: { slug: true },
      })
      const existingSlugs = new Set(existing.map(a => a.slug))

      let slug: string
      if (rawSlug !== undefined) {
        if (!isValidSlug(rawSlug)) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'slug must be 1-50 chars, lowercase a-z, 0-9, hyphens, not start/end with hyphen, and not a reserved word.' } })
        }
        if (existingSlugs.has(rawSlug)) {
          return reply.code(409).send({ error: { code: 'slug_conflict', message: 'An app with this slug already exists.' } })
        }
        slug = rawSlug
      } else {
        slug = generateSlug(name.trim(), existingSlugs)
      }

      const sandboxWriteKey = `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`
      const sandboxReadKey  = `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`

      // Auto-generate the canonical live write + read keys at app creation.
      // Each app has at-most-one active live key per scope; rotation creates
      // a new one and demotes the old to the 14-day grace window.
      // Nested writes are atomic and sidestep the FK-visibility quirk that
      // bit us with sequential prisma.$transaction(tx => ...) statements.
      const liveWrite = generateLiveKey('write')
      const liveRead  = generateLiveKey('read')

      const app = await prisma.app.create({
        data: {
          customerId,
          name: name.trim(),
          slug,
          description: description ?? null,
          sandboxWriteKey,
          sandboxReadKey,
          signPayloadMinConfidence: 'high',
          apiKeys: {
            create: [
              { customerId, keyHash: liveWrite.hash, scope: 'write' },
              { customerId, keyHash: liveRead.hash,  scope: 'read'  },
            ],
          },
        },
      })

      return reply.code(201).send({
        app: appDetail(app, true),
        sandboxWriteKey,
        sandboxReadKey,
        liveWriteKey: liveWrite.rawKey,
        liveReadKey:  liveRead.rawKey,
      })
    }
  )

  // GET /v1/customers/:id/apps — list (?includeArchived=true to include)
  fastify.get<{
    Params: { id: string }
    Querystring: { includeArchived?: string }
  }>(
    '/customers/:id/apps',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const includeArchived = request.query.includeArchived === 'true'
      const apps = await prisma.app.findMany({
        where: {
          customerId: request.params.id,
          ...(includeArchived ? {} : { archivedAt: null }),
        },
        orderBy: { createdAt: 'asc' },
      })
      return reply.send({ apps: apps.map(appSummary) })
    }
  )

  // GET /v1/customers/:id/apps/:appId — full detail
  fastify.get<{ Params: { id: string; appId: string } }>(
    '/customers/:id/apps/:appId',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const app = await prisma.app.findFirst({
        where: { id: request.params.appId, customerId: request.params.id },
      })
      if (!app) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      }
      return reply.send(appDetail(app))
    }
  )

  // PATCH /v1/customers/:id/apps/:appId — update
  fastify.patch<{
    Params: { id: string; appId: string }
    Body: {
      name?: string
      slug?: string
      description?: string | null
      iosTeamId?: string | null
      iosBundleId?: string | null
      androidPackageName?: string | null
      androidSigningKeySha256?: string | null
      webSdkEnabled?: boolean
      webRpId?: string | null
      webAllowedOrigins?: string[]
      verifyMinConfidence?: string | null
      signPayloadMinConfidence?: string | null
      contextConfidenceOverrides?: Record<string, string>
    }
  }>(
    '/customers/:id/apps/:appId',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params
      const body = request.body ?? {}

      const existing = await prisma.app.findFirst({
        where: { id: appId, customerId },
      })
      if (!existing) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      }

      const data: Record<string, unknown> = {}

      if (body.name !== undefined) {
        if (typeof body.name !== 'string' || body.name.trim().length === 0 || body.name.length > 100) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'name must be 1-100 characters.' } })
        }
        data.name = body.name.trim()
      }

      if (body.slug !== undefined) {
        if (!isValidSlug(body.slug)) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'slug must be 1-50 chars, lowercase a-z, 0-9, hyphens, not start/end with hyphen, and not a reserved word.' } })
        }
        if (body.slug !== existing.slug) {
          const collision = await prisma.app.findFirst({
            where: { customerId, slug: body.slug },
          })
          if (collision) {
            return reply.code(409).send({ error: { code: 'slug_conflict', message: 'An app with this slug already exists.' } })
          }
          data.slug = body.slug
        }
      }

      if (body.description !== undefined) {
        if (body.description !== null && (typeof body.description !== 'string' || body.description.length > 500)) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'description must be 500 characters or fewer.' } })
        }
        data.description = body.description
      }

      // Attestation
      if (body.iosTeamId !== undefined) {
        if (body.iosTeamId !== null) {
          const err = validateIosTeamId(body.iosTeamId)
          if (err) return reply.code(400).send({ error: { code: 'invalid_field', message: err } })
        }
        data.iosTeamId = body.iosTeamId
      }
      if (body.iosBundleId !== undefined) {
        if (body.iosBundleId !== null) {
          const err = validateIosBundleId(body.iosBundleId)
          if (err) return reply.code(400).send({ error: { code: 'invalid_field', message: err } })
        }
        data.iosBundleId = body.iosBundleId
      }
      if (body.androidPackageName !== undefined) {
        if (body.androidPackageName !== null) {
          const err = validateAndroidPackageName(body.androidPackageName)
          if (err) return reply.code(400).send({ error: { code: 'invalid_field', message: err } })
        }
        data.androidPackageName = body.androidPackageName
      }
      if (body.androidSigningKeySha256 !== undefined) {
        if (body.androidSigningKeySha256 === null) {
          data.androidSigningKeySha256 = null
        } else {
          const r = normalizeAndroidSha256(body.androidSigningKeySha256)
          if (!r.ok) return reply.code(400).send({ error: { code: 'invalid_field', message: r.msg } })
          data.androidSigningKeySha256 = r.value
        }
      }

      // Web SDK
      let nextWebSdkEnabled = existing.webSdkEnabled
      let nextWebRpId       = existing.webRpId
      if (body.webRpId !== undefined) {
        if (body.webRpId !== null) {
          const err = validateWebRpId(body.webRpId)
          if (err) return reply.code(400).send({ error: { code: 'invalid_field', message: err } })
        }
        data.webRpId = body.webRpId
        nextWebRpId  = body.webRpId
      }
      if (body.webAllowedOrigins !== undefined) {
        if (!Array.isArray(body.webAllowedOrigins)) {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'webAllowedOrigins must be an array of origin strings.' } })
        }
        for (const origin of body.webAllowedOrigins) {
          if (typeof origin !== 'string') {
            return reply.code(400).send({ error: { code: 'invalid_field', message: 'webAllowedOrigins must be an array of origin strings.' } })
          }
          const err = validateWebOrigin(origin)
          if (err) return reply.code(400).send({ error: { code: 'invalid_field', message: err } })
        }
        data.webAllowedOrigins = body.webAllowedOrigins
      }
      if (body.webSdkEnabled !== undefined) {
        if (typeof body.webSdkEnabled !== 'boolean') {
          return reply.code(400).send({ error: { code: 'invalid_field', message: 'webSdkEnabled must be a boolean.' } })
        }
        data.webSdkEnabled = body.webSdkEnabled
        nextWebSdkEnabled  = body.webSdkEnabled
      }
      if (nextWebSdkEnabled && !nextWebRpId) {
        return reply.code(400).send({ error: { code: 'invalid_field', message: 'webRpId must be set when webSdkEnabled is true.' } })
      }

      // Confidence policy
      if (
        body.signPayloadMinConfidence !== undefined ||
        body.verifyMinConfidence !== undefined ||
        body.contextConfidenceOverrides !== undefined
      ) {
        const err = validateConfidencePolicy(body, {
          signPayloadMinConfidence: existing.signPayloadMinConfidence,
          verifyMinConfidence:      existing.verifyMinConfidence,
        })
        if (err) return reply.code(400).send({ error: { code: 'invalid_field', message: err } })
        if (body.signPayloadMinConfidence !== undefined) data.signPayloadMinConfidence = body.signPayloadMinConfidence
        if (body.verifyMinConfidence      !== undefined) data.verifyMinConfidence      = body.verifyMinConfidence
        if (body.contextConfidenceOverrides !== undefined) data.contextConfidenceOverrides = body.contextConfidenceOverrides
      }

      if (Object.keys(data).length === 0) {
        return reply.code(400).send({ error: { code: 'no_fields', message: 'No fields to update.' } })
      }

      const updated = await prisma.app.update({ where: { id: appId }, data })
      return reply.send(appDetail(updated))
    }
  )

  // POST /v1/customers/:id/apps/:appId/archive
  fastify.post<{ Params: { id: string; appId: string } }>(
    '/customers/:id/apps/:appId/archive',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params

      const app = await prisma.app.findFirst({ where: { id: appId, customerId } })
      if (!app) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      }
      if (app.archivedAt) {
        return reply.send({ ok: true, archivedAt: app.archivedAt })
      }
      const activeCount = await prisma.app.count({
        where: { customerId, archivedAt: null },
      })
      if (activeCount <= 1) {
        return reply.code(409).send({ error: { code: 'last_app', message: 'Cannot archive the customer\'s only active app. Create another app first.' } })
      }
      const archivedAt = new Date()
      await prisma.app.update({ where: { id: appId }, data: { archivedAt } })
      return reply.send({ ok: true, archivedAt })
    }
  )

  // POST /v1/customers/:id/apps/:appId/unarchive
  fastify.post<{ Params: { id: string; appId: string } }>(
    '/customers/:id/apps/:appId/unarchive',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params
      const app = await prisma.app.findFirst({ where: { id: appId, customerId } })
      if (!app) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      }
      await prisma.app.update({ where: { id: appId }, data: { archivedAt: null } })
      return reply.send({ ok: true })
    }
  )

  // GET /v1/customers/:id/apps/:appId/live-keys
  fastify.get<{ Params: { id: string; appId: string } }>(
    '/customers/:id/apps/:appId/live-keys',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params
      const app = await prisma.app.findFirst({ where: { id: appId, customerId } })
      if (!app) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      }
      // Returns ALL keys (active + deprecated-in-grace + expired). The
      // dashboard renders active prominently and groups deprecated keys
      // under a "Recently rotated" section showing their grace expiry.
      // Auth-time validation in apiKeyAuth.ts decides whether deprecated
      // keys are still accepted (14-day grace from deprecatedAt).
      const keys = await prisma.apiKey.findMany({
        where: { appId },
        select: { id: true, scope: true, createdAt: true, lastUsedAt: true, deprecated: true, deprecatedAt: true },
        orderBy: [{ deprecated: 'asc' }, { createdAt: 'desc' }],
      })
      return reply.send({ keys })
    }
  )

  // POST /v1/customers/:id/apps/:appId/live-keys — create live key(s)
  fastify.post<{
    Params: { id: string; appId: string }
    Body: { scope?: 'pair' | 'write' | 'read' }
  }>(
    '/customers/:id/apps/:appId/live-keys',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params
      const scope = request.body?.scope ?? 'pair'
      if (scope !== 'pair' && scope !== 'write' && scope !== 'read') {
        return reply.code(400).send({ error: { code: 'invalid_request', message: 'scope must be "pair", "write", or "read".' } })
      }
      const app = await prisma.app.findFirst({ where: { id: appId, customerId } })
      if (!app) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      }
      if (app.archivedAt) {
        return reply.code(409).send({ error: { code: 'app_archived', message: 'Cannot create keys for an archived app.' } })
      }

      const keysToCreate = scope === 'pair' ? 2 : 1
      const activeCount = await prisma.apiKey.count({
        where: { appId, deprecated: false },
      })
      if (activeCount + keysToCreate > MAX_ACTIVE_KEYS_PER_APP) {
        return reply.code(409).send({
          error: { code: 'key_limit_reached', message: `Maximum ${MAX_ACTIVE_KEYS_PER_APP} active live keys per app. Revoke an existing key first.` },
        })
      }

      const hashKey = (k: string) => crypto.createHash('sha256').update(k).digest('hex')
      const generate = (s: 'write' | 'read'): { rawKey: string; hash: string } => {
        const raw = s === 'write'
          ? `vsk_live_${crypto.randomBytes(20).toString('hex')}`
          : `vsk_live_read_${crypto.randomBytes(20).toString('hex')}`
        return { rawKey: raw, hash: hashKey(raw) }
      }

      if (scope === 'pair') {
        const w = generate('write')
        const r = generate('read')
        const [writeKey, readKey] = await Promise.all([
          prisma.apiKey.create({ data: { customerId, appId, keyHash: w.hash, scope: 'write' } }),
          prisma.apiKey.create({ data: { customerId, appId, keyHash: r.hash, scope: 'read'  } }),
        ])
        return reply.send({
          writeKey: { id: writeKey.id, rawKey: w.rawKey, scope: 'write', createdAt: writeKey.createdAt },
          readKey:  { id: readKey.id,  rawKey: r.rawKey, scope: 'read',  createdAt: readKey.createdAt  },
        })
      }
      const g = generate(scope)
      const created = await prisma.apiKey.create({
        data: { customerId, appId, keyHash: g.hash, scope },
      })
      return reply.send({
        key: { id: created.id, rawKey: g.rawKey, scope, createdAt: created.createdAt },
      })
    }
  )

  // DELETE /v1/customers/:id/apps/:appId/live-keys/:keyId
  fastify.delete<{ Params: { id: string; appId: string; keyId: string } }>(
    '/customers/:id/apps/:appId/live-keys/:keyId',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId, keyId } = request.params
      const key = await prisma.apiKey.findFirst({
        where: { id: keyId, appId, customerId },
      })
      if (!key) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Key not found.' } })
      }
      if (key.deprecated) {
        return reply.code(409).send({ error: { code: 'already_revoked', message: 'Key is already deprecated.' } })
      }
      const updated = await prisma.apiKey.update({
        where: { id: keyId },
        data:  { deprecated: true, deprecatedAt: new Date() },
        select: { id: true, scope: true, deprecatedAt: true },
      })
      return reply.send({ key: updated })
    }
  )

  // POST /v1/customers/:id/apps/:appId/live-keys/rotate — rotate a live key
  // Creates a new key with the given scope and marks the previous active key
  // as deprecated (still valid for 14 days). If rotating a 'pair' key, it
  // auto-splits into separate write+read keys.
  fastify.post<{
    Params: { id: string; appId: string }
    Body: { scope: 'write' | 'read' }
  }>(
    '/customers/:id/apps/:appId/live-keys/rotate',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params
      const { scope } = request.body
      if (!scope || (scope !== 'write' && scope !== 'read')) {
        return reply.code(400).send({ error: { code: 'invalid_scope', message: 'scope must be "write" or "read".' } })
      }
      const app = await prisma.app.findFirst({ where: { id: appId, customerId } })
      if (!app) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      }

      // Find the current active key for this scope (or 'pair' if it exists)
      const existing = await prisma.apiKey.findFirst({
        where: {
          appId,
          deprecated: false,
          OR: [{ scope }, { scope: 'pair' }],
        },
        orderBy: { createdAt: 'desc' },
      })

      // Generate new key
      const newKey = generateLiveKey(scope)
      const created = await prisma.apiKey.create({
        data: {
          appId,
          customerId,
          scope,
          keyHash: newKey.hash,
          environment: 'production',
        },
        select: { id: true, scope: true, createdAt: true },
      })

      // Deprecate the old key if it exists
      let deprecated = null
      if (existing) {
        deprecated = await prisma.apiKey.update({
          where: { id: existing.id },
          data: { deprecated: true, deprecatedAt: new Date() },
          select: { id: true, scope: true, deprecatedAt: true },
        })
      }

      // If the old key was a 'pair' and we're rotating to split it, also
      // generate the companion key (e.g., rotating write from pair creates read too)
      let companion = null
      if (existing?.scope === 'pair') {
        const companionScope: 'write' | 'read' = scope === 'write' ? 'read' : 'write'
        const companionKey = generateLiveKey(companionScope)
        const companionCreated = await prisma.apiKey.create({
          data: {
            appId,
            customerId,
            scope: companionScope,
            keyHash: companionKey.hash,
            environment: 'production',
          },
          select: { id: true, scope: true, createdAt: true },
        })
        companion = {
          id: companionCreated.id,
          rawKey: companionKey.rawKey,
          scope: companionScope,
          createdAt: companionCreated.createdAt,
        }
      }

      return reply.send({
        key: { id: created.id, rawKey: newKey.rawKey, scope: created.scope, createdAt: created.createdAt },
        deprecated: deprecated || undefined,
        companion: companion || undefined,
      })
    }
  )

  // POST /v1/customers/:id/apps/:appId/live-keys/generate — generate initial live keys
  // Creates the canonical write+read pair for apps that don't have them yet.
  fastify.post<{ Params: { id: string; appId: string } }>(
    '/customers/:id/apps/:appId/live-keys/generate',
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params
      const app = await prisma.app.findFirst({ where: { id: appId, customerId } })
      if (!app) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      }

      // Check if live keys already exist
      const existing = await prisma.apiKey.findFirst({
        where: { appId, environment: 'production', deprecated: false },
      })
      if (existing) {
        return reply.code(409).send({
          error: { code: 'keys_exist', message: 'Active live keys already exist. Use rotate to refresh.' },
        })
      }

      // Generate write + read pair
      const writeKey = generateLiveKey('write')
      const readKey = generateLiveKey('read')

      await prisma.apiKey.createMany({
        data: [
          { appId, customerId, scope: 'write', keyHash: writeKey.hash, environment: 'production' },
          { appId, customerId, scope: 'read', keyHash: readKey.hash, environment: 'production' },
        ],
      })

      return reply.code(201).send({
        liveWriteKey: writeKey.rawKey,
        liveReadKey: readKey.rawKey,
      })
    }
  )

  // ── Per-app webhooks (admin-keyed) ────────────────────────────────────
  // The dashboard manages webhooks per-app from the apps-detail page.
  // The /v1/webhooks family in webhooks.ts is API-key-auth scoped to the
  // *current request's* app, which doesn't fit the admin/dashboard flow
  // — so these admin-keyed mirror endpoints exist alongside.
  fastify.get<{ Params: { id: string; appId: string } }>(
    '/customers/:id/apps/:appId/webhooks',
    { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } },
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params
      const app = await prisma.app.findFirst({ where: { id: appId, customerId } })
      if (!app) return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })
      const endpoints = await prisma.webhookEndpoint.findMany({
        where: { appId }, orderBy: { createdAt: 'asc' },
      })
      return {
        webhooks: endpoints.map(e => ({
          id:        e.id,
          url:       e.url,
          events:    e.events,
          createdAt: e.createdAt.toISOString(),
        })),
      }
    },
  )

  fastify.post<{
    Params: { id: string; appId: string }
    Body:   { url?: string; events?: string[] }
  }>(
    '/customers/:id/apps/:appId/webhooks',
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId } = request.params
      const url = (request.body?.url ?? '').trim()
      const events = request.body?.events ?? []
      if (!url || !/^https?:\/\//.test(url)) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: 'url must be a valid http(s) URL.' } })
      }
      if (!Array.isArray(events) || events.length === 0) {
        return reply.code(400).send({ error: { code: 'invalid_request', message: 'events must be a non-empty array.' } })
      }
      for (const ev of events) {
        if (!ALLOWED_WEBHOOK_EVENTS.has(ev)) {
          return reply.code(400).send({ error: { code: 'invalid_request', message: `Unknown event: ${ev}` } })
        }
      }
      const app = await prisma.app.findFirst({ where: { id: appId, customerId } })
      if (!app) return reply.code(404).send({ error: { code: 'not_found', message: 'App not found.' } })

      const existing = await prisma.webhookEndpoint.count({ where: { appId } })
      if (existing >= MAX_ENDPOINTS_PER_APP) {
        return reply.code(409).send({
          error: { code: 'endpoint_limit_reached', message: `Maximum ${MAX_ENDPOINTS_PER_APP} webhook endpoints per app.` },
        })
      }
      const rawSecret = `whsec_${crypto.randomBytes(24).toString('hex')}`
      const secretEncrypted = await encryptWebhookSecret(rawSecret)
      const endpoint = await prisma.webhookEndpoint.create({
        data: { customerId, appId, url, events, secretEncrypted },
      })
      return reply.code(201).send({
        id:        endpoint.id,
        url:       endpoint.url,
        events:    endpoint.events,
        secret:    rawSecret,
        createdAt: endpoint.createdAt.toISOString(),
      })
    },
  )

  fastify.delete<{ Params: { id: string; appId: string; webhookId: string } }>(
    '/customers/:id/apps/:appId/webhooks/:webhookId',
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (request, reply) => {
      if (!verifyAdminKey(request.headers.authorization)) {
        return reply.code(401).send({ error: { code: 'unauthorized', message: 'Invalid admin key.' } })
      }
      const { id: customerId, appId, webhookId } = request.params
      const found = await prisma.webhookEndpoint.findFirst({
        where: { id: webhookId, appId, customerId },
      })
      if (!found) {
        return reply.code(404).send({ error: { code: 'not_found', message: 'Webhook endpoint not found.' } })
      }
      await prisma.$transaction([
        prisma.webhookDelivery.deleteMany({ where: { endpointId: found.id } }),
        prisma.webhookEndpoint.delete({ where: { id: found.id } }),
      ])
      return reply.code(204).send()
    },
  )
}
