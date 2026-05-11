// PATCH /v1/customers/:id/apps/:appId — attestation, Web SDK, and confidence
// policy validation. Most validators were moved here from customers.patch.ts
// when the attestation fields migrated to App.

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import customerRoute from '../customers.js'
import appsRoute from '../apps.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip
const ADMIN_KEY = 'a'.repeat(64)

d('PATCH /v1/customers/:id/apps/:appId — validation', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    process.env.ADMIN_KEY = ADMIN_KEY
    app = await buildTestApp(async (fastify) => {
      await fastify.register(customerRoute, { prefix: '/v1' })
      await fastify.register(appsRoute,     { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  async function patchApp(payload: Record<string, unknown>) {
    const { customer, app: a } = await createSandboxCustomer()
    return app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}/apps/${a.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload,
    })
  }

  // ── iOS Team ID ────────────────────────────────────────────────────────

  it('accepts a valid 10-char uppercase iosTeamId', async () => {
    const r = await patchApp({ iosTeamId: 'ABCDE12345' })
    expect(r.statusCode).toBe(200)
    expect((r.json() as any).iosTeamId).toBe('ABCDE12345')
  })
  it('rejects iosTeamId of wrong length', async () => {
    expect((await patchApp({ iosTeamId: 'ABCDE1234' })).statusCode).toBe(400)
  })
  it('rejects lowercase iosTeamId', async () => {
    expect((await patchApp({ iosTeamId: 'abcde12345' })).statusCode).toBe(400)
  })
  it('rejects iosTeamId with special chars', async () => {
    expect((await patchApp({ iosTeamId: 'ABCDE-2345' })).statusCode).toBe(400)
  })

  // ── iOS Bundle ID ──────────────────────────────────────────────────────

  it('accepts iosBundleId with hyphens', async () => {
    expect((await patchApp({ iosBundleId: 'com.my-app.cool' })).statusCode).toBe(200)
  })
  it('rejects iosBundleId without a dot', async () => {
    expect((await patchApp({ iosBundleId: 'singlesegment' })).statusCode).toBe(400)
  })

  // ── Android package name ───────────────────────────────────────────────

  it('rejects single-segment androidPackageName', async () => {
    expect((await patchApp({ androidPackageName: 'app' })).statusCode).toBe(400)
  })
  it('rejects androidPackageName starting with a digit', async () => {
    expect((await patchApp({ androidPackageName: '4chan.app' })).statusCode).toBe(400)
  })
  it('rejects androidPackageName with hyphens', async () => {
    expect((await patchApp({ androidPackageName: 'com.my-cool.app' })).statusCode).toBe(400)
  })
  it('accepts androidPackageName with underscores', async () => {
    expect((await patchApp({ androidPackageName: 'com.my_cool.app' })).statusCode).toBe(200)
  })

  // ── Android signing-key SHA256 ─────────────────────────────────────────

  it('normalizes signing-key SHA256 (uppercase → lowercase)', async () => {
    const r = await patchApp({ androidSigningKeySha256: 'A'.repeat(64) })
    expect(r.statusCode).toBe(200)
    expect((r.json() as any).androidSigningKeySha256).toBe('a'.repeat(64))
  })
  it('strips colons from signing-key SHA256', async () => {
    const colons = '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF'
    const r = await patchApp({ androidSigningKeySha256: colons })
    expect(r.statusCode).toBe(200)
    expect((r.json() as any).androidSigningKeySha256).toBe('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')
  })
  it('rejects signing-key SHA256 of wrong length', async () => {
    expect((await patchApp({ androidSigningKeySha256: 'a'.repeat(62) })).statusCode).toBe(400)
  })
  it('rejects signing-key SHA256 with non-hex chars', async () => {
    expect((await patchApp({ androidSigningKeySha256: 'g'.repeat(64) })).statusCode).toBe(400)
  })

  // ── Web SDK: webRpId ───────────────────────────────────────────────────

  it('accepts webRpId as a domain', async () => {
    expect((await patchApp({ webRpId: 'app.example.com' })).statusCode).toBe(200)
  })
  it('accepts webRpId "localhost"', async () => {
    expect((await patchApp({ webRpId: 'localhost' })).statusCode).toBe(200)
  })
  it('rejects webRpId with scheme prefix', async () => {
    expect((await patchApp({ webRpId: 'https://app.example.com' })).statusCode).toBe(400)
  })
  it('rejects webRpId empty string', async () => {
    expect((await patchApp({ webRpId: '' })).statusCode).toBe(400)
  })

  // ── Web SDK: webAllowedOrigins ─────────────────────────────────────────

  it('accepts https origins and http://localhost', async () => {
    const r = await patchApp({
      webAllowedOrigins: ['https://app.example.com', 'http://localhost:3000'],
    })
    expect(r.statusCode).toBe(200)
    expect((r.json() as any).webAllowedOrigins).toEqual(['https://app.example.com', 'http://localhost:3000'])
  })
  it('rejects http://example.com (non-localhost http)', async () => {
    expect((await patchApp({ webAllowedOrigins: ['http://example.com'] })).statusCode).toBe(400)
  })
  it('rejects origin with path', async () => {
    expect((await patchApp({ webAllowedOrigins: ['https://example.com/app'] })).statusCode).toBe(400)
  })
  it('rejects non-array webAllowedOrigins', async () => {
    expect((await patchApp({ webAllowedOrigins: 'https://x.com' })).statusCode).toBe(400)
  })

  // ── Web SDK: enable requires rpId ──────────────────────────────────────

  it('webSdkEnabled=true without webRpId set → 400', async () => {
    expect((await patchApp({ webSdkEnabled: true })).statusCode).toBe(400)
  })
  it('webSdkEnabled=true after webRpId is already set → ok', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const url = `/v1/customers/${customer.id}/apps/${a.id}`
    const r1 = await app.inject({ method: 'PATCH', url, headers: { authorization: `Bearer ${ADMIN_KEY}` }, payload: { webRpId: 'app.example.com' } })
    expect(r1.statusCode).toBe(200)
    const r2 = await app.inject({ method: 'PATCH', url, headers: { authorization: `Bearer ${ADMIN_KEY}` }, payload: { webSdkEnabled: true } })
    expect(r2.statusCode).toBe(200)
    expect((r2.json() as any).webSdkEnabled).toBe(true)
  })
  it('webSdkEnabled=true together with webRpId in same call → ok', async () => {
    const r = await patchApp({ webSdkEnabled: true, webRpId: 'app.example.com' })
    expect(r.statusCode).toBe(200)
  })

  // ── Confidence policy ──────────────────────────────────────────────────

  it('signPayloadMinConfidence accepts low/medium/high', async () => {
    for (const v of ['low', 'medium', 'high'] as const) {
      const r = await patchApp({ signPayloadMinConfidence: v })
      expect(r.statusCode).toBe(200)
    }
  })
  it('signPayloadMinConfidence rejects unknown value', async () => {
    expect((await patchApp({ signPayloadMinConfidence: 'very_high' })).statusCode).toBe(400)
  })
  it('verifyMinConfidence rejects unknown value', async () => {
    expect((await patchApp({ verifyMinConfidence: 'super' })).statusCode).toBe(400)
  })
  it('verifyMinConfidence accepts null (clears)', async () => {
    expect((await patchApp({ verifyMinConfidence: null })).statusCode).toBe(200)
  })

  it('rejects context override below signPayload default', async () => {
    // Default is 'high' on createSandboxCustomer
    const r = await patchApp({ contextConfidenceOverrides: { login: 'medium' } })
    expect(r.statusCode).toBe(400)
  })
  it('accepts context override at or above default', async () => {
    const r = await patchApp({ contextConfidenceOverrides: { login: 'high' } })
    expect(r.statusCode).toBe(200)
    expect((r.json() as any).contextConfidenceOverrides).toEqual({ login: 'high' })
  })
  it('rejects non-object contextConfidenceOverrides', async () => {
    expect((await patchApp({ contextConfidenceOverrides: ['high'] })).statusCode).toBe(400)
  })
  it('rejects override value that is not a confidence level', async () => {
    const r = await patchApp({ contextConfidenceOverrides: { login: 'super' } })
    expect(r.statusCode).toBe(400)
  })

  it('lowering signPayloadMinConfidence allows previously-illegal overrides in same call', async () => {
    const r = await patchApp({
      signPayloadMinConfidence: 'medium',
      contextConfidenceOverrides: { login: 'medium' },
    })
    expect(r.statusCode).toBe(200)
  })

  // ── Round-trip ─────────────────────────────────────────────────────────

  it('GET reflects all PATCHed fields', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const url = `/v1/customers/${customer.id}/apps/${a.id}`
    await app.inject({
      method: 'PATCH', url, headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {
        iosTeamId: 'ABCDE12345',
        iosBundleId: 'com.acme.app',
        androidPackageName: 'com.acme.app',
        androidSigningKeySha256: 'a'.repeat(64),
        webRpId: 'app.example.com',
        webAllowedOrigins: ['https://app.example.com'],
        webSdkEnabled: true,
        verifyMinConfidence: 'medium',
        signPayloadMinConfidence: 'high',
        contextConfidenceOverrides: { transfer: 'high' },
      },
    })
    const get = await app.inject({ method: 'GET', url, headers: { authorization: `Bearer ${ADMIN_KEY}` } })
    const body = get.json() as any
    expect(body.iosTeamId).toBe('ABCDE12345')
    expect(body.iosBundleId).toBe('com.acme.app')
    expect(body.androidPackageName).toBe('com.acme.app')
    expect(body.androidSigningKeySha256).toBe('a'.repeat(64))
    expect(body.webRpId).toBe('app.example.com')
    expect(body.webAllowedOrigins).toEqual(['https://app.example.com'])
    expect(body.webSdkEnabled).toBe(true)
    expect(body.verifyMinConfidence).toBe('medium')
    expect(body.signPayloadMinConfidence).toBe('high')
    expect(body.contextConfidenceOverrides).toEqual({ transfer: 'high' })
  })
})
