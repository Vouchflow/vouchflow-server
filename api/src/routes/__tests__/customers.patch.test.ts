import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import customerRoute from '../customers.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// PATCH /v1/customers/:id accepts the four per-customer attestation
// parameters customers configure during onboarding (iosTeamId,
// iosBundleId, androidPackageName, androidSigningKeySha256). The
// regex validators are the only thing standing between a typo
// in the dashboard and a silent confidence_ceiling=medium downgrade
// on every device — worth pinning their behaviour.

const ADMIN_KEY = 'a'.repeat(64)

d('PATCH /v1/customers/:id — attestation field validation', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    process.env.ADMIN_KEY = ADMIN_KEY
    app = await buildTestApp(async (fastify) => {
      await fastify.register(customerRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  // ── Happy path ──────────────────────────────────────────────────────────

  it('accepts a valid set of all four attestation fields', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {
        androidPackageName:      'com.acme.app',
        androidSigningKeySha256: 'A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10',
        iosTeamId:               'ABCDE12345',
        iosBundleId:             'com.acme.app',
      },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as Record<string, unknown>
    expect(body.androidPackageName).toBe('com.acme.app')
    // Colons + whitespace stripped, lowercased.
    expect(body.androidSigningKeySha256).toBe(
      'a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f10',
    )
    expect(body.iosTeamId).toBe('ABCDE12345')
    expect(body.iosBundleId).toBe('com.acme.app')
  })

  it('accepts null to clear individual fields', async () => {
    const { customer } = await createSandboxCustomer({
      iosTeamId: 'ABCDE12345',
      iosBundleId: 'com.acme.app',
    })
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { iosTeamId: null, iosBundleId: null },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as Record<string, unknown>
    expect(body.iosTeamId).toBeNull()
    expect(body.iosBundleId).toBeNull()
  })

  it('leaves attestation fields unchanged when not in the body', async () => {
    const { customer } = await createSandboxCustomer({
      iosTeamId: 'KEEPMETEAM',
      iosBundleId: 'com.keep.me',
    })
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { orgName: 'New Org Name' },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as Record<string, unknown>
    expect(body.iosTeamId).toBe('KEEPMETEAM')
    expect(body.iosBundleId).toBe('com.keep.me')
  })

  // ── androidPackageName ─────────────────────────────────────────────────

  it('rejects androidPackageName without a dot (single segment)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { androidPackageName: 'app' },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toMatchObject({ error: { code: 'invalid_field' } })
  })

  it('rejects androidPackageName starting with a digit', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { androidPackageName: '4chan.app' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('rejects androidPackageName with hyphens (Java identifiers don\'t allow them)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { androidPackageName: 'com.my-cool.app' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('accepts androidPackageName with underscores (legal in Java identifiers)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { androidPackageName: 'com.my_cool.app' },
    })
    expect(res.statusCode).toBe(200)
  })

  // ── androidSigningKeySha256 ────────────────────────────────────────────

  it('normalizes signing-key SHA256 (strips colons, lowercases)', async () => {
    const { customer } = await createSandboxCustomer()
    const upper = 'A'.repeat(64)
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { androidSigningKeySha256: upper },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as Record<string, unknown>
    expect(body.androidSigningKeySha256).toBe('a'.repeat(64))
  })

  it('accepts colon-formatted signing-key SHA256 (typical keytool output)', async () => {
    const { customer } = await createSandboxCustomer()
    const colons = '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF'
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { androidSigningKeySha256: colons },
    })
    expect(res.statusCode).toBe(200)
    expect((res.json() as Record<string, unknown>).androidSigningKeySha256)
      .toBe('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')
  })

  it('rejects signing-key SHA256 of wrong length (62 hex chars)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { androidSigningKeySha256: 'a'.repeat(62) },
    })
    expect(res.statusCode).toBe(400)
  })

  it('rejects signing-key SHA256 with non-hex chars', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { androidSigningKeySha256: 'g'.repeat(64) }, // g is not hex
    })
    expect(res.statusCode).toBe(400)
  })

  // ── iosTeamId ──────────────────────────────────────────────────────────

  it('rejects iosTeamId of wrong length (9 chars)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { iosTeamId: 'ABCDE1234' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('rejects iosTeamId with lowercase letters (Apple uses uppercase)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { iosTeamId: 'abcde12345' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('rejects iosTeamId with special chars', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { iosTeamId: 'ABCDE-2345' },
    })
    expect(res.statusCode).toBe(400)
  })

  // ── iosBundleId ────────────────────────────────────────────────────────

  it('accepts iosBundleId with hyphens (legal in iOS bundle IDs)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { iosBundleId: 'com.my-app.cool' },
    })
    expect(res.statusCode).toBe(200)
  })

  it('rejects iosBundleId without a dot', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { iosBundleId: 'singlesegment' },
    })
    expect(res.statusCode).toBe(400)
  })

  // ── Auth ───────────────────────────────────────────────────────────────

  it('rejects requests without the admin key', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      payload: { iosTeamId: 'ABCDE12345' },
    })
    expect(res.statusCode).toBe(401)
  })
})
