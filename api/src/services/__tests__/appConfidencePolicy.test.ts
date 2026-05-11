// Unit tests for the per-app confidence resolver. No DB needed for the pure
// helpers (meetsLevel, maxLevel); the loader test uses the integration DB.

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import {
  meetsLevel,
  maxLevel,
  loadAppPolicy,
  resolveVerifyMin,
  resolveSignMin,
} from '../appConfidencePolicy.js'
import { prisma } from '../../lib/prisma.js'
import { HAS_DB, cleanDb, createSandboxCustomer } from '../../__tests__/helpers/testApp.js'

describe('meetsLevel', () => {
  it('null required → always true', () => {
    expect(meetsLevel('low', null)).toBe(true)
    expect(meetsLevel(null, null)).toBe(true)
  })
  it('null actual with required → false', () => {
    expect(meetsLevel(null, 'low')).toBe(false)
  })
  it('high satisfies high/medium/low', () => {
    expect(meetsLevel('high', 'high')).toBe(true)
    expect(meetsLevel('high', 'medium')).toBe(true)
    expect(meetsLevel('high', 'low')).toBe(true)
  })
  it('medium does not satisfy high', () => {
    expect(meetsLevel('medium', 'high')).toBe(false)
  })
  it('low does not satisfy medium or high', () => {
    expect(meetsLevel('low', 'medium')).toBe(false)
    expect(meetsLevel('low', 'high')).toBe(false)
  })
})

describe('maxLevel', () => {
  it('returns the higher level', () => {
    expect(maxLevel('low', 'medium')).toBe('medium')
    expect(maxLevel('high', 'low')).toBe('high')
  })
  it('handles null branches', () => {
    expect(maxLevel(null, 'medium')).toBe('medium')
    expect(maxLevel('low', null)).toBe('low')
    expect(maxLevel(null, null)).toBeNull()
  })
})

const d = HAS_DB ? describe : describe.skip

d('loadAppPolicy + resolvers (DB-backed)', () => {
  beforeAll(async () => { /* nothing */ })
  afterAll(async () => { /* nothing */ })
  beforeEach(async () => cleanDb())

  it('default: signPayload defaults to high, verify falls back to customer minimumConfidence', async () => {
    const { customer, app } = await createSandboxCustomer()
    await prisma.customer.update({ where: { id: customer.id }, data: { minimumConfidence: 'medium' } })
    const policy = await loadAppPolicy(app.id)
    expect(resolveSignMin(policy, null)).toBe('high')
    expect(resolveVerifyMin(policy, null)).toBe('medium')
  })

  it('App.verifyMinConfidence overrides customer default when higher', async () => {
    const { customer, app } = await createSandboxCustomer()
    await prisma.customer.update({ where: { id: customer.id }, data: { minimumConfidence: 'low' } })
    await prisma.app.update({ where: { id: app.id }, data: { verifyMinConfidence: 'high' } })
    const policy = await loadAppPolicy(app.id)
    expect(resolveVerifyMin(policy, null)).toBe('high')
  })

  it('per-context override raises the floor for that context only', async () => {
    const { customer: _, app } = await createSandboxCustomer()
    await prisma.app.update({
      where: { id: app.id },
      data: {
        signPayloadMinConfidence: 'high',
        contextConfidenceOverrides: { transfer: 'high', login: 'high' },
        verifyMinConfidence: 'medium',
      },
    })
    const policy = await loadAppPolicy(app.id)
    expect(resolveVerifyMin(policy, 'login')).toBe('high')
    expect(resolveVerifyMin(policy, 'something_else')).toBe('medium')
    expect(resolveSignMin(policy, 'login')).toBe('high')
  })

  it('throws when app does not exist', async () => {
    await expect(loadAppPolicy('app_does_not_exist')).rejects.toThrow()
  })
})
