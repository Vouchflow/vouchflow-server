import { describe, it, expect } from 'vitest'
import type { Device } from '@prisma/client'
import { computeConfidence } from '../confidence.js'
import { confidenceMeets } from '../../routes/verify.js'

// The confidence ladder is the visible product surface of every Vouchflow
// verification. Customers gate behavior off it ("verified: true" + a level).
// A bug here doesn't fail-closed — it returns the wrong level — so each
// branch needs explicit coverage. Pure unit tests, no DB.

/** Builds a Device row with sensible defaults for the test cases below.
 *  Every test specifies only the fields it cares about. */
function device(overrides: Partial<Device> = {}): Device {
  return {
    id: 'test-device',
    deviceToken: 'dvt_test',
    customerId: 'cust_test',
    publicKey: '',
    keyFingerprint: '',
    platform: 'ios',
    attestationVerified: true,
    confidenceCeiling: 'high',
    strongboxBacked: null,
    enrolledAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000), // 60 days old
    lastSeen: null,
    status: 'active',
    networkParticipant: false,
    createdAt: new Date(),
    ...overrides,
  }
}

describe('computeConfidence', () => {
  // ── Fallback path always returns low ────────────────────────────────────

  it('returns low when fallbackUsed is true, regardless of biometric', () => {
    const d = device()
    expect(computeConfidence({ device: d, biometricUsed: true,  fallbackUsed: true })).toBe('low')
    expect(computeConfidence({ device: d, biometricUsed: false, fallbackUsed: true })).toBe('low')
  })

  it('returns low when fallbackUsed is true even on a high-ceiling device', () => {
    const d = device({ confidenceCeiling: 'high', attestationVerified: true })
    expect(computeConfidence({ device: d, biometricUsed: true, fallbackUsed: true })).toBe('low')
  })

  // ── Attestation gate ───────────────────────────────────────────────────

  it('returns low when attestationVerified is false (regardless of biometric/age)', () => {
    const d = device({ attestationVerified: false })
    expect(computeConfidence({ device: d, biometricUsed: true,  fallbackUsed: false })).toBe('low')
    expect(computeConfidence({ device: d, biometricUsed: false, fallbackUsed: false })).toBe('low')
  })

  // ── High path: all three conditions required ───────────────────────────

  it('returns high when all of attestation + biometric + ceiling=high + age>30 are met', () => {
    const d = device({
      attestationVerified: true,
      confidenceCeiling: 'high',
      enrolledAt: new Date(Date.now() - 31 * 24 * 60 * 60 * 1000),
    })
    expect(computeConfidence({ device: d, biometricUsed: true, fallbackUsed: false })).toBe('high')
  })

  it('downgrades from high to medium when biometric was not used', () => {
    const d = device({
      attestationVerified: true,
      confidenceCeiling: 'high',
      enrolledAt: new Date(Date.now() - 31 * 24 * 60 * 60 * 1000),
    })
    expect(computeConfidence({ device: d, biometricUsed: false, fallbackUsed: false })).toBe('medium')
  })

  it('downgrades from high to medium when ceiling is medium (no attestation chain)', () => {
    const d = device({
      attestationVerified: true,
      confidenceCeiling: 'medium',
      enrolledAt: new Date(Date.now() - 31 * 24 * 60 * 60 * 1000),
    })
    expect(computeConfidence({ device: d, biometricUsed: true, fallbackUsed: false })).toBe('medium')
  })

  it('downgrades from high to medium when device is younger than 30 days (cohort-too-fresh)', () => {
    const d = device({
      attestationVerified: true,
      confidenceCeiling: 'high',
      enrolledAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
    })
    expect(computeConfidence({ device: d, biometricUsed: true, fallbackUsed: false })).toBe('medium')
  })

  // ── Boundary: age == 30 days ───────────────────────────────────────────

  it('age exactly 30 days does NOT qualify for high (strict >30 rule)', () => {
    const d = device({
      attestationVerified: true,
      confidenceCeiling: 'high',
      enrolledAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    })
    // Note: deviceAgeDays > 30 is strict — exactly 30 falls below.
    expect(computeConfidence({ device: d, biometricUsed: true, fallbackUsed: false })).toBe('medium')
  })
})

describe('confidenceMeets', () => {
  // §7 minimum_confidence comparison: ceiling >= minimum

  it('high satisfies high / medium / low', () => {
    expect(confidenceMeets('high', 'high')).toBe(true)
    expect(confidenceMeets('high', 'medium')).toBe(true)
    expect(confidenceMeets('high', 'low')).toBe(true)
  })

  it('medium satisfies medium / low but NOT high', () => {
    expect(confidenceMeets('medium', 'high')).toBe(false)
    expect(confidenceMeets('medium', 'medium')).toBe(true)
    expect(confidenceMeets('medium', 'low')).toBe(true)
  })

  it('low satisfies only low', () => {
    expect(confidenceMeets('low', 'high')).toBe(false)
    expect(confidenceMeets('low', 'medium')).toBe(false)
    expect(confidenceMeets('low', 'low')).toBe(true)
  })

  it('treats unknown ceiling as rank 0 — denies high and medium minimums', () => {
    // If a future migration introduces a new level and this code isn't
    // updated, fail-closed: the device's ceiling can't satisfy a high
    // or medium minimum.
    expect(confidenceMeets('chromium', 'high')).toBe(false)
    expect(confidenceMeets('chromium', 'medium')).toBe(false)
    // Edge: unknown ceiling DOES match 'low' because both default to rank
    // 0. Documented here so a future tightening of this helper (e.g. to
    // require an exact-match enum) catches the behavior change.
    expect(confidenceMeets('chromium', 'low')).toBe(true)
  })

  it('treats unknown minimum as rank 0 (matches anything)', () => {
    // Symmetry of the previous case. The route layer rejects unknown
    // minimum_confidence values via the Zod enum, so this is just the
    // defensive default in the helper itself — never reached in prod.
    expect(confidenceMeets('low',    'plutonium')).toBe(true)
    expect(confidenceMeets('medium', 'plutonium')).toBe(true)
    expect(confidenceMeets('high',   'plutonium')).toBe(true)
  })
})
