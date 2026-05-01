import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  validateAttestation,
  buildAttestationConfig,
  type AttestationConfig,
} from '../attestation.js'

// ── buildAttestationConfig ────────────────────────────────────────────────────
//
// The fallback rule is the load-bearing piece for a clean migration: existing
// single-tenant deployments must keep working when Customer rows are null,
// and per-customer values must take precedence when they are set.

describe('buildAttestationConfig', () => {
  let originalEnv: NodeJS.ProcessEnv
  beforeEach(() => {
    originalEnv = { ...process.env }
  })
  afterEach(() => {
    process.env = originalEnv
  })

  it('uses env vars when customer is null (legacy single-tenant deploy)', () => {
    process.env.APPLE_TEAM_ID = 'ENVTEAM123'
    process.env.APPLE_BUNDLE_ID = 'com.env.app'
    process.env.ANDROID_PACKAGE_NAME = 'com.env.android'
    process.env.ANDROID_SIGNING_KEY_SHA256 = 'envdigest'
    process.env.APPLE_APP_ATTEST_ROOT_CA = 'apple-pem'
    process.env.GOOGLE_HARDWARE_ATTESTATION_ROOT_CA = 'google-pem'

    const cfg = buildAttestationConfig(null)
    expect(cfg.appleTeamId).toBe('ENVTEAM123')
    expect(cfg.appleBundleId).toBe('com.env.app')
    expect(cfg.androidPackageName).toBe('com.env.android')
    expect(cfg.androidSigningKeySha256).toBe('envdigest')
    expect(cfg.appleRootCa).toBe('apple-pem')
    expect(cfg.googleAttestationRootCa).toBe('google-pem')
  })

  it('prefers customer values over env vars', () => {
    process.env.APPLE_TEAM_ID = 'ENVTEAM'
    process.env.APPLE_BUNDLE_ID = 'com.env.app'
    process.env.ANDROID_PACKAGE_NAME = 'com.env.android'
    process.env.ANDROID_SIGNING_KEY_SHA256 = 'envdigest'

    const cfg = buildAttestationConfig({
      iosTeamId: 'CUSTID1234',
      iosBundleId: 'com.cust.app',
      androidPackageName: 'com.cust.android',
      androidSigningKeySha256: 'custdigest',
    })
    expect(cfg.appleTeamId).toBe('CUSTID1234')
    expect(cfg.appleBundleId).toBe('com.cust.app')
    expect(cfg.androidPackageName).toBe('com.cust.android')
    expect(cfg.androidSigningKeySha256).toBe('custdigest')
  })

  it('falls back per-field — partial customer values mix with env defaults', () => {
    process.env.APPLE_TEAM_ID = 'ENVTEAM'
    process.env.APPLE_BUNDLE_ID = 'com.env.app'

    const cfg = buildAttestationConfig({
      iosTeamId: 'CUSTID1234',
      iosBundleId: null, // unset → falls back to env
      androidPackageName: null,
      androidSigningKeySha256: null,
    })
    expect(cfg.appleTeamId).toBe('CUSTID1234')
    expect(cfg.appleBundleId).toBe('com.env.app')
  })

  it('returns undefined for unset fields with no env fallback', () => {
    delete process.env.APPLE_TEAM_ID
    delete process.env.ANDROID_PACKAGE_NAME

    const cfg = buildAttestationConfig(null)
    expect(cfg.appleTeamId).toBeUndefined()
    expect(cfg.androidPackageName).toBeUndefined()
  })
})

// ── validateAttestation routing ───────────────────────────────────────────────

describe('validateAttestation routing', () => {
  const minimalConfig: AttestationConfig = {} // missing everything → credentials_not_configured

  it('routes ios → App Attest', async () => {
    const r = await validateAttestation(
      { platform: 'ios', token: 'bogus', keyId: null, certChain: null, nonce: 'n' },
      minimalConfig,
    )
    expect(r.verified).toBe(false)
    expect(r.reason).toBe('credentials_not_configured')
  })

  it('routes android → Keystore Attestation', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: ['somebase64'], nonce: 'n' },
      minimalConfig,
    )
    expect(r.verified).toBe(false)
    expect(r.reason).toBe('credentials_not_configured')
  })

  it('rejects web platform — no on-device attestation primitive', async () => {
    const r = await validateAttestation(
      { platform: 'web', token: null, keyId: null, certChain: null, nonce: 'n' },
      minimalConfig,
    )
    expect(r.verified).toBe(false)
    expect(r.reason).toBe('platform_does_not_support_attestation')
  })

  it('rejects unknown platform values', async () => {
    const r = await validateAttestation(
      { platform: 'macos', token: null, keyId: null, certChain: null, nonce: 'n' },
      minimalConfig,
    )
    expect(r.verified).toBe(false)
    expect(r.reason).toBe('platform_does_not_support_attestation')
  })
})

// ── App Attest input validation ──────────────────────────────────────────────
//
// We don't have real App Attest fixtures in this test suite (they require a
// physical iOS device + entitled provisioning profile). These tests cover the
// guard rails that fire before the cryptographic path.

describe('validateAppAttest input validation', () => {
  const fullConfig: AttestationConfig = {
    appleRootCa: 'placeholder-pem', // not a real cert; cryptographic path won't run
    appleTeamId: 'TEAM1234AB',
    appleBundleId: 'com.example.app',
  }

  it('rejects when root CA env var is unset', async () => {
    const r = await validateAttestation(
      { platform: 'ios', token: 'cbor', keyId: 'kid', certChain: null, nonce: 'n' },
      { ...fullConfig, appleRootCa: undefined },
    )
    expect(r).toEqual({ verified: false, reason: 'credentials_not_configured' })
  })

  it('rejects when team id is unset (multi-tenant misconfigured)', async () => {
    const r = await validateAttestation(
      { platform: 'ios', token: 'cbor', keyId: 'kid', certChain: null, nonce: 'n' },
      { ...fullConfig, appleTeamId: undefined },
    )
    expect(r).toEqual({ verified: false, reason: 'credentials_not_configured' })
  })

  it('rejects when bundle id is unset', async () => {
    const r = await validateAttestation(
      { platform: 'ios', token: 'cbor', keyId: 'kid', certChain: null, nonce: 'n' },
      { ...fullConfig, appleBundleId: undefined },
    )
    expect(r).toEqual({ verified: false, reason: 'credentials_not_configured' })
  })

  it('rejects when token is missing despite full config', async () => {
    const r = await validateAttestation(
      { platform: 'ios', token: null, keyId: 'kid', certChain: null, nonce: 'n' },
      fullConfig,
    )
    expect(r).toEqual({ verified: false, reason: 'missing_attestation_token' })
  })

  it('returns parse_error on garbage token without leaking exceptions', async () => {
    const r = await validateAttestation(
      { platform: 'ios', token: 'not-base64-cbor', keyId: 'kid', certChain: null, nonce: 'n' },
      fullConfig,
    )
    // Could be parse_error or a downstream cert/format reason, but must NOT throw.
    expect(r.verified).toBe(false)
    expect(r.reason).toBeTypeOf('string')
  })
})

// ── Keystore Attestation input validation ────────────────────────────────────

describe('validateKeystoreAttestation input validation', () => {
  const fullConfig: AttestationConfig = {
    googleAttestationRootCa: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
    androidPackageName: 'com.example.app',
    androidSigningKeySha256: 'a'.repeat(64),
  }

  it('rejects when Google root CA env var is unset', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: ['cert'], nonce: 'n' },
      { ...fullConfig, googleAttestationRootCa: undefined },
    )
    expect(r).toEqual({ verified: false, reason: 'credentials_not_configured' })
  })

  it('rejects when package name is unset (customer not onboarded)', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: ['cert'], nonce: 'n' },
      { ...fullConfig, androidPackageName: undefined },
    )
    expect(r).toEqual({ verified: false, reason: 'credentials_not_configured' })
  })

  it('rejects when signing key SHA-256 is unset', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: ['cert'], nonce: 'n' },
      { ...fullConfig, androidSigningKeySha256: undefined },
    )
    expect(r).toEqual({ verified: false, reason: 'credentials_not_configured' })
  })

  it('rejects when cert chain is missing', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: null, nonce: 'n' },
      fullConfig,
    )
    expect(r).toEqual({ verified: false, reason: 'missing_cert_chain' })
  })

  it('rejects empty cert chain', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: [], nonce: 'n' },
      fullConfig,
    )
    expect(r).toEqual({ verified: false, reason: 'missing_cert_chain' })
  })

  it('returns parse_error on a malformed cert without leaking exceptions', async () => {
    const r = await validateAttestation(
      {
        platform: 'android',
        token: null,
        keyId: null,
        certChain: ['bm90LWEtY2VydA=='], // base64("not-a-cert")
        nonce: 'n',
      },
      fullConfig,
    )
    expect(r.verified).toBe(false)
    expect(r.reason).toBeTypeOf('string')
  })
})
