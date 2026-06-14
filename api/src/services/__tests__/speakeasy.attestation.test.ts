import { describe, it, expect, beforeAll } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { validateAttestation, buildAttestationConfig } from '../attestation.js'

// Wire-up test for the Speakeasy app (customer lunchboxfortwo@gmail.com, app id
// cmp7bs32o000bhl1ifb43f5ff) using its real per-app attestation config from
// production. Snapshotted 2026-06-14 — refetch if the user rotates these:
//   curl -H "Authorization: Bearer $ADMIN_KEY" \
//     https://api.vouchflow.dev/v1/customers/<cust>/apps/<app>
const SPEAKEASY = {
  iosTeamId:               null,
  iosBundleId:             null,
  androidPackageName:      'xyz.speakeasyapp.app',
  androidSigningKeySha256: '741ea7f6a6958afd9f3b76685223e444c643c8ead1f6698362618327cc33dd62',
} as const

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const FIX = path.join(__dirname, 'fixtures')

let chain: string[]
let sampleRoot: string

beforeAll(() => {
  chain = [0, 1, 2, 3].map(i => {
    const pem = fs.readFileSync(path.join(FIX, `cert${i}.pem`), 'utf8')
    return pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '')
  })
  sampleRoot = fs.readFileSync(path.join(FIX, 'cert3.pem'), 'utf8')
})

// ── buildAttestationConfig: per-app values override env fallback ────────────

describe('buildAttestationConfig for Speakeasy (live prod values)', () => {
  it('threads Speakeasy android values through unchanged', () => {
    const c = buildAttestationConfig(SPEAKEASY)
    expect(c.androidPackageName).toBe('xyz.speakeasyapp.app')
    expect(c.androidSigningKeySha256).toBe(
      '741ea7f6a6958afd9f3b76685223e444c643c8ead1f6698362618327cc33dd62',
    )
  })

  it('leaves apple values nullish (Speakeasy has not configured iOS)', () => {
    const c = buildAttestationConfig(SPEAKEASY)
    // The per-app value is null → falls through to process.env, which in the
    // test environment is also unset, so both are undefined-or-null.
    expect(c.appleTeamId   ?? null).toBeNull()
    expect(c.appleBundleId ?? null).toBeNull()
  })
})

// ── Android path: Speakeasy config is live, not stubbed ─────────────────────
//
// We can't synthesize a real KeyMint attestation chain for Speakeasy without
// a physical device. The shipped golden-vector chain is for the sample app
// "com.android.keychain" (see fixtures/README.md), so when we run validation
// with Speakeasy's package_name configured, we EXPECT package_name_mismatch.
// That's exactly the outcome we want from this test: it proves we reached the
// AttestationApplicationId comparison — i.e. the deploy isn't short-circuiting
// at the missing-credentials guard anymore.

describe('Speakeasy android validation pipeline reaches the identity check', () => {
  it('runs past credentials_not_configured with Speakeasy values + a root CA', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: chain, nonce: 'abc' },
      { ...buildAttestationConfig(SPEAKEASY), googleAttestationRootCa: sampleRoot },
    )
    expect(r.verified).toBe(false)
    // The important assertion: the failure is downstream of the chain walk +
    // KeyDescription parse — it's the live package-name comparison rejecting
    // a chain that legitimately belongs to a different app.
    expect(r.reason).toBe('package_name_mismatch')
  })

  it('still rejects with credentials_not_configured when the root CA is absent', async () => {
    // Sanity check: removing the root CA (the only env-side input on Android)
    // collapses everything back to the early-return path. This is what prod
    // looked like BEFORE GOOGLE_HARDWARE_ATTESTATION_ROOT_CA was set on
    // vouchflow-server on 2026-06-14.
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: chain, nonce: 'abc' },
      { ...buildAttestationConfig(SPEAKEASY), googleAttestationRootCa: undefined },
    )
    expect(r).toEqual({ verified: false, reason: 'credentials_not_configured' })
  })
})

// ── iOS path: Speakeasy has not configured iOS → credentials_not_configured ─

describe('Speakeasy ios validation pipeline (unconfigured per-app)', () => {
  it('returns credentials_not_configured when iosTeamId/iosBundleId are null', async () => {
    // Even with the Apple App Attest root CA loaded (as it now is in prod),
    // Speakeasy's per-app config has iosTeamId=null/iosBundleId=null, so the
    // early guard fires. Confidence stays capped at medium for iOS until the
    // user fills those fields in /settings/apps/cmp7bs32o000bhl1ifb43f5ff.
    const r = await validateAttestation(
      { platform: 'ios', token: 'AAAA', keyId: 'AAAA', certChain: null, nonce: 'abc' },
      { ...buildAttestationConfig(SPEAKEASY), appleRootCa: 'unused-here-because-teamId-is-null' },
    )
    expect(r).toEqual({ verified: false, reason: 'credentials_not_configured' })
  })
})
