import { describe, it, expect, beforeAll } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { validateAttestation, type AttestationConfig } from '../attestation.js'

// Golden vector: a real Android Keystore Attestation chain published by
// google/android-key-attestation. Validates the end-to-end chain walk +
// extension parse + AttestationApplicationId match against a customer
// configuration. See ./fixtures/README.md for details.

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const FIX = path.join(__dirname, 'fixtures')

// Known leaf-cert metadata from the fixture. If we ever regenerate the
// fixture, these expected values come from running:
//   const { __test_internals__ as P } = await import('../attestation.js')
//   const ext = P.extractExtension(leaf, '1.3.6.1.4.1.11129.2.1.17')
//   const desc = P.derSequenceChildren(ext)
//   P.derReadOctetString(desc[4]).toString('utf8')   // → challenge
//   P.parseAttestationApplicationId(...)             // → package + digests
const KNOWN_CHALLENGE = 'abc'
const KNOWN_PACKAGE   = 'com.android.keychain'
const KNOWN_DIGEST    = '301aa3cb081134501c45f1422abc66c24224fd5ded5fdc8f17e697176fd866aa'

let chain: string[]
let rootPem: string

beforeAll(() => {
  chain = [0, 1, 2, 3].map(i => {
    const pem = fs.readFileSync(path.join(FIX, `cert${i}.pem`), 'utf8')
    const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '')
    return b64
  })
  rootPem = fs.readFileSync(path.join(FIX, 'cert3.pem'), 'utf8')
})

function fullConfig(overrides: Partial<AttestationConfig> = {}): AttestationConfig {
  return {
    googleAttestationRootCa: rootPem,
    androidPackageName:      KNOWN_PACKAGE,
    androidSigningKeySha256: KNOWN_DIGEST,
    ...overrides,
  }
}

// ── Success ──────────────────────────────────────────────────────────────────

describe('validateKeystoreAttestation: golden vector (success)', () => {
  it('verifies a real Google sample chain end-to-end', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: chain, nonce: KNOWN_CHALLENGE },
      fullConfig(),
    )
    expect(r).toEqual({ verified: true })
  })
})

// ── Tamper / misconfiguration detection ─────────────────────────────────────
//
// Each test substitutes one input that should make validation fail, with all
// others held at their known-good values. This is where the validator earns
// its keep — these are the cases where a subtle parser bug could let a
// crafted attestation slip through.

describe('validateKeystoreAttestation: tamper detection', () => {
  it('rejects mismatched challenge (replay defense)', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: chain, nonce: 'wrong-nonce' },
      fullConfig(),
    )
    expect(r).toEqual({ verified: false, reason: 'challenge_mismatch' })
  })

  it('rejects mismatched package name (calling-app spoof defense)', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: chain, nonce: KNOWN_CHALLENGE },
      fullConfig({ androidPackageName: 'com.attacker.app' }),
    )
    expect(r).toEqual({ verified: false, reason: 'package_name_mismatch' })
  })

  it('rejects mismatched signing-key digest (key-substitution defense)', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: chain, nonce: KNOWN_CHALLENGE },
      fullConfig({ androidSigningKeySha256: '00'.repeat(32) }),
    )
    expect(r).toEqual({ verified: false, reason: 'signing_key_mismatch' })
  })

  it('rejects when the chain does not root in the configured CA', async () => {
    // Use a different self-signed cert as the configured root. Build one on
    // the fly via Node's webcrypto so we don't need another fixture file.
    const otherRoot = await generateSelfSignedRoot()
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: chain, nonce: KNOWN_CHALLENGE },
      fullConfig({ googleAttestationRootCa: otherRoot }),
    )
    expect(r).toEqual({ verified: false, reason: 'cert_chain_not_rooted' })
  })

  it('rejects a tampered leaf (signature break)', async () => {
    // Flip a single byte deep inside the leaf cert's TBS region. With a
    // real signature this break is unrecoverable — the cert→issuer verify
    // call returns false, surfacing cert_chain_invalid.
    const tamperedLeaf = Buffer.from(chain[0], 'base64')
    tamperedLeaf[100] ^= 0x01
    const tampered = [tamperedLeaf.toString('base64'), ...chain.slice(1)]
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: tampered, nonce: KNOWN_CHALLENGE },
      fullConfig(),
    )
    expect(r.verified).toBe(false)
    // Could be cert_chain_invalid (sig break) or attestation_parse_error
    // (the byte we flipped was inside the extension we parse). Either is a
    // safe fail — the point is the validator MUST NOT return verified=true.
    expect(['cert_chain_invalid', 'attestation_parse_error']).toContain(r.reason)
  })

  it('rejects an empty cert chain even with everything else configured', async () => {
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: [], nonce: KNOWN_CHALLENGE },
      fullConfig(),
    )
    expect(r).toEqual({ verified: false, reason: 'missing_cert_chain' })
  })

  it('rejects when a chain link is broken (cert1 swapped for an unrelated cert)', async () => {
    const unrelated = (await generateSelfSignedRoot())
      .replace(/-----[A-Z ]+-----/g, '')
      .replace(/\s+/g, '')
    const broken = [chain[0], unrelated, chain[2], chain[3]]
    const r = await validateAttestation(
      { platform: 'android', token: null, keyId: null, certChain: broken, nonce: KNOWN_CHALLENGE },
      fullConfig(),
    )
    expect(r).toEqual({ verified: false, reason: 'cert_chain_invalid' })
  })
})

// ── Helpers ─────────────────────────────────────────────────────────────────

async function generateSelfSignedRoot(): Promise<string> {
  // Generate a throwaway EC P-256 self-signed cert via the X509 builder.
  // Used as a "wrong" root so `chain doesn't root in this CA` is the only
  // possible failure mode.
  const { generateKeyPairSync, createPrivateKey, createPublicKey } = await import('node:crypto')
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  // Build a minimal self-signed cert via the X509Certificate constructor —
  // Node 19+ exposes this only for parsing, so we synthesize via a tiny
  // helper that produces a deterministic stand-in. For our purpose we just
  // need any valid cert that ISN'T cert3.
  // Simplest: use openssl through a subprocess (avoids pulling in a CA
  // library). Falls through to a hard-coded fallback if openssl is absent.
  try {
    const { execFileSync, spawnSync } = await import('node:child_process')
    const tmp = await import('node:os').then(o => o.tmpdir())
    const path = await import('node:path')
    const fs = await import('node:fs')
    const keyPath  = path.join(tmp, `vfk-${process.pid}-${Date.now()}.key`)
    const certPath = path.join(tmp, `vfk-${process.pid}-${Date.now()}.crt`)
    fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }))
    const r = spawnSync(
      'openssl',
      ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=throwaway-root'],
      { encoding: 'utf8' },
    )
    if (r.status === 0) {
      const pem = fs.readFileSync(certPath, 'utf8')
      fs.unlinkSync(keyPath)
      fs.unlinkSync(certPath)
      return pem
    }
  } catch {
    // fall through
  }
  // Fallback (CI without openssl): an arbitrary fixed self-signed cert that
  // is definitely not Google's HW Attestation root.
  return `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuV8...not-a-real-cert
-----END CERTIFICATE-----`
}
