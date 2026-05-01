// §6 Decision 4: Attestation-anchored request signing.
//
// When attestation credentials are absent, validateAttestation returns
// { verified: false, reason: "credentials_not_configured" } and enrollment
// proceeds with confidence_ceiling: "medium". This is correct production-safe
// behaviour — not a development shortcut.
//
// Multi-tenant: iOS team_id and bundle_id, plus the Android package name, are
// per-customer values stored on the Customer row. Apple's App Attest root CA
// and Google's Play Integrity decryption/verification keys remain process-wide
// (the Apple root is a public cert; Play Integrity Classic keys are still
// global pending the Keystore Attestation switch — see TODO below).
//
// Required env vars (fallback when Customer row is missing values):
//   iOS:     APPLE_APP_ATTEST_ROOT_CA  (always env — public root cert)
//            APPLE_TEAM_ID, APPLE_BUNDLE_ID  (single-tenant fallback)
//   Android: GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY,
//            GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY  (always env for now)
//            ANDROID_PACKAGE_NAME  (single-tenant fallback)
//
// TODO: Replace Play Integrity Classic with Keystore Attestation. The
// per-customer secret-sharing problem (decryption keys) only goes away when
// we move to chain-validation against the Google Hardware Attestation root.
// Customer.androidSigningKeySha256 is reserved for that path.

import crypto from 'node:crypto'
import { compactDecrypt, compactVerify } from 'jose'

// cbor-x is ESM-only; dynamic import is required from a CJS module.
// Cached after first call — one import() per process lifetime.
let _cborDecode: ((data: Uint8Array | Buffer) => unknown) | undefined
async function cborDecode(data: Buffer): Promise<unknown> {
  if (!_cborDecode) {
    const cbor = await import('cbor-x')
    _cborDecode = cbor.decode
  }
  return _cborDecode(data)
}

export interface AttestationInput {
  platform: string
  token: string
  keyId: string | null
  nonce: string
}

/**
 * Per-call attestation configuration. iOS and Android values come from the
 * Customer row when present, falling back to process env when not — that
 * preserves the prior single-tenant deployment shape during migration.
 */
export interface AttestationConfig {
  // Apple App Attest. rootCa is a global Apple cert (env only).
  appleRootCa?: string
  appleTeamId?: string
  appleBundleId?: string
  // Play Integrity Classic. Encryption keys remain global env until the
  // Keystore Attestation switch lands; package name is now per-customer.
  playIntegrityDecryptionKey?: string
  playIntegrityVerificationKey?: string
  androidPackageName?: string
}

export interface AttestationResult {
  verified: boolean
  reason?: string
}

/**
 * Builds an AttestationConfig from a Customer row, layering env vars beneath
 * for backwards compatibility with the single-tenant deployment. Pass `null`
 * when the customer record is unavailable to use env-only.
 */
export function buildAttestationConfig(
  customer: {
    iosTeamId?: string | null
    iosBundleId?: string | null
    androidPackageName?: string | null
  } | null,
): AttestationConfig {
  return {
    appleRootCa: process.env.APPLE_APP_ATTEST_ROOT_CA,
    appleTeamId: customer?.iosTeamId ?? process.env.APPLE_TEAM_ID,
    appleBundleId: customer?.iosBundleId ?? process.env.APPLE_BUNDLE_ID,
    playIntegrityDecryptionKey: process.env.GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY,
    playIntegrityVerificationKey: process.env.GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY,
    androidPackageName: customer?.androidPackageName ?? process.env.ANDROID_PACKAGE_NAME,
  }
}

export async function validateAttestation(
  input: AttestationInput,
  config: AttestationConfig,
): Promise<AttestationResult> {
  if (input.platform === 'ios') {
    return validateAppAttest(input, config)
  } else if (input.platform === 'android') {
    return validatePlayIntegrity(input, config)
  }
  // 'web' platform has no device attestation — confidence_ceiling will be "medium"
  return { verified: false, reason: 'platform_does_not_support_attestation' }
}

// ── Apple App Attest ──────────────────────────────────────────────────────────

async function validateAppAttest(
  input: AttestationInput,
  config: AttestationConfig,
): Promise<AttestationResult> {
  const { appleRootCa: rootCa, appleTeamId: teamId, appleBundleId: bundleId } = config

  if (!rootCa || !teamId || !bundleId) {
    return { verified: false, reason: 'credentials_not_configured' }
  }

  try {
    // 1. CBOR-decode the base64-encoded attestation object.
    const attestation = await cborDecode(Buffer.from(input.token, 'base64')) as {
      fmt: string
      attStmt: { x5c: Uint8Array[]; receipt: Uint8Array }
      authData: Uint8Array
    }

    if (attestation.fmt !== 'apple-appattest') {
      return { verified: false, reason: 'invalid_attestation_format' }
    }

    const { x5c } = attestation.attStmt
    const authData = Buffer.from(attestation.authData)

    if (!x5c || x5c.length < 2) {
      return { verified: false, reason: 'missing_certificate_chain' }
    }

    // 2. Verify the certificate chain: credCert → intermediate → Apple App Attest Root CA.
    const credCertDer = Buffer.from(x5c[0])
    const intermediateCertDer = Buffer.from(x5c[1])

    const credCert = new crypto.X509Certificate(credCertDer)
    const intermediateCert = new crypto.X509Certificate(intermediateCertDer)
    const rootCert = new crypto.X509Certificate(
      rootCa.includes('BEGIN CERTIFICATE') ? rootCa : Buffer.from(rootCa, 'base64')
    )

    if (!intermediateCert.verify(rootCert.publicKey)) {
      return { verified: false, reason: 'certificate_chain_invalid' }
    }
    if (!credCert.verify(intermediateCert.publicKey)) {
      return { verified: false, reason: 'certificate_chain_invalid' }
    }

    // 3. Verify the nonce in credCert's OID 1.2.840.113635.100.8.2 extension.
    //
    //    iOS client computes:
    //      clientDataHash = SHA256(idempotencyKey.utf8)
    //    and passes it to DCAppAttestService.attestKey(_:clientDataHash:).
    //    Apple embeds SHA256(authData || clientDataHash) in the extension.
    const clientDataHash = crypto.createHash('sha256').update(input.nonce, 'utf8').digest()
    const expectedNonce = crypto
      .createHash('sha256')
      .update(Buffer.concat([authData, clientDataHash]))
      .digest()

    const certNonce = extractAppAttestNonce(credCertDer)
    if (!certNonce) {
      return { verified: false, reason: 'nonce_extension_missing' }
    }
    if (!crypto.timingSafeEqual(certNonce, expectedNonce)) {
      return { verified: false, reason: 'nonce_mismatch' }
    }

    // 4. Verify rpIdHash = SHA256(teamId + "." + bundleId).
    //    authData layout: rpIdHash[0:32] | flags[32] | signCount[33:37] | aaguid[37:53] | ...
    const rpIdHash = authData.subarray(0, 32)
    const expectedRpIdHash = crypto
      .createHash('sha256')
      .update(`${teamId}.${bundleId}`, 'utf8')
      .digest()
    if (!crypto.timingSafeEqual(rpIdHash, expectedRpIdHash)) {
      return { verified: false, reason: 'rp_id_mismatch' }
    }

    // 5. Verify signCount = 0 (initial attestation — no assertions have been made yet).
    const signCount = authData.readUInt32BE(33)
    if (signCount !== 0) {
      return { verified: false, reason: 'counter_nonzero' }
    }

    // 6. Verify aaguid (bytes 37–52) identifies a genuine App Attest environment.
    //    Production: ASCII "appattest" + seven 0x00 bytes
    //    Development: ASCII "appattestdevelop"
    const aaguid = authData.subarray(37, 53).toString('ascii')
    const isProd = aaguid === 'appattest\x00\x00\x00\x00\x00\x00\x00'
    const isDev = aaguid === 'appattestdevelop'
    if (!isProd && !isDev) {
      return { verified: false, reason: 'invalid_aaguid' }
    }

    // 7. Verify credentialId in authData matches the keyId sent by the app.
    //    credIdLen[53:55] | credentialId[55 : 55+credIdLen]
    //    DCAppAttestService.generateKey() returns a base64-encoded credentialId.
    if (input.keyId !== null) {
      const credIdLen = authData.readUInt16BE(53)
      const credentialId = authData.subarray(55, 55 + credIdLen)
      const expectedCredId = Buffer.from(input.keyId, 'base64')
      if (
        credentialId.length !== expectedCredId.length ||
        !crypto.timingSafeEqual(credentialId, expectedCredId)
      ) {
        return { verified: false, reason: 'credential_id_mismatch' }
      }
    }

    return { verified: true }
  } catch {
    return { verified: false, reason: 'attestation_parse_error' }
  }
}

// ── Play Integrity ────────────────────────────────────────────────────────────

// Reject tokens issued more than 5 minutes ago.
const PLAY_INTEGRITY_MAX_AGE_MS = 5 * 60 * 1000

async function validatePlayIntegrity(
  input: AttestationInput,
  config: AttestationConfig,
): Promise<AttestationResult> {
  const {
    playIntegrityDecryptionKey: decryptionKey,
    playIntegrityVerificationKey: verificationKey,
    androidPackageName: packageName,
  } = config

  if (!decryptionKey || !verificationKey || !packageName) {
    return { verified: false, reason: 'credentials_not_configured' }
  }

  try {
    // 1. Decrypt the JWE (Play Integrity Classic API — A256KW + A256GCM).
    //    decryptionKey is a base64-encoded 32-byte AES key from the Play Console.
    const decKeyBytes = Buffer.from(decryptionKey, 'base64')
    const { plaintext: jwsBytes } = await compactDecrypt(input.token, decKeyBytes)
    const jws = Buffer.from(jwsBytes).toString('utf8')

    // 2. Verify the inner JWS signature.
    //    verificationKey is a base64-encoded DER SubjectPublicKeyInfo EC public key.
    const verKeyObj = crypto.createPublicKey({
      key: Buffer.from(verificationKey, 'base64'),
      format: 'der',
      type: 'spki',
    })
    const { payload: payloadBytes } = await compactVerify(jws, verKeyObj)

    const verdict = JSON.parse(Buffer.from(payloadBytes).toString('utf8')) as {
      requestDetails?: {
        requestPackageName?: string
        nonce?: string
        timestampMillis?: number
      }
      appIntegrity?: {
        appRecognitionVerdict?: string
        packageName?: string
      }
      deviceIntegrity?: {
        deviceRecognitionVerdict?: string[]
      }
    }

    const details = verdict.requestDetails
    if (!details) {
      return { verified: false, reason: 'missing_request_details' }
    }

    // 3. Verify requestPackageName matches our known package name.
    if (details.requestPackageName !== packageName) {
      return { verified: false, reason: 'package_name_mismatch' }
    }

    // 4. Verify the nonce matches the idempotency key we issued.
    //    Android SDK passes idempotency_key directly as the nonce string.
    if (details.nonce !== input.nonce) {
      return { verified: false, reason: 'nonce_mismatch' }
    }

    // 5. Reject stale tokens.
    if (details.timestampMillis !== undefined) {
      const ageMs = Date.now() - details.timestampMillis
      if (ageMs > PLAY_INTEGRITY_MAX_AGE_MS) {
        return { verified: false, reason: 'token_expired' }
      }
    }

    // 6. Verify the app is PLAY_RECOGNIZED (not sideloaded or tampered).
    if (verdict.appIntegrity?.appRecognitionVerdict !== 'PLAY_RECOGNIZED') {
      return { verified: false, reason: 'app_not_recognized' }
    }

    // 7. Verify the device passes basic integrity (not rooted / emulator with no Play cert).
    const deviceVerdicts = verdict.deviceIntegrity?.deviceRecognitionVerdict ?? []
    if (!deviceVerdicts.includes('MEETS_DEVICE_INTEGRITY')) {
      return { verified: false, reason: 'device_integrity_failed' }
    }

    return { verified: true }
  } catch {
    return { verified: false, reason: 'attestation_parse_error' }
  }
}

// ── DER parsing helpers ───────────────────────────────────────────────────────

// OID 1.2.840.113635.100.8.2 as a DER TLV (tag=0x06, length=9, then 9 OID bytes).
// Encoding: 2A 86 48 86 F7 63 64 08 02
//   1.2       → 1*40+2 = 42 = 0x2A
//   840       → 0x86 0x48
//   113635    → 0x86 0xF7 0x63
//   100       → 0x64
//   8         → 0x08
//   2         → 0x02
const APP_ATTEST_NONCE_OID_TLV = Buffer.from('06092a864886f763640802', 'hex')

/**
 * Extracts the 32-byte nonce from an Apple App Attest credential certificate.
 *
 * Extension OID 1.2.840.113635.100.8.2 value (inside the OCTET STRING extnValue wrapper):
 *   SEQUENCE { SEQUENCE { [1] EXPLICIT { OCTET STRING(32) } } }
 *
 * Returns null if the extension is absent or the structure is unexpected.
 */
function extractAppAttestNonce(certDer: Buffer): Buffer | null {
  const oidIdx = certDer.indexOf(APP_ATTEST_NONCE_OID_TLV)
  if (oidIdx === -1) return null

  let pos = oidIdx + APP_ATTEST_NONCE_OID_TLV.length

  // Skip optional BOOLEAN criticality flag (tag 0x01).
  if (pos < certDer.length && certDer[pos] === 0x01) {
    pos += 2 + certDer[pos + 1]
  }

  // extnValue is an OCTET STRING (tag 0x04) wrapping the DER-encoded extension value.
  if (pos >= certDer.length || certDer[pos] !== 0x04) return null
  const extnValue = derReadValue(certDer, pos)
  if (!extnValue) return null
  let inner = extnValue

  // Outer SEQUENCE
  if (inner[0] !== 0x30) return null
  const seq1 = derReadValue(inner, 0)
  if (!seq1) return null
  inner = seq1

  // Inner SEQUENCE
  if (inner[0] !== 0x30) return null
  const seq2 = derReadValue(inner, 0)
  if (!seq2) return null
  inner = seq2

  // [1] EXPLICIT (tag 0xa1 = context-specific + constructed + tag 1)
  if (inner[0] !== 0xa1) return null
  const explicit1 = derReadValue(inner, 0)
  if (!explicit1) return null
  inner = explicit1

  // OCTET STRING containing the 32-byte nonce (tag 0x04, length 0x20)
  if (inner[0] !== 0x04) return null
  const nonce = derReadValue(inner, 0)
  if (!nonce || nonce.length !== 32) return null

  return nonce
}

/**
 * Reads the value bytes of a DER TLV at `offset` within `buf`.
 * Returns the value (without tag and length bytes), or null on any parse error.
 */
function derReadValue(buf: Buffer, offset: number): Buffer | null {
  if (offset + 2 > buf.length) return null

  // Tag is at offset; length starts at offset+1.
  const lenByte = buf[offset + 1]
  let length: number
  let headerLen: number // tag byte + length bytes

  if (lenByte < 0x80) {
    length = lenByte
    headerLen = 2
  } else {
    const numLenBytes = lenByte & 0x7f
    if (numLenBytes === 0 || numLenBytes > 4 || offset + 2 + numLenBytes > buf.length) return null
    length = 0
    for (let i = 0; i < numLenBytes; i++) {
      length = (length << 8) | buf[offset + 2 + i]
    }
    headerLen = 2 + numLenBytes
  }

  const valueStart = offset + headerLen
  if (valueStart + length > buf.length) return null
  return Buffer.from(buf.subarray(valueStart, valueStart + length))
}
