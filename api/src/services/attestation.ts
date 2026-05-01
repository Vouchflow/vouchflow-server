// §6 Decision 4: Attestation-anchored request signing.
//
// When attestation credentials are absent, validateAttestation returns
// { verified: false, reason: "credentials_not_configured" } and enrollment
// proceeds with confidence_ceiling: "medium". This is correct production-safe
// behaviour — not a development shortcut.
//
// Multi-tenant: iOS team_id and bundle_id, plus the Android package name and
// signing-key SHA-256, are per-customer values stored on the Customer row.
// Both root CAs (Apple App Attest, Google Hardware Attestation) are public
// certs and remain in env — they're identical across customers.
//
// Required env vars (fallback when Customer row is missing values):
//   iOS:     APPLE_APP_ATTEST_ROOT_CA  (always env — public root cert)
//            APPLE_TEAM_ID, APPLE_BUNDLE_ID  (single-tenant fallback)
//   Android: GOOGLE_HARDWARE_ATTESTATION_ROOT_CA  (always env — public roots,
//                                                  may contain multiple PEMs
//                                                  separated by blank lines)
//            ANDROID_PACKAGE_NAME, ANDROID_SIGNING_KEY_SHA256  (fallback)

import crypto from 'node:crypto'

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
  /** iOS App Attest base64 attestation object. */
  token: string | null
  /** iOS App Attest credential ID. */
  keyId: string | null
  /** Android Keystore Attestation cert chain, leaf-first, each cert base64-DER. */
  certChain: string[] | null
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
  // Android Keystore Attestation. Root CA(s) are public Google certs (env
  // only); package name and signing-key SHA-256 are per-customer.
  googleAttestationRootCa?: string
  androidPackageName?: string
  androidSigningKeySha256?: string
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
    androidSigningKeySha256?: string | null
  } | null,
): AttestationConfig {
  return {
    appleRootCa: process.env.APPLE_APP_ATTEST_ROOT_CA,
    appleTeamId: customer?.iosTeamId ?? process.env.APPLE_TEAM_ID,
    appleBundleId: customer?.iosBundleId ?? process.env.APPLE_BUNDLE_ID,
    googleAttestationRootCa: process.env.GOOGLE_HARDWARE_ATTESTATION_ROOT_CA,
    androidPackageName: customer?.androidPackageName ?? process.env.ANDROID_PACKAGE_NAME,
    androidSigningKeySha256:
      customer?.androidSigningKeySha256 ?? process.env.ANDROID_SIGNING_KEY_SHA256,
  }
}

export async function validateAttestation(
  input: AttestationInput,
  config: AttestationConfig,
): Promise<AttestationResult> {
  if (input.platform === 'ios') {
    return validateAppAttest(input, config)
  } else if (input.platform === 'android') {
    return validateKeystoreAttestation(input, config)
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
  if (!input.token) {
    return { verified: false, reason: 'missing_attestation_token' }
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

// ── Android Keystore Attestation ──────────────────────────────────────────────
//
// The Android Keystore generates the device signing key with
// setAttestationChallenge(idempotencyKey) and exposes a certificate chain
// rooted in the Google Hardware Attestation Root CA. The leaf certificate
// carries an extension (OID 1.3.6.1.4.1.11129.2.1.17) describing how the
// key was created — security level, the original challenge, and the
// AttestationApplicationId of the calling app (package name + signing cert
// digest). Validating the chain + parsing this extension proves the key
// lives in genuine TEE/StrongBox hardware on a real Android device, was
// generated in response to *our* challenge, and was created by *this*
// customer's app.
//
// References:
//   https://source.android.com/docs/security/features/keystore/attestation
//   https://developer.android.com/privacy-and-security/security-key-attestation

const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17'

// Tag numbers used inside the AuthorizationList SEQUENCE. Each is a
// context-specific EXPLICIT tag wrapping the value. Only the ones we care
// about are listed here; the rest are skipped during parsing.
const ATTESTATION_APPLICATION_ID_TAG = 709
// SecurityLevel ENUMERATED values (KeyDescription field).
const SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
const SECURITY_LEVEL_STRONG_BOX = 2

async function validateKeystoreAttestation(
  input: AttestationInput,
  config: AttestationConfig,
): Promise<AttestationResult> {
  const { googleAttestationRootCa, androidPackageName, androidSigningKeySha256 } = config

  if (!googleAttestationRootCa || !androidPackageName || !androidSigningKeySha256) {
    return { verified: false, reason: 'credentials_not_configured' }
  }
  if (!input.certChain || input.certChain.length === 0) {
    return { verified: false, reason: 'missing_cert_chain' }
  }

  try {
    // 1. Parse the chain (leaf-first, base64-DER) and walk it to one of the
    //    pinned Google Hardware Attestation roots.
    const chain = input.certChain.map(b64 => new crypto.X509Certificate(Buffer.from(b64, 'base64')))
    const roots = parsePemBundle(googleAttestationRootCa).map(d => new crypto.X509Certificate(d))

    for (let i = 0; i < chain.length - 1; i++) {
      if (!chain[i].verify(chain[i + 1].publicKey)) {
        return { verified: false, reason: 'cert_chain_invalid' }
      }
    }
    const topOfChain = chain[chain.length - 1]
    const rootMatch = roots.find(r => topOfChain.verify(r.publicKey) || areSameCert(topOfChain, r))
    if (!rootMatch) {
      return { verified: false, reason: 'cert_chain_not_rooted' }
    }

    // 2. Extract the KeyDescription extension from the leaf cert.
    const leafDer = Buffer.from(input.certChain[0], 'base64')
    const keyDescription = extractExtension(leafDer, KEY_DESCRIPTION_OID)
    if (!keyDescription) {
      return { verified: false, reason: 'attestation_extension_missing' }
    }

    // 3. Parse the KeyDescription SEQUENCE.
    //    KeyDescription ::= SEQUENCE {
    //       attestationVersion       INTEGER,
    //       attestationSecurityLevel SecurityLevel,
    //       keyMintVersion           INTEGER,
    //       keyMintSecurityLevel     SecurityLevel,
    //       attestationChallenge     OCTET_STRING,
    //       uniqueId                 OCTET_STRING,
    //       softwareEnforced         AuthorizationList,
    //       hardwareEnforced         AuthorizationList,
    //    }
    const desc = derSequenceChildren(keyDescription)
    if (!desc || desc.length < 8) {
      return { verified: false, reason: 'attestation_extension_malformed' }
    }
    const attestationSecurityLevel = derReadEnumerated(desc[1])
    const attestationChallenge = derReadOctetString(desc[4])
    const softwareEnforced = derSequenceChildren(desc[6]) ?? []
    const hardwareEnforced = derSequenceChildren(desc[7]) ?? []

    // 4. Security level: require TEE or StrongBox. Reject Software (0).
    if (attestationSecurityLevel !== SECURITY_LEVEL_TRUSTED_ENVIRONMENT &&
        attestationSecurityLevel !== SECURITY_LEVEL_STRONG_BOX) {
      return { verified: false, reason: 'security_level_software' }
    }

    // 5. Challenge: must equal our idempotency key (UTF-8 bytes).
    //    Compare length first — timingSafeEqual throws on mismatched
    //    lengths rather than returning false, which would otherwise be
    //    surfaced as the generic 'attestation_parse_error'.
    {
      const expected = Buffer.from(input.nonce, 'utf8')
      if (!attestationChallenge ||
          attestationChallenge.length !== expected.length ||
          !crypto.timingSafeEqual(attestationChallenge, expected)) {
        return { verified: false, reason: 'challenge_mismatch' }
      }
    }

    // 6. AttestationApplicationId: package name + signing-cert digest. Must
    //    match the customer's registered values. The field appears in the
    //    softwareEnforced AuthorizationList (KeyMint records the calling
    //    app's identity here, not in hardwareEnforced).
    const appIdOctets = findAuthListField(softwareEnforced, ATTESTATION_APPLICATION_ID_TAG)
      ?? findAuthListField(hardwareEnforced, ATTESTATION_APPLICATION_ID_TAG)
    if (!appIdOctets) {
      return { verified: false, reason: 'attestation_application_id_missing' }
    }
    const appId = parseAttestationApplicationId(appIdOctets)
    if (!appId) {
      return { verified: false, reason: 'attestation_application_id_malformed' }
    }
    if (!appId.packageNames.includes(androidPackageName)) {
      return { verified: false, reason: 'package_name_mismatch' }
    }
    const expectedDigest = Buffer.from(androidSigningKeySha256, 'hex')
    const digestMatch = appId.signatureDigests.some(
      d => d.length === expectedDigest.length && crypto.timingSafeEqual(d, expectedDigest),
    )
    if (!digestMatch) {
      return { verified: false, reason: 'signing_key_mismatch' }
    }

    return { verified: true }
  } catch {
    return { verified: false, reason: 'attestation_parse_error' }
  }
}

/** True when both certs have identical DER. Used to accept a self-signed
 *  root that's already in our pinned bundle without recomputing signatures. */
function areSameCert(a: crypto.X509Certificate, b: crypto.X509Certificate): boolean {
  return Buffer.compare(Buffer.from(a.raw), Buffer.from(b.raw)) === 0
}

/** Splits a PEM bundle into one DER buffer per certificate. Accepts CRLF or
 *  LF, with or without surrounding whitespace. */
function parsePemBundle(pem: string): Buffer[] {
  const matches = pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)
  const out: Buffer[] = []
  for (const m of matches) {
    const b64 = m[1].replace(/\s+/g, '')
    out.push(Buffer.from(b64, 'base64'))
  }
  return out
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

/** Reads the full TLV header at `offset`, returning the decoded tag number,
 *  the offset of the value bytes, and the value length. Handles both
 *  short-form (single tag byte) and long-form (low 5 bits == 0x1f, with
 *  base-128 continuation bytes) tag encodings — the latter is used by the
 *  context-specific EXPLICIT tags inside Keystore Attestation's
 *  AuthorizationList (e.g. tag 709 for attestationApplicationId). For
 *  short-form tags, the returned `tag` equals the literal first byte (so
 *  callers checking `tag === 0x30` for SEQUENCE still work unchanged). */
function derReadHeader(buf: Buffer, offset: number): { tag: number; valueOffset: number; length: number } | null {
  if (offset + 2 > buf.length) return null
  let pos = offset
  const firstTagByte = buf[pos]
  pos += 1

  let tag = firstTagByte
  if ((firstTagByte & 0x1f) === 0x1f) {
    // Long-form tag: continuation bytes with high bit until cleared.
    let tagNumber = 0
    let consumed = 0
    while (pos < buf.length) {
      const b = buf[pos]
      pos += 1
      consumed += 1
      tagNumber = (tagNumber << 7) | (b & 0x7f)
      if ((b & 0x80) === 0) break
      if (consumed > 4) return null  // defensive cap on tag length
    }
    if (consumed === 0) return null
    tag = tagNumber
  }

  if (pos >= buf.length) return null
  const lenByte = buf[pos]
  pos += 1
  let length: number

  if (lenByte < 0x80) {
    length = lenByte
  } else {
    const numLenBytes = lenByte & 0x7f
    if (numLenBytes === 0 || numLenBytes > 4 || pos + numLenBytes > buf.length) return null
    length = 0
    for (let i = 0; i < numLenBytes; i++) {
      length = (length << 8) | buf[pos + i]
    }
    pos += numLenBytes
  }

  const valueOffset = pos
  if (valueOffset + length > buf.length) return null
  return { tag, valueOffset, length }
}

/** Splits a DER SEQUENCE / SET / constructed value into its element TLVs (each
 *  element returned with its tag bytes intact, suitable for re-parsing). The
 *  input is the *contents* of the SEQUENCE — i.e. caller has already stripped
 *  the outer tag/length. */
function derSplitChildren(contents: Buffer): Buffer[] | null {
  const out: Buffer[] = []
  let pos = 0
  while (pos < contents.length) {
    const h = derReadHeader(contents, pos)
    if (!h) return null
    const total = (h.valueOffset - pos) + h.length
    out.push(Buffer.from(contents.subarray(pos, pos + total)))
    pos += total
  }
  return out
}

/** Splits the contents of a SEQUENCE-tagged buffer (tag + length + value).
 *  Convenience wrapper that strips the outer tag. */
function derSequenceChildren(seq: Buffer): Buffer[] | null {
  if (seq.length < 2) return null
  const h = derReadHeader(seq, 0)
  if (!h || h.tag !== 0x30) return null
  return derSplitChildren(seq.subarray(h.valueOffset, h.valueOffset + h.length))
}

/** Reads the integer value of an ENUMERATED (tag 0x0a). Returns null on
 *  malformed input or a value too large to fit in a JS safe integer. */
function derReadEnumerated(tlv: Buffer): number | null {
  if (tlv.length < 2 || tlv[0] !== 0x0a) return null
  const h = derReadHeader(tlv, 0)
  if (!h) return null
  if (h.length === 0 || h.length > 6) return null
  let v = 0
  for (let i = 0; i < h.length; i++) v = (v << 8) | tlv[h.valueOffset + i]
  return v
}

/** Reads the bytes of an OCTET STRING (tag 0x04). */
function derReadOctetString(tlv: Buffer): Buffer | null {
  if (tlv.length < 2 || tlv[0] !== 0x04) return null
  const h = derReadHeader(tlv, 0)
  if (!h) return null
  return Buffer.from(tlv.subarray(h.valueOffset, h.valueOffset + h.length))
}

/** Walks the AuthorizationList SEQUENCE looking for a context-specific
 *  EXPLICIT tag matching `tagNumber`. Returns the inner OCTET_STRING contents
 *  for tag 709 (attestationApplicationId), or null if not found. */
function findAuthListField(children: Buffer[], tagNumber: number): Buffer | null {
  // Context-specific constructed tags >30 use long-form: 0xbf, then the tag
  // number encoded base-128 with high bit set on continuation bytes.
  // For tag 709 (= 0b101_1000101), the encoded form is 0xbf 0x85 0x45.
  const expectedTagBytes = encodeContextTag(tagNumber)
  for (const child of children) {
    if (child.length < expectedTagBytes.length) continue
    if (Buffer.compare(child.subarray(0, expectedTagBytes.length), expectedTagBytes) !== 0) continue
    // EXPLICIT tag wraps the inner value. Skip past the context-specific
    // header and read the inner OCTET STRING.
    const outerHdrLen = derReadVarHeaderLength(child, expectedTagBytes.length)
    if (outerHdrLen < 0) return null
    const innerStart = expectedTagBytes.length + outerHdrLen
    const inner = child.subarray(innerStart)
    if (inner.length < 2 || inner[0] !== 0x04) return null
    return derReadOctetString(inner)
  }
  return null
}

/** Encodes a context-specific constructed EXPLICIT tag (class=10, P/C=1) for
 *  a given tag number. Tag numbers <31 use a single byte; >=31 use long form. */
function encodeContextTag(tagNumber: number): Buffer {
  if (tagNumber < 31) {
    return Buffer.from([0xa0 | tagNumber])
  }
  // Long form: leading byte 0xbf, then base-128 with high bit on continuation.
  const bytes: number[] = [0xbf]
  const tmp: number[] = []
  let n = tagNumber
  while (n > 0) {
    tmp.unshift(n & 0x7f)
    n >>>= 7
  }
  for (let i = 0; i < tmp.length - 1; i++) tmp[i] |= 0x80
  return Buffer.from(bytes.concat(tmp))
}

/** Reads only the length-bytes portion of a TLV header at `offset`, returning
 *  the number of bytes the length itself occupies (1 for short form, 1 + N
 *  for long form). Returns -1 on malformed input. */
function derReadVarHeaderLength(buf: Buffer, offset: number): number {
  if (offset >= buf.length) return -1
  const lenByte = buf[offset]
  if (lenByte < 0x80) return 1
  const numLenBytes = lenByte & 0x7f
  if (numLenBytes === 0 || numLenBytes > 4 || offset + 1 + numLenBytes > buf.length) return -1
  return 1 + numLenBytes
}

/** Locates an X.509 v3 extension by OID and returns its extnValue (the
 *  contents of the OCTET STRING wrapping the extension's payload). */
function extractExtension(certDer: Buffer, oidDotted: string): Buffer | null {
  const oidBytes = encodeOid(oidDotted)
  if (!oidBytes) return null
  // The extension OID appears as a TLV inside the cert. Search for the OID's
  // DER TLV form, then read the surrounding extension SEQUENCE's extnValue.
  const oidTlv = Buffer.concat([Buffer.from([0x06, oidBytes.length]), oidBytes])
  const idx = certDer.indexOf(oidTlv)
  if (idx === -1) return null

  let pos = idx + oidTlv.length
  // Optional BOOLEAN criticality flag.
  if (pos < certDer.length && certDer[pos] === 0x01) {
    const h = derReadHeader(certDer, pos)
    if (!h) return null
    pos = h.valueOffset + h.length
  }
  // extnValue OCTET STRING wrapping the actual extension content.
  if (pos >= certDer.length || certDer[pos] !== 0x04) return null
  const outer = derReadValue(certDer, pos)
  if (!outer) return null
  return outer
}

/** DER-encodes a dotted OID string (e.g. "1.3.6.1.4.1.11129.2.1.17") as a
 *  raw value (without the leading tag/length bytes). Returns null on
 *  malformed input. */
function encodeOid(dotted: string): Buffer | null {
  const parts = dotted.split('.').map(p => parseInt(p, 10))
  if (parts.length < 2 || parts.some(p => Number.isNaN(p) || p < 0)) return null
  const out: number[] = [parts[0] * 40 + parts[1]]
  for (let i = 2; i < parts.length; i++) {
    let n = parts[i]
    if (n < 0x80) {
      out.push(n)
    } else {
      const tmp: number[] = []
      while (n > 0) {
        tmp.unshift(n & 0x7f)
        n >>>= 7
      }
      for (let j = 0; j < tmp.length - 1; j++) tmp[j] |= 0x80
      out.push(...tmp)
    }
  }
  return Buffer.from(out)
}

/** Parses an AttestationApplicationId DER blob:
 *    AttestationApplicationId ::= SEQUENCE {
 *       package_infos         SET OF AttestationPackageInfo,
 *       signature_digests     SET OF OCTET_STRING
 *    }
 *    AttestationPackageInfo ::= SEQUENCE {
 *       package_name          OCTET_STRING,
 *       version               INTEGER
 *    }
 *  Returns the package names and signing-cert digests, or null on parse error. */
function parseAttestationApplicationId(
  octets: Buffer,
): { packageNames: string[]; signatureDigests: Buffer[] } | null {
  const top = derSequenceChildren(octets)
  if (!top || top.length < 2) return null
  // packageInfos SET OF SEQUENCE
  const packageInfosOuter = top[0]
  if (packageInfosOuter[0] !== 0x31) return null
  const packageInfoTLVs = derSplitChildren(
    packageInfosOuter.subarray(derReadHeader(packageInfosOuter, 0)?.valueOffset ?? 0),
  )
  if (!packageInfoTLVs) return null
  const packageNames: string[] = []
  for (const piTlv of packageInfoTLVs) {
    const piChildren = derSequenceChildren(piTlv)
    if (!piChildren || piChildren.length < 1) continue
    const name = derReadOctetString(piChildren[0])
    if (name) packageNames.push(name.toString('utf8'))
  }
  // signatureDigests SET OF OCTET_STRING
  const sigOuter = top[1]
  if (sigOuter[0] !== 0x31) return null
  const sigTLVs = derSplitChildren(
    sigOuter.subarray(derReadHeader(sigOuter, 0)?.valueOffset ?? 0),
  )
  if (!sigTLVs) return null
  const signatureDigests: Buffer[] = []
  for (const sigTlv of sigTLVs) {
    const d = derReadOctetString(sigTlv)
    if (d) signatureDigests.push(d)
  }
  return { packageNames, signatureDigests }
}

// ── Internals exposed for unit testing ────────────────────────────────────────
//
// The ASN.1 parsers above are private to the validators in production use, but
// they're exactly the surface where a subtle off-by-one or length-confusion bug
// could let a crafted attestation chain bypass validation. Exposing them under
// a clearly-internal name lets the test suite hit them directly with crafted
// DER without needing real device fixtures. Production callers should never
// import this object — it's a stable test seam, not a public API.
export const __test_internals__ = {
  derReadHeader,
  derReadValue,
  derSplitChildren,
  derSequenceChildren,
  derReadEnumerated,
  derReadOctetString,
  encodeContextTag,
  encodeOid,
  extractExtension,
  parseAttestationApplicationId,
  parsePemBundle,
  findAuthListField,
}
