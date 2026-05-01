import { describe, it, expect } from 'vitest'
import { __test_internals__ as P } from '../attestation.js'

// Hand-rolled ASN.1 parsers carry the highest single-bug-blast-radius in
// security-critical code. These tests hit each helper with crafted DER, both
// well-formed and malformed, to cover the cases where a parser bug could
// leak the wrong field — or worse, silently accept a tampered attestation.

// ── Helpers for building DER bytes ───────────────────────────────────────────

/** Encodes a length in DER (short form for <128, long form otherwise). */
function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n])
  const bytes: number[] = []
  let v = n
  while (v > 0) { bytes.unshift(v & 0xff); v >>>= 8 }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}
function tlv(tag: number, value: Buffer | number[]): Buffer {
  const v = Buffer.isBuffer(value) ? value : Buffer.from(value)
  return Buffer.concat([Buffer.from([tag]), derLen(v.length), v])
}
const SEQ = 0x30
const SET = 0x31
const OCTET_STRING = 0x04
const INTEGER = 0x02
const ENUMERATED = 0x0a

// ── derReadHeader ────────────────────────────────────────────────────────────

describe('derReadHeader', () => {
  it('parses short-form length (single byte)', () => {
    const buf = Buffer.from([0x04, 0x05, 1, 2, 3, 4, 5])
    const h = P.derReadHeader(buf, 0)
    expect(h).toEqual({ tag: 0x04, valueOffset: 2, length: 5 })
  })

  it('parses long-form length (1 length byte → encodes value 0x80+)', () => {
    const buf = Buffer.concat([Buffer.from([0x04, 0x81, 200]), Buffer.alloc(200, 0xaa)])
    const h = P.derReadHeader(buf, 0)
    expect(h).toEqual({ tag: 0x04, valueOffset: 3, length: 200 })
  })

  it('parses long-form length (2 length bytes)', () => {
    const len = 0x1234
    const buf = Buffer.concat([Buffer.from([0x04, 0x82, 0x12, 0x34]), Buffer.alloc(len, 0)])
    const h = P.derReadHeader(buf, 0)
    expect(h).toEqual({ tag: 0x04, valueOffset: 4, length: len })
  })

  it('returns null on truncated header', () => {
    expect(P.derReadHeader(Buffer.from([0x04]), 0)).toBeNull()
  })

  it('returns null when long-form length declares more length bytes than fit', () => {
    expect(P.derReadHeader(Buffer.from([0x04, 0x82, 0x12]), 0)).toBeNull()
  })

  it('returns null when value bytes would extend past buffer', () => {
    expect(P.derReadHeader(Buffer.from([0x04, 0x05, 1, 2]), 0)).toBeNull()
  })

  it('returns null for length-of-length = 0 (indefinite form not allowed in DER)', () => {
    expect(P.derReadHeader(Buffer.from([0x04, 0x80]), 0)).toBeNull()
  })

  it('returns null for length-of-length > 4 (over our parse cap)', () => {
    expect(P.derReadHeader(Buffer.from([0x04, 0x85, 0, 0, 0, 0, 0]), 0)).toBeNull()
  })
})

// ── derReadValue ─────────────────────────────────────────────────────────────

describe('derReadValue', () => {
  it('extracts the value bytes of a TLV', () => {
    const buf = Buffer.from([0x04, 0x03, 0xaa, 0xbb, 0xcc])
    const v = P.derReadValue(buf, 0)
    expect(v).toEqual(Buffer.from([0xaa, 0xbb, 0xcc]))
  })

  it('returns null on a truncated TLV', () => {
    expect(P.derReadValue(Buffer.from([0x04, 0x05, 1, 2]), 0)).toBeNull()
  })
})

// ── derSplitChildren / derSequenceChildren ──────────────────────────────────

describe('derSequenceChildren', () => {
  it('splits a SEQUENCE into its element TLVs', () => {
    const inner1 = tlv(INTEGER, [0x07])
    const inner2 = tlv(OCTET_STRING, [0xde, 0xad])
    const seq = tlv(SEQ, Buffer.concat([inner1, inner2]))
    const out = P.derSequenceChildren(seq)
    expect(out).not.toBeNull()
    expect(out!.length).toBe(2)
    expect(out![0]).toEqual(inner1)
    expect(out![1]).toEqual(inner2)
  })

  it('returns null when the outer tag is not SEQUENCE', () => {
    const notSeq = tlv(OCTET_STRING, [0x01, 0x02])
    expect(P.derSequenceChildren(notSeq)).toBeNull()
  })

  it('returns null on a malformed inner element', () => {
    const seq = Buffer.from([SEQ, 0x04, 0x04, 0x05, 0x01, 0x02]) // inner says len=5 but only 2 bytes
    expect(P.derSequenceChildren(seq)).toBeNull()
  })

  it('handles an empty SEQUENCE', () => {
    const seq = tlv(SEQ, [])
    expect(P.derSequenceChildren(seq)).toEqual([])
  })
})

// ── derReadEnumerated ───────────────────────────────────────────────────────

describe('derReadEnumerated', () => {
  it('reads a 1-byte ENUMERATED', () => {
    expect(P.derReadEnumerated(tlv(ENUMERATED, [0x02]))).toBe(2)
  })

  it('reads a multi-byte ENUMERATED in big-endian', () => {
    expect(P.derReadEnumerated(tlv(ENUMERATED, [0x01, 0x00]))).toBe(0x100)
  })

  it('rejects non-ENUMERATED tag', () => {
    expect(P.derReadEnumerated(tlv(INTEGER, [0x02]))).toBeNull()
  })

  it('rejects empty value', () => {
    expect(P.derReadEnumerated(Buffer.from([ENUMERATED, 0x00]))).toBeNull()
  })

  it('rejects values larger than 6 bytes (defensive cap)', () => {
    expect(P.derReadEnumerated(tlv(ENUMERATED, [0, 0, 0, 0, 0, 0, 0]))).toBeNull()
  })
})

// ── derReadOctetString ──────────────────────────────────────────────────────

describe('derReadOctetString', () => {
  it('reads bytes of an OCTET STRING', () => {
    expect(P.derReadOctetString(tlv(OCTET_STRING, [0xab, 0xcd]))).toEqual(Buffer.from([0xab, 0xcd]))
  })

  it('rejects non-OCTET-STRING tag', () => {
    expect(P.derReadOctetString(tlv(INTEGER, [0xab]))).toBeNull()
  })

  it('handles a zero-length OCTET STRING', () => {
    expect(P.derReadOctetString(tlv(OCTET_STRING, []))).toEqual(Buffer.alloc(0))
  })
})

// ── encodeOid ──────────────────────────────────────────────────────────────

describe('encodeOid', () => {
  it('encodes the Android Keystore Attestation extension OID 1.3.6.1.4.1.11129.2.1.17', () => {
    const expected = Buffer.from('2b06010401d679020111', 'hex')
    expect(P.encodeOid('1.3.6.1.4.1.11129.2.1.17')).toEqual(expected)
  })

  it('encodes the App Attest nonce extension OID 1.2.840.113635.100.8.2', () => {
    // 113635 = 6·128² + 119·128 + 99 → base-128 [6, 119, 99] with continuation
    // bits on all but the last byte → 0x86 0xF7 0x63
    const expected = Buffer.from('2a864886f763640802', 'hex')
    expect(P.encodeOid('1.2.840.113635.100.8.2')).toEqual(expected)
  })

  it('returns null on malformed OID', () => {
    expect(P.encodeOid('not-an-oid')).toBeNull()
    expect(P.encodeOid('1')).toBeNull()  // need at least two parts for the first byte rule
    expect(P.encodeOid('1.-1.5')).toBeNull()
  })

  it('handles single-byte arc values', () => {
    // 1.2.0 → first byte 0x2a, then 0x00
    expect(P.encodeOid('1.2.0')).toEqual(Buffer.from([0x2a, 0x00]))
  })
})

// ── encodeContextTag ───────────────────────────────────────────────────────

describe('encodeContextTag', () => {
  it('encodes short-form for tags <31', () => {
    expect(P.encodeContextTag(0)).toEqual(Buffer.from([0xa0]))
    expect(P.encodeContextTag(1)).toEqual(Buffer.from([0xa1]))
    expect(P.encodeContextTag(30)).toEqual(Buffer.from([0xa0 | 30]))
  })

  it('encodes long-form for tag 709 (attestationApplicationId)', () => {
    // 709 = 0b101_1000101 → high-7-bit byte 0b00000101 (5), low-7-bit byte 0b1000101 (0x45)
    // With continuation bit on the high byte: 0x85 0x45
    expect(P.encodeContextTag(709)).toEqual(Buffer.from([0xbf, 0x85, 0x45]))
  })

  it('encodes long-form for tag 31 (smallest long-form value)', () => {
    expect(P.encodeContextTag(31)).toEqual(Buffer.from([0xbf, 0x1f]))
  })
})

// ── extractExtension ────────────────────────────────────────────────────────

describe('extractExtension', () => {
  // Build a minimal cert-shaped buffer that contains an extension with our OID.
  // We don't need a real cert; extractExtension just searches for the OID TLV.
  it('returns the extnValue contents for a known OID', () => {
    const oidDer = P.encodeOid('1.3.6.1.4.1.11129.2.1.17')!
    const oidTlv = Buffer.concat([Buffer.from([0x06, oidDer.length]), oidDer])
    const innerPayload = Buffer.from([0xde, 0xad, 0xbe, 0xef])
    const extnValue = tlv(OCTET_STRING, innerPayload)
    const blob = Buffer.concat([Buffer.from([0xff, 0xff]), oidTlv, extnValue])
    const got = P.extractExtension(blob, '1.3.6.1.4.1.11129.2.1.17')
    expect(got).toEqual(innerPayload)
  })

  it('skips the optional BOOLEAN criticality flag between OID and extnValue', () => {
    const oidDer = P.encodeOid('1.3.6.1.4.1.11129.2.1.17')!
    const oidTlv = Buffer.concat([Buffer.from([0x06, oidDer.length]), oidDer])
    const criticalFlag = Buffer.from([0x01, 0x01, 0xff]) // BOOLEAN TRUE
    const innerPayload = Buffer.from([0xab, 0xcd])
    const extnValue = tlv(OCTET_STRING, innerPayload)
    const blob = Buffer.concat([oidTlv, criticalFlag, extnValue])
    const got = P.extractExtension(blob, '1.3.6.1.4.1.11129.2.1.17')
    expect(got).toEqual(innerPayload)
  })

  it('returns null when the OID is absent', () => {
    const blob = Buffer.from([0x00, 0x01, 0x02])
    expect(P.extractExtension(blob, '1.3.6.1.4.1.11129.2.1.17')).toBeNull()
  })

  it('returns null on malformed input OID string', () => {
    expect(P.extractExtension(Buffer.alloc(10), 'not-an-oid')).toBeNull()
  })
})

// ── parseAttestationApplicationId ──────────────────────────────────────────

describe('parseAttestationApplicationId', () => {
  function buildAttApId(packages: string[], digests: Buffer[]): Buffer {
    const packageInfos = packages.map(name =>
      tlv(SEQ, Buffer.concat([
        tlv(OCTET_STRING, Buffer.from(name, 'utf8')),
        tlv(INTEGER, [0x01]),
      ])),
    )
    const sigDigests = digests.map(d => tlv(OCTET_STRING, d))
    return tlv(SEQ, Buffer.concat([
      tlv(SET, Buffer.concat(packageInfos)),
      tlv(SET, Buffer.concat(sigDigests)),
    ]))
  }

  it('parses a single package with a single signature digest', () => {
    const digest = Buffer.alloc(32, 0x55)
    const blob = buildAttApId(['com.example.app'], [digest])
    const got = P.parseAttestationApplicationId(blob)
    expect(got).not.toBeNull()
    expect(got!.packageNames).toEqual(['com.example.app'])
    expect(got!.signatureDigests).toEqual([digest])
  })

  it('parses multiple packages and multiple signature digests', () => {
    const d1 = Buffer.alloc(32, 0xaa)
    const d2 = Buffer.alloc(32, 0xbb)
    const blob = buildAttApId(['com.a', 'com.b'], [d1, d2])
    const got = P.parseAttestationApplicationId(blob)
    expect(got!.packageNames).toEqual(['com.a', 'com.b'])
    expect(got!.signatureDigests).toEqual([d1, d2])
  })

  it('returns null on a non-SEQUENCE root', () => {
    expect(P.parseAttestationApplicationId(tlv(OCTET_STRING, [0]))).toBeNull()
  })

  it('returns null when the second child is not a SET', () => {
    const garbage = tlv(SEQ, Buffer.concat([
      tlv(SET, tlv(SEQ, Buffer.concat([tlv(OCTET_STRING, Buffer.from('com.x', 'utf8')), tlv(INTEGER, [1])]))),
      tlv(OCTET_STRING, Buffer.alloc(32, 0)), // wrong tag where SET is expected
    ]))
    expect(P.parseAttestationApplicationId(garbage)).toBeNull()
  })

  it('returns null on truncated input', () => {
    expect(P.parseAttestationApplicationId(Buffer.from([0x30, 0x05, 0x01]))).toBeNull()
  })
})

// ── parsePemBundle ──────────────────────────────────────────────────────────

describe('parsePemBundle', () => {
  it('returns one DER per BEGIN/END block', () => {
    const cert = 'AAAA'
    const pem = `-----BEGIN CERTIFICATE-----
${cert}
-----END CERTIFICATE-----`
    const der = P.parsePemBundle(pem)
    expect(der.length).toBe(1)
    expect(der[0].toString('base64')).toBe(cert)
  })

  it('handles multiple concatenated certs separated by whitespace', () => {
    const pem = [
      '-----BEGIN CERTIFICATE-----', 'AAAA', '-----END CERTIFICATE-----',
      '',
      '-----BEGIN CERTIFICATE-----', 'BBBB', '-----END CERTIFICATE-----',
    ].join('\n')
    const der = P.parsePemBundle(pem)
    expect(der.length).toBe(2)
    expect(der[0].toString('base64')).toBe('AAAA')
    expect(der[1].toString('base64')).toBe('BBBB')
  })

  it('tolerates CRLF line endings and surrounding whitespace', () => {
    const pem = '\r\n  -----BEGIN CERTIFICATE-----\r\n  AAAA  \r\n-----END CERTIFICATE-----  \r\n'
    const der = P.parsePemBundle(pem)
    expect(der.length).toBe(1)
    expect(der[0].toString('base64')).toBe('AAAA')
  })

  it('returns empty array when no BEGIN/END blocks are present', () => {
    expect(P.parsePemBundle('totally not a pem')).toEqual([])
  })
})

// ── findAuthListField ──────────────────────────────────────────────────────

describe('findAuthListField', () => {
  it('returns the inner OCTET STRING value for tag 709 (attestationApplicationId)', () => {
    const inner = Buffer.from([0xde, 0xad, 0xbe, 0xef])
    const innerOctet = tlv(OCTET_STRING, inner)
    // Build the EXPLICIT [709] wrapper: tag 0xbf 0x85 0x45 + length + inner OCTET STRING
    const tagBytes = P.encodeContextTag(709)
    const wrapper = Buffer.concat([tagBytes, derLen(innerOctet.length), innerOctet])
    expect(P.findAuthListField([wrapper], 709)).toEqual(inner)
  })

  it('returns null when the tag is not present in the children', () => {
    const otherWrapper = Buffer.concat([P.encodeContextTag(1), Buffer.from([0x02, 0x04, 0x00])])
    expect(P.findAuthListField([otherWrapper], 709)).toBeNull()
  })

  it('returns null when the inner is not an OCTET STRING', () => {
    const innerNotOctet = tlv(INTEGER, [0x05])
    const tagBytes = P.encodeContextTag(709)
    const wrapper = Buffer.concat([tagBytes, derLen(innerNotOctet.length), innerNotOctet])
    expect(P.findAuthListField([wrapper], 709)).toBeNull()
  })
})
