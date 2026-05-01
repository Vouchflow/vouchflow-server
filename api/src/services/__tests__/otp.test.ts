import { describe, it, expect } from 'vitest'
import {
  generateOtp,
  hashOtp,
  verifyOtp,
  OTP_LENGTH,
  OTP_EXPIRY_MINUTES,
  OTP_MAX_ATTEMPTS,
} from '../otp.js'

// Pure-unit tests for the OTP primitives. The fallback flow's only
// auth-relevant decision is `verifyOtp(candidate, storedHash)` returning
// true ↔ the candidate matches the original OTP. Cover that path along
// with the format/length invariants other code depends on.

describe('OTP parameters (§7)', () => {
  it('matches the documented spec — 6 digits, 5 min expiry, 3 attempts', () => {
    expect(OTP_LENGTH).toBe(6)
    expect(OTP_EXPIRY_MINUTES).toBe(5)
    expect(OTP_MAX_ATTEMPTS).toBe(3)
  })
})

describe('generateOtp', () => {
  it('returns a 6-digit string', () => {
    for (let i = 0; i < 50; i++) {
      const otp = generateOtp()
      expect(otp).toMatch(/^\d{6}$/)
    }
  })

  it('preserves leading zeros (000123, not 123)', () => {
    // Statistically, in 100k samples we should see at least one OTP with
    // a leading zero. If padStart is broken we'd see strings shorter than 6.
    let leadingZeroSeen = false
    for (let i = 0; i < 100_000 && !leadingZeroSeen; i++) {
      const otp = generateOtp()
      if (otp.length !== 6) {
        throw new Error(`Got OTP with wrong length: "${otp}"`)
      }
      if (otp.startsWith('0')) leadingZeroSeen = true
    }
    expect(leadingZeroSeen).toBe(true)
  })

  it('produces values with reasonable entropy across many samples', () => {
    // Not a real entropy test — just a sanity check that we're not
    // accidentally returning the same value over and over.
    const seen = new Set<string>()
    for (let i = 0; i < 1000; i++) seen.add(generateOtp())
    expect(seen.size).toBeGreaterThan(900)
  })
})

describe('hashOtp / verifyOtp', () => {
  it('hashes the OTP — output is hex SHA-256 of the input', () => {
    const otp = '123456'
    const h = hashOtp(otp)
    // SHA-256 of "123456" — well-known
    expect(h).toBe('8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92')
    expect(h).toMatch(/^[0-9a-f]{64}$/)
  })

  it('verifyOtp returns true for the matching plaintext', () => {
    const otp = generateOtp()
    expect(verifyOtp(otp, hashOtp(otp))).toBe(true)
  })

  it('verifyOtp returns false for a different OTP', () => {
    expect(verifyOtp('111111', hashOtp('123456'))).toBe(false)
  })

  it('verifyOtp returns false for a malformed stored hash (defensive)', () => {
    expect(verifyOtp('123456', 'not-hex')).toBe(false)
    expect(verifyOtp('123456', '')).toBe(false)
    expect(verifyOtp('123456', 'a'.repeat(63))).toBe(false) // wrong length
  })

  it('verifyOtp uses constant-time comparison (no early-exit on first byte)', () => {
    // We can't directly measure timing in a unit test, but we can verify
    // that crypto.timingSafeEqual is being used by feeding it inputs that
    // differ only in the LAST byte vs the FIRST byte. Both must return
    // false; that's all the test can assert at the API level. The
    // constant-time-ness is a property of the underlying primitive.
    const correctHash = hashOtp('123456')
    const flipFirst   = ('1' + correctHash.slice(1))
    const flipLast    = (correctHash.slice(0, -1) + '1')
    expect(verifyOtp('123456', flipFirst)).toBe(false)
    expect(verifyOtp('123456', flipLast)).toBe(false)
  })
})
