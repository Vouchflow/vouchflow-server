import { describe, it, expect } from 'vitest'
import { extractAppAttestNonce } from '../attestation.js'

// Golden vector: the credential certificate from a REAL Apple App Attest
// attestation (dev environment, app 979F6L8R8M.org.reactjs.native.example.
// RNClientAttest). Sourced from the appattest-checker-node reference suite.
//
// Regression guard for the nonce-extension parser. The credCert extension
// (OID 1.2.840.113635.100.8.2) is DER:  30 24 A1 22 04 20 <32-byte nonce>
//   = SEQUENCE { [1] EXPLICIT { OCTET STRING(32) } }   ← ONE sequence.
// A prior version unwrapped TWO sequences and returned null for every genuine
// attestation, flooring real iPhones to low confidence. This test fails if
// that regresses.
const CRED_CERT_DER_B64 = 'MIIDQTCCAsegAwIBAgIGAY1LtHElMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI0MDEyNjE2MTUzM1oXDTI1MDExMzEzNDYzM1owgZExSTBHBgNVBAMMQGZiYjM1NjJkYWMyMmMyMmQ2NWM4YWVhZmM2YTFmMzUyOWQ1YjVmMzMyMzhiZjE2ZGYzZGNlZDMyYTNkNmUwN2UxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBxvOEkYXjdJPbouGYZZwNN1aaK+YtqAC2aStd1CUVnVwk9ntq+U+Jcf3kDaLQTLl7rgPRl3LM8BzvgCz1gNTl6OCAUowggFGMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMIGXBgkqhkiG92NkCAUEgYkwgYakAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIBAb+JMwMCAQG/iTQ2BDQ5NzlGNkw4UjhNLm9yZy5yZWFjdGpzLm5hdGl2ZS5leGFtcGxlLlJOQ2xpZW50QXR0ZXN0pQYEBHNrcyC/iTYDAgEFv4k3AwIBAL+JOQMCAQC/iToDAgEAv4k7AwIBADBXBgkqhkiG92NkCAcESjBIv4p4CAQGMTcuMi4xv4hQBwIFAP////+/insHBAUyMUM2Nr+KfQgEBjE3LjIuMb+KfgMCAQC/iwwPBA0yMS4zLjY2LjAuMCwwMDMGCSqGSIb3Y2QIAgQmMCShIgQgVpc8LKzNN3nGeZHVE3ulZOWLJ5eaCRS80Xr0l1qbH/wwCgYIKoZIzj0EAwIDaAAwZQIwTB3HSX9uExLcAvOZddR4J6hzndlu5ln/tftoB/5mUGaP1BrjmQZZoV9ZiwDW0oX7AjEAtW5dUTV/WioXujB1RAItag5gBGcKaViXJlH9b30j836XRZDXzJ9ru/Q3D9S0nhjr'
const EXPECTED_NONCE_HEX =
  '56973c2caccd3779c67991d5137ba564e58b27979a0914bcd17af4975a9b1ffc'

describe('extractAppAttestNonce (real Apple attestation golden vector)', () => {
  it('extracts the 32-byte nonce from a genuine credCert', () => {
    const der = Buffer.from(CRED_CERT_DER_B64, 'base64')
    const nonce = extractAppAttestNonce(der)
    expect(nonce).not.toBeNull()
    expect(nonce!.length).toBe(32)
    expect(nonce!.toString('hex')).toBe(EXPECTED_NONCE_HEX)
  })
})
