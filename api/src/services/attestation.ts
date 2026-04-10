// §6 Decision 4: Attestation-anchored request signing.
//
// When attestation credentials are absent, validateAttestation returns
// { verified: false, reason: "credentials_not_configured" } and enrollment
// proceeds with confidence_ceiling: "medium". This is correct production-safe
// behaviour — not a development shortcut.
//
// Required env vars:
//   iOS:     APPLE_APP_ATTEST_ROOT_CA, APPLE_TEAM_ID, APPLE_BUNDLE_ID
//   Android: GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY,
//            GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY,
//            GOOGLE_CLOUD_PROJECT_NUMBER

export interface AttestationInput {
  platform: string
  token: string
  keyId: string
}

export interface AttestationResult {
  verified: boolean
  reason?: string
}

export async function validateAttestation(input: AttestationInput): Promise<AttestationResult> {
  if (input.platform === 'ios') {
    return validateAppAttest(input)
  } else if (input.platform === 'android') {
    return validatePlayIntegrity(input)
  }
  // 'web' platform has no device attestation — confidence_ceiling will be "medium"
  return { verified: false, reason: 'platform_does_not_support_attestation' }
}

async function validateAppAttest(input: AttestationInput): Promise<AttestationResult> {
  const rootCa = process.env.APPLE_APP_ATTEST_ROOT_CA
  const teamId = process.env.APPLE_TEAM_ID
  const bundleId = process.env.APPLE_BUNDLE_ID

  if (!rootCa || !teamId || !bundleId) {
    return { verified: false, reason: 'credentials_not_configured' }
  }

  // TODO: implement Apple App Attest validation:
  // 1. Decode CBOR-encoded attestation object
  // 2. Verify certificate chain up to APPLE_APP_ATTEST_ROOT_CA
  // 3. Verify nonce (SHA-256 of challenge) is embedded in the leaf cert extension
  // 4. Verify key_id matches the public key in the leaf cert
  // 5. Verify teamId + bundleId in cert subject match env vars
  throw new Error('Apple App Attest validation not yet implemented')
}

async function validatePlayIntegrity(input: AttestationInput): Promise<AttestationResult> {
  const decryptionKey = process.env.GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY
  const verificationKey = process.env.GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY
  const projectNumber = process.env.GOOGLE_CLOUD_PROJECT_NUMBER

  if (!decryptionKey || !verificationKey || !projectNumber) {
    return { verified: false, reason: 'credentials_not_configured' }
  }

  // TODO: implement Play Integrity token validation:
  // 1. Decrypt the integrity token using GOOGLE_PLAY_INTEGRITY_DECRYPTION_KEY
  // 2. Verify the JWT signature with GOOGLE_PLAY_INTEGRITY_VERIFICATION_KEY
  // 3. Check requestDetails.requestPackageName and nonce
  // 4. Check appIntegrity.appRecognitionVerdict === "PLAY_RECOGNIZED"
  // §10: Play Integrity has 10-second timeout; non-fatal on timeout
  throw new Error('Play Integrity validation not yet implemented')
}
