// Verification is terminally verified after biometric/signed-challenge
// completion or email-OTP fallback completion. Reuse this list for lookups
// that require verified states.
export const TERMINAL_VERIFIED_STATES = ['COMPLETED', 'FALLBACK_COMPLETE'] as const
