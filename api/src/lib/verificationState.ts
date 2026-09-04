// A verification is "verified" once it reaches either terminal success
// state: COMPLETED (biometric/signed-challenge) or FALLBACK_COMPLETE (email
// OTP fallback). Every lookup that means "find the device's last verified
// result" must match both — device.ts and verify.ts previously drifted on
// this and email-fallback completions became invisible to device lookups.
export const TERMINAL_VERIFIED_STATES = ['COMPLETED', 'FALLBACK_COMPLETE'] as const
