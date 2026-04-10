import crypto from 'node:crypto'
import { Resend } from 'resend'

// §7 OTP parameters: 6 digits, 5 minute expiry, max 3 attempts

export const OTP_LENGTH = 6
export const OTP_EXPIRY_MINUTES = 5
export const OTP_MAX_ATTEMPTS = 3

export function generateOtp(): string {
  // Cryptographically random 6-digit OTP with leading-zero preservation
  const buf = crypto.randomBytes(4)
  const num = buf.readUInt32BE(0) % 1_000_000
  return num.toString().padStart(OTP_LENGTH, '0')
}

export function hashOtp(otp: string): string {
  return crypto.createHash('sha256').update(otp).digest('hex')
}

export function verifyOtp(candidate: string, storedHash: string): boolean {
  const candidateHash = hashOtp(candidate)
  try {
    return crypto.timingSafeEqual(
      Buffer.from(candidateHash, 'hex'),
      Buffer.from(storedHash, 'hex'),
    )
  } catch {
    return false
  }
}

// The fallback request sends both:
//   email       — plaintext, used here once to deliver the OTP, then discarded
//   email_hash  — stored for rate limiting and deduplication; never the plaintext
//
// Vouchflow does not persist the plaintext email anywhere after this call returns.
export async function sendOtp(params: {
  email: string       // plaintext — used for delivery only, not stored
  emailHash: string   // stored on the verification record
  otp: string
  expiresAt: Date
}): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY
  if (!apiKey) {
    // In development without Resend configured, log OTP to console.
    // This must never happen in production — set RESEND_API_KEY.
    console.warn('[otp] RESEND_API_KEY not set — OTP will not be delivered.', {
      email: params.email,
      otp: params.otp,
      expiresAt: params.expiresAt.toISOString(),
    })
    return
  }

  const resend = new Resend(apiKey)
  const from = process.env.EMAIL_FROM ?? 'Vouchflow <noreply@vouchflow.dev>'

  await resend.emails.send({
    from,
    to: params.email,
    subject: `Your verification code: ${params.otp}`,
    text: [
      `Your Vouchflow verification code is: ${params.otp}`,
      `This code expires in ${OTP_EXPIRY_MINUTES} minutes.`,
      `If you did not request this, ignore this email.`,
    ].join('\n\n'),
  })
}
