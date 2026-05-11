// Shared admin-key verification used by routes that the web layer calls
// directly with `Bearer $ADMIN_KEY`. Constant-time comparison so length
// differences don't leak through timing.

import crypto from 'node:crypto'

export function verifyAdminKey(authHeader: string | undefined): boolean {
  const adminKey = process.env.ADMIN_KEY
  if (!adminKey) return false
  if (!authHeader?.startsWith('Bearer ')) return false
  const provided = authHeader.slice(7)
  try {
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(adminKey))
  } catch {
    return false
  }
}
