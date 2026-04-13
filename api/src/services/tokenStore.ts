import { redis } from '../lib/redis.js'

const TOKEN_TTL = 60 * 15   // 15 minutes in seconds
const RATE_WINDOW = 60 * 60  // 1 hour in seconds
const RATE_MAX = 3

export async function createToken(email: string): Promise<string> {
  const { randomBytes } = await import('crypto')
  const token = randomBytes(32).toString('hex')
  await redis.set(`token:${token}`, JSON.stringify({ email }), 'EX', TOKEN_TTL)
  return token
}

export async function consumeToken(token: string): Promise<string | null> {
  // Atomic get-then-delete. If two requests race, only the first gets the email.
  const raw = await redis.get(`token:${token}`)
  if (!raw) return null
  await redis.del(`token:${token}`)
  const { email } = JSON.parse(raw)
  return email
}

export async function checkRateLimit(email: string): Promise<boolean> {
  const key = `ratelimit:${email}`
  const count = await redis.incr(key)
  if (count === 1) await redis.expire(key, RATE_WINDOW)
  return count <= RATE_MAX
}
