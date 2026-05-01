// Vitest setup file — runs once per test process. Stamps the env vars that
// `src/config.ts` insists on, so test files that transitively import config
// (via routes/services) don't crash at import-time. Real values are
// irrelevant for the tests; only the presence of the var matters.

if (!process.env.INTERNAL_HMAC_SECRET) {
  process.env.INTERNAL_HMAC_SECRET = '0'.repeat(64)
}
if (!process.env.WEBHOOK_SECRET_ENCRYPTION_KEY) {
  process.env.WEBHOOK_SECRET_ENCRYPTION_KEY = '0'.repeat(64)
}
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = '0'.repeat(64)
}
if (!process.env.ADMIN_KEY) {
  process.env.ADMIN_KEY = '0'.repeat(64)
}
