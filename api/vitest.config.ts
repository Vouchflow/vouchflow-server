import { defineConfig } from 'vitest/config'

// Tests share a single Postgres + Redis (the apiKeyAuth + multi-key
// integration tests truncate the customers/api_keys tables in beforeEach).
// Running test files in parallel would have them stomp on each other —
// pin to a single thread/fork so the DB-touching tests see a clean state.
// Pure-unit tests (asn1, attestation, ...) don't care.
export default defineConfig({
  test: {
    // Vitest 4: top-level `pool` accepts a config object; serializing
    // forks at the file level prevents the integration tests from
    // racing each other in the shared Postgres.
    pool: { type: 'forks', maxWorkers: 1, minWorkers: 1 },
    fileParallelism: false,
    setupFiles: ['./src/__tests__/helpers/setup.ts'],
  },
})
