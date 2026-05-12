// One-shot data migration: enforce the "at-most-one-canonical-live-key
// per scope per app" invariant introduced in the live-keys refactor.
//
// For each app:
// - Group active live keys (deprecated=false) by scope.
// - Pick the most-recent per scope (write, read, pair) as canonical.
// - Mark the rest as deprecated with deprecatedAt = now() — they enter
//   the existing 14-day grace window from apiKeyAuth.ts.
//
// Pair keys: a pair acts as both write+read in auth, so we leave it alone
// unless there's another active key of any scope on the same app — in
// which case we keep the pair (it's the simplest config) and demote the
// rest. Apps with both a pair and a separate write/read get the pair
// retained as canonical, others demoted.
//
// Usage:
//   DRY_RUN=true  npx tsx scripts/backfill-canonical-live-keys.ts   # logs only
//   DRY_RUN=false npx tsx scripts/backfill-canonical-live-keys.ts   # writes
//
// Run this on production after deploying server-vX.Y.Z that contains the
// rotation surface.

import { prisma } from '../src/lib/prisma.js'

const DRY_RUN = (process.env.DRY_RUN ?? 'true').toLowerCase() !== 'false'

async function main() {
  console.log(`backfill-canonical-live-keys: dry_run=${DRY_RUN}`)
  const apps = await prisma.app.findMany({
    select: { id: true, name: true, slug: true, customerId: true },
  })
  console.log(`scanning ${apps.length} apps`)

  let appsTouched = 0
  let keysDeprecated = 0

  for (const app of apps) {
    const keys = await prisma.apiKey.findMany({
      where: { appId: app.id, deprecated: false },
      orderBy: { createdAt: 'desc' },
    })
    if (keys.length === 0) continue

    // Group by scope.
    const byScope: Record<string, typeof keys> = { write: [], read: [], pair: [] }
    for (const k of keys) byScope[k.scope]?.push(k)

    const toDemote: typeof keys = []

    // If there's a pair key, it covers both write+read. Keep the most
    // recent pair as canonical and demote everything else (including any
    // separate write/read keys, since they're redundant).
    if (byScope.pair.length > 0) {
      const [pairCanonical, ...extraPairs] = byScope.pair
      toDemote.push(...extraPairs, ...byScope.write, ...byScope.read)
      // pairCanonical stays active.
    } else {
      // No pair — keep the most recent write + most recent read.
      const [, ...extraWrites] = byScope.write
      const [, ...extraReads]  = byScope.read
      toDemote.push(...extraWrites, ...extraReads)
    }

    if (toDemote.length === 0) continue

    appsTouched++
    keysDeprecated += toDemote.length
    console.log(
      `  app ${app.slug} (${app.id}): keep ${keys.length - toDemote.length}, demote ${toDemote.length}`
    )

    if (!DRY_RUN) {
      await prisma.apiKey.updateMany({
        where: { id: { in: toDemote.map(k => k.id) } },
        data:  { deprecated: true, deprecatedAt: new Date() },
      })
    }
  }

  console.log(`done: ${appsTouched} apps touched, ${keysDeprecated} keys demoted${DRY_RUN ? ' (dry run — nothing written)' : ''}`)
  await prisma.$disconnect()
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
