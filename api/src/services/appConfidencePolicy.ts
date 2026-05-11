// Resolves the effective minimum confidence policy for a given app + operation.
// Per the apps refactor (chunk 3): both verify() and signPayload() consult
// per-app fields with per-context overrides; verify additionally falls back
// to the customer-wide Customer.minimumConfidence when App.verifyMinConfidence
// is null. signPayload uses 'high' as the absolute default.

import { prisma } from '../lib/prisma.js'

export type ConfidenceLevel = 'low' | 'medium' | 'high'
const RANK: Record<ConfidenceLevel, number> = { low: 0, medium: 1, high: 2 }

export function meetsLevel(actual: string | null | undefined, required: ConfidenceLevel | null | undefined): boolean {
  if (!required) return true
  if (!actual) return false
  const a = RANK[actual as ConfidenceLevel]
  const r = RANK[required]
  if (a === undefined || r === undefined) return false
  return a >= r
}

export function maxLevel(a: ConfidenceLevel | null | undefined, b: ConfidenceLevel | null | undefined): ConfidenceLevel | null {
  if (!a) return b ?? null
  if (!b) return a ?? null
  return RANK[a] >= RANK[b] ? a : b
}

interface AppPolicySnapshot {
  appId: string
  customerId: string
  verifyMinConfidence: ConfidenceLevel | null
  signPayloadMinConfidence: ConfidenceLevel
  contextConfidenceOverrides: Record<string, ConfidenceLevel>
  customerMinimumConfidence: ConfidenceLevel | null
}

/**
 * Loads policy for an app. Throws if the app doesn't exist (this is a server
 * invariant — request.appId always points at a real row).
 */
export async function loadAppPolicy(appId: string): Promise<AppPolicySnapshot> {
  const app = await prisma.app.findUnique({
    where: { id: appId },
    select: {
      id: true,
      customerId: true,
      verifyMinConfidence: true,
      signPayloadMinConfidence: true,
      contextConfidenceOverrides: true,
      customer: { select: { minimumConfidence: true } },
    },
  })
  if (!app) throw new Error(`loadAppPolicy: app ${appId} not found`)
  const overrides = (app.contextConfidenceOverrides ?? {}) as Record<string, ConfidenceLevel>
  return {
    appId: app.id,
    customerId: app.customerId,
    verifyMinConfidence: (app.verifyMinConfidence ?? null) as ConfidenceLevel | null,
    signPayloadMinConfidence: (app.signPayloadMinConfidence ?? 'high') as ConfidenceLevel,
    contextConfidenceOverrides: overrides,
    customerMinimumConfidence: (app.customer.minimumConfidence ?? null) as ConfidenceLevel | null,
  }
}

/**
 * Resolves the minimum confidence required for a verify() call.
 *
 * Precedence (highest wins): per-context override → App.verifyMinConfidence
 * → Customer.minimumConfidence. Returns null when no policy is set; the
 * SDK request's `minimum_confidence` parameter is then the only floor.
 */
export function resolveVerifyMin(
  policy: AppPolicySnapshot,
  context: string | null | undefined,
): ConfidenceLevel | null {
  const ctxOverride = context ? policy.contextConfidenceOverrides[context] : undefined
  return maxLevel(maxLevel(ctxOverride ?? null, policy.verifyMinConfidence), policy.customerMinimumConfidence)
}

/**
 * Resolves the minimum confidence required for a signPayload() call.
 *
 * Precedence: per-context override → App.signPayloadMinConfidence (default
 * 'high'). Customer-level minimumConfidence does NOT apply to signPayload —
 * sign is a higher-stakes operation with its own floor.
 */
export function resolveSignMin(
  policy: AppPolicySnapshot,
  context: string | null | undefined,
): ConfidenceLevel {
  const ctxOverride = context ? policy.contextConfidenceOverrides[context] : undefined
  return (maxLevel(ctxOverride ?? null, policy.signPayloadMinConfidence) ?? 'high') as ConfidenceLevel
}
