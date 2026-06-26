import { FastifyPluginAsync } from 'fastify'
import crypto from 'node:crypto'
import { z } from 'zod'
import { prisma } from '../lib/prisma.js'
import { makeApiKeyAuthPlugin } from '../plugins/apiKeyAuth.js'
import { validateAttestation, buildAttestationConfig } from '../services/attestation.js'
import { validateWebAuthnAttestation } from '../services/webauthn.js'
import { scoreAnomaly } from '../services/anomaly.js'

// §7 POST /v1/enroll rate limit: 10/minute per customer + IP
const RATE_LIMIT_MAX = 10
const RATE_LIMIT_WINDOW = '1 minute'

// §11 Security: enrollment response normalized to 250ms (timing attack mitigation)
const ENROLL_RESPONSE_TIME_MS = 250

// §7: idempotency_key checked within 24h window
const IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60

const AttestationSchema = z.object({
  // iOS App Attest: base64 attestation object + base64 credential ID.
  token: z.string().nullish(),
  key_id: z.string().nullish(),
  // Android Keystore Attestation: leaf-first certificate chain, each cert
  // base64-encoded DER. Server walks to Google HW Attestation Root CA and
  // parses the leaf's attestation extension.
  cert_chain: z.array(z.string()).nullish(),
  // WebAuthn attestation: CBOR-encoded attestation object and clientDataJSON,
  // both base64url-encoded. The server CBOR-decodes the attestation object,
  // verifies the attestation statement (format-dependent), and extracts the
  // credential public key in SPKI DER format — the same format iOS/Android send
  // as `public_key`.
  webauthn_attestation: z.object({
    attestation_object: z.string(),    // base64url of raw WebAuthn attestationObject
    client_data_json: z.string(),      // base64url of raw clientDataJSON
  }).nullish(),
})

const EnrollRequestSchema = z.object({
  idempotency_key: z.string().min(1),
  platform: z.enum(['ios', 'android', 'web']),
  reason: z.enum(['fresh_enrollment', 'reinstall', 'key_invalidated', 'corrupted']),
  attestation: AttestationSchema.nullish(),
  // Mobile SDKs send their SPKI-DER public key directly. The Web SDK sends
  // an empty string and the server extracts the key from the WebAuthn
  // attestation object — see effectivePublicKey override below.
  public_key: z.string(),
  device_token: z.string().nullish(),
  strongbox_backed: z.boolean().nullish(),
}).refine(
  (val) => val.platform === 'web' || val.public_key.length > 0,
  { message: 'public_key required for non-web platforms', path: ['public_key'] },
)

type EnrollRequest = z.infer<typeof EnrollRequestSchema>

const route: FastifyPluginAsync = async (fastify) => {
  await fastify.register(makeApiKeyAuthPlugin('write'))

  fastify.post('/enroll', {
    config: {
      rateLimit: {
        max: RATE_LIMIT_MAX,
        timeWindow: RATE_LIMIT_WINDOW,
        // §7: per customer + IP
        // §7: per customer + IP — using IP here since customerId isn't available
        // at onRequest. The IP naturally combines both concerns at this endpoint.
        keyGenerator: (request: any) => `enroll:${request.ip}`,
      },
    },
    handler: async (request, reply) => {
      const start = Date.now()

      // ── Parse & validate ─────────────────────────────────────────────────
      const parsed = EnrollRequestSchema.safeParse(request.body)
      if (!parsed.success) {
        return reply.code(400).send({
          error: { code: 'invalid_request', message: parsed.error.message },
        })
      }
      const body: EnrollRequest = parsed.data

      // ── Idempotency check (Postgres, single source of truth) ────────────
      // §7: "if seen within 24h, return original response". Used to read a
      // Redis cache first with Postgres as fallback; the Redis hop added
      // ~1ms in the happy path and is gone now that we've torn out the
      // Upstash dependency. Postgres lookup on `key` (unique index) is
      // still sub-millisecond at our scale.
      const dbRecord = await prisma.idempotencyRecord.findUnique({
        where: { key: body.idempotency_key },
      })
      if (dbRecord && dbRecord.expiresAt > new Date()) {
        await normalizeLatency(start, ENROLL_RESPONSE_TIME_MS)
        return reply.code(200).send(JSON.parse(dbRecord.responseJson))
      }

      // ── Public key uniqueness check ───────────────────────────────────────
      // §7: "if exists under different device_token, reject 409"
      //
      // The point of this check is to keep someone else from cloning a key
      // and re-registering it under their own customer/app. Cross-tenant
      // collision = 409, same-tenant re-token = legitimate (e.g. an SDK
      // reset() that wiped the local token but the Android Keystore key
      // survived the wipe — the upsert below correctly handles it). The
      // older form blanket-409'd on ANY token mismatch, which made the
      // sandbox-app→production-app device migration impossible to recover
      // from on the integrator side; see issue #6.
      //
      // Skip when body.public_key is empty (Web SDK enrollment — the key is
      // extracted from the WebAuthn attestation below; running the check on
      // an empty key would either be a no-op or false-positive against legacy
      // rows). Web duplicates are caught downstream by the credential_id
      // uniqueness constraint.
      const existingDevice = body.public_key.length > 0
        ? await prisma.device.findFirst({ where: { publicKey: body.public_key } })
        : null
      if (existingDevice && existingDevice.deviceToken !== (body.device_token ?? '')) {
        const crossTenant =
          existingDevice.customerId !== request.customerId ||
          existingDevice.appId      !== request.appId
        if (crossTenant) {
          await normalizeLatency(start, ENROLL_RESPONSE_TIME_MS)
          return reply.code(409).send({
            error: {
              code: 'public_key_already_registered',
              message: 'This public key is already registered to a different device under another customer or app.',
            },
          })
        }
        // Same customer + same app, different device_token — re-token. Force
        // the upsert below to target the existing row rather than try to
        // create a duplicate (which would violate the deviceToken unique
        // index in a different and less helpful way).
        body.device_token = existingDevice.deviceToken
      }

      // ── Attestation validation ────────────────────────────────────────────
      // §7: "If attestation null/failed: accept, set attestation_verified: false,
      //      confidence_ceiling: medium"
      // In sandbox, attestation is always treated as verified so developers can
      // test the full confidence ladder without a Play Console-registered APK.
      let attestationVerified = request.isSandbox
      let confidenceCeiling = attestationVerified ? 'high' : 'medium'

      // WebAuthn attestation fields — populated only for platform === 'web'
      let webauthnCredentialId: string | undefined
      let webauthnAttestationFormat: string | undefined
      // Override body.public_key with the one extracted from WebAuthn authData
      // when a WebAuthn attestation is provided (the COSE key is authoritative).
      let effectivePublicKey = body.public_key
      // Store user_agent from the request for web devices
      const userAgent = request.headers['user-agent'] ?? undefined

      // WebAuthn key extraction runs in both sandbox and production — we
      // always need the COSE-extracted SPKI DER as the stored public_key for
      // a web device. (Cert-chain trust verification still respects the
      // sandbox short-circuit elsewhere — see attestationVerified.)
      if (body.platform === 'web' && body.attestation?.webauthn_attestation) {
        try {
          const attObj = Buffer.from(
            body.attestation.webauthn_attestation.attestation_object,
            'base64',
          )
          const clientDataJSON = Buffer.from(
            body.attestation.webauthn_attestation.client_data_json,
            'base64',
          )
          const result = await validateWebAuthnAttestation(attObj, clientDataJSON)
          effectivePublicKey = result.publicKey || body.public_key
          webauthnCredentialId = result.credentialId
          webauthnAttestationFormat = result.attestationFormat
          if (request.isSandbox) {
            // Sandbox: skip cert-chain trust, accept the COSE key.
            attestationVerified = true
            confidenceCeiling = 'high'
          } else {
            attestationVerified = result.verified
            confidenceCeiling = result.confidenceCeiling
          }
        } catch {
          // Non-fatal per §7 — proceed at lower confidence
          attestationVerified = false
          confidenceCeiling = 'medium'
        }
      }

      if (!request.isSandbox && body.attestation) {
        if (body.platform !== 'web') {
          // ── iOS / Android attestation path ────────────────────────────────
          // chunk1-compile-fix: attestation params moved from Customer to App.
          // Chunk 3 reshapes this lookup but the simple App.findUnique by id
          // keeps the behaviour identical.
          try {
            const app = await prisma.app.findUnique({
              where: { id: request.appId },
              select: {
                iosTeamId: true,
                iosBundleId: true,
                androidPackageName: true,
                androidSigningKeySha256: true,
              },
            })
            const result = await validateAttestation(
              {
                platform: body.platform,
                token: body.attestation.token ?? null,
                keyId: body.attestation.key_id ?? null,
                certChain: body.attestation.cert_chain ?? null,
                nonce: body.idempotency_key,
              },
              buildAttestationConfig(app),
            )
            attestationVerified = result.verified
            // Observability: an absent reason here means it silently fell to
            // low confidence. Genuine devices that fail attestation should be
            // rare; when they aren't, this `reason` is the whole diagnosis
            // (e.g. nonce_extension_missing, rp_id_mismatch, counter_nonzero).
            if (!result.verified) {
              request.log.warn(
                {
                  appId: request.appId,
                  platform: body.platform,
                  reason: result.reason,
                  hadToken: !!body.attestation.token,
                  hadKeyId: !!body.attestation.key_id,
                  hadCertChain: !!body.attestation.cert_chain,
                },
                'attestation rejected',
              )
            }
          } catch (err) {
            // Non-fatal per §7, but never silent: a thrown error here was
            // previously invisible and indistinguishable from a clean reject.
            attestationVerified = false
            request.log.warn(
              { appId: request.appId, platform: body.platform, err: (err as Error).message },
              'attestation threw',
            )
          }
          confidenceCeiling = attestationVerified ? 'high' : 'medium'
        }
      }

      // Observability: a live mobile enroll that carries NO attestation at all
      // (SDK didn't attach a token — e.g. App Attest unsupported, or a bug)
      // also falls to low confidence. Distinguish it from a failed-validation
      // reject above so "real iPhone → low" can be triaged from logs alone.
      if (!request.isSandbox && body.platform !== 'web' && !body.attestation) {
        request.log.warn(
          { appId: request.appId, platform: body.platform },
          'enroll without attestation (live mobile) — confidence will be low',
        )
      }

      // If platform is 'web' and no webauthn_attestation was provided,
      // allow enrollment at medium confidence (still a hardware authenticator
      // with user verification, just no attestation certificate).
      if (body.platform === 'web' && !body.attestation?.webauthn_attestation && !request.isSandbox) {
        attestationVerified = false
        confidenceCeiling = 'medium'
      }

      // ── Compute public key fingerprint ────────────────────────────────────
      // §11 Network Graph Privacy: fingerprint stored internally, never returned
      const keyFingerprint = crypto
        .createHash('sha256')
        .update(effectivePublicKey)
        .digest('hex')

      // ── Create or update device record ───────────────────────────────────
      const deviceToken = body.device_token ?? generateDeviceToken()

      const platform = body.platform

      const device = await prisma.device.upsert({
        where: { deviceToken },
        create: {
          deviceToken,
          customerId: request.customerId,
          appId:      request.appId,  // chunk1-compile-fix: every Device belongs to an App
          publicKey: effectivePublicKey,
          keyFingerprint,
          platform,
          attestationVerified,
          confidenceCeiling,
          strongboxBacked: body.strongbox_backed ?? null,
          credentialId: webauthnCredentialId,
          attestationFormat: webauthnAttestationFormat,
          enrolledAt: new Date(),
          lastSeen: new Date(),
          status: 'active',
          isSandbox: request.isSandbox,
        },
        update: {
          publicKey: effectivePublicKey,
          keyFingerprint,
          attestationVerified,
          confidenceCeiling,
          strongboxBacked: body.strongbox_backed ?? null,
          credentialId: webauthnCredentialId,
          attestationFormat: webauthnAttestationFormat,
          lastSeen: new Date(),
          status: 'active',
          isSandbox: request.isSandbox,
        },
      })

      // ── Network graph: enrollment event ──────────────────────────────────
      // §15 Write Path step 3: only if customer is network participant; never in sandbox
      if (device.networkParticipant && !request.isSandbox) {
        await writeNetworkEvent({
          keyFingerprint,
          customerId: request.customerId,
          eventType: body.reason === 'fresh_enrollment' ? 'enrollment' : body.reason,
          platform,
          attestationVerified,
          strongboxBacked: device.strongboxBacked,
        })
      }

      // ── Build response ────────────────────────────────────────────────────
      const response = {
        device_token: device.deviceToken,
        enrolled_at: device.enrolledAt.toISOString(),
        status: device.status,
        attestation_verified: device.attestationVerified,
        confidence_ceiling: device.confidenceCeiling,
        idempotency_key: body.idempotency_key,
      }

      // ── Store idempotency record ──────────────────────────────────────────
      const responseJson = JSON.stringify(response)
      const expiresAt = new Date(Date.now() + IDEMPOTENCY_TTL_SECONDS * 1000)

      await prisma.idempotencyRecord.upsert({
        where: { key: body.idempotency_key },
        create: { key: body.idempotency_key, responseJson, expiresAt },
        update: { responseJson, expiresAt },
      })

      // ── Normalize response time (§11 timing attack mitigation) ───────────
      await normalizeLatency(start, ENROLL_RESPONSE_TIME_MS)

      return reply.code(200).send(response)
    },
  })
}

export default route

// ─── Helpers ─────────────────────────────────────────────────────────────────

function generateDeviceToken(): string {
  return `dvt_${crypto.randomBytes(16).toString('hex')}`
}

async function normalizeLatency(startMs: number, targetMs: number): Promise<void> {
  const elapsed = Date.now() - startMs
  const remaining = targetMs - elapsed
  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining))
  }
}

async function writeNetworkEvent(params: {
  keyFingerprint: string
  customerId: string
  eventType: string
  platform: string
  attestationVerified: boolean
  strongboxBacked: boolean | null
}) {
  await prisma.$transaction(async (tx) => {
    const networkDevice = await tx.networkDevice.upsert({
      where: { keyFingerprint: params.keyFingerprint },
      create: {
        keyFingerprint: params.keyFingerprint,
        platform: params.platform,
        strongboxBacked: params.strongboxBacked,
        attestationEverVerified: params.attestationVerified,
        totalVerifications: 0,
        customerCount: 1,
      },
      update: {
        lastSeen: new Date(),
        attestationEverVerified: params.attestationVerified ? true : undefined,
      },
    })

    await tx.networkEvent.create({
      data: {
        networkDeviceId: networkDevice.id,
        customerId: params.customerId,
        eventType: params.eventType,
        confidence: null,
        biometricUsed: null,
        fallbackUsed: false,
      },
    })
  })

  // §15 anomaly scoring runs inline (no queue) — `void` keeps the response
  // path fast even when scoring does a few extra Postgres reads. Errors are
  // swallowed: scoring is best-effort; missing it just means the row keeps
  // its old riskScore until the next enroll/verify recomputes.
  void scoreAnomaly({ keyFingerprint: params.keyFingerprint }).catch((err) => {
    console.error(`[anomaly] inline scoring failed for ${params.keyFingerprint}: ${err.message}`)
  })
}
