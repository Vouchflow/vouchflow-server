import { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify'
import crypto from 'node:crypto'
import { z } from 'zod'
import { Verification } from '@prisma/client'
import { prisma } from '../lib/prisma.js'
import { counterIncr } from '../lib/inMemoryCounter.js'
import { makeApiKeyAuthPlugin } from '../plugins/apiKeyAuth.js'
import { computeConfidence } from '../services/confidence.js'
import { dispatchWebhook } from '../services/webhooks.js'
import { generateOtp, hashOtp, verifyOtp, sendOtp, OTP_EXPIRY_MINUTES, OTP_MAX_ATTEMPTS } from '../services/otp.js'
import { isDisposableEmailDomain } from '../services/disposableEmail.js'
import { verifyWebAuthnAssertion, extractRpIdFromClientData } from '../services/webauthn.js'
import { scoreAnomaly } from '../services/anomaly.js'
import { config } from '../config.js'
import { loadAppPolicy, resolveVerifyMin } from '../services/appConfidencePolicy.js'

// §7 Session expiry: 60 seconds
const SESSION_EXPIRY_SECONDS = 60

// §7 Rate limits
const VERIFY_RATE = { max: 100, window: '1 minute' }
const COMPLETE_RATE = { max: 10, window: '1 minute' }
// §7: fallback rate limit is per device_token: 3 per 24h — enforced in handler
const FALLBACK_RATE = { max: 3, window: '24 hours' }

// ─── Request schemas ──────────────────────────────────────────────────────────

const PostVerifySchema = z.object({
  device_token: z.string().min(1),
  context: z.enum(['signup', 'login', 'sensitive_action']),
  minimum_confidence: z.enum(['high', 'medium', 'low']).optional(),
})

const CompleteSchema = z.object({
  device_token: z.string().min(1),
  signed_challenge: z.string().min(1),
  biometric_used: z.boolean(),
  // WebAuthn assertion fields — present when the device was enrolled via
  // the Web SDK (platform === 'web'). When these are provided, the server
  // verifies the WebAuthn assertion structure instead of the mobile SDK's
  // simple challenge signature.
  client_data_json: z.string().nullish(),
  authenticator_data: z.string().nullish(),
  credential_id: z.string().nullish(),
})

const FallbackSchema = z.object({
  device_token: z.string().nullish(),
  email: z.string().email(),       // plaintext — used for OTP delivery, not stored
  email_hash: z.string().min(1),   // SHA-256 of email — stored for rate limiting
  reason: z.enum([
    'attestation_unavailable',
    'attestation_failed',
    'attestation_timeout',
    'biometric_unavailable',
    'biometric_failed',
    'biometric_cancelled',
    'key_invalidated',
    'sdk_error',
    'minimum_confidence_unmet',
    'developer_initiated',
    'enrollment_failed',
  ]),
})

const FallbackCompleteSchema = z.object({
  device_token: z.string().nullish(),
  otp: z.string().length(6),
})

const route: FastifyPluginAsync = async (fastify) => {
  // ── POST /v1/verify ────────────────────────────────────────────────────────
  const writeAuth = makeApiKeyAuthPlugin('write')
  const readAuth = makeApiKeyAuthPlugin('read')

  await fastify.register(async (scope) => {
    await scope.register(writeAuth)

    scope.post('/verify', {
      config: {
        rateLimit: {
          max: VERIFY_RATE.max,
          timeWindow: VERIFY_RATE.window,
          keyGenerator: (req: any) => `verify:${req.ip}`,
        },
      },
      handler: async (request, reply) => {
        const parsed = PostVerifySchema.safeParse(request.body)
        if (!parsed.success) {
          return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.message } })
        }
        const body = parsed.data

        const device = await prisma.device.findUnique({ where: { deviceToken: body.device_token } })
        if (!device) {
          return reply.code(404).send({ error: { code: 'device_not_found', message: 'Device token not found.' } })
        }
        // Cross-app isolation: a device enrolled under one app cannot be
        // verified through a different app's API key, even within the same
        // customer. We return the same `device_not_owned` code rather than
        // a new one to avoid leaking the existence of the device to a
        // sibling app via a unique error path.
        if (device.customerId !== request.customerId || device.appId !== request.appId) {
          return reply.code(403).send({ error: { code: 'device_not_owned', message: 'Device does not belong to this customer.' } })
        }
        if (device.status !== 'active') {
          return reply.code(409).send({ error: { code: 'device_inactive', message: `Device status is ${device.status}.` } })
        }
        // Issue #4: For web devices, verify credentialId is set. An enrollment that
        // created the device record but where the WebAuthn ceremony was cancelled
        // leaves an orphan device with no platform credential. Reject these early.
        if (device.platform === 'web' && !device.credentialId) {
          return reply.code(409).send({ error: { code: 'device_not_enrolled', message: 'Device enrollment incomplete. Please re-enroll.' } })
        }

        // §7 + apps refactor: minimum confidence is the max of (SDK request,
        // App per-context override, App.verifyMinConfidence,
        // Customer.minimumConfidence). The SDK request is still the floor —
        // this only ratchets it up, never down.
        const policy = await loadAppPolicy(request.appId)
        const appFloor = resolveVerifyMin(policy, body.context)
        const effectiveMin = body.minimum_confidence
          ? (CONFIDENCE_RANK[appFloor ?? 'low'] >= CONFIDENCE_RANK[body.minimum_confidence]
              ? appFloor
              : body.minimum_confidence)
          : appFloor
        if (effectiveMin) {
          const ceiling = device.confidenceCeiling
          if (!confidenceMeets(ceiling, effectiveMin)) {
            return reply.code(422).send({
              error: {
                code: 'verification_impossible',
                message: `Device cannot meet minimum_confidence: ${effectiveMin}. Ceiling is ${ceiling}.`,
              },
            })
          }
        }

        const challenge = crypto.randomBytes(32).toString('base64')
        const sessionId = `ses_${crypto.randomBytes(12).toString('hex')}`
        const expiresAt = new Date(Date.now() + SESSION_EXPIRY_SECONDS * 1000)

        await prisma.verification.create({
          data: {
            sessionId,
            deviceId: device.id,
            customerId: request.customerId,
            appId:      request.appId,  // chunk1-compile-fix: every Verification belongs to an App
            challenge,
            state: 'INITIATED',
            context: body.context,
            expiresAt,
            isSandbox: request.isSandbox,
          },
        })

        return reply.code(200).send({
          session_id: sessionId,
          challenge,
          expires_at: expiresAt.toISOString(),
          session_state: 'INITIATED',
        })
      },
    })

    // ── POST /v1/verify/{session_id}/complete ───────────────────────────────
    scope.post<{ Params: { session_id: string } }>('/verify/:session_id/complete', {
      config: {
        rateLimit: {
          max: COMPLETE_RATE.max,
          timeWindow: COMPLETE_RATE.window,
          keyGenerator: (req: any) => `complete:${req.params.session_id}`,
        },
      },
      handler: async (request, reply) => {
        const { session_id } = request.params

        // §7: "Fallback OTP submission uses same endpoint"
        // Session state determines which schema applies, so look up the session first.
        // Primary path: { device_token, signed_challenge, biometric_used }
        // Fallback OTP path: { device_token, otp } — detected by session state (FALLBACK)

        // ── Step 1: Session exists ──────────────────────────────────────────
        let session = await prisma.verification.findUnique({ where: { sessionId: session_id } })
        if (!session) {
          // session_id may be a fallback session ID (fbs_...) stored in retrySessionId
          session = await prisma.verification.findFirst({
            where: { retrySessionId: session_id, state: 'FALLBACK' },
          })
        }
        if (!session) {
          return reply.code(404).send({ error: { code: 'session_not_found', message: 'Session not found.' } })
        }

        // ── Step 2: State check ─────────────────────────────────────────────
        // If session is in FALLBACK state, treat as OTP completion (different schema).
        if (session.state === 'FALLBACK') {
          return handleFallbackComplete(session.sessionId, session, request, reply)
        }

        // Biometric completion path — validate schema now that we know state is not FALLBACK.
        const parsed = CompleteSchema.safeParse(request.body)
        if (!parsed.success) {
          return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.message } })
        }
        const body = parsed.data

        // Idempotency: if session is already COMPLETED and we have a cached response,
        // return it instead of failing. This handles the case where the first /complete
        // succeeded server-side but the response was lost (network blip, HMR reload, etc).
        if (session.state === 'COMPLETED') {
          if (session.completionResponse) {
            return reply.code(200).send(session.completionResponse)
          }
          // COMPLETED but no cached response - shouldn't happen normally
          return reply.code(409).send({
            error: {
              code: 'ceremony_already_completed',
              message: 'Session is already completed. Cannot retrieve original response.',
              current_state: session.state,
            },
          })
        }
        if (session.state !== 'INITIATED') {
          return reply.code(409).send({
            error: {
              code: 'invalid_session_state',
              message: `Session is in state ${session.state}, expected INITIATED.`,
              current_state: session.state,
            },
          })
        }

        // ── Step 3: Device token matches ────────────────────────────────────
        const device = await prisma.device.findUnique({ where: { id: session.deviceId! } })
        if (!device || device.deviceToken !== body.device_token) {
          return reply.code(403).send({ error: { code: 'device_token_mismatch', message: 'device_token does not match the session.' } })
        }

        // ── Step 4: Expiry check ─────────────────────────────────────────────
        if (new Date() > session.expiresAt) {
          // Auto-create retry session
          const retryChallenge = crypto.randomBytes(32).toString('base64')
          const retrySessionId = `ses_${crypto.randomBytes(12).toString('hex')}`
          const retryExpiresAt = new Date(Date.now() + SESSION_EXPIRY_SECONDS * 1000)

          await prisma.verification.create({
            data: {
              sessionId: retrySessionId,
              deviceId: device.id,
              customerId: session.customerId,
              appId:      session.appId,  // chunk1-compile-fix: retry inherits the original session's app
              challenge: retryChallenge,
              state: 'INITIATED',
              context: session.context,
              expiresAt: retryExpiresAt,
              isSandbox: session.isSandbox,
            },
          })
          await prisma.verification.update({
            where: { sessionId: session_id },
            data: { state: 'EXPIRED', retrySessionId },
          })

          return reply.code(410).send({
            error: {
              code: 'session_expired',
              message: 'Verification session expired after 60 seconds.',
              retry_session_id: retrySessionId,
              retry_challenge: retryChallenge,
              expires_at: retryExpiresAt.toISOString(),
            },
          })
        }

        // ── Step 5.5: Platform binding ─────────────────────────────────────
        // Reject submissions whose signature format doesn't match the device's
        // enrolled platform. Without this, a downgrade-shaped path exists where
        // a mobile device row could be probed with WebAuthn-formed assertions
        // (or vice versa). The signature check would still reject every actual
        // forgery, but the contract should be tight.
        const isWebAuthnPath = body.client_data_json != null
        if (isWebAuthnPath && device.platform !== 'web') {
          return reply.code(422).send({
            error: {
              code: 'platform_mismatch',
              message: 'WebAuthn assertion submitted for a non-web device.',
            },
          })
        }
        if (!isWebAuthnPath && device.platform === 'web') {
          return reply.code(422).send({
            error: {
              code: 'platform_mismatch',
              message: 'Mobile-format signature submitted for a web device.',
            },
          })
        }

        // ── Step 6: Validate signature ──────────────────────────────────────
        // WebAuthn assertions have a different structure than mobile SDK signatures:
        //   - Mobile: sign(SHA-256(challenge))
        //   - WebAuthn: sign(authenticatorData || SHA-256(clientDataJSON))
        // When client_data_json is present, we use the WebAuthn verification path.
        let signatureValid = false
        let sigFailReason: string | undefined
        let biometricUsed = body.biometric_used

        if (isWebAuthnPath) {
          // ── WebAuthn assertion verification path ──────────────────────────
          // Extract the expected RP ID from the clientDataJSON origin,
          // since the server doesn't store it on the Device record.
          // Guarded by isWebAuthnPath above; non-null after the platform check.
          const clientDataJson = body.client_data_json!
          let expectedRpId: string
          try {
            expectedRpId = extractRpIdFromClientData(clientDataJson)
          } catch {
            return reply.code(400).send({
              error: { code: 'invalid_client_data', message: 'Cannot parse origin from clientDataJSON.' },
            })
          }

          const assertionResult = verifyWebAuthnAssertion({
            publicKey: device.publicKey,
            challenge: session.challenge,
            clientDataJSON: clientDataJson,
            authenticatorData: body.authenticator_data!,
            signature: body.signed_challenge,
            expectedRpId,
          })
          signatureValid = assertionResult.valid
          sigFailReason = assertionResult.reason

          // For WebAuthn assertions with UV flag set (always required by SDK),
          // biometric_used is true regardless of what the client sent.
          // The UV flag is verified inside verifyWebAuthnAssertion.
          if (signatureValid) {
            biometricUsed = true
          }
        } else {
          // ── Mobile SDK signature verification path (constant-time) ────────
          const sigResult = verifySignature({
            publicKey: device.publicKey,
            challenge: session.challenge,
            signature: body.signed_challenge,
          })
          signatureValid = sigResult.valid
          sigFailReason = sigResult.reason
        }

        if (!signatureValid) {
          request.log.warn(
            { sessionId: session_id, deviceToken: device.deviceToken, sigFailReason },
            'Signature verification failed',
          )
        }

        // ── Step 7: Transition state ─────────────────────────────────────────
        const newState = signatureValid ? 'COMPLETED' : 'FAILED'
        const confidence = signatureValid
          ? computeConfidence({ device, biometricUsed: body.biometric_used, fallbackUsed: false })
          : null

        // ── Fetch network signals for response (before state transition) ────
        const networkDevice = await prisma.networkDevice.findUnique({
          where: { keyFingerprint: device.keyFingerprint },
        })

        const deviceAgeDays = Math.floor(
          (Date.now() - device.enrolledAt.getTime()) / (1000 * 60 * 60 * 24),
        )

        // Build the response object - we'll store this for idempotency
        const responseBody = {
          verified: signatureValid,
          confidence,
          session_state: newState,
          device_token: device.deviceToken,
          device_age_days: deviceAgeDays,
          network_verifications: networkDevice?.totalVerifications ?? 0,
          first_seen: device.enrolledAt.toISOString(),
          signals: {
            keychain_persistent: true, // §9: iOS Keychain AfterFirstUnlock always persistent
            biometric_used: body.biometric_used,
            cross_app_history: (networkDevice?.customerCount ?? 0) > 1,
            anomaly_flags: networkDevice?.anomalyFlags ?? [],
            attestation_verified: device.attestationVerified,
          },
          fallback_used: false,
          context: session.context,
        }

        // Store the completion state and response for idempotency.
        // Atomic single-use check + state update: only consume challenge if we
        // successfully verified the signature. If verification failed before this
        // point, the challenge remains unconsumed for SDK retry.
        const updated = await prisma.verification.updateMany({
          where: { sessionId: session_id, challengeConsumed: false },
          data: {
            challengeConsumed: true,
            state: newState,
            biometricUsed: biometricUsed,
            confidence,
            completedAt: new Date(),
            completionResponse: signatureValid ? (responseBody as any) : null,
          },
        })
        
        if (updated.count === 0) {
          // Challenge was already consumed by a previous request
          return reply.code(409).send({
            error: { code: 'challenge_already_consumed', message: 'Challenge has already been used.' },
          })
        }
        
        // Fetch the updated session for webhook dispatch
        const completedSession = await prisma.verification.findUnique({
          where: { sessionId: session_id },
        })

        // Update device last_seen
        await prisma.device.update({ where: { id: device.id }, data: { lastSeen: new Date() } })

        // ── Network graph write (§15) ─────────────────────────────────────────
        if (signatureValid && device.networkParticipant && !request.isSandbox) {
          await writeNetworkVerificationEvent({
            device,
            customerId: session.customerId,
            confidence: confidence!,
            biometricUsed: body.biometric_used,
          })
        }

        // ── Dispatch webhook ─────────────────────────────────────────────────
        // §7: device_token intentionally absent from webhook payload
        if (signatureValid) {
          await dispatchWebhook({ customerId: session.customerId, appId: session.appId }, {
            event: 'verification.complete',
            session_id,
            verified: true,
            confidence: confidence!,
            context: session.context,
            timestamp: new Date().toISOString(),
            api_version: config.apiVersion,
          })
        }

        return reply.code(200).send(responseBody)
      },
    })

    // ── POST /v1/verify/{session_id}/fallback ───────────────────────────────
    scope.post<{ Params: { session_id: string } }>('/verify/:session_id/fallback', {
      config: {
        rateLimit: {
          max: FALLBACK_RATE.max,
          timeWindow: FALLBACK_RATE.window,
          keyGenerator: (req: any) => {
            // §7: per device_token per 24h (also per email_hash and per IP — enforced in handler)
            const body = req.body as any
            return `fallback_init:${body?.device_token ?? req.ip}`
          },
        },
      },
      handler: async (request, reply) => {
        const { session_id } = request.params

        // Detect if this is fallback initiation or OTP completion
        // §7: fallback complete uses POST /v1/verify/{id}/complete but the brief's
        // fallback section implies a different schema. Implementing OTP completion
        // as a secondary parse path on this same handler since the brief shows
        // "Fallback OTP submission uses same endpoint" for complete.
        // Actually the brief says OTP submission is on /complete. Fallback initiation
        // is on /fallback. Initiation and completion are separate endpoints.

        const parsed = FallbackSchema.safeParse(request.body)
        if (!parsed.success) {
          return reply.code(400).send({ error: { code: 'invalid_request', message: parsed.error.message } })
        }
        const body = parsed.data

        // ── Session exists ───────────────────────────────────────────────────
        const session = await prisma.verification.findUnique({ where: { sessionId: session_id } })
        if (!session) {
          return reply.code(404).send({ error: { code: 'session_not_found', message: 'Session not found.' } })
        }
        if (session.customerId !== request.customerId || session.appId !== request.appId) {
          return reply.code(403).send({ error: { code: 'session_not_owned', message: 'Session does not belong to this app.' } })
        }

        // ── Session must be in INITIATED state ────────────────────────────
        // §7 state machine: INITIATED → FALLBACK (terminal for primary path)
        if (session.state !== 'INITIATED') {
          return reply.code(409).send({
            error: {
              code: 'invalid_session_state',
              message: `Session is in state ${session.state}, expected INITIATED.`,
              current_state: session.state,
            },
          })
        }

        // ── Per-IP rate limit (§11: max 10 fallback initiations / hr) ───
        // In-process counter (was Redis INCR+EXPIRE). Per-machine, not
        // per-tenant — same trade-off we accepted for the global
        // @fastify/rate-limit move off Redis. At 1 API machine the limit
        // is effectively the same; if we add machines we revisit.
        const ipCount = counterIncr(`fallback_ip:${request.ip}`, 3600)
        if (ipCount > 10) {
          return reply.code(429).send({ error: { code: 'rate_limited', message: 'Too many fallback attempts from this IP.' } })
        }

        // ── Per-email_hash rate limit (§11: max 5 OTP sends / hr) ────────
        const emailCount = counterIncr(`fallback_email:${body.email_hash}`, 3600)
        if (emailCount > 5) {
          return reply.code(429).send({ error: { code: 'rate_limited', message: 'Too many OTP requests for this email.' } })
        }

        // ── Atomic state transition to FALLBACK ───────────────────────────
        const otp = generateOtp()
        const otpHash = hashOtp(otp)
        const otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000)
        const fallbackSessionId = `fbs_${crypto.randomBytes(12).toString('hex')}`

        const transitioned = await prisma.verification.updateMany({
          where: { sessionId: session_id, state: 'INITIATED' },
          data: {
            state: 'FALLBACK',
            fallbackUsed: true,
            fallbackReason: body.reason,
            otpHash,
            otpExpiresAt,
            otpAttempts: 0,
            otpEmailHash: body.email_hash,
            disposableEmailDomain: isDisposableEmailDomain(body.email),
            ipAddress: request.ip,
            // Store fallback_session_id in retrySessionId field (reusing for fallback tracking)
            retrySessionId: fallbackSessionId,
          },
        })

        if (transitioned.count === 0) {
          return reply.code(409).send({
            error: { code: 'concurrent_state_change', message: 'Session state changed concurrently.' },
          })
        }

        // Handle device_token null/absent case (§7: may be null if enrollment failed)
        if (body.device_token == null) {
          // Create minimal device record flagged enrollment_failed, link to session
          const failedDevice = await prisma.device.upsert({
            where: { deviceToken: `dvt_failed_${session_id}` },
            create: {
              deviceToken: `dvt_failed_${session_id}`,
              customerId: session.customerId,
              appId:      session.appId,  // chunk1-compile-fix: failed-enrollment placeholder Device
              publicKey: '',
              keyFingerprint: '',
              platform: 'unknown',
              status: 'enrollment_failed',
              isSandbox: session.isSandbox,
            },
            update: {},
          })
          await prisma.verification.update({
            where: { sessionId: session_id },
            data: { deviceId: failedDevice.id },
          })
        }

        // Deliver OTP via Resend. Plaintext email used here and then discarded —
        // only the hash is persisted on the verification record.
        await sendOtp({ email: body.email, emailHash: body.email_hash, otp, expiresAt: otpExpiresAt, appName: request.appName })

        return reply.code(200).send({
          fallback_session_id: fallbackSessionId,
          method: 'email_otp',
          expires_at: otpExpiresAt.toISOString(),
          session_state: 'FALLBACK',
        })
      },
    })
  })

  // ── GET /v1/verify/{session_id} — read-scoped ──────────────────────────────
  await fastify.register(async (scope) => {
    await scope.register(readAuth)

    scope.get<{ Params: { session_id: string } }>('/verify/:session_id', {
      handler: async (request, reply) => {
        const { session_id } = request.params

        const session = await prisma.verification.findUnique({
          where: { sessionId: session_id },
          include: { device: true },
        })

        if (!session) {
          return reply.code(404).send({ error: { code: 'session_not_found', message: 'Session not found.' } })
        }

        if (session.customerId !== request.customerId) {
          return reply.code(403).send({ error: { code: 'forbidden', message: 'Session does not belong to this customer.' } })
        }

        return reply.code(200).send({
          session_id: session.sessionId,
          session_state: session.state,
          verified: session.state === 'COMPLETED' || session.state === 'FALLBACK_COMPLETE',
          confidence: session.confidence,
          context: session.context,
          fallback_used: session.fallbackUsed,
          expires_at: session.expiresAt.toISOString(),
          created_at: session.createdAt.toISOString(),
        })
      },
    })
  })

  // ── GET /v1/webhook/test — write-scoped ───────────────────────────────────
  await fastify.register(async (scope) => {
    await scope.register(writeAuth)

    scope.get('/webhook/test', {
      handler: async (request, reply) => {
        const endpoint = await prisma.webhookEndpoint.findFirst({
          where: { customerId: request.customerId },
        })

        if (!endpoint) {
          return reply.code(422).send({
            error: { code: 'webhook_not_configured', message: 'No webhook endpoint configured for this customer.' },
          })
        }

        const testPayload = {
          event: 'verification.test',
          session_id: `ses_test_${crypto.randomBytes(12).toString('hex')}`,
          verified: true,
          confidence: 'high',
          context: 'signup',
          timestamp: new Date().toISOString(),
          api_version: config.apiVersion,
        }

        const { delivered, statusCode, error } = await deliverWebhookTest(
          endpoint.url,
          endpoint.secretEncrypted,
          testPayload,
        )

        return reply.code(200).send(
          delivered
            ? { delivered: true, status_code: statusCode, payload: testPayload }
            : { delivered: false, status_code: statusCode, error, payload: testPayload },
        )
      },
    })
  })
}

export default route

// ─── Fallback OTP completion ──────────────────────────────────────────────────
// §7: "Fallback OTP submission uses same endpoint" (POST /v1/verify/{id}/complete)
// Called when session.state === 'FALLBACK'

async function handleFallbackComplete(
  sessionId: string,
  session: Verification,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  // §7 fallback complete request schema not explicitly specified for the /complete path.
  // The brief shows primary { device_token, signed_challenge, biometric_used }.
  // For OTP, we need { device_token, otp } — derived from the fallback complete response
  // description which shows session_state: FALLBACK_COMPLETE.
  const otpParsed = FallbackCompleteSchema.safeParse(request.body)
  if (!otpParsed.success) {
    return reply.code(400).send({ error: { code: 'invalid_request', message: otpParsed.error.message } })
  }
  const body = otpParsed.data

  // Idempotency: if fallback is already complete and we have a cached response, return it
  if (session.state === 'FALLBACK_COMPLETE') {
    if (session.completionResponse) {
      return reply.code(200).send(session.completionResponse)
    }
    // FALLBACK_COMPLETE but no cached response - shouldn't happen normally
    return reply.code(409).send({
      error: {
        code: 'ceremony_already_completed',
        message: 'Fallback is already completed. Cannot retrieve original response.',
        current_state: session.state,
      },
    })
  }

  // §7: FALLBACK_LOCKED — max attempts exceeded (locked for 1 hour)
  if (session.state === 'FALLBACK_LOCKED' as any) {
    return reply.code(423).send({ error: { code: 'fallback_locked', message: 'Too many OTP attempts. Try again in 1 hour.' } })
  }

  // OTP expiry
  if (!session.otpExpiresAt || new Date() > session.otpExpiresAt) {
    await prisma.verification.update({ where: { sessionId }, data: { state: 'FALLBACK_EXPIRED' } })
    return reply.code(410).send({ error: { code: 'otp_expired', message: 'OTP has expired.' } })
  }

  // Increment attempt count atomically; lock if max exceeded
  const newAttempts = session.otpAttempts + 1
  if (newAttempts > OTP_MAX_ATTEMPTS) {
    await prisma.verification.update({ where: { sessionId }, data: { state: 'FALLBACK_LOCKED' } })
    return reply.code(423).send({ error: { code: 'fallback_locked', message: 'Maximum OTP attempts exceeded. Locked for 1 hour.' } })
  }
  await prisma.verification.update({ where: { sessionId }, data: { otpAttempts: newAttempts } })

  // Verify OTP
  if (!session.otpHash || !verifyOtp(body.otp, session.otpHash)) {
    if (newAttempts >= OTP_MAX_ATTEMPTS) {
      await prisma.verification.update({ where: { sessionId }, data: { state: 'FALLBACK_LOCKED' } })
      return reply.code(423).send({ error: { code: 'fallback_locked', message: 'Maximum OTP attempts exceeded. Locked for 1 hour.' } })
    }
    return reply.code(422).send({
      error: {
        code: 'invalid_otp',
        message: 'Incorrect OTP.',
        attempts_remaining: OTP_MAX_ATTEMPTS - newAttempts,
      },
    })
  }

  // OTP correct — complete
  const completedAt = new Date()
  const timeToComplete = Math.floor((completedAt.getTime() - session.createdAt.getTime()) / 1000)

  // Build the response object for idempotency
  const responseBody = {
    verified: true,
    confidence: 'low',
    session_state: 'FALLBACK_COMPLETE',
    fallback_signals: {
      ip_consistent: session.ipAddress === request.ip,
      disposable_email_domain: session.disposableEmailDomain ?? false,
      device_has_prior_verifications: false, // populated from network_devices if device enrolled
      email_domain_age_days: null,     // TODO: implement domain age lookup
      otp_attempts: newAttempts,
      time_to_complete_seconds: timeToComplete,
    },
  }

  // Store completion state and response for idempotency
  await prisma.verification.update({
    where: { sessionId },
    data: {
      state: 'FALLBACK_COMPLETE',
      confidence: 'low',
      completedAt,
      fallbackTimeToCompleteSeconds: timeToComplete,
      completionResponse: responseBody as any,
    },
  })

  // Dispatch fallback_complete webhook
  await dispatchWebhook({ customerId: session.customerId, appId: session.appId }, {
    event: 'verification.fallback_complete',
    session_id: sessionId,
    verified: true,
    confidence: 'low',
    fallback_method: 'email_otp',
    fallback_reason: session.fallbackReason,
    context: session.context,
    timestamp: completedAt.toISOString(),
    api_version: config.apiVersion,
  })

  return reply.code(200).send(responseBody)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// §7 confidence ladder for minimum_confidence comparison
const CONFIDENCE_RANK: Record<string, number> = { low: 0, medium: 1, high: 2 }

// Exported for unit testing — see __tests__/verify.confidenceMeets.test.ts.
// `ceiling` is the device's confidence_ceiling at enrollment time, `minimum`
// is the minimum_confidence the SDK request asked for.
export function confidenceMeets(ceiling: string, minimum: string): boolean {
  return (CONFIDENCE_RANK[ceiling] ?? 0) >= (CONFIDENCE_RANK[minimum] ?? 0)
}

// Exposed for unit testing in __tests__/verify.signature.test.ts. The
// verifySignature function is the load-bearing crypto check on the verify
// path — a bug here is total auth bypass — so it gets direct test coverage.
export function verifySignature(params: {
  publicKey: string
  challenge: string
  signature: string
}): { valid: boolean; reason?: string } {
  try {
    const verify = crypto.createVerify('SHA256')
    verify.update(Buffer.from(params.challenge, 'base64'))
    // §6 Decision 4: EC secp256r1 keys — public_key is SubjectPublicKeyInfo DER, base64-encoded.
    // Java's PublicKey.encoded / iOS's derRepresentation both produce this format.
    // Constant-time comparison is implicit in crypto.Verify.verify().
    const valid = verify.verify(
      { key: Buffer.from(params.publicKey, 'base64'), format: 'der', type: 'spki' },
      Buffer.from(params.signature, 'base64'),
    )
    return valid ? { valid: true } : { valid: false, reason: 'signature_mismatch' }
  } catch (e) {
    return { valid: false, reason: (e as Error).message }
  }
}

async function deliverWebhookTest(
  url: string,
  secretEncrypted: Buffer,
  payload: object,
): Promise<{ delivered: boolean; statusCode: number | null; error?: string }> {
  const { decryptWebhookSecret } = await import('../services/webhookSecrets.js')
  const secret = await decryptWebhookSecret(secretEncrypted)
  const body = JSON.stringify(payload)
  const timestamp = Math.floor(Date.now() / 1000).toString()
  const hmac = crypto.createHmac('sha256', secret)
  hmac.update(`${timestamp}.${body}`)
  const signature = hmac.digest('hex')

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vouchflow-Signature': `t=${timestamp},v1=${signature}`,
      },
      body,
      signal: AbortSignal.timeout(10_000),
    })
    return { delivered: response.ok, statusCode: response.status }
  } catch (err) {
    return { delivered: false, statusCode: null, error: (err as Error).message }
  }
}

async function writeNetworkVerificationEvent(params: {
  device: { keyFingerprint: string; platform: string; strongboxBacked: boolean | null }
  customerId: string
  confidence: string
  biometricUsed: boolean
}) {
  await prisma.$transaction(async (tx) => {
    const networkDevice = await tx.networkDevice.upsert({
      where: { keyFingerprint: params.device.keyFingerprint },
      create: {
        keyFingerprint: params.device.keyFingerprint,
        platform: params.device.platform,
        strongboxBacked: params.device.strongboxBacked,
        attestationEverVerified: true,
        totalVerifications: 1,
        customerCount: 1,
      },
      update: {
        lastSeen: new Date(),
        totalVerifications: { increment: 1 },
        attestationEverVerified: true,
      },
    })

    await tx.networkEvent.create({
      data: {
        networkDeviceId: networkDevice.id,
        customerId: params.customerId,
        eventType: 'verification',
        confidence: params.confidence,
        biometricUsed: params.biometricUsed,
        fallbackUsed: false,
      },
    })
  })

  // §15 anomaly scoring runs inline — see enroll.ts for the rationale.
  void scoreAnomaly({ keyFingerprint: params.device.keyFingerprint }).catch((err) => {
    console.error(`[anomaly] inline scoring failed for ${params.device.keyFingerprint}: ${err.message}`)
  })
}
