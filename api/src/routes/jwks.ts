import { FastifyPluginAsync } from 'fastify'
import { getJwksEntries } from '../services/signingKeys.js'

// Public JWKS endpoint. Customers fetch this to verify Vouchflow-signed
// JWS assertions returned by POST /v1/sign/:session_id/complete.
//
// Cache headers: 1-hour browser cache, longer CDN cache. The set is small
// and rotates infrequently; aggressive caching is safe since `kid` lookup
// will trigger a refetch on rotation.
const route: FastifyPluginAsync = async (fastify) => {
  fastify.get(
    '/.well-known/jwks.json',
    {
      config: { rateLimit: { max: 600, timeWindow: '1 minute' } },
    },
    async (_request, reply) => {
      const jwks = await getJwksEntries()
      reply.header('cache-control', 'public, max-age=3600, stale-while-revalidate=86400')
      reply.header('content-type', 'application/json')
      return reply.code(200).send(jwks)
    },
  )
}

export default route
