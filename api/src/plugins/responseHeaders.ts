import { FastifyPluginAsync } from 'fastify'
import fp from 'fastify-plugin'
import { config } from '../config.js'

// §7 Standard Response Headers — applied to all responses
const plugin: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('onSend', async (_request, reply) => {
    reply.header('Vouchflow-API-Version', config.apiVersion)
    reply.header('Vouchflow-API-Deprecated', 'false')
    // X-RateLimit-* headers are added by @fastify/rate-limit per route
  })
}

export default fp(plugin, { name: 'response-headers' })
