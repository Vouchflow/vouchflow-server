import type { FastifyInstance } from 'fastify'
import { requireSession } from '../middleware/requireSession.js'

export default async function pageRoutes(fastify: FastifyInstance) {

  // Public pages
  fastify.get('/',              async (_, reply) => reply.sendFile('index.html'))
  fastify.get('/signup',        async (_, reply) => reply.sendFile('signup.html'))
  fastify.get('/docs',          async (_, reply) => reply.sendFile('docs.html'))
  fastify.get('/api-reference', async (_, reply) => reply.sendFile('api-reference.html'))

  // Protected pages
  const protected_ = { preHandler: requireSession }

  fastify.get('/onboarding',    protected_, async (_, reply) => reply.sendFile('onboarding.html'))
  fastify.get('/dashboard',     protected_, async (_, reply) => reply.sendFile('dashboard.html'))
  fastify.get('/verifications', protected_, async (_, reply) => reply.sendFile('verifications.html'))
  fastify.get('/settings',      protected_, async (_, reply) => reply.sendFile('settings.html'))
}
