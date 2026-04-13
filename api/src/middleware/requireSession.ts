import type { FastifyRequest, FastifyReply } from 'fastify'

export async function requireSession(
  request: FastifyRequest,
  reply: FastifyReply
) {
  if (!request.session.get('email')) {
    return reply.redirect('/signup')
  }
}
