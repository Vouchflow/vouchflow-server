export {}

declare module 'fastify' {
  interface Session {
    email: string
    customerId: string
    sandboxWriteKey: string
    sandboxReadKey: string
    webhookSecret: string
    createdAt: string
    onboardingComplete: boolean
  }
}
