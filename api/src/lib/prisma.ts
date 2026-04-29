import { PrismaClient, Prisma } from '@prisma/client'

const client = new PrismaClient()

// Retry once on P1017 (server closed connection — stale idle connection after DB sleep).
export const prisma = client.$extends({
  query: {
    $allModels: {
      async $allOperations({ args, query }) {
        try {
          return await query(args)
        } catch (e) {
          if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P1017') {
            await client.$disconnect()
            await client.$connect()
            return await query(args)
          }
          throw e
        }
      },
    },
  },
})
