import { buildApp } from './app.js'
import { config } from './config.js'
import { prisma } from './lib/prisma.js'

async function main() {
  const app = await buildApp()

  await app.listen({ port: config.port, host: config.host })

  const shutdown = async () => {
    await app.close()
    await prisma.$disconnect()
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
