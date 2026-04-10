import { Queue } from 'bullmq'
import { redis } from './redis.js'

// Shared BullMQ queue instances.
// Workers consume these in src/workers/index.ts.

export const webhookQueue = new Queue('webhooks', { connection: redis })
export const anomalyQueue = new Queue('anomaly', { connection: redis })
