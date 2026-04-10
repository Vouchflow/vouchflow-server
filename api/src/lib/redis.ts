import Redis from 'ioredis'
import { config } from '../config.js'

export const redis = new Redis(config.redisUrl, {
  maxRetriesPerRequest: null, // required by BullMQ
  enableReadyCheck: false,
})
