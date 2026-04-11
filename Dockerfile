FROM node:22-alpine AS builder

WORKDIR /app
COPY api/package*.json ./
RUN npm ci
COPY api/prisma ./prisma
RUN npx prisma generate
COPY api/tsconfig.json ./
COPY api/src ./src
RUN npm run build

FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

RUN apk add --no-cache openssl

COPY api/package*.json ./
RUN npm ci --omit=dev
COPY api/prisma ./prisma
RUN npx prisma generate
COPY --from=builder /app/dist ./dist

# Default entrypoint: API server.
# Worker uses: docker-compose override with CMD ["node", "dist/workers/index.js"]
CMD ["node", "dist/index.js"]
