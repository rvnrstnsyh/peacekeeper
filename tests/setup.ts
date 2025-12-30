import { setupTestEnv } from '!/helpers/mock-env'

setupTestEnv()

import type { Context, Next } from 'hono'

import { vi } from 'vitest'

vi.spyOn(process, 'exit').mockImplementation(((code?: number): void => {
  throw new Error(`process.exit(${code}) was called during test`)
}) as never)

// Mock the entire endpoints registration to skip route loading
vi.mock('@/infra/http/endpoints', () => ({
  registerEndpoints: vi.fn()
}))

// Mock logger middleware to avoid context storage issues
vi.mock('@/shared/middlewares/logger.middleware', () => ({
  honoLogger: vi.fn(() => async (ctx: Context<Generics>, next: Next) => {
    await next()
  })
}))

// Mock other infrastructure dependencies
vi.mock('@/config/redis', () => ({
  connectRedis: vi.fn().mockResolvedValue(undefined),
  disconnectRedis: vi.fn().mockResolvedValue(undefined)
}))

vi.mock('@/database/connection', () => ({
  connectDatabase: vi.fn().mockResolvedValue(undefined),
  disconnectDatabase: vi.fn().mockResolvedValue(undefined)
}))

vi.mock('@/infra/grpc/client', () => ({
  default: vi.fn().mockImplementation(() => ({
    public: {
      health: vi.fn().mockResolvedValue('localhost:50051')
    },
    close: vi.fn()
  }))
}))

vi.mock('@/infra/ws/events', () => ({
  closeAllWsConnections: vi.fn(),
  ws: {
    injectWebSocket: vi.fn()
  }
}))
