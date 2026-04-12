import * as schema from '@/database/schema'

import type { PoolClient } from 'pg'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'

import { Pool } from 'pg'
import { logger } from '@/configs/logger.configs'
import { env } from '@/configs/environment.configs'
import { drizzle } from 'drizzle-orm/node-postgres'

const pool: Pool = new Pool({
  host: env.DB_HOST,
  port: env.DB_PORT,
  database: env.DB_NAME,
  user: env.DB_USER,
  password: env.DB_PASSWORD,
  ssl: env.DB_SSL ? { rejectUnauthorized: false } : false,
  min: env.DB_POOL_MIN,
  max: env.DB_POOL_MAX,
  connectionTimeoutMillis: env.DB_CONNECTION_TIMEOUT_MILLIS,
  idleTimeoutMillis: env.DB_IDLE_TIMEOUT_MILLIS
})

export const db: NodePgDatabase<Record<string, unknown>> = drizzle(pool, {
  schema
})

export async function connectDatabase(): Promise<void> {
  try {
    // Test connection
    const client: PoolClient = await pool.connect()

    logger.info('Database connection established', {
      host: env.DB_HOST,
      port: env.DB_PORT,
      database: env.DB_NAME,
      ssl: env.DB_SSL
    })
    // Release the test client
    client.release()
  } catch (error: unknown) {
    logger.error('Failed to connect to database', { error })
    throw error
  }
}

export async function disconnectDatabase(): Promise<void> {
  try {
    await pool.end()
    logger.info('Database connection closed')
  } catch (error: unknown) {
    logger.error('Error closing database connection', { error })
    throw error
  }
}

export function getPool(): Pool {
  return pool
}

export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const client: PoolClient = await pool.connect()
    await client.query('SELECT 1')
    client.release()
    return true
  } catch (error: unknown) {
    logger.error('Database health check failed', { error })
    return false
  }
}
