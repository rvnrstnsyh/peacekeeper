import { sql } from 'drizzle-orm'
import { logger } from '@/configs/logger.configs'
import { db, getPool } from '@/database/connection'

async function resetDatabase(): Promise<void> {
  try {
    logger.warning('Starting database reset...')

    // Drop all tables
    await db.execute(sql`DROP SCHEMA public CASCADE`)
    await db.execute(sql`CREATE SCHEMA public`)
    await db.execute(sql`GRANT ALL ON SCHEMA public TO public`)

    logger.info('Database reset completed')

    // Close pool
    await getPool().end()

    process.exit(0)
  } catch (error: unknown) {
    logger.error('Database reset failed', { error })
    process.exit(1)
  }
}

// Confirm before reset
const args: Array<string> = process.argv.slice(2)
if (args.includes('--force')) {
  resetDatabase()
} else {
  logger.error('Add --force flag to confirm database reset')
  logger.warning('   This will DELETE ALL DATA!')
  logger.warning('   Usage: npm run db:reset -- --force')
  process.exit(1)
}
