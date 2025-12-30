import { logger } from '@/config/logger'
import { db } from '@/database/connection'
import { migrate } from 'drizzle-orm/node-postgres/migrator'

async function runMigrations(): Promise<void> {
  try {
    logger.info('Starting database migrations...')
    await migrate(db, { migrationsFolder: '_drizzle' })
    logger.info('Migrations completed successfully')
    process.exit(0)
  } catch (error: unknown) {
    logger.error('Migration failed', { error })
    process.exit(1)
  }
}

runMigrations()
