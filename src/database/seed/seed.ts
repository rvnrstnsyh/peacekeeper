import type { User } from '@/database/schema'

import { logger } from '@/config/logger'
import { users } from '@/database/schema'
import { db } from '@/database/connection'

async function seed(): Promise<void> {
  try {
    logger.info('Starting database seeding...')

    // Create admin
    const [admin]: Array<User> = await db
      .insert(users)
      .values({
        email: 'admin@nvll.me',
        username: 'admin',
        firstName: 'System',
        lastName: 'Admin',
        role: 'admin',
        isEmailVerified: true,
        isActive: true,
        phone: '+1234567890'
      })
      .onConflictDoNothing()
      .returning()

    if (admin) {
      logger.info('Admin user created', { email: admin.email })
    }

    // Create sample user
    const [user]: Array<User> = await db
      .insert(users)
      .values({
        email: 'doe@nvll.me',
        username: 'johndoe',
        firstName: 'John',
        lastName: 'Doe',
        role: 'user',
        isEmailVerified: true,
        isActive: true,
        phone: '+1234567891'
      })
      .onConflictDoNothing()
      .returning()

    if (user) {
      logger.info('User created', { email: user.email })
    }

    logger.info('Database seeding completed successfully')
    logger.info('\nDefault credentials:')
    logger.info('   Email: admin@nvll.me')
    logger.info('   Password: Admin@123\n')

    process.exit(0)
  } catch (error: unknown) {
    logger.error('Seeding failed', { error })
    process.exit(1)
  }
}

seed()
