import * as dotenv from 'dotenv'

import type { Config } from 'drizzle-kit'

// Load environment-specific .env file
const nodeEnv: string = process.env.NODE_ENV || 'development'
const envFile: string = `.env.${nodeEnv}`

dotenv.config({ path: envFile })
dotenv.config() // Fallback to .env

export default {
  dialect: 'postgresql',
  out: '_drizzle',
  schema: 'src/database/schema',
  dbCredentials: {
    host: String(process.env.DB_HOST) || 'localhost',
    port: Number(process.env.DB_PORT) || 5432,
    user: String(process.env.DB_USER) || 'postgres',
    password: String(process.env.DB_PASSWORD) || '',
    database: String(process.env.DB_NAME) || 'postgres',
    ssl: String(process.env.DB_SSL) === 'true' ? { rejectUnauthorized: false } : false
  },
  verbose: true,
  strict: true,
  casing: 'snake_case'
} satisfies Config
