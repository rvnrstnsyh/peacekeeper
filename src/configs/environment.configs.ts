/* eslint-disable no-console */

import dotenv from 'dotenv'

import type { $ZodIssue } from 'zod/v4/core'

import { z } from 'zod'

// Load environment-specific .env file
const nodeEnv: string = process.env.NODE_ENV || 'development'
const envFile: string = `.env.${nodeEnv}`

dotenv.config({ path: envFile, quiet: true })
dotenv.config({ quiet: true }) // Fallback to .env

function mustBeByteLength(bytes: number) {
  return z.string().refine((v: string): boolean => {
    try {
      return Buffer.from(v, 'base64').length === bytes
    } catch {
      return false
    }
  }, `Value must be base64 representing exactly ${bytes} bytes`)
}

const schema = z.object({
  // Core
  NODE_ENV: z.enum(['development', 'production', 'test', 'staging']).default('development'),

  // Application
  APP_HOSTNAME: z.string().default('localhost'),
  APP_PORT: z.string().transform(Number).pipe(z.number().min(1).max(65535)).default(3000),
  APP_NAME: z.string().default('peacekeeper'),
  APP_VERSION: z.string().default('0.1.0'),
  APP_URL: z.url().default('http://localhost:3000'),

  // gRPC
  GRPC_HOSTNAME: z.string().default('localhost'),
  GRPC_PORT: z.string().transform(Number).pipe(z.number().min(1).max(65535)).default(50051),
  GRPC_TIMEOUT: z.transform(Number).pipe(z.number()).default(3000),
  GRPC_ACCESS_TOKEN: mustBeByteLength(32),

  // Database
  DB_TYPE: z.enum(['postgresql', 'mysql', 'sqlite', 'singlestore', 'turso', 'gel']).default('postgresql'),
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.string().transform(Number).pipe(z.number().min(1).max(65535)).default(5432),
  DB_NAME: z.string().min(1, 'Database name is required'),
  DB_USER: z.string().min(1, 'Database user is required'),
  DB_PASSWORD: z.string().min(1, 'Database password is required'),
  DB_SSL: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(false),
  DB_POOL_MIN: z.string().transform(Number).pipe(z.number().min(0)).default(2),
  DB_POOL_MAX: z.string().transform(Number).pipe(z.number().min(1)).default(10),
  DB_CONNECTION_TIMEOUT_MILLIS: z.transform(Number).pipe(z.number()).default(10000),
  DB_IDLE_TIMEOUT_MILLIS: z.transform(Number).pipe(z.number()).default(30000),
  DB_SYNC: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(false),
  DB_LOGGING: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(false),

  // Redis
  REDIS_ENABLED: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(true),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.string().transform(Number).pipe(z.number().min(1).max(65535)).default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.string().transform(Number).pipe(z.number().min(0).max(15)).default(0),
  REDIS_TTL: z.string().transform(Number).pipe(z.number().min(1)).default(3600),
  REDIS_MAX_RETRIES: z.string().transform(Number).pipe(z.number().min(1)).default(3),
  REDIS_RETRY_DELAY: z.string().transform(Number).pipe(z.number().min(1)).default(1000),
  REDIS_CONNECTION_TIMEOUT: z.string().transform(Number).pipe(z.number().min(1)).default(10000),
  REDIS_ENABLE_OFFLINE_QUEUE: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(false),

  // OPAQUE
  OPAQUE_SEED: mustBeByteLength(64),
  OPAQUE_SERVER_PRIVATE_KEY: mustBeByteLength(32),
  OPAQUE_SERVER_PUBLIC_KEY: mustBeByteLength(32),
  OPAQUE_CONTEXT: z.string().default('OPAQUE-RFC9807-ristretto255-SHA512'),

  // JWT
  JWT_ACCESS_EXPIRES_IN: z.string().default('1h'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),

  // Security
  CORS_ORIGIN: z.string().default('*'),
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).pipe(z.number().min(1)).default(900000),
  RATE_LIMIT_MAX: z.string().transform(Number).pipe(z.number().min(1)).default(100),

  // Email (Optional)
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.string().transform(Number).pipe(z.number().min(1).max(65535)).optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.email().optional(),

  // File Upload
  UPLOAD_DIR: z.string().default('./uploads'),
  MAX_FILE_SIZE: z.string().transform(Number).pipe(z.number().min(1)).default(5242880), // 5MB
  ALLOWED_FILE_TYPES: z.string().default('image/jpeg,image/png,image/jpg,application/pdf'),

  // Logging
  LOG_LEVEL: z.enum(['error', 'warning', 'info', 'http', 'debug']).default('info'),
  LOG_DIR: z.string().default('./logs'),
  LOG_TO_FILE: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(false),

  // External Services (Optional)
  SENTRY_DSN: z.url().optional(),
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  AWS_ACCESS_KEY_ID: z.string().optional(),
  AWS_SECRET_ACCESS_KEY: z.string().optional(),
  AWS_REGION: z.string().optional(),
  AWS_S3_BUCKET: z.string().optional(),

  // Feature Flags
  ENABLE_SWAGGER: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(true),
  ENABLE_WEBSOCKET: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(true),
  ENABLE_CRON_JOBS: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(true),
  ENABLE_METRICS: z
    .string()
    .transform((value: string): boolean => value === 'true')
    .default(false)
})

export let environmentSchema: z.infer<typeof schema>

try {
  environmentSchema = schema.parse(process.env)
} catch (validation) {
  if (validation instanceof z.ZodError) {
    console.error('Invalid environment variables:')
    validation.issues.forEach((error: $ZodIssue): void => {
      console.error(`  - ${error.path.join('.')}: ${error.message}`)
    })
    process.exit(1)
  }
  throw validation
}

export const env = {
  ...environmentSchema,
  // Database connection string
  get DATABASE_URL(): string {
    const { DB_TYPE, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME } = environmentSchema

    if (DB_TYPE === 'postgresql') {
      return `postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=no-verify`
    } else if (DB_TYPE === 'mysql') {
      return `mysql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}`
    } else if (DB_TYPE === 'sqlite') {
      return `file:${DB_NAME || './database.sqlite'}`
    } else if (DB_TYPE === 'singlestore') {
      return `mysql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?ssl=false`
    } else if (DB_TYPE === 'turso') {
      return `libsql://${DB_HOST}`
    } else if (DB_TYPE === 'gel') {
      return `postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=no-verify`
    }

    throw new Error(`Unsupported database type: ${DB_TYPE}`)
  },

  // Redis connection string
  get REDIS_URL(): string | undefined {
    if (!environmentSchema.REDIS_ENABLED) return undefined

    const { REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB } = environmentSchema
    const auth: string = REDIS_PASSWORD ? `:${REDIS_PASSWORD}@` : ''

    return `redis://${auth}${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}`
  },

  // Is production environment
  get isProduction(): boolean {
    return environmentSchema.NODE_ENV === 'production'
  },

  // Is development environment
  get isDevelopment(): boolean {
    return environmentSchema.NODE_ENV === 'development'
  },

  // Is test environment
  get isTest(): boolean {
    return environmentSchema.NODE_ENV === 'test'
  },

  // Parse allowed file types
  get allowedFileTypes(): Array<string> {
    return environmentSchema.ALLOWED_FILE_TYPES.split(',').map((t: string): string => t.trim())
  },

  // Parse CORS origins
  get corsOrigins(): Array<string> {
    return environmentSchema.CORS_ORIGIN.split(',').map((o: string): string => o.trim())
  },

  get serverIdentity() {
    return new TextEncoder().encode(`${environmentSchema.APP_NAME}@${environmentSchema.APP_VERSION}`)
  },

  get oprfSeed(): Buffer {
    return Buffer.from(environmentSchema.OPAQUE_SEED, 'base64')
  },

  get serverKeyPair(): { privateKey: Buffer; publicKey: Buffer } {
    return {
      privateKey: Buffer.from(environmentSchema.OPAQUE_SERVER_PRIVATE_KEY, 'base64'),
      publicKey: Buffer.from(environmentSchema.OPAQUE_SERVER_PUBLIC_KEY, 'base64')
    }
  }
}

export function validateConfig(): void {
  const errors: Array<string> = []

  // Check critical configurations
  if (env.isProduction) {
    if (env.CORS_ORIGIN === '*') {
      errors.push('CORS_ORIGIN should not be "*" in production')
    }
    if (!env.DB_SSL) {
      console.warn('Warning: Database SSL is disabled in production')
    }
  }

  if (errors.length > 0) {
    console.error('Configuration validation failed:')
    errors.forEach((error: unknown): void => console.error(`  - ${error}`))
    process.exit(1)
  }
}

export default env
