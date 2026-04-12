function base64Bytes(bytes: number): string {
  return Buffer.alloc(bytes, 1).toString('base64')
}

export function setupTestEnv(): void {
  // Core
  process.env.NODE_ENV = 'test'
  // Application
  process.env.APP_HOSTNAME = '127.0.0.1'
  process.env.APP_PORT = '3000'
  process.env.APP_NAME = 'peacekeeper-test'
  process.env.APP_VERSION = '0.1.0'
  process.env.APP_URL = 'http://127.0.0.1:3000'
  // gRPC
  process.env.GRPC_HOSTNAME = '127.0.0.1'
  process.env.GRPC_PORT = '50051'
  process.env.GRPC_TIMEOUT = '3000'
  process.env.GRPC_ACCESS_TOKEN = base64Bytes(32)
  // Database
  process.env.DB_TYPE = 'postgresql'
  process.env.DB_HOST = 'localhost'
  process.env.DB_PORT = '5432'
  process.env.DB_NAME = 'test_db'
  process.env.DB_USER = 'test_user'
  process.env.DB_PASSWORD = 'test_password'
  process.env.DB_SSL = 'false'
  process.env.DB_POOL_MIN = '2'
  process.env.DB_POOL_MAX = '15'
  process.env.DB_CONNECTION_TIMEOUT_MILLIS = '10000'
  process.env.DB_IDLE_TIMEOUT_MILLIS = '30000'
  process.env.DB_SYNC = 'false'
  process.env.DB_LOGGING = 'false'
  // Redis
  process.env.REDIS_ENABLED = 'false'
  process.env.REDIS_HOST = '127.0.0.1'
  process.env.REDIS_PORT = '6379'
  process.env.REDIS_DB = '0'
  process.env.REDIS_TTL = '3600'
  process.env.REDIS_MAX_RETRIES = '3'
  process.env.REDIS_RETRY_DELAY = '1000'
  process.env.REDIS_CONNECTION_TIMEOUT = '10000'
  process.env.REDIS_ENABLE_OFFLINE_QUEUE = 'false'
  // optional
  delete process.env.REDIS_PASSWORD
  // OPAQUE (STRICT BYTE LENGTH)
  process.env.OPAQUE_SEED = base64Bytes(64)
  process.env.OPAQUE_SERVER_PRIVATE_KEY = base64Bytes(32)
  process.env.OPAQUE_SERVER_PUBLIC_KEY = base64Bytes(32)
  process.env.OPAQUE_CONTEXT = 'OPAQUE-RFC9807-ristretto255-SHA512'
  // JWT
  process.env.JWT_ACCESS_EXPIRES_IN = '3m'
  process.env.JWT_REFRESH_EXPIRES_IN = '24h'
  // Session TTL
  process.env.SESSION_REMEMBER_ME_TTL = '30d'
  process.env.SESSION_TTL = '24h'
  // Security
  process.env.CORS_ORIGIN = 'http://localhost,http://127.0.0.1'
  process.env.RATE_LIMIT_WINDOW_MS = '900000'
  process.env.RATE_LIMIT_MAX = '100'
  // Email
  process.env.SMTP_HOST = '127.0.0.1'
  process.env.SMTP_PORT = '465'
  process.env.SMTP_FROM = 'noreply@test.local'
  // optional auth
  delete process.env.SMTP_USER
  delete process.env.SMTP_PASSWORD
  // File Upload
  process.env.UPLOAD_DIR = 'uploads'
  process.env.MAX_FILE_SIZE = '5242880'
  process.env.ALLOWED_FILE_TYPES = 'image/jpeg,image/png,image/jpg,application/pdf'
  // Logging
  process.env.LOG_LEVEL = 'info'
  process.env.LOG_DIR = 'logs'
  process.env.LOG_TO_FILE = 'false'
  // External Services
  delete process.env.SENTRY_DSN
  delete process.env.GOOGLE_CLIENT_ID
  delete process.env.GOOGLE_CLIENT_SECRET
  delete process.env.AWS_ACCESS_KEY_ID
  delete process.env.AWS_SECRET_ACCESS_KEY
  delete process.env.AWS_REGION
  delete process.env.AWS_S3_BUCKET
  // Feature Flags
  process.env.ENABLE_SWAGGER = 'true'
  process.env.ENABLE_WEBSOCKET = 'true'
  process.env.ENABLE_CRON_JOBS = 'true'
  process.env.ENABLE_METRICS = 'false'
}
