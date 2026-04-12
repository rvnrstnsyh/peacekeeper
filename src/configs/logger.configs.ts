import path from 'path'
import winston from 'winston'
import DailyRotateFile from 'winston-daily-rotate-file'

import type { Logform, Logger } from 'winston'

import { env } from '@/configs/environment.configs'
import { SENSITIVE_KEYS } from '@/shared/constants/common.constants'

const levels: Record<string, number> = {
  error: 0,
  warning: 1,
  info: 2,
  http: 3,
  debug: 4
}

winston.addColors({
  error: 'red',
  warning: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white'
})

// Type for metadata to be sanitized
type LogMetadata = Record<string, unknown>

// Sanitize function for sensitive data
function sanitizeSensitiveData(obj: unknown): unknown {
  if (typeof obj !== 'object' || obj === null) {
    return obj
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeSensitiveData(item))
  }

  if (!env.isProduction) {
    return obj
  }

  const sanitized: LogMetadata = {}

  for (const [key, value] of Object.entries(obj as LogMetadata)) {
    if (SENSITIVE_KEYS.some((sensitive: string): boolean => key.toLowerCase().includes(sensitive))) {
      sanitized[key] = '[REDACTED]'
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeSensitiveData(value)
    } else {
      sanitized[key] = value
    }
  }
  return sanitized
}

// Format for production (JSON)
const productionFormat: Logform.Format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json(),
  winston.format.printf((info) => {
    const { timestamp, level, message, ...metadata }: Logform.TransformableInfo = info
    const log: Record<string, unknown> = {
      timestamp,
      level,
      message,
      ...(sanitizeSensitiveData(metadata) as Record<string, unknown>)
    }
    return JSON.stringify(log)
  })
)

// Format for development (Colorized & Pretty)
const developmentFormat: Logform.Format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format((info: Logform.TransformableInfo): Logform.TransformableInfo => {
    info.level = info.level.toUpperCase()
    return info
  })(),
  winston.format.colorize({ all: true }),
  winston.format.printf(({ timestamp, level, message, ...metadata }): string => {
    let msg: string = `${timestamp} [${level}]: ${message}`
    // Add metadata if exists (excluding sensitive info)
    const metaKeys: Array<string> = Object.keys(metadata).filter((key) => !['password', 'token', 'authorization', 'cookie'].includes(key))

    if (metaKeys.length > 0) {
      const meta: Record<string, unknown> = metaKeys.reduce(
        (acc: Record<string, unknown>, key: string): Record<string, unknown> => {
          acc[key] = metadata[key]
          return acc
        },
        {} as Record<string, unknown>
      )
      msg = `${msg} ${JSON.stringify(meta, null, 2)}`
    }
    return msg
  })
)

function level(): 'info' | 'debug' {
  return env.NODE_ENV === 'development' ? 'debug' : 'info'
}

const transports: Array<winston.transport> = []

// Console Transport
transports.push(
  new winston.transports.Console({
    format: env.NODE_ENV === 'production' ? productionFormat : developmentFormat
  })
)

// File Transports (Only in Production or when LOG_TO_FILE is true)
if (env.NODE_ENV === 'production' || env.LOG_TO_FILE === true) {
  const logDir: string = env.LOG_DIR || 'logs'
  // All Logs (Daily Rotate)
  transports.push(
    new DailyRotateFile({
      filename: path.join(logDir, 'application-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d', // Keep logs for 14 days
      format: productionFormat,
      level: 'info'
    })
  )

  // Error Logs (Daily Rotate)
  transports.push(
    new DailyRotateFile({
      filename: path.join(logDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d', // Keep error logs for 30 days
      format: productionFormat,
      level: 'error'
    })
  )

  // HTTP Logs (Daily Rotate)
  transports.push(
    new DailyRotateFile({
      filename: path.join(logDir, 'http-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '7d', // Keep HTTP logs for 7 days
      format: productionFormat,
      level: 'http'
    })
  )

  // Debug Logs (Only in development with file logging)
  if (env.NODE_ENV === 'development') {
    transports.push(
      new DailyRotateFile({
        filename: path.join(logDir, 'debug-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '3d', // Keep debug logs for 3 days
        format: productionFormat,
        level: 'debug'
      })
    )
  }
}

export const logger: Logger = winston.createLogger({
  level: level(),
  levels,
  transports,
  // Don't exit on handled exceptions
  exitOnError: false,
  // Handle uncaught exceptions
  exceptionHandlers:
    env.NODE_ENV === 'production' || env.LOG_TO_FILE === true
      ? [
          new DailyRotateFile({
            filename: path.join(env.LOG_DIR || 'logs', 'exceptions-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '30d'
          })
        ]
      : [],
  // Handle unhandled promise rejections
  rejectionHandlers:
    env.NODE_ENV === 'production' || env.LOG_TO_FILE === true
      ? [
          new DailyRotateFile({
            filename: path.join(env.LOG_DIR || 'logs', 'rejections-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '30d'
          })
        ]
      : []
})

/**
 * Log HTTP request
 */
export function logRequest(method: string, path: string, statusCode: number, durationMs: number, _id?: string | undefined): void {
  const level: 'error' | 'warning' | 'http' = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'http'

  logger.log(level, 'HTTP request', {
    method,
    path,
    statusCode,
    durationMs: durationMs.toFixed(2),
    _id
  })
}

/**
 * Log database query
 */
export function logQuery(query: string, durationMs: number, success: boolean): void {
  logger.debug('Database Query', {
    query: query.substring(0, 200), // Truncate long queries
    durationMs: durationMs.toFixed(2),
    success
  })
}

/**
 * Log authentication event
 */
export function logAuth(
  event: 'sign_in_alpha' | 'sign_in_beta' | 'sign_out' | 'sign_up_alpha' | 'sign_up_beta' | 'change_password_alpha' | 'change_password_beta' | 'token_refresh',
  userId: string | number,
  success: boolean,
  metadata?: Record<string, unknown>
): void {
  logger.info('Authentication Event', {
    event,
    userId,
    success,
    ...metadata
  })
}

/**
 * Log security event
 */
export function logSecurity(event: string, severity: 'low' | 'medium' | 'high' | 'critical', details: Record<string, unknown>): void {
  const level: 'info' | 'error' | 'warning' = severity === 'critical' ? 'error' : severity === 'high' ? 'warning' : 'info'

  logger.log(level, 'Security Event', {
    event,
    severity,
    ...details
  })
}

/**
 * Log business event
 */
export function logBusiness(event: string, metadata: Record<string, unknown>): void {
  logger.info('Business Event', {
    event,
    ...metadata
  })
}

/**
 * Log performance metric
 */
export function logPerformance(operation: string, durationMs: number, metadata?: Record<string, unknown>): void {
  const level: 'info' | 'debug' | 'warning' = durationMs > 5000 ? 'warning' : durationMs > 1000 ? 'info' : 'debug'

  logger.log(level, 'Performance Metric', {
    operation,
    durationMs: durationMs.toFixed(2),
    ...metadata
  })
}

/**
 * Log error with context
 */
export function logError(error: Error, context?: Record<string, unknown>): void {
  logger.error('Application Error', {
    message: error.message,
    stack: error.stack,
    name: error.name,
    ...context
  })
}

/**
 * Create child logger with default metadata
 */
export function createChildLogger(defaultMeta: Record<string, unknown>): Logger {
  return logger.child(defaultMeta)
}

export const stream: { write: (message: string) => void } = {
  write: (message: string): void => {
    logger.http(message.trim())
  }
}
