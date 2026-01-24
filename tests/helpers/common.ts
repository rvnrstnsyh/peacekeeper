import type { SuccessResponse, ErrorResponse, ApiError } from '@/shared/types/http-response.utils.types'

import { expect } from 'vitest'

/**
 * Test helpers for validating HTTP responses
 */

interface ResponseValidationOptions {
  checkData?: boolean
  checkErrors?: boolean
  checkDetails?: boolean
  checkExtra?: boolean
}

interface ResponseMeta {
  requestId: string
  path: string
  method: string
  status: number
  code: string
  timestamp: string
  message: string
  responseTimeMs: number
  errors?: ApiError[]
  details?: string
  extra?: Record<string, unknown>
  [key: string]: unknown
}

interface BaseResponse {
  meta: ResponseMeta
  [key: string]: unknown
}

interface PaginationData {
  page: number
  limit: number
  total: number
  totalPages: number
  [key: string]: unknown
}

interface MetaWithPagination extends ResponseMeta {
  extra: {
    pagination: PaginationData
    [key: string]: unknown
  }
}

/**
 * Type guard to check if value is a record object
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Validate base meta structure (common to all responses)
 */
export function validateBaseMeta(meta: unknown, expectedPath: string, expectedMethod: string = 'GET'): asserts meta is ResponseMeta {
  expect(meta).toBeDefined()
  expect(typeof meta).toBe('object')
  expect(meta).not.toBeNull()

  if (!isRecord(meta)) {
    throw new Error('Meta is not a valid object')
  }

  expect(meta).toHaveProperty('requestId')
  expect(meta).toHaveProperty('path', expectedPath)
  expect(meta).toHaveProperty('method', expectedMethod)
  expect(meta).toHaveProperty('status')
  expect(meta).toHaveProperty('code')
  expect(meta).toHaveProperty('timestamp')
  expect(meta).toHaveProperty('message')
  expect(meta).toHaveProperty('responseTimeMs')

  // Validate types
  expect(typeof meta.requestId).toBe('string')
  expect(typeof meta.path).toBe('string')
  expect(typeof meta.method).toBe('string')
  expect(typeof meta.status).toBe('number')
  expect(typeof meta.code).toBe('string')
  expect(typeof meta.timestamp).toBe('string')
  expect(typeof meta.message).toBe('string')
  expect(typeof meta.responseTimeMs).toBe('number')

  // Validate timestamp format
  const timestamp = meta.timestamp as string
  expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
  expect(new Date(timestamp).toString()).not.toBe('Invalid Date')

  // Validate response time is reasonable
  const responseTime = meta.responseTimeMs as number
  expect(responseTime).toBeGreaterThanOrEqual(0)
  expect(responseTime).toBeLessThan(5000) // 5 seconds max
}

/**
 * Validate success response structure
 */
export function validateSuccessResponse<T = unknown>(
  body: unknown,
  expectedPath: string,
  expectedStatus: number,
  expectedCode: string,
  options: ResponseValidationOptions = {}
): asserts body is SuccessResponse<T> {
  const { checkData = true, checkExtra = false } = options

  expect(body).toBeDefined()
  expect(typeof body).toBe('object')
  expect(body).not.toBeNull()

  if (!isRecord(body)) {
    throw new Error('Response body is not a valid object')
  }

  // Check top-level structure
  expect(body).toHaveProperty('meta')
  expect(body).toHaveProperty('data')
  expect(body).not.toHaveProperty('errors')

  // Validate meta
  validateBaseMeta(body.meta, expectedPath)

  if (!isRecord(body.meta)) {
    throw new Error('Meta is not a valid object')
  }

  expect(body.meta.status).toBe(expectedStatus)
  expect(body.meta.code).toBe(expectedCode)

  // Validate data exists if required
  if (checkData) {
    expect(body.data).toBeDefined()
  }

  // Validate extra metadata if required
  if (checkExtra) {
    expect(body.meta.extra).toBeDefined()
  }
}

/**
 * Validate error response structure
 */
export function validateErrorResponse(body: unknown, expectedPath: string, expectedStatus: number, expectedCode: string, options: ResponseValidationOptions = {}): asserts body is ErrorResponse {
  const { checkErrors = false, checkDetails = false } = options

  expect(body).toBeDefined()
  expect(typeof body).toBe('object')
  expect(body).not.toBeNull()

  if (!isRecord(body)) {
    throw new Error('Response body is not a valid object')
  }

  // Check top-level structure
  expect(body).toHaveProperty('meta')
  expect(body).not.toHaveProperty('data')

  // Validate meta
  validateBaseMeta(body.meta, expectedPath)

  if (!isRecord(body.meta)) {
    throw new Error('Meta is not a valid object')
  }

  expect(body.meta.status).toBe(expectedStatus)
  expect(body.meta.code).toBe(expectedCode)

  // Validate errors if required
  if (checkErrors) {
    expect(body.meta.errors).toBeDefined()
    expect(Array.isArray(body.meta.errors)).toBe(true)

    const errors = body.meta.errors
    if (errors && Array.isArray(errors) && errors.length > 0) {
      errors.forEach((error: unknown) => {
        if (!isRecord(error)) {
          throw new Error('Error item is not a valid object')
        }
        expect(error).toHaveProperty('field')
        expect(error).toHaveProperty('message')
        expect(typeof error.field).toBe('string')
        expect(typeof error.message).toBe('string')
      })
    }
  }

  // Validate details if required
  if (checkDetails) {
    expect(body.meta.details).toBeDefined()
    expect(typeof body.meta.details).toBe('string')
  }
}

/**
 * Validate response headers
 */
export function validateResponseHeaders(response: Response): void {
  const contentType = response.headers.get('Content-Type')
  expect(contentType).toBeTruthy()
  expect(contentType).toContain('application/json')

  const requestId = response.headers.get('X-Request-Id')
  expect(requestId).toBeTruthy()

  const responseTime = response.headers.get('X-Response-Time')
  expect(responseTime).toBeTruthy()
  expect(responseTime).toMatch(/^\d+\.?\d*ms$/)
}

/**
 * Validate pagination metadata
 */
export function validatePaginationMeta(meta: unknown): asserts meta is MetaWithPagination {
  expect(meta).toBeDefined()
  expect(typeof meta).toBe('object')
  expect(meta).not.toBeNull()

  if (!isRecord(meta)) {
    throw new Error('Meta is not a valid object')
  }

  expect(meta.extra).toBeDefined()
  expect(typeof meta.extra).toBe('object')
  expect(meta.extra).not.toBeNull()

  if (!isRecord(meta.extra)) {
    throw new Error('Meta extra is not a valid object')
  }

  expect(meta.extra.pagination).toBeDefined()
  expect(typeof meta.extra.pagination).toBe('object')
  expect(meta.extra.pagination).not.toBeNull()

  if (!isRecord(meta.extra.pagination)) {
    throw new Error('Pagination is not a valid object')
  }

  const pagination = meta.extra.pagination

  expect(pagination).toHaveProperty('page')
  expect(pagination).toHaveProperty('limit')
  expect(pagination).toHaveProperty('total')
  expect(pagination).toHaveProperty('totalPages')

  expect(typeof pagination.page).toBe('number')
  expect(typeof pagination.limit).toBe('number')
  expect(typeof pagination.total).toBe('number')
  expect(typeof pagination.totalPages).toBe('number')

  const page = pagination.page as number
  const limit = pagination.limit as number
  const total = pagination.total as number
  const totalPages = pagination.totalPages as number

  expect(page).toBeGreaterThanOrEqual(1)
  expect(limit).toBeGreaterThanOrEqual(1)
  expect(total).toBeGreaterThanOrEqual(0)
  expect(totalPages).toBeGreaterThanOrEqual(0)
}

/**
 * Compare two responses for structural consistency
 */
export function compareResponseStructures(response1: BaseResponse, response2: BaseResponse): void {
  const keys1: string[] = Object.keys(response1.meta).sort()
  const keys2: string[] = Object.keys(response2.meta).sort()

  expect(keys1).toEqual(keys2)

  // Check if both have data or both don't
  const hasData1 = 'data' in response1
  const hasData2 = 'data' in response2
  expect(hasData1).toBe(hasData2)
}

/**
 * Validate that response time is reasonable
 */
export function validateResponseTime(responseTimeMs: number, maxTime: number = 1000): void {
  expect(responseTimeMs).toBeGreaterThanOrEqual(0)
  expect(responseTimeMs).toBeLessThan(maxTime)
}

/**
 * Validate unique request IDs across multiple responses
 */
export function validateUniqueRequestIds(responses: BaseResponse[]): void {
  const requestIds = responses.map((r) => r.meta.requestId)
  const uniqueIds = new Set(requestIds)

  expect(uniqueIds.size).toBe(requestIds.length)
}

/**
 * Validate status code matches meta.status
 */
export function validateStatusConsistency(response: Response, body: BaseResponse): void {
  expect(response.status).toBe(body.meta.status)
}

/**
 * Create a test response validator factory
 */
export function createResponseValidator(expectedPath: string, expectedMethod: string = 'GET') {
  return {
    validateSuccess: <T = unknown>(body: unknown, expectedStatus: number, expectedCode: string, options?: ResponseValidationOptions): void => {
      validateSuccessResponse<T>(body, expectedPath, expectedStatus, expectedCode, options)
    },

    validateError: (body: unknown, expectedStatus: number, expectedCode: string, options?: ResponseValidationOptions): void => {
      validateErrorResponse(body, expectedPath, expectedStatus, expectedCode, options)
    },

    validateMeta: (meta: unknown): void => {
      validateBaseMeta(meta, expectedPath, expectedMethod)
    }
  }
}

/**
 * Helper to check if error message doesn't leak sensitive info
 */
export function assertNoSensitiveDataInError(body: BaseResponse, sensitiveTerms: string[]): void {
  const message = body.meta.message?.toLowerCase() || ''
  const details = body.meta.details?.toLowerCase() || ''

  sensitiveTerms.forEach((term: string) => {
    expect(message).not.toContain(term.toLowerCase())
    expect(details).not.toContain(term.toLowerCase())
  })
}

/**
 * Validate redirect response
 */
export function validateRedirectResponse(response: Response, body: BaseResponse, expectedLocation: string, expectedStatus: number): void {
  expect(response.status).toBe(expectedStatus)

  const location = response.headers.get('Location')
  expect(location).toBe(expectedLocation)
  expect(body.meta.status).toBe(expectedStatus)
}

/**
 * Validate rate limit headers
 */
export function validateRateLimitHeaders(response: Response, expectedRetryAfter?: number): void {
  expect(response.status).toBe(429)

  if (expectedRetryAfter !== undefined) {
    const retryAfter = response.headers.get('Retry-After')
    expect(retryAfter).toBe(expectedRetryAfter.toString())
  }
}

/**
 * Batch validate multiple responses
 */
export async function validateMultipleResponses(responses: Response[], validator: (body: unknown, index: number) => void): Promise<void> {
  const bodies = await Promise.all(responses.map((r) => r.json()))

  bodies.forEach((body: unknown, index: number) => {
    validator(body, index)
  })
}

/**
 * Check if two error responses have consistent structure
 */
export function assertErrorStructureConsistency(error1: BaseResponse, error2: BaseResponse): void {
  // Both should have same top-level keys
  const topKeys1 = Object.keys(error1).sort()
  const topKeys2 = Object.keys(error2).sort()
  expect(topKeys1).toEqual(topKeys2)

  // Both should have same meta keys (excluding dynamic values)
  const excludedKeys = ['requestId', 'timestamp', 'responseTimeMs']

  const meta1Keys = Object.keys(error1.meta)
    .filter((k: string) => !excludedKeys.includes(k))
    .sort()

  const meta2Keys = Object.keys(error2.meta)
    .filter((k: string) => !excludedKeys.includes(k))
    .sort()

  expect(meta1Keys).toEqual(meta2Keys)
}

/**
 * Performance test helper
 */
export async function measureResponseTime(fn: () => Promise<Response>): Promise<number> {
  const start: number = performance.now()
  await fn()
  const end: number = performance.now()
  return end - start
}

/**
 * Validate array response
 */
export function validateArrayResponse<T = unknown>(body: SuccessResponse<T[]>, minLength: number = 0, maxLength?: number): void {
  expect(Array.isArray(body.data)).toBe(true)

  if (body.data) {
    expect(body.data.length).toBeGreaterThanOrEqual(minLength)

    if (maxLength !== undefined) {
      expect(body.data.length).toBeLessThanOrEqual(maxLength)
    }
  }
}

/**
 * Validate object response with required keys
 */
export function validateObjectResponse<T extends Record<string, unknown>>(body: SuccessResponse<T>, requiredKeys: string[]): void {
  expect(typeof body.data).toBe('object')
  expect(body.data).not.toBeNull()

  if (body.data) {
    requiredKeys.forEach((key: string): void => {
      expect(body.data).toHaveProperty(key)
    })
  }
}

/**
 * Type guard for success response
 */
export function isSuccessResponse<T = unknown>(body: unknown): body is SuccessResponse<T> {
  if (typeof body !== 'object' || body === null) {
    return false
  }

  const response = body as Record<string, unknown>
  return 'meta' in response && 'data' in response && !('errors' in response)
}

/**
 * Type guard for error response
 */
export function isErrorResponse(body: unknown): body is ErrorResponse {
  if (typeof body !== 'object' || body === null) {
    return false
  }

  const response = body as Record<string, unknown>
  return 'meta' in response && !('data' in response)
}

/**
 * Validate response body type
 */
export function assertResponseType<T = unknown>(body: unknown, expectedType: 'success' | 'error'): asserts body is SuccessResponse<T> | ErrorResponse {
  expect(body).toBeDefined()
  expect(typeof body).toBe('object')
  expect(body).not.toBeNull()

  if (expectedType === 'success') {
    expect(isSuccessResponse(body)).toBe(true)
  } else {
    expect(isErrorResponse(body)).toBe(true)
  }
}

/**
 * Extract and validate meta from response
 */
export function extractMeta(body: unknown): ResponseMeta {
  expect(body).toBeDefined()
  expect(typeof body).toBe('object')
  expect(body).not.toBeNull()

  if (!isRecord(body)) {
    throw new Error('Response body is not a valid object')
  }

  expect(body).toHaveProperty('meta')

  const meta = body.meta
  validateBaseMeta(meta, '', '')

  return meta as ResponseMeta
}

/**
 * Validate error array structure
 */
export function validateErrorArray(errors: unknown): asserts errors is ApiError[] {
  expect(Array.isArray(errors)).toBe(true)

  if (!Array.isArray(errors)) {
    throw new Error('Errors is not an array')
  }

  errors.forEach((error: unknown) => {
    expect(typeof error).toBe('object')
    expect(error).not.toBeNull()

    if (!isRecord(error)) {
      throw new Error('Error item is not a valid object')
    }

    expect(error).toHaveProperty('field')
    expect(error).toHaveProperty('message')
    expect(typeof error.field).toBe('string')
    expect(typeof error.message).toBe('string')
  })
}

export default {
  validateBaseMeta,
  validateSuccessResponse,
  validateErrorResponse,
  validateResponseHeaders,
  validatePaginationMeta,
  compareResponseStructures,
  validateResponseTime,
  validateUniqueRequestIds,
  validateStatusConsistency,
  createResponseValidator,
  assertNoSensitiveDataInError,
  validateRedirectResponse,
  validateRateLimitHeaders,
  validateMultipleResponses,
  assertErrorStructureConsistency,
  measureResponseTime,
  validateArrayResponse,
  validateObjectResponse,
  isSuccessResponse,
  isErrorResponse,
  assertResponseType,
  extractMeta,
  validateErrorArray
}
