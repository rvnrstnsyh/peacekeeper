import type { Context } from 'hono'
import type { ContentfulStatusCode } from 'hono/utils/http-status'
import type { ApiError, CustomHeaders, ErrorMeta, ErrorResponse, MetaBase, PaginationMeta, SuccessMeta, SuccessResponse } from '@/shared/types/http-response.types'

/**
 * Comprehensive HTTP response module providing standardized
 * response formats for all HTTP status codes as per IANA registry.
 *
 * @module httpResponse
 * @reference https://www.iana.org/assignments/http-status-codes/http-status-codes.txt
 */

/** Get response time from context */
function getResponseTime(ctx: Context<Generics>): number {
  const requestTime: number = ctx.get('requestTime')
  return parseFloat((performance.now() - requestTime).toFixed(2))
}

/** Build base metadata */
function buildBaseMeta(ctx: Context<Generics>, status: number, code: string, message: string): Omit<MetaBase, 'responseTimeMs'> {
  return {
    requestId: ctx.get('requestId'),
    path: ctx.req.path,
    method: ctx.req.method,
    status,
    code,
    timestamp: new Date().toISOString(),
    message
  }
}

/** Build response headers */
function buildHeaders(ctx: Context<Generics>, headers?: CustomHeaders): CustomHeaders {
  const responseTime: number = getResponseTime(ctx)
  return {
    'Content-Type': 'application/json',
    'X-Response-Time': `${responseTime}ms`,
    'X-Request-Id': ctx.get('requestId'),
    ...headers
  }
}

/** Final JSON Response generator */
function send<T>(ctx: Context<Generics>, status: ContentfulStatusCode, response: SuccessResponse<T>, headers?: CustomHeaders): Response {
  return ctx.json(response, status, buildHeaders(ctx, headers))
}

/** Create success response */
function createSuccessResponse<T>(ctx: Context<Generics>, status: ContentfulStatusCode, code: string, message: string, headers?: CustomHeaders, data?: T, extra?: unknown): Response {
  const baseMeta: Omit<MetaBase, 'responseTimeMs'> = buildBaseMeta(ctx, status, code, message)
  const meta: SuccessMeta = {
    ...baseMeta,
    responseTimeMs: getResponseTime(ctx),
    ...(typeof extra !== 'undefined' ? { extra } : {})
  }
  const response: SuccessResponse<T> = {
    meta,
    data: data ?? null
  }
  return send(ctx, status, response, headers)
}

/** Create error response */
function createErrorResponse(
  ctx: Context<Generics>,
  status: ContentfulStatusCode,
  code: string,
  message: string,
  details?: string,
  errors?: ReadonlyArray<ApiError>,
  headers?: CustomHeaders
): Response {
  const baseMeta: Omit<MetaBase, 'responseTimeMs'> = buildBaseMeta(ctx, status, code, message)
  const meta: ErrorMeta = {
    ...baseMeta,
    responseTimeMs: getResponseTime(ctx),
    ...(details && { details }),
    ...(errors && errors.length > 0 && { errors })
  }
  const response: ErrorResponse = { meta }
  return ctx.json(response, status, buildHeaders(ctx, headers))
}

// =============================================================================
// 1xx - INFORMATIONAL RESPONSES
// =============================================================================

export function continueRequest(ctx: Context<Generics>, message: string = '100 Continue', headers?: CustomHeaders): Response {
  return createSuccessResponse(ctx, 100, 'CONTINUE', message, headers, null)
}

export function switchingProtocols(ctx: Context<Generics>, message: string, protocol: string, headers?: CustomHeaders, code?: string): Response {
  const customHeaders = {
    ...headers,
    Upgrade: protocol
  }
  return createSuccessResponse(ctx, 101 as ContentfulStatusCode, code || 'SWITCHING_PROTOCOLS', message, customHeaders, null)
}

export function processing(ctx: Context<Generics>, message: string = '102 Processing', headers?: CustomHeaders, code?: string): Response {
  return createSuccessResponse(ctx, 102, code || 'PROCESSING', message, headers, null)
}

export function earlyHints(ctx: Context<Generics>, message: string, linkHeaders: ReadonlyArray<string>, headers?: CustomHeaders, code?: string): Response {
  const customHeaders = {
    ...headers,
    Link: linkHeaders.join(', ')
  }
  return createSuccessResponse(ctx, 103, code || 'EARLY_HINTS', message, customHeaders, null)
}

// =============================================================================
// 2xx - SUCCESS RESPONSES
// =============================================================================

export function ok<T>(ctx: Context<Generics>, message: string, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 200, code || 'OK', message, headers, data)
}

export function okNoData(ctx: Context<Generics>, message: string, headers?: CustomHeaders, code?: string): Response {
  return createSuccessResponse(ctx, 200, code || 'OK', message, headers, null)
}

export function okWithMeta<T, M>(ctx: Context<Generics>, message: string, metaData: M, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 200, code || 'OK', message, headers, data, metaData)
}

export function created<T>(ctx: Context<Generics>, message: string, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 201, code || 'CREATED', message, headers, data)
}

export function accepted(ctx: Context<Generics>, message: string = 'Request accepted for processing', headers?: CustomHeaders, code?: string): Response {
  return createSuccessResponse(ctx, 202, code || 'ACCEPTED', message, headers, null)
}

export function acceptedWithData<T>(ctx: Context<Generics>, message: string, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 202, code || 'ACCEPTED', message, headers, data)
}

export function nonAuthoritativeInfo<T>(ctx: Context<Generics>, message: string, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 203, code || 'NON_AUTHORITATIVE_INFORMATION', message, headers, data)
}

export function noContent(ctx: Context<Generics>, headers?: CustomHeaders): Response {
  return ctx.body(null, 204, buildHeaders(ctx, headers))
}

export function resetContent(ctx: Context<Generics>, headers?: CustomHeaders): Response {
  return ctx.body(null, 205, buildHeaders(ctx, headers))
}

export function partialContent<T>(ctx: Context<Generics>, message: string, contentRange: string, headers?: CustomHeaders, data?: T, code?: string): Response {
  const customHeaders: { 'Content-Range': string } = {
    ...headers,
    'Content-Range': contentRange
  }
  return createSuccessResponse(ctx, 206, code || 'PARTIAL_CONTENT', message, customHeaders, data)
}

export function multiStatus<T>(ctx: Context<Generics>, message: string, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 207, code || 'MULTI_STATUS', message, headers, data)
}

export function alreadyReported<T>(ctx: Context<Generics>, message: string, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 208, code || 'ALREADY_REPORTED', message, headers, data)
}

export function imUsed<T>(ctx: Context<Generics>, message: string, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 226, code || 'IM_USED', message, headers, data)
}

export function paginated<T extends ReadonlyArray<unknown>>(ctx: Context<Generics>, message: string, pagination: PaginationMeta, headers?: CustomHeaders, data?: T, code?: string): Response {
  return createSuccessResponse(ctx, 200, code || 'OK', message, headers, data, {
    pagination
  })
}

// =============================================================================
// 3xx - REDIRECTION RESPONSES
// =============================================================================

export function multipleChoices(ctx: Context<Generics>, message: string, choices: ReadonlyArray<string>, headers?: CustomHeaders, code?: string): Response {
  return createSuccessResponse(ctx, 300, code || 'MULTIPLE_CHOICES', message, headers, { choices })
}

export function movedPermanently(ctx: Context<Generics>, message: string, location: string, headers?: CustomHeaders, code?: string): Response {
  const customHeaders = { ...headers, Location: location }
  return createSuccessResponse(ctx, 301, code || 'MOVED_PERMANENTLY', message, customHeaders, null)
}

export function found(ctx: Context<Generics>, message: string, location: string, headers?: CustomHeaders, code?: string): Response {
  const customHeaders = { ...headers, Location: location }
  return createSuccessResponse(ctx, 302, code || 'FOUND', message, customHeaders, null)
}

export function seeOther(ctx: Context<Generics>, message: string, location: string, headers?: CustomHeaders, code?: string): Response {
  const customHeaders = { ...headers, Location: location }
  return createSuccessResponse(ctx, 303, code || 'SEE_OTHER', message, customHeaders, null)
}

export function notModified(ctx: Context<Generics>, headers?: CustomHeaders): Response {
  return ctx.body(null, 304, buildHeaders(ctx, headers))
}

export function useProxy(ctx: Context<Generics>, message: string, proxyLocation: string, headers?: CustomHeaders, code?: string): Response {
  const customHeaders = { ...headers, Location: proxyLocation }
  return createSuccessResponse(ctx, 305, code || 'USE_PROXY', message, customHeaders, null)
}

export function unusedRedirect(ctx: Context<Generics>, headers?: CustomHeaders): Response {
  return ctx.body(null, 306, buildHeaders(ctx, headers))
}

export function temporaryRedirect(ctx: Context<Generics>, message: string, location: string, headers?: CustomHeaders, code?: string): Response {
  const customHeaders = { ...headers, Location: location }
  return createSuccessResponse(ctx, 307, code || 'TEMPORARY_REDIRECT', message, customHeaders, null)
}

export function permanentRedirect(ctx: Context<Generics>, message: string, location: string, headers?: CustomHeaders, code?: string): Response {
  const customHeaders = { ...headers, Location: location }
  return createSuccessResponse(ctx, 308, code || 'PERMANENT_REDIRECT', message, customHeaders, null)
}

// =============================================================================
// 4xx - CLIENT ERROR RESPONSES
// =============================================================================

export function badRequest(ctx: Context<Generics>, message: string = '400 Bad Request', errors?: ReadonlyArray<ApiError>, code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 400, code || 'BAD_REQUEST', message, undefined, errors, headers)
}

export function unauthorized(ctx: Context<Generics>, message: string = '401 Unauthorized', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 401, code || 'UNAUTHORIZED', message, details, undefined, headers)
}

export function paymentRequired(ctx: Context<Generics>, message: string = '402 Payment Required', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 402, code || 'PAYMENT_REQUIRED', message, details, undefined, headers)
}

export function forbidden(ctx: Context<Generics>, message: string = '403 Forbidden', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 403, code || 'FORBIDDEN', message, details, undefined, headers)
}

export function notFound(ctx: Context<Generics>, message: string = '404 Not Found', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 404, code || 'NOT_FOUND', message, details, undefined, headers)
}

export function methodNotAllowed(ctx: Context<Generics>, message: string = '405 Method Not Allowed', allowedMethods?: ReadonlyArray<string>, code?: string, headers?: CustomHeaders): Response {
  const details: string | undefined = allowedMethods ? `Allowed methods: ${allowedMethods.join(', ')}` : undefined
  const customHeaders: { Allow?: string | undefined } = {
    ...headers,
    ...(allowedMethods && { Allow: allowedMethods.join(', ') })
  }
  return createErrorResponse(ctx, 405, code || 'METHOD_NOT_ALLOWED', message, details, undefined, customHeaders)
}

export function notAcceptable(ctx: Context<Generics>, message: string = '406 Not Acceptable', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 406, code || 'NOT_ACCEPTABLE', message, details, undefined, headers)
}

export function proxyAuthRequired(ctx: Context<Generics>, message: string = '407 Proxy Authentication Required', code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 407, code || 'PROXY_AUTH_REQUIRED', message, undefined, undefined, headers)
}

export function requestTimeout(ctx: Context<Generics>, message: string = '408 Request Timeout', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 408, code || 'REQUEST_TIMEOUT', message, details, undefined, headers)
}

export function conflict(ctx: Context<Generics>, message: string = '409 Conflict', errors?: ReadonlyArray<ApiError>, code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 409, code || 'CONFLICT', message, undefined, errors, headers)
}

export function gone(ctx: Context<Generics>, message: string = '410 Gone', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 410, code || 'GONE', message, details, undefined, headers)
}

export function lengthRequired(ctx: Context<Generics>, message: string = '411 Length Required', code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 411, code || 'LENGTH_REQUIRED', message, undefined, undefined, headers)
}

export function preconditionFailed(ctx: Context<Generics>, message: string = '412 Precondition Failed', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 412, code || 'PRECONDITION_FAILED', message, details, undefined, headers)
}

export function contentTooLarge(ctx: Context<Generics>, message: string = '413 Content Too Large', maxSize?: string, code?: string, headers?: CustomHeaders): Response {
  const details: string | undefined = maxSize ? `Maximum allowed size: ${maxSize}` : undefined
  return createErrorResponse(ctx, 413, code || 'CONTENT_TOO_LARGE', message, details, undefined, headers)
}

export function payloadTooLarge(ctx: Context<Generics>, message: string = '413 Payload Too Large', maxSize?: string, code?: string, headers?: CustomHeaders): Response {
  return contentTooLarge(ctx, message, maxSize, code, headers)
}

export function uriTooLong(ctx: Context<Generics>, message: string = '414 URI Too Long', code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 414, code || 'URI_TOO_LONG', message, undefined, undefined, headers)
}

export function unsupportedMediaType(ctx: Context<Generics>, message: string = '415 Unsupported Media Type', supportedTypes?: ReadonlyArray<string>, code?: string, headers?: CustomHeaders): Response {
  const details: string | undefined = supportedTypes ? `Supported types: ${supportedTypes.join(', ')}` : undefined
  return createErrorResponse(ctx, 415, code || 'UNSUPPORTED_MEDIA_TYPE', message, details, undefined, headers)
}

export function rangeNotSatisfiable(ctx: Context<Generics>, message: string = '416 Range Not Satisfiable', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 416, code || 'RANGE_NOT_SATISFIABLE', message, details, undefined, headers)
}

export function expectationFailed(ctx: Context<Generics>, message: string = '417 Expectation Failed', code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 417, code || 'EXPECTATION_FAILED', message, undefined, undefined, headers)
}

export function imATeapot(ctx: Context<Generics>, message: string = "418 I'm a teapot", code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 418, code || 'IM_A_TEAPOT', message, undefined, undefined, headers)
}

export function misdirectedRequest(ctx: Context<Generics>, message: string = '421 Misdirected Request', code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 421, code || 'MISDIRECTED_REQUEST', message, undefined, undefined, headers)
}

export function unprocessableContent(ctx: Context<Generics>, message: string = '422 Unprocessable Content', errors?: ReadonlyArray<ApiError>, code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 422, code || 'UNPROCESSABLE_CONTENT', message, undefined, errors, headers)
}

export function unprocessableEntity(ctx: Context<Generics>, message: string = '422 Unprocessable Entity', errors?: ReadonlyArray<ApiError>, code?: string, headers?: CustomHeaders): Response {
  return unprocessableContent(ctx, message, errors, code, headers)
}

export function locked(ctx: Context<Generics>, message: string = '423 Locked', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 423, code || 'LOCKED', message, details, undefined, headers)
}

export function failedDependency(ctx: Context<Generics>, message: string = '424 Failed Dependency', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 424, code || 'FAILED_DEPENDENCY', message, details, undefined, headers)
}

export function tooEarly(ctx: Context<Generics>, message: string = '425 Too Early', code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 425, code || 'TOO_EARLY', message, undefined, undefined, headers)
}

export function upgradeRequired(ctx: Context<Generics>, message: string = '426 Upgrade Required', requiredProtocol?: string, code?: string, headers?: CustomHeaders): Response {
  const details: string | undefined = requiredProtocol ? `Required protocol: ${requiredProtocol}` : undefined
  const customHeaders = {
    ...headers,
    ...(requiredProtocol && { Upgrade: requiredProtocol })
  }
  return createErrorResponse(ctx, 426, code || 'UPGRADE_REQUIRED', message, details, undefined, customHeaders)
}

export function preconditionRequired(ctx: Context<Generics>, message: string = '428 Precondition Required', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 428, code || 'PRECONDITION_REQUIRED', message, details, undefined, headers)
}

export function tooManyRequests(ctx: Context<Generics>, message: string = '429 Too Many Requests', retryAfter?: number, code?: string, headers?: CustomHeaders): Response {
  const details: string | undefined = retryAfter ? `Retry after ${retryAfter} seconds` : undefined
  const customHeaders = {
    ...headers,
    ...(retryAfter && { 'Retry-After': retryAfter.toString() })
  }
  return createErrorResponse(ctx, 429, code || 'RATE_LIMIT_EXCEEDED', message, details, undefined, customHeaders)
}

export function requestHeaderFieldsTooLarge(ctx: Context<Generics>, message: string = '431 Request Header Fields Too Large', code?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 431, code || 'REQUEST_HEADER_FIELDS_TOO_LARGE', message, undefined, undefined, headers)
}

export function unavailableForLegalReasons(ctx: Context<Generics>, message: string = '451 Unavailable For Legal Reasons', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 451, code || 'UNAVAILABLE_FOR_LEGAL_REASONS', message, details, undefined, headers)
}

// =============================================================================
// 5xx - SERVER ERROR RESPONSES
// =============================================================================

export function internalServerError(ctx: Context<Generics>, message: string = '500 Internal Server Error', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 500, code || 'INTERNAL_SERVER_ERROR', message, details, undefined, headers)
}

export function notImplemented(ctx: Context<Generics>, message: string = '501 Not Implemented', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 501, code || 'NOT_IMPLEMENTED', message, details, undefined, headers)
}

export function badGateway(ctx: Context<Generics>, message: string = '502 Bad Gateway', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 502, code || 'BAD_GATEWAY', message, details, undefined, headers)
}

export function serviceUnavailable(ctx: Context<Generics>, message: string = '503 Service Unavailable', retryAfter?: number, code?: string, headers?: CustomHeaders): Response {
  const details: string | undefined = retryAfter ? `Retry after ${retryAfter} seconds` : undefined
  const customHeaders = {
    ...headers,
    ...(retryAfter && { 'Retry-After': retryAfter.toString() })
  }
  return createErrorResponse(ctx, 503, code || 'SERVICE_UNAVAILABLE', message, details, undefined, customHeaders)
}

export function gatewayTimeout(ctx: Context<Generics>, message: string = '504 Gateway Timeout', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 504, code || 'GATEWAY_TIMEOUT', message, details, undefined, headers)
}

export function httpVersionNotSupported(ctx: Context<Generics>, message: string = '505 HTTP Version Not Supported', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 505, code || 'HTTP_VERSION_NOT_SUPPORTED', message, details, undefined, headers)
}

export function variantAlsoNegotiates(ctx: Context<Generics>, message: string = '506 Variant Also Negotiates', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 506, code || 'VARIANT_ALSO_NEGOTIATES', message, details, undefined, headers)
}

export function insufficientStorage(ctx: Context<Generics>, message: string = '507 Insufficient Storage', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 507, code || 'INSUFFICIENT_STORAGE', message, details, undefined, headers)
}

export function loopDetected(ctx: Context<Generics>, message: string = '508 Loop Detected', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 508, code || 'LOOP_DETECTED', message, details, undefined, headers)
}

export function notExtended(ctx: Context<Generics>, message: string = '510 Not Extended', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 510, code || 'NOT_EXTENDED', message, details, undefined, headers)
}

export function networkAuthenticationRequired(ctx: Context<Generics>, message: string = '511 Network Authentication Required', code?: string, details?: string, headers?: CustomHeaders): Response {
  return createErrorResponse(ctx, 511, code || 'NETWORK_AUTH_REQUIRED', message, details, undefined, headers)
}

// =============================================================================
// DEFAULT EXPORT (ALL FUNCTIONS)
// =============================================================================

export default {
  continueRequest,
  switchingProtocols,
  processing,
  earlyHints,

  ok,
  okNoData,
  okWithMeta,
  created,
  accepted,
  acceptedWithData,
  nonAuthoritativeInfo,
  noContent,
  resetContent,
  partialContent,
  multiStatus,
  alreadyReported,
  imUsed,
  paginated,

  multipleChoices,
  movedPermanently,
  found,
  seeOther,
  notModified,
  useProxy,
  unusedRedirect,
  temporaryRedirect,
  permanentRedirect,

  badRequest,
  unauthorized,
  paymentRequired,
  forbidden,
  notFound,
  methodNotAllowed,
  notAcceptable,
  proxyAuthRequired,
  requestTimeout,
  conflict,
  gone,
  lengthRequired,
  preconditionFailed,
  contentTooLarge,
  payloadTooLarge,
  uriTooLong,
  unsupportedMediaType,
  rangeNotSatisfiable,
  expectationFailed,
  imATeapot,
  misdirectedRequest,
  unprocessableContent,
  unprocessableEntity,
  locked,
  failedDependency,
  tooEarly,
  upgradeRequired,
  preconditionRequired,
  tooManyRequests,
  requestHeaderFieldsTooLarge,
  unavailableForLegalReasons,

  internalServerError,
  notImplemented,
  badGateway,
  serviceUnavailable,
  gatewayTimeout,
  httpVersionNotSupported,
  variantAlsoNegotiates,
  insufficientStorage,
  loopDetected,
  notExtended,
  networkAuthenticationRequired
}
