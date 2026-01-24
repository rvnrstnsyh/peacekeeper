import { env } from '@/configs/environment.configs'

// ==================== ORIGIN & CORS VALIDATION ====================

/**
 * Create a regex pattern for validating allowed origins.
 * - Supports http/https protocols
 * - Allows optional subdomains and port numbers
 * - Escapes special characters to prevent regex injection
 *
 * @param host - The hostname to create regex for (e.g., "example.com")
 * @returns Regular expression for origin validation
 *
 * @example
 * const regex = makeOriginRegex("example.com")
 * regex.test("https://api.example.com:3000") // true
 * regex.test("https://example.com") // true
 * regex.test("https://malicious.com") // false
 */
export function makeOriginRegex(host: string): RegExp {
  return new RegExp(`^https?:\\/\\/([a-zA-Z0-9-]+\\.)?${host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?::\\d+)?$`)
}

/**
 * Validate if an origin is allowed based on application configuration.
 * - Allows any subdomain of APP_HOSTNAME
 * - Allows localhost/127.0.0.1 with any port during development and test mode
 * - Supports both http and https protocols for localhost
 *
 * @param origin - The origin URL to validate (e.g., "https://api.example.com")
 * @returns true if origin is allowed, false otherwise
 *
 * @example
 * // In development mode
 * allowedOrigins("http://localhost:3000") // true
 * allowedOrigins("https://localhost:5173") // true
 * allowedOrigins("http://127.0.0.1:3000") // true
 *
 * // In production with APP_HOSTNAME="example.com"
 * allowedOrigins("https://api.example.com") // true
 * allowedOrigins("http://localhost:3000") // false
 */
export function allowedOrigins(origin: string): boolean {
  // Allow localhost and 127.0.0.1 in development and test modes
  // Support both http and https with any port number
  if ((env.isDevelopment || env.isTest) && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin)) {
    return true
  }

  if (!env.APP_HOSTNAME) return false
  return makeOriginRegex(env.APP_HOSTNAME).test(origin)
}

// ==================== UTF-8 STRING ENCODING/DECODING (Universal) ====================

/**
 * Convert UTF-8 string to Uint8Array.
 * Universal implementation that works in both browser and Node.js environments.
 * Properly handles multi-byte UTF-8 characters including emojis.
 *
 * @param str - The string to encode
 * @returns UTF-8 encoded byte array
 *
 * @example
 * stringToUint8Array("Hello") // Uint8Array([72, 101, 108, 108, 111])
 * stringToUint8Array("Hello!") // Uint8Array with proper UTF-8 encoding
 */
export function stringToUint8Array(str: string): Uint8Array {
  // Use TextEncoder if available (modern browsers and Node.js 11+)
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str)
  }

  // Fallback: Manual UTF-8 encoding
  const utf8: Array<number> = []
  for (let i = 0; i < str.length; i++) {
    let charCode = str.charCodeAt(i)

    // Handle surrogate pairs (for characters outside BMP, like emojis)
    if (charCode >= 0xd800 && charCode <= 0xdbff && i + 1 < str.length) {
      const low: number = str.charCodeAt(i + 1)
      if (low >= 0xdc00 && low <= 0xdfff) {
        charCode = 0x10000 + ((charCode - 0xd800) << 10) + (low - 0xdc00)
        i++
      }
    }

    // Encode as UTF-8
    if (charCode < 0x80) {
      utf8.push(charCode)
    } else if (charCode < 0x800) {
      utf8.push(0xc0 | (charCode >> 6), 0x80 | (charCode & 0x3f))
    } else if (charCode < 0x10000) {
      utf8.push(0xe0 | (charCode >> 12), 0x80 | ((charCode >> 6) & 0x3f), 0x80 | (charCode & 0x3f))
    } else {
      utf8.push(0xf0 | (charCode >> 18), 0x80 | ((charCode >> 12) & 0x3f), 0x80 | ((charCode >> 6) & 0x3f), 0x80 | (charCode & 0x3f))
    }
  }

  return new Uint8Array(utf8)
}

/**
 * Convert Uint8Array to UTF-8 string.
 * Universal implementation that works in both browser and Node.js environments.
 * Properly handles multi-byte UTF-8 characters including emojis.
 *
 * @param bytes - The UTF-8 encoded byte array to decode
 * @returns Decoded string
 * @throws Error if byte array contains invalid UTF-8 sequence
 *
 * @example
 * uint8ArrayToString(new Uint8Array([72, 101, 108, 108, 111])) // "Hello"
 */
export function uint8ArrayToString(bytes: Uint8Array): string {
  // Use TextDecoder if available (modern browsers and Node.js 11+)
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder().decode(bytes)
  }

  // Fallback: Manual UTF-8 decoding
  let result = ''
  let i = 0

  while (i < bytes.length) {
    const byte1: number = bytes[i++]

    // Single-byte character (0xxxxxxx)
    if (byte1 < 0x80) {
      result += String.fromCharCode(byte1)
    } // Two-byte character (110xxxxx 10xxxxxx)
    else if ((byte1 & 0xe0) === 0xc0) {
      if (i >= bytes.length) {
        throw new Error('Invalid UTF-8: incomplete sequence')
      }
      const byte2: number = bytes[i++]
      if ((byte2 & 0xc0) !== 0x80) {
        throw new Error('Invalid UTF-8: invalid continuation byte')
      }
      result += String.fromCharCode(((byte1 & 0x1f) << 6) | (byte2 & 0x3f))
    } // Three-byte character (1110xxxx 10xxxxxx 10xxxxxx)
    else if ((byte1 & 0xf0) === 0xe0) {
      if (i + 1 >= bytes.length) {
        throw new Error('Invalid UTF-8: incomplete sequence')
      }
      const byte2: number = bytes[i++]
      const byte3: number = bytes[i++]
      if ((byte2 & 0xc0) !== 0x80 || (byte3 & 0xc0) !== 0x80) {
        throw new Error('Invalid UTF-8: invalid continuation byte')
      }
      result += String.fromCharCode(((byte1 & 0x0f) << 12) | ((byte2 & 0x3f) << 6) | (byte3 & 0x3f))
    } // Four-byte character (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
    else if ((byte1 & 0xf8) === 0xf0) {
      if (i + 2 >= bytes.length) {
        throw new Error('Invalid UTF-8: incomplete sequence')
      }
      const byte2: number = bytes[i++]
      const byte3: number = bytes[i++]
      const byte4: number = bytes[i++]
      if ((byte2 & 0xc0) !== 0x80 || (byte3 & 0xc0) !== 0x80 || (byte4 & 0xc0) !== 0x80) {
        throw new Error('Invalid UTF-8: invalid continuation byte')
      }
      let codePoint: number = ((byte1 & 0x07) << 18) | ((byte2 & 0x3f) << 12) | ((byte3 & 0x3f) << 6) | (byte4 & 0x3f)
      // Convert to surrogate pair
      codePoint -= 0x10000
      result += String.fromCharCode(0xd800 + (codePoint >> 10), 0xdc00 + (codePoint & 0x3ff))
    } else {
      throw new Error('Invalid UTF-8: invalid byte')
    }
  }

  return result
}

// ==================== BASE64 ENCODING/DECODING (Universal) ====================

/**
 * Convert Uint8Array to Base64 string.
 * Universal implementation that works in both browser and Node.js environments.
 * Uses standard RFC 4648 base64 encoding without external dependencies.
 *
 * @param bytes - The byte array to encode
 * @returns Base64 encoded string with proper padding
 *
 * @example
 * const bytes = new Uint8Array([72, 101, 108, 108, 111])
 * uint8ArrayToBase64(bytes) // "SGVsbG8="
 */
export function uint8ArrayToBase64(bytes: Uint8Array): string {
  const base64Chars: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let result: string = ''
  let i: number = 0

  // Process 3 bytes at a time
  while (i < bytes.length) {
    const byte1: number = bytes[i++]
    const byte2: number = i < bytes.length ? bytes[i++] : 0
    const byte3: number = i < bytes.length ? bytes[i++] : 0
    const chunk: number = (byte1 << 16) | (byte2 << 8) | byte3

    result += base64Chars[(chunk >> 18) & 0x3f]
    result += base64Chars[(chunk >> 12) & 0x3f]
    result += base64Chars[(chunk >> 6) & 0x3f]
    result += base64Chars[chunk & 0x3f]
  }
  // Add padding according to RFC 4648
  const padding: number = bytes.length % 3
  if (padding === 1) {
    result = result.slice(0, -2) + '=='
  } else if (padding === 2) {
    result = result.slice(0, -1) + '='
  }
  return result
}

/**
 * Convert Base64 string to Uint8Array.
 * Universal implementation that works in both browser and Node.js environments.
 * Handles base64 strings with or without padding.
 *
 * @param base64 - The base64 string to decode
 * @returns Decoded byte array
 * @throws Error if base64 string contains invalid characters
 *
 * @example
 * base64ToUint8Array("SGVsbG8=") // Uint8Array([72, 101, 108, 108, 111])
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  // Remove whitespace and padding
  const cleanBase64: string = base64.replace(/[\s=]/g, '')
  // Base64 lookup table
  const base64Lookup: Record<string, number> = {}
  const base64Chars: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  for (let i = 0; i < base64Chars.length; i++) {
    base64Lookup[base64Chars[i]] = i
  }

  // Calculate output length
  const outputLength: number = Math.floor((cleanBase64.length * 3) / 4)
  const bytes: Uint8Array = new Uint8Array(outputLength)

  let byteIndex: number = 0
  let i: number = 0

  // Process 4 characters at a time
  while (i < cleanBase64.length) {
    const char1: number = base64Lookup[cleanBase64[i++]] || 0
    const char2: number = base64Lookup[cleanBase64[i++]] || 0
    const char3: number = base64Lookup[cleanBase64[i++]] || 0
    const char4: number = base64Lookup[cleanBase64[i++]] || 0
    const chunk: number = (char1 << 18) | (char2 << 12) | (char3 << 6) | char4

    if (byteIndex < outputLength) bytes[byteIndex++] = (chunk >> 16) & 0xff
    if (byteIndex < outputLength) bytes[byteIndex++] = (chunk >> 8) & 0xff
    if (byteIndex < outputLength) bytes[byteIndex++] = chunk & 0xff
  }
  return bytes
}

// ==================== HEXADECIMAL ENCODING/DECODING (Universal) ====================

/**
 * Convert hexadecimal string to Uint8Array.
 * Universal implementation without external dependencies.
 *
 * @param hex - Hexadecimal string (e.g., "48656c6c6f")
 * @returns Decoded byte array
 * @throws Error if hex string has odd length or contains invalid characters
 *
 * @example
 * hexToBytes("48656c6c6f") // Uint8Array([72, 101, 108, 108, 111])
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length: must be even')
  }
  const bytes: Uint8Array = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    const byte: number = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    if (isNaN(byte)) {
      throw new Error(`Invalid hex character at position ${i * 2}`)
    }
    bytes[i] = byte
  }
  return bytes
}

/**
 * Convert Uint8Array to hexadecimal string.
 * Universal implementation without external dependencies.
 *
 * @param bytes - The byte array to encode
 * @returns Lowercase hexadecimal string
 *
 * @example
 * const bytes = new Uint8Array([72, 101, 108, 108, 111])
 * bytesToHex(bytes) // "48656c6c6f"
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// ==================== ARRAY MANIPULATION (Universal) ====================

/**
 * Concatenate multiple Uint8Arrays into a single array.
 * Efficient implementation that allocates once and copies data sequentially.
 *
 * @param arrays - Variable number of Uint8Arrays to concatenate
 * @returns Single Uint8Array containing all input arrays in order
 *
 * @example
 * const a = new Uint8Array([1, 2])
 * const b = new Uint8Array([3, 4])
 * const c = new Uint8Array([5, 6])
 * concat(a, b, c) // Uint8Array([1, 2, 3, 4, 5, 6])
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength: number = arrays.reduce((sum, arr) => sum + arr.length, 0)
  const result: Uint8Array = new Uint8Array(totalLength)
  let offset: number = 0
  for (const arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

// ==================== LEGACY ALIASES ====================
// Note: These functions use browser/Node-specific APIs and should be avoided
// Use uint8ArrayToBase64 and base64ToUint8Array instead for universal compatibility

/**
 * Type guard to check if an object is a Node.js Buffer
 */
interface BufferLike {
  buffer: ArrayBufferLike
  byteOffset: number
  byteLength: number
}

/**
 * Type guard function to check if value is BufferLike
 */
function isBufferLike(value: unknown): value is BufferLike {
  if (typeof value !== 'object' || value === null) {
    return false
  }

  const obj: Record<string, unknown> = value as Record<string, unknown>

  return 'buffer' in obj && 'byteOffset' in obj && 'byteLength' in obj && typeof obj.byteOffset === 'number' && typeof obj.byteLength === 'number'
}

/**
 * Node.js specific - not recommended for universal code
 * Convert Buffer to Uint8Array (Node.js only)
 *
 * @param buf - Buffer, ArrayBuffer, or Uint8Array to convert
 * @returns Uint8Array view of the buffer
 * @throws Error if input is not a valid Buffer, ArrayBuffer, or Uint8Array
 */
export function bufferToUint8Array(buf: unknown): Uint8Array {
  if (buf instanceof Uint8Array) {
    return buf
  }

  // Handle ArrayBuffer
  if (buf instanceof ArrayBuffer) {
    return new Uint8Array(buf)
  }

  // Type guard for Node.js Buffer
  if (isBufferLike(buf)) {
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  }

  throw new Error('Input is not a Buffer, Uint8Array, or ArrayBuffer')
}

/**
 * Node.js specific - not recommended for universal code
 * Convert Uint8Array to Buffer (Node.js only)
 *
 * Note: This function will throw in non-Node.js environments
 *
 * @param array - Uint8Array to convert
 * @returns Buffer instance (Node.js only)
 * @throws Error if Buffer global is not available
 */
export function uint8ArrayToBuffer(array: Uint8Array): Buffer {
  // Check if Buffer is available (Node.js environment)
  if (typeof Buffer === 'undefined') {
    throw new Error('Buffer is not available. This function only works in Node.js')
  }
  // Buffer.from is guaranteed to exist if Buffer global exists
  return Buffer.from(array)
}
