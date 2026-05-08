import { randomBytes } from '@noble/hashes/utils.js'

const CHANNEL_ENC_INFO: Uint8Array = new TextEncoder().encode('peacekeeper-channel-enc-v1')

async function deriveAesKey(sessionKey: Uint8Array): Promise<CryptoKey> {
  // Cast to Uint8Array<ArrayBuffer> to satisfy the strict BufferSource constraint.
  const keyBytes = sessionKey.buffer instanceof ArrayBuffer ? (sessionKey as unknown as Uint8Array<ArrayBuffer>) : (new Uint8Array(sessionKey) as unknown as Uint8Array<ArrayBuffer>)
  const rawKey: CryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HKDF' }, false, ['deriveKey'])
  const infoBytes = CHANNEL_ENC_INFO.buffer instanceof ArrayBuffer ? (CHANNEL_ENC_INFO as unknown as Uint8Array<ArrayBuffer>) : (new Uint8Array(CHANNEL_ENC_INFO) as unknown as Uint8Array<ArrayBuffer>)
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0) as unknown as Uint8Array<ArrayBuffer>, info: infoBytes }, rawKey, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt'
  ])
}

/**
 * Encrypt a plaintext string using AES-256-GCM derived from `sessionKey` via HKDF-SHA256.
 *
 * Returns a base64 string encoding `nonce[12] || ciphertext || tag[16]`.
 */
export async function channelEncrypt(sessionKey: Uint8Array, plaintext: string): Promise<string> {
  const key: CryptoKey = await deriveAesKey(sessionKey)
  const nonce: Uint8Array = randomBytes(12)
  const encoded: Uint8Array = new TextEncoder().encode(plaintext)
  const ciphertextAndTag: ArrayBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce as unknown as Uint8Array<ArrayBuffer> }, key, encoded as unknown as Uint8Array<ArrayBuffer>)
  const combined: Uint8Array = new Uint8Array(12 + ciphertextAndTag.byteLength)
  combined.set(nonce, 0)
  combined.set(new Uint8Array(ciphertextAndTag), 12)
  return Buffer.from(combined).toString('base64')
}

/**
 * Decrypt a base64 string produced by `channelEncrypt`.
 *
 * Throws if the payload is malformed or the authentication tag does not verify.
 */
export async function channelDecrypt(sessionKey: Uint8Array, enc: string): Promise<string> {
  const key: CryptoKey = await deriveAesKey(sessionKey)
  const combined: Buffer = Buffer.from(enc, 'base64')
  // 12-byte nonce + minimum 16-byte tag = 28 bytes minimum
  if (combined.byteLength < 28) throw new Error('Invalid encrypted payload: too short')
  const nonce: Uint8Array = combined.subarray(0, 12)
  const ciphertext: Uint8Array = combined.subarray(12)
  const plaintext: ArrayBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce as unknown as Uint8Array<ArrayBuffer> }, key, ciphertext as unknown as Uint8Array<ArrayBuffer>)
  return new TextDecoder().decode(plaintext)
}
