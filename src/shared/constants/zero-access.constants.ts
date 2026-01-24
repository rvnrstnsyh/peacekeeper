import type { OpaqueConfig } from '@/shared/types/zero-access.types'

export const CONFIG: OpaqueConfig = {
  hash: 'sha512',
  kdf: 'hkdf-sha512',
  mac: 'hmac-sha512',
  context: 'OPAQUE-RFC9807-ristretto255-SHA512',
  Nh: 64, // Hash output length (SHA-512)
  Nn: 32, // Nonce length
  Nm: 64, // MAC output length (HMAC-SHA512)
  Npk: 32, // Public key length (X25519)
  Noe: 32, // OPRF element length (ristretto255)
  Nok: 32, // OPRF key length (ristretto255 scalar)
  Nseed: 32, // Seed length
  Nsk: 32 // Secret key length (X25519)
} as const

// RFC 7748 Section 6.1 - Low-order points for X25519
export const LOW_ORDER_POINTS: Set<string> = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'
])
