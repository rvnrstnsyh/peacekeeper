//! RFC 9807 ristretto255-SHA512 OPAQUE configuration constants.
//!
//! All values in this module are derived directly from the specification and
//! **must** stay in sync with the TypeScript counterpart in
//! `src/shared/constants/zero-access.constants.ts`.
//!
//! ## Size parameters
//!
//! | Constant    | Value | Meaning                              |
//! |-------------|-------|--------------------------------------|
//! | [`NH`]      | 64    | Hash output length (SHA-512)         |
//! | [`NN`]      | 32    | Nonce length                         |
//! | [`NM`]      | 64    | MAC output length (HMAC-SHA512)      |
//! | [`NPK`]     | 32    | Public key length (X25519)           |
//! | [`NOE`]     | 32    | OPRF element length (ristretto255)   |
//! | [`NOK`]     | 32    | OPRF key length (scalar)             |
//! | [`NSEED`]   | 32    | Seed length                          |
//! | [`NSK`]     | 32    | Secret key length (X25519)           |

/// RFC 9807 ristretto255-SHA512 OPAQUE configuration constants.
///
/// All values mirror the TypeScript CONFIG in zero-access.constants.ts.

// ─── Size parameters ─────────────────────────────────────────────────────────

/// Hash output length: SHA-512 produces 64 bytes.
pub const NH: usize = 64;

/// Nonce length: 32 bytes.
pub const NN: usize = 32;

/// MAC output length: HMAC-SHA512 produces 64 bytes.
pub const NM: usize = 64;

/// Public key length: X25519 public keys are 32 bytes.
pub const NPK: usize = 32;

/// OPRF element length: ristretto255 compressed points are 32 bytes.
pub const NOE: usize = 32;

/// OPRF key length: ristretto255 scalars are 32 bytes.
pub const NOK: usize = 32;

/// Seed length: 32 bytes.
pub const NSEED: usize = 32;

/// Secret key length: X25519 private keys are 32 bytes.
pub const NSK: usize = 32;

// ─── Protocol strings ────────────────────────────────────────────────────────

/// OPAQUE protocol context string (RFC 9807 §6.2.2).
/// Matches TypeScript: `CONFIG.context`.
pub const CONTEXT: &str = "OPAQUE-RFC9807-ristretto255-SHA512";

/// OPRF hash-to-group domain separation tag (RFC 9497 / RFC 9380).
///
/// Contains embedded null bytes: `RFCXXXX-\x00\x00\x03-HashToGroup-ristretto255-SHA512`.
/// Must match TypeScript DST byte-for-byte:
/// ```ts
/// const DST = 'RFCXXXX-\x00\x00\x03-HashToGroup-ristretto255-SHA512'
/// ```
pub const OPRF_DST: &[u8] = b"RFCXXXX-\x00\x00\x03-HashToGroup-ristretto255-SHA512";

// ─── Derived sizes ────────────────────────────────────────────────────────────

/// Masked credential response length: Npk + Nn + Nm + Nseed = 32+32+64+32 = 160 bytes.
pub const MASKED_RESPONSE_LEN: usize = NPK + NN + NM + NSEED;

// ─── Low-order points ────────────────────────────────────────────────────────

/// RFC 7748 §6.1 — Low-order X25519 points (small subgroup elements).
///
/// Must match TypeScript `LOW_ORDER_POINTS` set exactly:
/// ```ts
/// export const LOW_ORDER_POINTS: Set<string> = new Set([
///   '0000000000000000000000000000000000000000000000000000000000000000',
///   '0100000000000000000000000000000000000000000000000000000000000000',
///   'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
///   '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
///   'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
/// ])
/// ```
pub static LOW_ORDER_POINTS: [[u8; 32]; 5] = [
  // "0000000000000000000000000000000000000000000000000000000000000000"
  [0u8; 32],
  // "0100000000000000000000000000000000000000000000000000000000000000"
  [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ],
  // "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
  [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ],
  // "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"
  [
    0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
  ],
  // "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
  [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
  ],
];
