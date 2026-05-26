//! Low-level cryptographic primitives for OPAQUE ristretto255-SHA512.
//!
//! This module contains the foundational building blocks used by [`helpers`]
//! and [`protocol`]:
//!
//! | Function                  | Purpose                                         |
//! |---------------------------|-------------------------------------------------|
//! | [`expand_message_xmd`]    | RFC 9380 §5.4.1 hash expansion (SHA-512)        |
//! | [`hash_to_group`]         | OPRF blind: password → ristretto255 point       |
//! | [`bytes_to_scalar`]       | LE 32-byte slice → ristretto255 scalar          |
//! | [`scalar_to_bytes`]       | ristretto255 scalar → LE 32-byte array          |
//! | [`ct_equal`]              | Constant-time byte slice equality               |
//! | [`try_decompress_ristretto`] | Decompress + identity-check a ristretto255 point |
//!
//! All operations are purely functional (no side effects, no allocations beyond
//! what is necessary) and work with fixed-size byte arrays where possible.
//!
//! [`helpers`]: crate::security::opaque::helpers
//! [`protocol`]: crate::security::opaque::protocol

use curve25519_dalek::{
  ristretto::{CompressedRistretto, RistrettoPoint},
  scalar::Scalar,
  traits::Identity,
};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

use crate::security::opaque::config;

// ─── expand_message_xmd ───────────────────────────────────────────────────────

/// Implements RFC 9380 §5.4.1 `expand_message_xmd` with SHA-512.
///
/// Produces `len_in_bytes` uniform pseudorandom bytes derived from `msg`
/// and the domain-separation tag `dst`. Used for OPRF hash-to-group.
///
/// SHA-512 parameters:
/// - `b_in_bytes` (output size) = 64
/// - `r_in_bytes` (block size)  = 128
///
/// # Arguments
///
/// * `msg`          — Input message (the blinded password element or similar).
/// * `dst`          — Domain-separation tag; must be < 256 bytes.
/// * `len_in_bytes` — Desired output length; must be ≤ 255 × 64 = 16 320 bytes.
///
/// # Panics
///
/// Panics (debug only) if `len_in_bytes > 255 * 64` or `dst.len() >= 256`.
///
/// # Equivalent TypeScript
///
/// ```ts
/// import { expand_message_xmd } from '@noble/hashes/utils'
/// const bytes = expand_message_xmd(sha512, msg, dst, len_in_bytes)
/// ```
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
  const B_IN_BYTES: usize = 64; // SHA-512 output size
  const R_IN_BYTES: usize = 128; // SHA-512 block size

  let ell: usize = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES;
  debug_assert!(ell <= 255, "expand_message_xmd: len_in_bytes too large");
  debug_assert!(dst.len() < 256, "expand_message_xmd: DST too long");

  // DST_prime = DST || I2OSP(len(DST), 1)
  let mut dst_prime: Vec<u8> = dst.to_vec();
  dst_prime.push(dst.len() as u8);

  // l_i_b_str = I2OSP(len_in_bytes, 2)
  let lib_str: [u8; 2] = [(len_in_bytes >> 8) as u8, (len_in_bytes & 0xff) as u8];

  // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
  let b0 = {
    let mut h: Sha512 = Sha512::new();
    h.update([0u8; R_IN_BYTES]); // Z_pad
    h.update(msg);
    h.update(lib_str);
    h.update([0u8]); // I2OSP(0, 1)
    h.update(&dst_prime);
    h.finalize()
  };

  let mut uniform_bytes: Vec<u8> = Vec::with_capacity(ell * B_IN_BYTES);

  // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  let mut b_prev = {
    let mut h: Sha512 = Sha512::new();
    h.update(&b0);
    h.update([1u8]);
    h.update(&dst_prime);
    h.finalize()
  };
  uniform_bytes.extend_from_slice(&b_prev);

  for i in 2..=ell {
    // b_i = H((b_0 XOR b_{i-1}) || I2OSP(i, 1) || DST_prime)
    let xored: Vec<u8> = b0.iter().zip(b_prev.iter()).map(|(a, b)| a ^ b).collect();
    let mut h: Sha512 = Sha512::new();
    h.update(&xored);
    h.update([i as u8]);
    h.update(&dst_prime);
    b_prev = h.finalize();
    uniform_bytes.extend_from_slice(&b_prev);
  }

  uniform_bytes.truncate(len_in_bytes);
  uniform_bytes
}

// ─── hash_to_group ────────────────────────────────────────────────────────────

/// Hash a message to a ristretto255 group element (OPRF Blind, RFC 9497).
///
/// Expands `msg` to 64 uniform bytes using [`expand_message_xmd`] with the OPRF
/// domain-separation tag ([`config::OPRF_DST`]), then maps to a [`RistrettoPoint`]
/// via `RistrettoPoint::from_uniform_bytes`.
///
/// This is the server-side OPRF evaluation input. On the client side the
/// blinded element is produced by multiplying this point with a random scalar.
///
/// # Arguments
///
/// * `msg` — The raw message to hash (typically the blinded OPRF input).
///
/// # Returns
///
/// A uniformly distributed [`RistrettoPoint`] that is indistinguishable from
/// a random group element for any PPT adversary.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const DST = 'RFCXXXX-\x00\x00\x03-HashToGroup-ristretto255-SHA512'
/// const point = ristretto255_hasher.hashToCurve(msg, { DST })
/// ```
pub fn hash_to_group(msg: &[u8]) -> RistrettoPoint {
  let uniform_bytes: Vec<u8> = expand_message_xmd(msg, config::OPRF_DST, 64);
  let bytes: [u8; 64] = uniform_bytes.try_into().expect("expand_message_xmd(len=64) always returns exactly 64 bytes");
  RistrettoPoint::from_uniform_bytes(&bytes)
}

// ─── Scalar helpers ───────────────────────────────────────────────────────────

/// Interpret 32 little-endian bytes as a Scalar mod the ristretto255 group order.
///
/// The ristretto255 group order is:
/// `l = 2^252 + 27742317777372353535851937790883648493`.
///
/// # Arguments
///
/// * `bytes` — 32-byte little-endian representation; reduced mod `l` if ≥ `l`.
///
/// # Returns
///
/// A canonical [`Scalar`] in the range `[0, l)`.
///
/// # Equivalent TypeScript
///
/// ```ts
/// // LE interpretation: bytes[0] is the least-significant byte
/// const scalar = BigInt(bytes[0]) + BigInt(bytes[1])*256n + ... (mod l)
/// ```
pub fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
  Scalar::from_bytes_mod_order(*bytes)
}

/// Encode a Scalar as 32 little-endian bytes.
///
/// # Returns
///
/// A canonical 32-byte little-endian representation of the scalar value.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const bytes: Uint8Array = scalarToBytes(scalar)
/// ```
pub fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
  scalar.to_bytes()
}

// ─── Constant-time equality ───────────────────────────────────────────────────

/// Constant-time equality comparison for byte slices.
///
/// Returns `true` iff both slices have the same length and identical content,
/// checked in constant time to prevent timing side-channel attacks.
///
/// Length mismatch returns `false` immediately (non-constant time for the
/// length check itself, which leaks no secret information since lengths are
/// typically public).
///
/// # Arguments
///
/// * `a` — First byte slice.
/// * `b` — Second byte slice.
///
/// # Returns
///
/// `true` if `a == b` (constant-time); `false` otherwise.
///
/// # Security
///
/// Uses [`subtle::ConstantTimeEq`] to prevent MAC-comparison timing attacks
/// as required by RFC 9807 §6.2.6 for KE3 MAC verification.
///
/// # Equivalent TypeScript
///
/// ```ts
/// import { timingSafeEqual } from 'node:crypto'
/// const equal = timingSafeEqual(a, b)
/// ```
pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  a.ct_eq(b).into()
}

// ─── ristretto255 element validation ─────────────────────────────────────────

/// Attempt to decompress a 32-byte value as a ristretto255 point.
///
/// Validates both canonical encoding (decompression must succeed) and that
/// the resulting point is not the group identity element.
///
/// Used in input validation before any OPRF operation to reject malformed or
/// low-security client inputs.
///
/// # Arguments
///
/// * `bytes` — 32-byte compressed ristretto255 point encoding.
///
/// # Returns
///
/// `Some(point)` if the bytes represent a valid non-identity ristretto255 point;
/// `None` if decompression fails or the point is the identity element.
///
/// # Security
///
/// Rejecting the identity element prevents trivial OPRF output prediction
/// (a client submitting the identity would receive the identity back, regardless
/// of the OPRF key, leaking no information about the key but enabling
/// protocol confusion).
pub fn try_decompress_ristretto(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
  let point: RistrettoPoint = CompressedRistretto(*bytes).decompress()?;
  if point == RistrettoPoint::identity() {
    return None;
  }
  Some(point)
}
