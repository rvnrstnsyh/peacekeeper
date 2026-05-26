//! Mid-level cryptographic helpers for OPAQUE ristretto255-SHA512.
//!
//! This module sits between the raw [`primitives`] and the protocol-level
//! [`protocol`] functions. It provides:
//!
//! - **Key management** — HKDF wrappers, key-schedule helpers, key-pair
//!   derivation for both X25519 (DH) and Ed25519 (signing).
//! - **OPRF** — Per-credential OPRF key derivation and server-side blind
//!   evaluation.
//! - **Credential response** — Envelope masking and credential response
//!   construction (RFC 9807 §5.1.2).
//! - **Preamble** — Exact RFC 9807 §6.2.1 transcript byte layout.
//! - **Utility** — `rand_bytes_32`, `i2osp2`, `hmac_sha512`, `sha512_digest`.
//!
//! # Key layout
//!
//! The server holds three long-term secrets, each stored base64-encoded in
//! environment variables:
//!
//! ```text
//! OPAQUE_SERVER_PRIVATE_KEY  (32 bytes) — X25519 long-term private key
//! OPAQUE_SERVER_PUBLIC_KEY   (32 bytes) — corresponding X25519 public key
//! OPAQUE_SEED                (64 bytes) — OPRF master seed (Nh bytes)
//! ```
//!
//! Per-credential OPRF keys are derived on the fly:
//! ```text
//! oprfKey = HKDF-Expand(PRK=OPAQUE_SEED, info=credId||"OprfKey", L=32)
//! ```
//!
//! [`primitives`]: crate::security::opaque::primitives
//! [`protocol`]:   crate::security::opaque::protocol

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, KeyInit};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::security::opaque::{
  config,
  errors::OpaqueError,
  primitives::{bytes_to_scalar, try_decompress_ristretto},
};

type HmacSha512 = Hmac<Sha512>;

// ─── Internal types ───────────────────────────────────────────────────────────

/// Server's stored OPAQUE registration record, reconstructed from the database.
///
/// The server stores this record at the end of the registration phase
/// (step 3 of 3). It is retrieved during authentication to construct the
/// masked credential response (KE2) without ever seeing the client's raw
/// password.
///
/// All fields are derived exclusively from the client-side registration
/// finalization step — the server never learns the plaintext password or the
/// client's OPRF output.
///
/// # Field sizes
///
/// | Field                        | Bytes | Description                            |
/// |------------------------------|-------|----------------------------------------|
/// | `client_ed25519_public_key`  | 32    | Client's long-term Ed25519 signing key |
/// | `client_x25519_public_key`   | 32    | Client's long-term X25519 key (3DH)    |
/// | `masking_key`                | 64    | HKDF-derived key for envelope masking  |
/// | `envelope_nonce`             | 32    | Per-enrollment random nonce            |
/// | `envelope_auth_tag`          | 64    | HMAC-SHA512 over the encrypted seed    |
/// | `envelope_seed`              | 32    | Encrypted exportKey seed (HKDF input)  |
///
/// # Equivalent TypeScript
///
/// ```ts
/// interface RegistrationRecord {
///   clientED25519PublicKey: Uint8Array   // 32 bytes
///   clientX25519PublicKey:  Uint8Array   // 32 bytes
///   maskingKey:             Uint8Array   // 64 bytes
///   envelopeNonce:          Uint8Array   // 32 bytes
///   envelopeAuthTag:        Uint8Array   // 64 bytes
///   envelopeSeed:           Uint8Array   // 32 bytes
/// }
/// ```
pub struct OpaqueRecord {
  /// Client's long-term Ed25519 public key (32 bytes). Used to verify the
  /// client's identity binding inside the OPAQUE envelope.
  pub client_ed25519_public_key: [u8; 32],
  /// Client's long-term X25519 public key (32 bytes). Used in the triple-DH
  /// computation during [`generate_ke2`].
  ///
  /// [`generate_ke2`]: crate::security::opaque::protocol::generate_ke2
  pub client_x25519_public_key: [u8; 32],
  /// HKDF-derived masking key ([`config::NH`] = 64 bytes). Used in
  /// [`create_credential_response`] to XOR-mask the envelope contents.
  pub masking_key: [u8; config::NH],
  /// Per-enrollment envelope nonce ([`config::NN`] = 32 bytes). Mixed into
  /// the masking pad derivation to ensure per-enrollment uniqueness.
  pub envelope_nonce: [u8; config::NN],
  /// HMAC-SHA512 authentication tag for the envelope ([`config::NM`] = 64 bytes).
  /// Verified by the client after unmasking to detect tampering.
  pub envelope_auth_tag: [u8; config::NM],
  /// Encrypted envelope seed ([`config::NSEED`] = 32 bytes). The client derives
  /// its `exportKey` and signing key pair from this value.
  pub envelope_seed: [u8; config::NSEED],
}

// ─── Random bytes ─────────────────────────────────────────────────────────────

/// Generate 32 cryptographically random bytes using the OS RNG.
///
/// Used for nonces (`server_nonce`) and ephemeral key-pair seeds
/// (`server_keyshare_seed`) throughout the protocol.
///
/// # Returns
///
/// 32 bytes sourced from the operating system's cryptographically secure
/// random number generator ([`OsRng`]).
///
/// # Panics
///
/// Panics if the OS RNG is unavailable (extremely rare; indicates a broken
/// system configuration).
pub fn rand_bytes_32() -> [u8; 32] {
  let mut buf = [0u8; 32];
  OsRng.fill_bytes(&mut buf);
  buf
}

// ─── Validation ───────────────────────────────────────────────────────────────

/// Validate an X25519 public key against RFC 7748 security requirements.
///
/// Rejects low-order points (small-subgroup attacks) and the identity element
/// (all-zero key). A 32-byte type is enforced at compile time.
///
/// # Arguments
///
/// * `key` — 32-byte X25519 public key to validate.
///
/// # Errors
///
/// Returns [`OpaqueError::LowOrderPoint`] if the key matches any of the 5
/// low-order points listed in RFC 7748 §6.1 (see [`config::LOW_ORDER_POINTS`]).
///
/// Returns [`OpaqueError::IdentityElement`] if the key is all zeros.
///
/// # Security
///
/// Low-order points have small subgroup order, allowing an attacker to force
/// DH shared secrets into a tiny subgroup and recover the static private key
/// or break forward secrecy. The all-zero "identity" key always produces the
/// zero shared secret regardless of the private key, defeating authentication.
pub fn validate_x25519_public_key(key: &[u8; 32]) -> Result<(), OpaqueError> {
  for low_order in config::LOW_ORDER_POINTS.iter() {
    if key == low_order {
      return Err(OpaqueError::LowOrderPoint);
    }
  }
  if key.iter().all(|&b| b == 0) {
    return Err(OpaqueError::IdentityElement);
  }
  Ok(())
}

/// Validate a 32-byte ristretto255 element (non-identity, canonical encoding).
///
/// Decompresses the point and rejects the identity element. Used before any
/// OPRF scalar multiplication to prevent trivially predictable outputs.
///
/// # Arguments
///
/// * `element` — 32-byte compressed ristretto255 point.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidElement`] if the bytes do not decompress to
/// a valid, non-identity ristretto255 point.
pub fn validate_ristretto255_element(element: &[u8; 32]) -> Result<(), OpaqueError> {
  try_decompress_ristretto(element).ok_or_else(|| OpaqueError::InvalidElement("decompression failed or identity element".into()))?;
  Ok(())
}

// ─── HKDF wrappers ───────────────────────────────────────────────────────────

/// HKDF-SHA512 Extract: derive a pseudorandom key from input keying material.
///
/// When `salt = None`, uses a 64-zero-byte salt (RFC 5869 §2.2 default for
/// SHA-512: the HMAC key is zero-padded to the block size of 128 bytes,
/// effectively using a 128-zero salt internally). This matches the TypeScript
/// `Hkdf.extract(null, ikm)` call which passes an empty salt.
///
/// # Arguments
///
/// * `salt` — Optional salt value. `None` uses the RFC 5869 default (zero-bytes).
/// * `ikm`  — Input keying material (e.g. a DH output or concatenated DH outputs).
///
/// # Returns
///
/// A 64-byte pseudorandom key (`prk`) suitable for use with [`hkdf_expand`].
///
/// # Equivalent TypeScript
///
/// ```ts
/// const [prk] = Hkdf.extract(salt ?? null, ikm)  // Nh = 64 bytes
/// ```
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; config::NH] {
  let (prk, _) = Hkdf::<Sha512>::extract(salt, ikm);
  let mut out: [u8; 64] = [0u8; config::NH];
  out.copy_from_slice(&prk);
  out
}

/// HKDF-SHA512 Expand: produce output keying material from a PRK.
///
/// `prk` must be at least 64 bytes (the HashLen for SHA-512). Returns
/// `length` bytes of output keying material.
///
/// # Arguments
///
/// * `prk`    — Pseudorandom key from [`hkdf_extract`]; must be ≥ 64 bytes.
/// * `info`   — Context-specific label bytes (not secret).
/// * `length` — Number of output bytes; must be ≤ 255 × 64 = 16 320.
///
/// # Errors
///
/// Returns [`OpaqueError::HkdfExpand`] if `prk` is too short or `length`
/// exceeds 255 × HashLen.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const okm = Hkdf.expand(prk, info, length)
/// ```
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, OpaqueError> {
  let hkdf: hkdf::GenericHkdf<Hmac<Sha512>> = Hkdf::<Sha512>::from_prk(prk).map_err(|_| OpaqueError::HkdfExpand)?;
  let mut okm: Vec<u8> = vec![0u8; length];
  hkdf.expand(info, &mut okm).map_err(|_| OpaqueError::HkdfExpand)?;
  Ok(okm)
}

/// HKDF-SHA512 Expand with a fixed 32-byte output.
///
/// Convenience wrapper around [`hkdf_expand`] for the common case of
/// deriving 32-byte values (scalars, seeds, private keys).
///
/// # Errors
///
/// Returns [`OpaqueError::HkdfExpand`] if expansion fails.
pub fn hkdf_expand_32(prk: &[u8], info: &[u8]) -> Result<[u8; 32], OpaqueError> {
  let hkdf: hkdf::GenericHkdf<Hmac<Sha512>> = Hkdf::<Sha512>::from_prk(prk).map_err(|_| OpaqueError::HkdfExpand)?;
  let mut okm: [u8; 32] = [0u8; 32];
  hkdf.expand(info, &mut okm).map_err(|_| OpaqueError::HkdfExpand)?;
  Ok(okm)
}

/// HKDF-SHA512 Expand with a fixed 64-byte output (one full hash-length, Nh).
///
/// Convenience wrapper around [`hkdf_expand`] for deriving 64-byte keys such
/// as MAC keys, session keys, and masking keys.
///
/// # Errors
///
/// Returns [`OpaqueError::HkdfExpand`] if expansion fails.
pub fn hkdf_expand_64(prk: &[u8], info: &[u8]) -> Result<[u8; config::NH], OpaqueError> {
  let hkdf: hkdf::GenericHkdf<Hmac<Sha512>> = Hkdf::<Sha512>::from_prk(prk).map_err(|_| OpaqueError::HkdfExpand)?;
  let mut okm: [u8; 64] = [0u8; config::NH];
  hkdf.expand(info, &mut okm).map_err(|_| OpaqueError::HkdfExpand)?;
  Ok(okm)
}

// ─── Key schedule helpers ─────────────────────────────────────────────────────

/// TLS 1.3-style HKDF-Expand-Label as specified in RFC 9807 §6.2.2.
///
/// Formats a structured label and expands the secret to exactly [`config::NH`]
/// (64) bytes:
///
/// ```text
/// customLabel = I2OSP(Nh, 2)
///            || I2OSP(len("RFCXXXX " + label), 1)
///            || "RFCXXXX " + label
///            || I2OSP(len(context), 1)
///            || context
/// output = HKDF-Expand(secret, customLabel, Nh)
/// ```
///
/// # Arguments
///
/// * `secret`  — Input secret (typically a PRK or handshake-secret).
/// * `label`   — Short ASCII label string (e.g. `"HandshakeSecret"`, `"ServerMAC"`).
/// * `context` — Optional binding context (often a transcript hash, or empty).
///
/// # Returns
///
/// A 64-byte output keying material array.
///
/// # Errors
///
/// Returns [`OpaqueError::HkdfExpand`] if expansion fails.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const okm = expandLabel(secret, label, context)  // 64 bytes
/// ```
pub fn expand_label(secret: &[u8], label: &str, context: &[u8]) -> Result<[u8; config::NH], OpaqueError> {
  let full_label: String = format!("RFCXXXX {}", label);
  let label_bytes: &[u8] = full_label.as_bytes();

  let mut custom_label: Vec<u8> = Vec::with_capacity(3 + label_bytes.len() + 1 + context.len());
  // I2OSP(Nh, 2)
  custom_label.push((config::NH >> 8) as u8);
  custom_label.push((config::NH & 0xff) as u8);
  // I2OSP(len(label_bytes), 1)
  custom_label.push(label_bytes.len() as u8);
  custom_label.extend_from_slice(label_bytes);
  // I2OSP(len(context), 1)
  custom_label.push(context.len() as u8);
  custom_label.extend_from_slice(context);

  hkdf_expand_64(secret, &custom_label)
}

/// Derive a labeled secret bound to a transcript (RFC 9807 §6.2.2).
///
/// If `transcript` is non-empty it is hashed with SHA-512 before being passed
/// as context to [`expand_label`]; otherwise an empty context is used (matching
/// the RFC's `Hash("")` = empty Transcript case).
///
/// # Arguments
///
/// * `secret`     — Input secret key material (PRK or handshake-secret).
/// * `label`      — Label string (e.g. `"HandshakeSecret"`, `"SessionKey"`).
/// * `transcript` — Raw protocol transcript bytes, or empty for `Hash("")`.
///
/// # Returns
///
/// A 64-byte derived secret.
///
/// # Errors
///
/// Returns [`OpaqueError::HkdfExpand`] if [`expand_label`] fails.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const secret = deriveSecret(secret, label, transcript)
/// ```
pub fn derive_secret(secret: &[u8], label: &str, transcript: &[u8]) -> Result<[u8; config::NH], OpaqueError> {
  let transcript_hash: Vec<u8> = if transcript.is_empty() { Vec::new() } else { Sha512::digest(transcript).to_vec() };
  expand_label(secret, label, &transcript_hash)
}

/// Derive all session keys from the triple-DH IKM and the protocol preamble.
///
/// Implements the RFC 9807 §6.2.2 key schedule:
///
/// ```text
/// prk               = HKDF-Extract(salt=nil, ikm)
/// handshake_secret  = DeriveSecret(prk,               "HandshakeSecret", SHA-512(preamble))
/// session_key       = DeriveSecret(prk,               "SessionKey",      SHA-512(preamble))
/// km2               = DeriveSecret(handshake_secret,  "ServerMAC",       "")
/// km3               = DeriveSecret(handshake_secret,  "ClientMAC",       "")
/// ```
///
/// # Arguments
///
/// * `ikm`      — Concatenation of three DH shared secrets: `dh1 || dh2 || dh3`
///                (96 bytes total; each DH output is 32 bytes).
/// * `preamble` — Full protocol transcript preamble (see [`build_preamble`]).
///
/// # Returns
///
/// `(km2, km3, session_key)` — each 64 bytes:
/// - `km2`         — Server MAC key; used to compute `server_mac` in KE2.
/// - `km3`         — Client MAC key; used to verify `ke3_client_mac` in KE3.
/// - `session_key` — Shared session key for application-layer use after KE3.
///
/// # Errors
///
/// Returns [`OpaqueError::HkdfExpand`] if any HKDF-Expand step fails.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const { km2, km3, sessionKey } = deriveKeys(ikm, preamble)
/// ```
pub fn derive_keys(ikm: &[u8], preamble: &[u8]) -> Result<([u8; config::NH], [u8; config::NH], [u8; config::NH]), OpaqueError> {
  let prk: [u8; 64] = hkdf_extract(None, ikm);

  let preamble_hash: Vec<u8> = Sha512::digest(preamble).to_vec();
  let handshake_secret: [u8; 64] = derive_secret(&prk, "HandshakeSecret", &preamble_hash)?;
  let session_key: [u8; 64] = derive_secret(&prk, "SessionKey", &preamble_hash)?;
  let km2: [u8; 64] = derive_secret(&handshake_secret, "ServerMAC", &[])?;
  let km3: [u8; 64] = derive_secret(&handshake_secret, "ClientMAC", &[])?;

  Ok((km2, km3, session_key))
}

// ─── X25519 helpers ───────────────────────────────────────────────────────────

/// Clamp an X25519 private scalar per RFC 7748 §5.
///
/// The clamping operations ensure the scalar has the correct bit pattern for
/// X25519 Diffie-Hellman per Bernstein's Curve25519 paper:
///
/// ```text
/// key[0]  &= 248   // clear bits 0, 1, 2 (cofactor clamping)
/// key[31] &= 127   // clear bit 255 (ensure < 2^255)
/// key[31] |= 64    // set bit 254 (ensure >= 2^254)
/// ```
///
/// # Arguments
///
/// * `key` — 32-byte X25519 private key to clamp (passed by value).
///
/// # Returns
///
/// The clamped 32-byte private key.
pub fn clamp_x25519_key(mut key: [u8; 32]) -> [u8; 32] {
  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;
  key
}

/// Derive an X25519 key pair from a seed using OPAQUE-DeriveAuthKeyPair.
///
/// Implements RFC 9807 §2 key-pair derivation:
///
/// ```text
/// prk         = HKDF-Extract(salt=nil, seed)
/// derived     = HKDF-Expand(prk, "OPAQUE-DeriveAuthKeyPair", 32)
/// private_key = clamp(derived)          // RFC 7748 §5 bit clamping
/// public_key  = X25519(private_key, G)  // G = basepoint
/// ```
///
/// # Arguments
///
/// * `seed` — Arbitrary-length seed material (typically 32 random bytes).
///
/// # Returns
///
/// `(private_key, public_key)` — each 32 bytes. The private key is clamped.
///
/// # Errors
///
/// Returns [`OpaqueError::HkdfExpand`] if HKDF expansion fails.
/// Returns [`OpaqueError::LowOrderPoint`] or [`OpaqueError::IdentityElement`]
/// if the derived public key is invalid (extremely unlikely with a good RNG).
///
/// # Equivalent TypeScript
///
/// ```ts
/// const { privateKey, publicKey } = deriveAuthKeyPair(seed)
/// ```
pub fn derive_dh_key_pair(seed: &[u8]) -> Result<([u8; config::NSK], [u8; config::NPK]), OpaqueError> {
  let prk: [u8; 64] = hkdf_extract(None, seed);
  let mut derived: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; config::NSK]);
  *derived = hkdf_expand_32(&prk, b"OPAQUE-DeriveAuthKeyPair")?;
  let private_key: [u8; 32] = clamp_x25519_key(*derived);
  let public_key: [u8; 32] = X25519PublicKey::from(&StaticSecret::from(private_key)).to_bytes();
  validate_x25519_public_key(&public_key)?;
  Ok((private_key, public_key))
}

/// Derive an Ed25519 signing key pair from a master seed.
///
/// The label `"ZeroAccess-DeriveSigningKeyPair"` is application-specific and
/// ensures domain separation from the X25519 key pair derived by
/// [`derive_dh_key_pair`] even when both use the same master seed.
///
/// ```text
/// prk      = HKDF-Extract(salt=nil, master_seed)
/// sub_seed = HKDF-Expand(prk, "ZeroAccess-DeriveSigningKeyPair", 32)
/// signing_key  = Ed25519SigningKey::from_bytes(sub_seed)
/// public_key   = signing_key.verifying_key()
/// ```
///
/// # Arguments
///
/// * `master_seed` — Arbitrary-length seed (typically the OPAQUE envelope seed).
///
/// # Returns
///
/// `(signing_key_bytes, public_key)` — each 32 bytes.
/// The signing key bytes are the raw 32-byte Ed25519 seed (not the expanded key).
///
/// # Errors
///
/// Returns [`OpaqueError::HkdfExpand`] if HKDF expansion fails.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const { signingKey, publicKey } = deriveSigningKeyPair(masterSeed)
/// ```
pub fn derive_signing_key_pair(master_seed: &[u8]) -> Result<([u8; 32], [u8; 32]), OpaqueError> {
  let prk: [u8; 64] = hkdf_extract(None, master_seed);
  let mut sub_seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
  *sub_seed = hkdf_expand_32(&prk, b"ZeroAccess-DeriveSigningKeyPair")?;
  let signing_key: SigningKey = SigningKey::from_bytes(&*sub_seed);
  let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();
  Ok((*sub_seed, public_key))
}

/// Perform an X25519 Diffie-Hellman exchange, rejecting unsafe inputs and outputs.
///
/// 1. Validates the peer public key against low-order point and identity checks.
/// 2. Computes `X25519(private_key, public_key)`.
/// 3. Rejects an all-zero result (indicates an invalid key pair or implementation bug).
///
/// # Arguments
///
/// * `private_key` — 32-byte X25519 private key (caller's ephemeral or static key).
/// * `public_key`  — 32-byte X25519 public key (peer's ephemeral or static key).
///
/// # Returns
///
/// 32-byte Diffie-Hellman shared secret.
///
/// # Errors
///
/// - [`OpaqueError::LowOrderPoint`]  — peer key is a low-order point.
/// - [`OpaqueError::IdentityElement`] — peer key is all zeros.
/// - [`OpaqueError::ZeroSharedSecret`] — DH output is all zeros.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const shared = x25519.getSharedSecret(privateKey, publicKey)
/// ```
pub fn diffie_hellman(private_key: &[u8; 32], public_key: &[u8; 32]) -> Result<[u8; 32], OpaqueError> {
  validate_x25519_public_key(public_key)?;
  let secret: StaticSecret = StaticSecret::from(*private_key);
  let peer: X25519PublicKey = X25519PublicKey::from(*public_key);
  let shared: x25519_dalek::SharedSecret = secret.diffie_hellman(&peer);
  let result: [u8; 32] = *shared.as_bytes();
  if result.iter().all(|&b| b == 0) {
    return Err(OpaqueError::ZeroSharedSecret);
  }
  Ok(result)
}

// ─── OPRF helpers ─────────────────────────────────────────────────────────────

/// Derive the per-credential OPRF private key scalar from a 32-byte seed.
///
/// Implements RFC 9497 §3.2 `DeriveKeyPair` for ristretto255:
///
/// ```text
/// prk          = HKDF-Extract(salt=nil, seed)
/// derived_seed = HKDF-Expand(prk, "RFCXXXX-DeriveKeyPair", 32)
/// oprf_key     = bytesToScalar(derived_seed)   // LE mod group order
/// ```
///
/// # Errors
///
/// - [`OpaqueError::HkdfExpand`]  — if HKDF expansion fails.
/// - [`OpaqueError::ZeroScalar`]  — if the derived scalar is zero (≈ 1/2^252 probability).
pub(crate) fn derive_oprf_key_scalar(seed: &[u8; 32]) -> Result<Scalar, OpaqueError> {
  let prk: [u8; 64] = hkdf_extract(None, seed.as_ref());
  let mut derived: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; config::NOK]);
  *derived = hkdf_expand_32(&prk, b"RFCXXXX-DeriveKeyPair")?;
  let scalar: Scalar = bytes_to_scalar(&*derived);
  if scalar == Scalar::ZERO {
    return Err(OpaqueError::ZeroScalar("derive_oprf_key"));
  }
  Ok(scalar)
}

/// Server-side OPRF BlindEvaluate (RFC 9497 §3.3.1).
///
/// Given the server's OPRF private key and the client's blinded element,
/// computes `evaluated = oprf_key × blinded_element` and returns the
/// compressed ristretto255 result.
///
/// # Arguments
///
/// * `oprf_key`        — 32-byte OPRF private key (little-endian scalar bytes).
/// * `blinded_element` — 32-byte compressed ristretto255 blinded element from
///                       the client.
///
/// # Returns
///
/// 32-byte compressed ristretto255 evaluated element.
///
/// # Errors
///
/// - [`OpaqueError::InvalidElement`] — if `blinded_element` is not a valid
///   non-identity ristretto255 point.
/// - [`OpaqueError::ZeroScalar`]     — if the OPRF key scalar is zero.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const evaluated = blindEvaluate(oprfKey, blindedElement)
/// ```
pub fn blind_evaluate(oprf_key: &[u8; 32], blinded_element: &[u8; 32]) -> Result<[u8; config::NOE], OpaqueError> {
  validate_ristretto255_element(blinded_element)?;
  let key_scalar: Scalar = bytes_to_scalar(oprf_key);
  if key_scalar == Scalar::ZERO {
    return Err(OpaqueError::ZeroScalar("blind_evaluate"));
  }
  let point: curve25519_dalek::RistrettoPoint = try_decompress_ristretto(blinded_element).ok_or_else(|| OpaqueError::InvalidElement("failed to decompress blinded element".into()))?;
  let evaluated: curve25519_dalek::RistrettoPoint = point * key_scalar;
  Ok(evaluated.compress().to_bytes())
}

// ─── Credential response ──────────────────────────────────────────────────────

/// Compute HMAC-SHA512 over `data` using `key`.
///
/// # Arguments
///
/// * `key`  — HMAC key (any length; HMAC accepts arbitrary key sizes).
/// * `data` — Data to authenticate.
///
/// # Returns
///
/// 64-byte ([`config::NM`]) HMAC-SHA512 authentication tag.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const tag = hmac(sha512, key, data)  // 64 bytes
/// ```
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; config::NM] {
  let mut mac: Hmac<Sha512> = HmacSha512::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
  mac.update(data);
  let result = mac.finalize().into_bytes();
  let mut out: [u8; 64] = [0u8; config::NM];
  out.copy_from_slice(&result);
  out
}

/// Compute SHA-512 digest of `data`.
///
/// # Returns
///
/// 64-byte ([`config::NH`]) SHA-512 hash.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const digest = sha512(data)  // 64 bytes
/// ```
pub fn sha512_digest(data: &[u8]) -> [u8; config::NH] {
  let result = Sha512::digest(data);
  let mut out: [u8; 64] = [0u8; config::NH];
  out.copy_from_slice(&result);
  out
}

/// Build the masked credential response for KE2 (RFC 9807 §5.1.2, server-side).
///
/// Constructs the server's credential response from the client's blinded OPRF
/// message and the stored registration record. The envelope contents are never
/// transmitted in plaintext — they are XOR-masked with a deterministic pad
/// derived from the record's masking key.
///
/// # Steps
///
/// 1. Derive per-credential OPRF key:
///    `seed = HKDF-Expand(PRK=oprf_seed, info=credId||"OprfKey", L=32)`
/// 2. Blind-evaluate: `evaluated = oprf_key × blinded_message`.
/// 3. Generate a 32-byte random masking nonce.
/// 4. Derive the credential response pad:
///    `pad = HKDF-Expand(PRK=masking_key, info=nonce||"CredentialResponsePad", L=160)`
/// 5. XOR-mask `serverPublicKey(32) || envelopeNonce(32) || envelopeAuthTag(64) || envelopeSeed(32)`.
///
/// # Arguments
///
/// * `blinded_message`       — 32-byte client OPRF blinded element.
/// * `server_public_key`     — 32-byte server X25519 long-term public key.
/// * `record`                — Stored [`OpaqueRecord`] for this credential.
/// * `credential_identifier` — Per-user credential identifier (1–256 bytes).
/// * `oprf_seed`             — 64-byte server OPRF master seed.
///
/// # Returns
///
/// `(evaluated_message, masking_nonce, masked_response)`:
/// - `evaluated_message` — 32-byte OPRF output.
/// - `masking_nonce`     — 32-byte random nonce used in pad derivation.
/// - `masked_response`   — 160-byte XOR-masked envelope.
///
/// # Errors
///
/// - [`OpaqueError::InvalidElement`] — if `blinded_message` is invalid.
/// - [`OpaqueError::ZeroScalar`]     — if derived OPRF key is zero.
/// - [`OpaqueError::HkdfExpand`]     — if any HKDF step fails.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const { evaluatedMessage, maskingNonce, maskedResponse } =
///   createCredentialResponse(blindedMsg, serverPub, record, credId, oprfSeed)
/// ```
pub fn create_credential_response(
  blinded_message: &[u8; 32],
  server_public_key: &[u8; 32],
  record: &OpaqueRecord,
  credential_identifier: &[u8],
  oprf_seed: &[u8; config::NH], // 64 bytes — used directly as HKDF PRK
) -> Result<([u8; config::NOE], [u8; config::NN], [u8; config::MASKED_RESPONSE_LEN]), OpaqueError> {
  // Derive per-credential OPRF key seed:
  //   seed = HKDF-Expand(PRK=oprfSeed, info=concat(credId, "OprfKey"), L=32)
  let mut expand_info: Vec<u8> = credential_identifier.to_vec();
  expand_info.extend_from_slice(b"OprfKey");
  let mut seed_32: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; config::NOK]);
  *seed_32 = hkdf_expand_32(oprf_seed, &expand_info)?;

  // Derive OPRF key scalar
  let oprf_key_scalar: Scalar = derive_oprf_key_scalar(&seed_32)?;
  let oprf_key_bytes: [u8; 32] = oprf_key_scalar.to_bytes(); // [u8; 32] LE

  // Evaluate OPRF
  let evaluated_message: [u8; 32] = blind_evaluate(&oprf_key_bytes, blinded_message)?;

  // Generate random masking nonce
  let masking_nonce: [u8; 32] = rand_bytes_32();

  // Derive credential response pad:
  //   pad = HKDF-Expand(PRK=maskingKey, info=maskingNonce||"CredentialResponsePad", L=160)
  let mut pad_info: Vec<u8> = masking_nonce.to_vec();
  pad_info.extend_from_slice(b"CredentialResponsePad");
  let pad_vec: Vec<u8> = hkdf_expand(&record.masking_key, &pad_info, config::MASKED_RESPONSE_LEN)?;
  let pad: [u8; config::MASKED_RESPONSE_LEN] = pad_vec.try_into().map_err(|_| OpaqueError::InvalidInput("pad wrong length".into()))?;

  // XOR-mask: pad XOR (serverPublicKey || envelopeNonce || envelopeAuthTag || envelopeSeed)
  let mut plaintext: [u8; 160] = [0u8; config::MASKED_RESPONSE_LEN];
  plaintext[..32].copy_from_slice(server_public_key);
  plaintext[32..64].copy_from_slice(&record.envelope_nonce);
  plaintext[64..128].copy_from_slice(&record.envelope_auth_tag);
  plaintext[128..160].copy_from_slice(&record.envelope_seed);

  let mut masked_response: [u8; 160] = [0u8; config::MASKED_RESPONSE_LEN];
  for i in 0..config::MASKED_RESPONSE_LEN {
    masked_response[i] = pad[i] ^ plaintext[i];
  }

  Ok((evaluated_message, masking_nonce, masked_response))
}

// ─── Preamble ─────────────────────────────────────────────────────────────────

/// Build the protocol transcript preamble (RFC 9807 §6.2.1).
///
/// The preamble is the byte-serialized transcript of all public KE1 and KE2
/// fields. It is hashed to form the binding context for MAC key derivation,
/// ensuring both parties compute the same MAC keys only if they agree on all
/// public message fields.
///
/// Exact byte layout:
///
/// ```text
/// preamble = "RFCXXXX"                                     (7 bytes, literal)
///          || I2OSP(len(context), 2)  || context
///          || I2OSP(len(clientIdentity), 2) || clientIdentity
///          || blindedMessage                               (32 bytes, fixed)
///          || clientNonce                                  (32 bytes, fixed)
///          || clientX25519PublicKeyshare                   (32 bytes, fixed)
///          || I2OSP(len(serverIdentity), 2) || serverIdentity
///          || evaluatedMessage                             (32 bytes, fixed)
///          || maskingNonce                                 (32 bytes, fixed)
///          || maskedResponse                               (160 bytes, fixed)
///          || serverNonce                                  (32 bytes, fixed)
///          || serverX25519PublicKeyshare                   (32 bytes, fixed)
/// ```
///
/// # Arguments
///
/// * `client_identity`             — Client identity bytes (public key or name).
/// * `blinded_message`             — 32-byte OPRF blinded element from KE1.
/// * `client_nonce`                — 32-byte client nonce from KE1.
/// * `client_x25519_public_keyshare` — 32-byte client ephemeral X25519 key.
/// * `server_identity`             — Server identity bytes (public key or name).
/// * `evaluated_message`           — 32-byte OPRF evaluated element from KE2.
/// * `masking_nonce`               — 32-byte masking nonce from KE2.
/// * `masked_response`             — 160-byte masked envelope from KE2.
/// * `server_nonce`                — 32-byte server nonce from KE2.
/// * `server_x25519_public_keyshare` — 32-byte server ephemeral X25519 key.
///
/// # Returns
///
/// Heap-allocated `Vec<u8>` containing the fully serialized preamble.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const preamble = buildPreamble(clientId, ke1, serverId, ke2Fields)
/// ```
#[allow(clippy::too_many_arguments)]
pub fn build_preamble(
  client_identity: &[u8],
  blinded_message: &[u8; 32],
  client_nonce: &[u8; 32],
  client_x25519_public_keyshare: &[u8; 32],
  server_identity: &[u8],
  evaluated_message: &[u8; config::NOE],
  masking_nonce: &[u8; config::NN],
  masked_response: &[u8; config::MASKED_RESPONSE_LEN],
  server_nonce: &[u8; config::NN],
  server_x25519_public_keyshare: &[u8; config::NPK],
) -> Vec<u8> {
  let context: &[u8] = config::CONTEXT.as_bytes();

  // Pre-compute total length for a single allocation
  let total: usize = 7  // "RFCXXXX"
    + 2 + context.len()
    + 2 + client_identity.len()
    + 32 + 32 + 32              // ke1 fields (no length prefix)
    + 2 + server_identity.len()
    + 32 + 32 + config::MASKED_RESPONSE_LEN // cred response fields (no prefix)
    + 32                        // serverNonce
    + 32; // serverX25519PublicKeyshare

  let mut out: Vec<u8> = Vec::with_capacity(total);

  // "RFCXXXX" (7 bytes)
  out.extend_from_slice(b"RFCXXXX");

  // context (length-prefixed)
  out.extend_from_slice(&i2osp2(context.len()));
  out.extend_from_slice(context);

  // clientIdentity (length-prefixed)
  out.extend_from_slice(&i2osp2(client_identity.len()));
  out.extend_from_slice(client_identity);

  // KE1 fields (no length prefix, fixed size)
  out.extend_from_slice(blinded_message);
  out.extend_from_slice(client_nonce);
  out.extend_from_slice(client_x25519_public_keyshare);

  // serverIdentity (length-prefixed)
  out.extend_from_slice(&i2osp2(server_identity.len()));
  out.extend_from_slice(server_identity);

  // Credential response fields (no length prefix)
  out.extend_from_slice(evaluated_message);
  out.extend_from_slice(masking_nonce);
  out.extend_from_slice(masked_response);

  // AKE fields (no length prefix)
  out.extend_from_slice(server_nonce);
  out.extend_from_slice(server_x25519_public_keyshare);

  out
}

// ─── i2OSP helpers ────────────────────────────────────────────────────────────

/// Encode an unsigned integer as 2 big-endian bytes — I2OSP(value, 2).
///
/// Used to length-prefix variable-size fields in the protocol preamble and
/// HKDF label construction. Follows RFC 8017 §4.1 I2OSP notation.
///
/// # Arguments
///
/// * `value` — Unsigned integer to encode; must be < 65 536 (`usize::MAX`
///   values ≥ 65 536 will silently truncate in release builds).
///
/// # Returns
///
/// Big-endian 2-byte representation `[(value >> 8) as u8, (value & 0xff) as u8]`.
#[inline]
pub fn i2osp2(value: usize) -> [u8; 2] {
  [(value >> 8) as u8, (value & 0xff) as u8]
}

// ─── Constant-time equality re-export ────────────────────────────────────────

/// Re-export of [`primitives::ct_equal`] for use in [`protocol`] and the gRPC service.
///
/// [`protocol`]: crate::security::opaque::protocol
pub use crate::security::opaque::primitives::ct_equal;
