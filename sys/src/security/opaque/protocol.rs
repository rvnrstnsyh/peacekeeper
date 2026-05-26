//! Top-level server-side OPAQUE protocol operations.
//!
//! This module exposes the four server functions that compose the OPAQUE
//! protocol, plus two data types returned by [`generate_ke2`] that the
//! caller must persist in Redis with a short TTL:
//!
//! | Function                        | RFC Reference      | Role                      |
//! |---------------------------------|--------------------|---------------------------|
//! | [`create_registration_response`]| RFC 9807 §5.1.2    | Registration step 2 of 3  |
//! | [`generate_ke2`]                | RFC 9807 §6.2.4    | AKE step 2 of 4           |
//! | [`server_finish`]               | RFC 9807 §6.2.6    | AKE step 4 of 4           |
//! | [`create_change_password_response`] | RFC 9807 combined | Change-password step 2 |
//!
//! # Caller responsibilities
//!
//! After [`generate_ke2`] or [`create_change_password_response`] returns:
//!
//! 1. **Store** `Ke2State` (or `ChangePasswordData::state`) in Redis keyed by
//!    `credential_identifier`, with a short TTL (e.g. 60 seconds).
//! 2. **Send** `Ke2Data` (or `ChangePasswordData::ke2`) to the client.
//! 3. On KE3 receipt, call [`server_finish`] with the stored
//!    `expected_client_mac` and the received MAC.
//! 4. On success, promote the new registration record to the database
//!    (change-password flow only).

use zeroize::Zeroizing;

use crate::security::opaque::{
  config,
  errors::OpaqueError,
  helpers::{
    build_preamble, create_credential_response, derive_dh_key_pair, derive_keys, diffie_hellman, hmac_sha512, rand_bytes_32, sha512_digest, validate_ristretto255_element, validate_x25519_public_key,
    OpaqueRecord,
  },
  primitives::ct_equal,
};

// ─── Return types ─────────────────────────────────────────────────────────────

/// KE1 fields received from the client (extracted from the proto message).
///
/// KE1 is the client's first AKE message, carrying:
/// - The OPRF blinded password element (credential request).
/// - The client's ephemeral X25519 public key share and nonce (auth request).
pub struct Ke1Data {
  /// OPRF blinded element: `H(password)^r` where `r` is a random scalar.
  /// 32 bytes (compressed ristretto255).
  pub blinded_message: [u8; 32],
  /// Client-generated random nonce. 32 bytes.
  pub client_nonce: [u8; 32],
  /// Client's ephemeral X25519 public key for triple-DH. 32 bytes.
  pub client_x25519_public_keyshare: [u8; 32],
}

/// KE2 message fields to send back to the client (step 2 of 4).
///
/// Contains the credential response (OPRF output + masked envelope) and the
/// AKE auth response (server ephemeral key + server MAC).
pub struct Ke2Data {
  /// OPRF evaluated element: `blinded_message^oprf_key`. 32 bytes.
  pub evaluated_message: [u8; config::NOE],
  /// Random nonce used to derive the masking pad. 32 bytes.
  pub masking_nonce: [u8; config::NN],
  /// XOR-masked envelope: `pad ⊕ (serverPK || envNonce || authTag || seed)`. 160 bytes.
  pub masked_response: [u8; config::MASKED_RESPONSE_LEN],
  /// Server-generated random nonce. 32 bytes.
  pub server_nonce: [u8; config::NN],
  /// Server's ephemeral X25519 public key for triple-DH. 32 bytes.
  pub server_x25519_public_keyshare: [u8; config::NPK],
  /// `HMAC-SHA512(km2, SHA-512(preamble))`. 64 bytes.
  pub server_mac: [u8; config::NM],
}

/// Server state produced during [`generate_ke2`] — must be stored server-side.
///
/// This state is **not** sent to the client. It must be persisted (e.g. in
/// Redis) between KE2 and KE3, keyed by `credential_identifier`, with a
/// short TTL to prevent replay attacks.
pub struct Ke2State {
  /// Client MAC expected in KE3; compare using [`server_finish`]. 64 bytes.
  pub expected_client_mac: [u8; config::NM],
  /// Shared session key established via triple-DH. 64 bytes.
  /// Available to the application after [`server_finish`] returns `true`.
  pub session_key: [u8; config::NH],
}

/// Combined output of [`create_change_password_response`].
///
/// Bundles the old-password KE2 authentication with the new-password
/// registration response into a single atomic server operation.
pub struct ChangePasswordData {
  /// KE2 message to send to the client (old-password authentication).
  pub ke2: Ke2Data,
  /// Server state for the old-password KE3 verification. Must be stored in Redis.
  pub state: Ke2State,
  /// New-password OPRF evaluated element (32 bytes). Send to the client so it
  /// can finalize the new registration envelope.
  pub new_evaluated_message: [u8; config::NOE],
  /// Server long-term public key echoed for the new enrollment (32 bytes).
  pub new_server_public_key: [u8; config::NPK],
}

// ─── create_registration_response ────────────────────────────────────────────

/// RFC 9807 §5.1.2 — Server creates registration response (step 2 of 3).
///
/// Derives the per-credential OPRF key from the server's OPRF master seed and
/// the credential identifier, evaluates the client's blinded message, and
/// returns both the OPRF output and the server's public key.
///
/// All sensitive intermediate values (OPRF key scalar, seed) are wrapped in
/// [`zeroize::Zeroizing`] and zeroed on drop.
///
/// # Arguments
///
/// * `blinded_message`       — 32-byte compressed ristretto255 blinded element from
///                             the client's registration request.
/// * `server_public_key`     — 32-byte server long-term X25519 public key.
/// * `credential_identifier` — Per-user credential identifier, 1–256 bytes.
/// * `oprf_seed`             — 64-byte server OPRF master seed.
///
/// # Returns
///
/// `(evaluated_message, server_public_key)`:
/// - `evaluated_message`  — 32-byte OPRF output.
/// - `server_public_key`  — Echo of the server's X25519 public key (32 bytes).
///
/// # Errors
///
/// - [`OpaqueError::InvalidInput`]   — `credential_identifier` is empty or > 256 bytes.
/// - [`OpaqueError::InvalidElement`] — `blinded_message` is not a valid ristretto255 point.
/// - [`OpaqueError::LowOrderPoint`] / [`OpaqueError::IdentityElement`] — `server_public_key` is unsafe.
/// - [`OpaqueError::HkdfExpand`]     — HKDF expansion failed.
/// - [`OpaqueError::ZeroScalar`]     — Derived OPRF key is zero.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const { evaluatedMessage, serverPublicKey } =
///   this.createRegistrationResponse(blindedMessage, credentialIdentifier)
/// ```
pub fn create_registration_response(
  blinded_message: &[u8; 32],
  server_public_key: &[u8; 32],
  credential_identifier: &[u8],
  oprf_seed: &[u8; config::NH],
) -> Result<([u8; config::NOE], [u8; config::NPK]), OpaqueError> {
  if credential_identifier.is_empty() || credential_identifier.len() > 256 {
    return Err(OpaqueError::InvalidInput("credential_identifier must be 1–256 bytes".into()));
  }

  validate_ristretto255_element(blinded_message)?;
  validate_x25519_public_key(server_public_key)?;

  // Derive per-credential OPRF key seed: HKDF-Expand(PRK=oprfSeed, info=credId||"OprfKey", 32)
  let mut expand_info: Vec<u8> = credential_identifier.to_vec();
  expand_info.extend_from_slice(b"OprfKey");
  let seed_vec: Vec<u8> = crate::security::opaque::helpers::hkdf_expand(oprf_seed, &expand_info, config::NOK)?;
  let seed_32: [u8; 32] = seed_vec.try_into().map_err(|_| OpaqueError::InvalidInput("seed wrong length".into()))?;

  // Derive OPRF key scalar via DeriveKeyPair (RFC 9497 §3.2) — must match create_credential_response
  let oprf_key_scalar: curve25519_dalek::Scalar = crate::security::opaque::helpers::derive_oprf_key_scalar(&seed_32)?;
  let oprf_key_bytes: [u8; 32] = oprf_key_scalar.to_bytes();

  // Evaluate OPRF
  let eval_msg: [u8; 32] = crate::security::opaque::helpers::blind_evaluate(&oprf_key_bytes, blinded_message)?;

  Ok((eval_msg, *server_public_key))
}

// ─── generate_ke2 ─────────────────────────────────────────────────────────────

/// RFC 9807 §6.2.4 — Server generates KE2 (step 2 of 4).
///
/// The second message of the Authenticated Key Exchange phase. The server
/// retrieves the stored registration record, creates a credential response
/// (OPRF evaluate + mask envelope), generates an ephemeral DH key pair,
/// performs triple-DH to establish a shared secret, derives session keys,
/// and creates a MAC for server authentication.
///
/// # Steps
///
/// 1. **Credential response** — OPRF evaluate + mask the stored envelope.
/// 2. **Ephemeral keypair** — Generate random server nonce and X25519 key share.
/// 3. **Effective identities** — Default to the respective public keys if not provided.
/// 4. **Preamble** — Serialize the full KE1 + KE2 transcript.
/// 5. **Triple-DH** — Compute three DH exchanges:
///    - `dh1 = server_ephemeral × client_ephemeral`
///    - `dh2 = server_static   × client_ephemeral`
///    - `dh3 = server_ephemeral × client_static`
/// 6. **Key derivation** — `(km2, km3, session_key) = DeriveKeys(dh1||dh2||dh3, preamble)`.
/// 7. **Server MAC** — `HMAC-SHA512(km2, SHA-512(preamble))`.
/// 8. **Expected client MAC** — `HMAC-SHA512(km3, SHA-512(preamble||serverMac))`.
///
/// # Arguments
///
/// * `record`               — Stored [`OpaqueRecord`] for this credential.
/// * `credential_identifier`— Per-user credential identifier (1–256 bytes).
/// * `ke1`                  — Client's KE1 message fields.
/// * `server_private_key`   — Server long-term X25519 private key (32 bytes).
/// * `server_public_key`    — Server long-term X25519 public key (32 bytes).
/// * `oprf_seed`            — Server OPRF master seed (64 bytes).
/// * `server_identity`      — Optional server identity; defaults to `server_public_key`.
/// * `client_identity`      — Optional client identity; defaults to `record.client_x25519_public_key`.
///
/// # Returns
///
/// `(Ke2Data, Ke2State)`:
/// - [`Ke2Data`]  — All fields to include in the KE2 response to the client.
/// - [`Ke2State`] — `expected_client_mac` and `session_key`; **must be stored
///                  in Redis** before sending the response.
///
/// # Errors
///
/// Any [`OpaqueError`] variant from validation or key derivation steps.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const { ke2, expectedClientMac, sessionKey } =
///   await this.zeroAccess.generateKe2(record, credId, ke1, serverId, clientId)
/// ```
///
/// [`OpaqueRecord`]: crate::security::opaque::helpers::OpaqueRecord
/// [`OpaqueError`]:  crate::security::opaque::errors::OpaqueError
pub fn generate_ke2(
  record: &OpaqueRecord,
  credential_identifier: &[u8],
  ke1: &Ke1Data,
  server_private_key: &[u8; 32],
  server_public_key: &[u8; 32],
  oprf_seed: &[u8; config::NH],
  server_identity: Option<&[u8]>,
  client_identity: Option<&[u8]>,
) -> Result<(Ke2Data, Ke2State), OpaqueError> {
  // Input validation
  if credential_identifier.is_empty() {
    return Err(OpaqueError::InvalidInput("credential_identifier cannot be empty".into()));
  }
  validate_x25519_public_key(server_public_key)?;
  validate_ristretto255_element(&ke1.blinded_message)?;
  validate_x25519_public_key(&ke1.client_x25519_public_keyshare)?;
  validate_x25519_public_key(&record.client_x25519_public_key)?;

  // Step 1: credential response
  let (evaluated_message, masking_nonce, masked_response) = create_credential_response(&ke1.blinded_message, server_public_key, record, credential_identifier, oprf_seed)?;

  // Step 2: server ephemeral keypair
  let server_nonce: [u8; 32] = rand_bytes_32();
  let server_keyshare_seed: [u8; 32] = rand_bytes_32();
  let (server_x25519_private_keyshare, server_x25519_public_keyshare) = derive_dh_key_pair(&server_keyshare_seed)?;

  // Step 3: effective identities
  let server_id: &[u8] = server_identity.unwrap_or(server_public_key.as_ref());
  let client_id: &[u8] = client_identity.unwrap_or(record.client_x25519_public_key.as_ref());

  // Step 4: preamble
  let preamble: Vec<u8> = build_preamble(
    client_id,
    &ke1.blinded_message,
    &ke1.client_nonce,
    &ke1.client_x25519_public_keyshare,
    server_id,
    &evaluated_message,
    &masking_nonce,
    &masked_response,
    &server_nonce,
    &server_x25519_public_keyshare,
  );

  // Step 5: triple-DH
  //   dh1 = server ephemeral × client ephemeral
  //   dh2 = server static   × client ephemeral
  //   dh3 = server ephemeral × client static
  let dh1: Zeroizing<[u8; 32]> = Zeroizing::new(diffie_hellman(&server_x25519_private_keyshare, &ke1.client_x25519_public_keyshare)?);
  let dh2: Zeroizing<[u8; 32]> = Zeroizing::new(diffie_hellman(server_private_key, &ke1.client_x25519_public_keyshare)?);
  let dh3: Zeroizing<[u8; 32]> = Zeroizing::new(diffie_hellman(&server_x25519_private_keyshare, &record.client_x25519_public_key)?);

  let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(96));
  ikm.extend_from_slice(&*dh1);
  ikm.extend_from_slice(&*dh2);
  ikm.extend_from_slice(&*dh3);

  // Step 6: key derivation
  let (km2, km3, session_key) = derive_keys(&ikm, &preamble)?;

  // Step 7: server MAC  = HMAC-SHA512(km2, SHA-512(preamble))
  let preamble_hash: [u8; 64] = sha512_digest(&preamble);
  let server_mac: [u8; 64] = hmac_sha512(&km2, &preamble_hash);

  // expected client MAC = HMAC-SHA512(km3, SHA-512(preamble || serverMac))
  let mut extended: Vec<u8> = preamble.clone();
  extended.extend_from_slice(&server_mac);
  let extended_hash: [u8; 64] = sha512_digest(&extended);
  let expected_client_mac: [u8; 64] = hmac_sha512(&km3, &extended_hash);

  Ok((
    Ke2Data {
      evaluated_message,
      masking_nonce,
      masked_response,
      server_nonce,
      server_x25519_public_keyshare,
      server_mac,
    },
    Ke2State { expected_client_mac, session_key },
  ))
}

// ─── server_finish ────────────────────────────────────────────────────────────

/// RFC 9807 §6.2.6 — Server verifies the client MAC from KE3 (step 4 of 4).
///
/// Compares the client-supplied MAC from KE3 with the expected MAC that was
/// computed during [`generate_ke2`] and stored in [`Ke2State`].
///
/// # Arguments
///
/// * `ke3_client_mac`      — 64-byte MAC received from the client in KE3.
/// * `expected_client_mac` — 64-byte MAC from the stored [`Ke2State`].
///
/// # Returns
///
/// `true` iff both MACs are identical (constant-time comparison).
///
/// # Security
///
/// Uses [`ct_equal`] (via [`subtle::ConstantTimeEq`]) to prevent timing
/// side-channel attacks on the MAC comparison.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const valid = await this.zeroAccess.serverFinish(ke3ClientMac, expectedClientMac)
/// ```
pub fn server_finish(ke3_client_mac: &[u8; 64], expected_client_mac: &[u8; 64]) -> bool {
  ct_equal(ke3_client_mac, expected_client_mac)
}

// ─── create_change_password_response ─────────────────────────────────────────

/// Combined old-password authentication + new-password registration (step 2 of 4).
///
/// Atomically handles the server side of a password change by running both
/// operations in a single call:
///
/// 1. **Old-password authentication** — Calls [`generate_ke2`] using the stored
///    registration record to authenticate the user's current password. The
///    caller must store [`ChangePasswordData::state`] in Redis and wait for a
///    successful KE3 before committing the new record.
/// 2. **New-password registration** — Calls [`create_registration_response`]
///    for the new blinded password so the client can finalize the new envelope
///    in the same round-trip.
///
/// # Arguments
///
/// * `record`                      — Stored [`OpaqueRecord`] for the current password.
/// * `credential_identifier`       — Per-user credential identifier (1–256 bytes).
/// * `old_password_ke1`            — Client's KE1 message for the current password.
/// * `new_password_blinded_message`— 32-byte OPRF blinded element for the new password.
/// * `server_private_key`          — Server long-term X25519 private key (32 bytes).
/// * `server_public_key`           — Server long-term X25519 public key (32 bytes).
/// * `oprf_seed`                   — Server OPRF master seed (64 bytes).
/// * `server_identity`             — Optional server identity override.
/// * `client_identity`             — Optional client identity override.
///
/// # Returns
///
/// [`ChangePasswordData`] containing:
/// - `ke2`                 — KE2 fields to send to the client.
/// - `state`               — [`Ke2State`] to persist in Redis.
/// - `new_evaluated_message` — 32-byte new OPRF output for client envelope finalization.
/// - `new_server_public_key` — 32-byte server public key for the new enrollment.
///
/// # Errors
///
/// Any [`OpaqueError`] from [`generate_ke2`] or [`create_registration_response`].
///
/// # Security
///
/// The new registration record must **not** be committed to the database until
/// [`server_finish`] confirms the KE3 MAC, proving the client knew the old
/// password. Committing before verification would allow password replacement
/// without authentication.
///
/// # Equivalent TypeScript
///
/// ```ts
/// const data = await this.zeroAccess.createChangePasswordResponse(
///   record, credId, oldKe1, newBlindedMsg, serverIdentity, clientIdentity)
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_change_password_response(
  record: &OpaqueRecord,
  credential_identifier: &[u8],
  old_password_ke1: &Ke1Data,
  new_password_blinded_message: &[u8; 32],
  server_private_key: &[u8; 32],
  server_public_key: &[u8; 32],
  oprf_seed: &[u8; config::NH],
  server_identity: Option<&[u8]>,
  client_identity: Option<&[u8]>,
) -> Result<ChangePasswordData, OpaqueError> {
  // Old-password authentication
  let (ke2, state) = generate_ke2(
    record,
    credential_identifier,
    old_password_ke1,
    server_private_key,
    server_public_key,
    oprf_seed,
    server_identity,
    client_identity,
  )?;

  // New-password registration response
  let (new_evaluated_message, new_server_public_key) = create_registration_response(new_password_blinded_message, server_public_key, credential_identifier, oprf_seed)?;

  Ok(ChangePasswordData {
    ke2,
    state,
    new_evaluated_message,
    new_server_public_key,
  })
}
