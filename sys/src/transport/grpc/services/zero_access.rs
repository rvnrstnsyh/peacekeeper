//! gRPC service implementation for OPAQUE server-side operations.
//!
//! This module bridges the Tonic-generated gRPC trait ([`proto::zero_access_server::ZeroAccess`])
//! to the cryptographic functions in [`crate::security::opaque`].
//!
//! # Service struct
//!
//! [`ZeroAccessService`] holds the three server secrets loaded from environment
//! variables at startup. Sensitive material is zeroed on drop.
//!
//! # Proto ↔ internal conversions
//!
//! Helper functions (not exported) convert between proto message types and the
//! fixed-size byte array types used by the crypto layer:
//!
//! | Helper                  | Direction               |
//! |-------------------------|-------------------------|
//! | [`to_32`]               | `&[u8]` → `[u8; 32]`   |
//! | [`to_64`]               | `&[u8]` → `[u8; 64]`   |
//! | [`proto_record_to_internal`] | proto → [`InternalOpaqueRecord`] |
//! | [`proto_ke1_to_ke1data`]| proto → [`Ke1Data`]     |
//! | [`ke2data_to_proto`]    | [`Ke2Data`] → proto     |
//! | [`optional_identity`]   | `&[u8]` → `Option<&[u8]>` (empty = None) |
//!
//! # RPC methods
//!
//! | Method                              | OPAQUE Role            |
//! |-------------------------------------|------------------------|
//! | `create_registration_response`      | Registration step 2/3  |
//! | `generate_ke2`                      | AKE step 2/4           |
//! | `server_finish`                     | AKE step 4/4           |
//! | `create_change_password_response`   | Change-password step 2 |
//!
//! # Error handling
//!
//! All [`OpaqueError`] variants are mapped to `tonic::Status::internal` by the
//! `From<OpaqueError> for tonic::Status` impl in [`crate::security::opaque::errors`].
//! This ensures no cryptographic details are ever leaked to the caller.
//!
//! [`OpaqueError`]: crate::security::opaque::errors::OpaqueError

use anyhow::{Context as _, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroize;

use crate::security::opaque::{
  self as opaque,
  helpers::OpaqueRecord as InternalOpaqueRecord,
  protocol::{Ke1Data, Ke2Data},
};
use crate::transport::grpc::proto;

// ─── Service struct ───────────────────────────────────────────────────────────

/// gRPC service that handles all server-side OPAQUE operations.
///
/// Holds the server's three long-term OPAQUE secrets in memory for the
/// lifetime of the process. Loaded once from environment variables at startup
/// via [`ZeroAccessService::new`].
///
/// # Memory safety
///
/// The private key (`opaque_server_private_key`) and OPRF seed (`opaque_seed`)
/// are zeroed via [`zeroize::Zeroize`] when the service is dropped, preventing
/// secret material from lingering in heap memory after shutdown.
///
/// # Environment variables (required)
///
/// | Variable                   | Encoding  | Raw size |
/// |----------------------------|-----------|----------|
/// | `OPAQUE_SERVER_PRIVATE_KEY`| Base64    | 32 bytes |
/// | `OPAQUE_SERVER_PUBLIC_KEY` | Base64    | 32 bytes |
/// | `OPAQUE_SEED`              | Base64    | 64 bytes |
#[derive(Debug)]
pub struct ZeroAccessService {
  opaque_server_private_key: [u8; 32],
  opaque_server_public_key: [u8; 32],
  opaque_seed: [u8; 64],
}

impl Drop for ZeroAccessService {
  fn drop(&mut self) {
    self.opaque_server_private_key.zeroize();
    self.opaque_seed.zeroize();
  }
}

impl ZeroAccessService {
  /// Load OPAQUE server keys from environment variables and construct the service.
  ///
  /// Reads three base64-encoded environment variables, decodes them, and
  /// validates the expected byte lengths. Called once during server bootstrap.
  ///
  /// # Required environment variables
  ///
  /// | Variable                    | Expected decoded size |
  /// |-----------------------------|-----------------------|
  /// | `OPAQUE_SERVER_PRIVATE_KEY` | 32 bytes              |
  /// | `OPAQUE_SERVER_PUBLIC_KEY`  | 32 bytes              |
  /// | `OPAQUE_SEED`               | 64 bytes              |
  ///
  /// # Errors
  ///
  /// Returns an error if any variable is missing, contains invalid base64, or
  /// decodes to the wrong number of bytes.
  ///
  /// # Equivalent TypeScript
  ///
  /// ```ts
  /// static createFromEnv(): ZeroAccessService {
  ///   if (_envInstance) return _envInstance
  ///   _envInstance = new ZeroAccessService(env.GRPC_ZERO_ACCESS_ADDRESS)
  ///   return _envInstance
  /// }
  /// ```
  pub fn new() -> Result<Self> {
    let priv_b64: String = std::env::var("OPAQUE_SERVER_PRIVATE_KEY").context("OPAQUE_SERVER_PRIVATE_KEY not set")?;
    let pub_b64: String = std::env::var("OPAQUE_SERVER_PUBLIC_KEY").context("OPAQUE_SERVER_PUBLIC_KEY not set")?;
    let seed_b64: String = std::env::var("OPAQUE_SEED").context("OPAQUE_SEED not set")?;

    let priv_vec: Vec<u8> = B64.decode(priv_b64.trim()).context("OPAQUE_SERVER_PRIVATE_KEY: invalid base64")?;
    let pub_vec: Vec<u8> = B64.decode(pub_b64.trim()).context("OPAQUE_SERVER_PUBLIC_KEY: invalid base64")?;
    let seed_vec: Vec<u8> = B64.decode(seed_b64.trim()).context("OPAQUE_SEED: invalid base64")?;

    let opaque_server_private_key: [u8; 32] = priv_vec.try_into().map_err(|_| anyhow::anyhow!("OPAQUE_SERVER_PRIVATE_KEY must decode to 32 bytes"))?;
    let opaque_server_public_key: [u8; 32] = pub_vec.try_into().map_err(|_| anyhow::anyhow!("OPAQUE_SERVER_PUBLIC_KEY must decode to 32 bytes"))?;
    let opaque_seed: [u8; 64] = seed_vec.try_into().map_err(|_| anyhow::anyhow!("OPAQUE_SEED must decode to 64 bytes"))?;

    Ok(Self {
      opaque_server_private_key,
      opaque_server_public_key,
      opaque_seed,
    })
  }
}

// ─── Proto ↔ internal conversions ─────────────────────────────────────────────

/// Convert a byte slice to a `[u8; 32]`, returning a gRPC error if the length differs.
fn to_32(v: &[u8], field: &'static str) -> Result<[u8; 32], tonic::Status> {
  v.try_into().map_err(|_| tonic::Status::invalid_argument(format!("'{field}' must be 32 bytes, got {}", v.len())))
}

/// Convert a byte slice to a `[u8; 64]`, returning a gRPC error if the length differs.
fn to_64(v: &[u8], field: &'static str) -> Result<[u8; 64], tonic::Status> {
  v.try_into().map_err(|_| tonic::Status::invalid_argument(format!("'{field}' must be 64 bytes, got {}", v.len())))
}

/// Convert a proto [`OpaqueRecord`] message to the internal [`InternalOpaqueRecord`].
///
/// Returns `tonic::Status::invalid_argument` if any field has the wrong byte length.
fn proto_record_to_internal(r: &proto::OpaqueRecord) -> Result<InternalOpaqueRecord, tonic::Status> {
  Ok(InternalOpaqueRecord {
    client_ed25519_public_key: to_32(&r.client_ed25519_public_key, "client_ed25519_public_key")?,
    client_x25519_public_key: to_32(&r.client_x25519_public_key, "client_x25519_public_key")?,
    masking_key: to_64(&r.masking_key, "masking_key")?,
    envelope_nonce: to_32(&r.envelope_nonce, "envelope_nonce")?,
    envelope_auth_tag: to_64(&r.envelope_auth_tag, "envelope_auth_tag")?,
    envelope_seed: to_32(&r.envelope_seed, "envelope_seed")?,
  })
}

/// Convert a proto [`OpaqueKe1`] message to the internal [`Ke1Data`].
///
/// Requires both `credential_request` and `auth_request` sub-messages to be present.
/// Returns `tonic::Status::invalid_argument` if either is missing or has wrong field sizes.
fn proto_ke1_to_ke1data(ke1: &proto::OpaqueKe1) -> Result<Ke1Data, tonic::Status> {
  let cred_req: &proto::OpaqueCredentialRequest = ke1.credential_request.as_ref().ok_or_else(|| tonic::Status::invalid_argument("ke1.credential_request missing"))?;
  let auth_req: &proto::OpaqueAuthRequest = ke1.auth_request.as_ref().ok_or_else(|| tonic::Status::invalid_argument("ke1.auth_request missing"))?;

  Ok(Ke1Data {
    blinded_message: to_32(&cred_req.blinded_message, "blinded_message")?,
    client_nonce: to_32(&auth_req.client_nonce, "client_nonce")?,
    client_x25519_public_keyshare: to_32(&auth_req.client_x25519_public_keyshare, "client_x25519_public_keyshare")?,
  })
}

/// Convert an internal [`Ke2Data`] to the proto [`OpaqueKe2`] message.
fn ke2data_to_proto(ke2: &Ke2Data) -> proto::OpaqueKe2 {
  proto::OpaqueKe2 {
    credential_response: Some(proto::OpaqueCredentialResponse {
      evaluated_message: ke2.evaluated_message.to_vec(),
      masking_nonce: ke2.masking_nonce.to_vec(),
      masked_response: ke2.masked_response.to_vec(),
    }),
    auth_response: Some(proto::OpaqueAuthResponse {
      server_nonce: ke2.server_nonce.to_vec(),
      server_x25519_public_keyshare: ke2.server_x25519_public_keyshare.to_vec(),
      server_mac: ke2.server_mac.to_vec(),
    }),
  }
}

/// Convert an optional bytes field to `Option<&[u8]>`: empty vec → `None`.
///
/// Proto3 represents absent optional strings/bytes as empty byte vectors.
/// This helper converts that convention to a Rust `Option`.
fn optional_identity(v: &[u8]) -> Option<&[u8]> {
  if v.is_empty() { None } else { Some(v) }
}

// ─── gRPC trait implementation ────────────────────────────────────────────────

#[tonic::async_trait]
impl proto::zero_access_server::ZeroAccess for ZeroAccessService {
  /// RFC 9807 §5.1.2 — CreateRegistrationResponse (registration step 2 of 3).
  ///
  /// Derives the per-credential OPRF key and evaluates the client's blinded
  /// message. Returns the OPRF output and the server's X25519 public key.
  ///
  /// The client uses these to finalize the registration envelope in step 3.
  async fn create_registration_response(&self, request: tonic::Request<proto::CreateRegistrationResponseRequest>) -> Result<tonic::Response<proto::CreateRegistrationResponseReply>, tonic::Status> {
    let req: proto::CreateRegistrationResponseRequest = request.into_inner();

    let blinded_message: [u8; 32] = to_32(&req.blinded_message, "blinded_message")?;
    let credential_identifier: &Vec<u8> = &req.credential_identifier;
    if credential_identifier.is_empty() || credential_identifier.len() > 256 {
      return Err(tonic::Status::invalid_argument("credential_identifier must be 1–256 bytes"));
    }

    let (evaluated_message, server_public_key) =
      opaque::create_registration_response(&blinded_message, &self.opaque_server_public_key, credential_identifier, &self.opaque_seed).map_err(tonic::Status::from)?;

    Ok(tonic::Response::new(proto::CreateRegistrationResponseReply {
      evaluated_message: evaluated_message.to_vec(),
      server_public_key: server_public_key.to_vec(),
    }))
  }

  /// RFC 9807 §6.2.4 — GenerateKE2 (AKE step 2 of 4).
  ///
  /// Performs OPRF evaluation, envelope masking, triple-DH, key derivation,
  /// and server MAC computation. Returns the full KE2 message plus the server
  /// session state (`expected_client_mac`, `session_key`).
  ///
  /// The caller (TypeScript layer) must persist `expected_client_mac` and
  /// `session_key` in Redis before returning the KE2 response to the client.
  async fn generate_ke2(&self, request: tonic::Request<proto::GenerateKe2Request>) -> Result<tonic::Response<proto::GenerateKe2Reply>, tonic::Status> {
    let req: proto::GenerateKe2Request = request.into_inner();

    let proto_record: &proto::OpaqueRecord = req.record.as_ref().ok_or_else(|| tonic::Status::invalid_argument("record missing"))?;
    let record: InternalOpaqueRecord = proto_record_to_internal(proto_record)?;

    let ke1: &proto::OpaqueKe1 = req.ke1.as_ref().ok_or_else(|| tonic::Status::invalid_argument("ke1 missing"))?;
    let ke1_data: Ke1Data = proto_ke1_to_ke1data(ke1)?;

    if req.credential_identifier.is_empty() {
      return Err(tonic::Status::invalid_argument("credential_identifier missing"));
    }

    let (ke2_data, ke2_state) = opaque::generate_ke2(
      &record,
      &req.credential_identifier,
      &ke1_data,
      &self.opaque_server_private_key,
      &self.opaque_server_public_key,
      &self.opaque_seed,
      optional_identity(&req.server_identity),
      optional_identity(&req.client_identity),
    )
    .map_err(tonic::Status::from)?;

    Ok(tonic::Response::new(proto::GenerateKe2Reply {
      ke2: Some(ke2data_to_proto(&ke2_data)),
      expected_client_mac: ke2_state.expected_client_mac.to_vec(),
      session_key: ke2_state.session_key.to_vec(),
    }))
  }

  /// RFC 9807 §6.2.6 — ServerFinish (AKE step 4 of 4).
  ///
  /// Constant-time comparison of the client-supplied KE3 MAC against the
  /// expected MAC stored from the KE2 round. Returns `{ valid: true }` iff
  /// the MACs match, completing mutual authentication and establishing the
  /// shared session key.
  async fn server_finish(&self, request: tonic::Request<proto::ServerFinishRequest>) -> Result<tonic::Response<proto::ServerFinishReply>, tonic::Status> {
    let req: proto::ServerFinishRequest = request.into_inner();

    let ke3_mac: [u8; 64] = to_64(&req.ke3_client_mac, "ke3_client_mac")?;
    let expected_mac: [u8; 64] = to_64(&req.expected_client_mac, "expected_client_mac")?;

    let valid: bool = opaque::server_finish(&ke3_mac, &expected_mac);

    Ok(tonic::Response::new(proto::ServerFinishReply { valid }))
  }

  /// RFC 9807 combined — CreateChangePasswordResponse (change-password step 2 of 4).
  ///
  /// Atomically handles two operations in one round-trip:
  /// 1. Generates KE2 for the old-password authentication flow.
  /// 2. Creates a registration response for the new blinded password.
  ///
  /// The caller must:
  /// - Persist `expected_client_mac` and `session_key` in Redis.
  /// - Wait for successful KE3 verification before storing the new record.
  /// - Only promote the new registration record to the database after
  ///   [`server_finish`] returns `true`.
  ///
  /// [`server_finish`]: Self::server_finish
  async fn create_change_password_response(
    &self,
    request: tonic::Request<proto::CreateChangePasswordResponseRequest>,
  ) -> Result<tonic::Response<proto::CreateChangePasswordResponseReply>, tonic::Status> {
    let req: proto::CreateChangePasswordResponseRequest = request.into_inner();

    let proto_record: &proto::OpaqueRecord = req.record.as_ref().ok_or_else(|| tonic::Status::invalid_argument("record missing"))?;
    let record: InternalOpaqueRecord = proto_record_to_internal(proto_record)?;

    let old_ke1: &proto::OpaqueKe1 = req.old_password_ke1.as_ref().ok_or_else(|| tonic::Status::invalid_argument("old_password_ke1 missing"))?;
    let old_ke1_data: Ke1Data = proto_ke1_to_ke1data(old_ke1)?;

    let new_reg_req: &proto::OpaqueCredentialRequest = req
      .new_password_reg_request
      .as_ref()
      .ok_or_else(|| tonic::Status::invalid_argument("new_password_reg_request missing"))?;
    let new_blinded_message: [u8; 32] = to_32(&new_reg_req.blinded_message, "new blinded_message")?;

    if req.credential_identifier.is_empty() {
      return Err(tonic::Status::invalid_argument("credential_identifier missing"));
    }

    let data: opaque::ChangePasswordData = opaque::create_change_password_response(
      &record,
      &req.credential_identifier,
      &old_ke1_data,
      &new_blinded_message,
      &self.opaque_server_private_key,
      &self.opaque_server_public_key,
      &self.opaque_seed,
      optional_identity(&req.server_identity),
      optional_identity(&req.client_identity),
    )
    .map_err(tonic::Status::from)?;

    Ok(tonic::Response::new(proto::CreateChangePasswordResponseReply {
      old_password_ke2: Some(ke2data_to_proto(&data.ke2)),
      expected_client_mac: data.state.expected_client_mac.to_vec(),
      session_key: data.state.session_key.to_vec(),
      new_evaluated_message: data.new_evaluated_message.to_vec(),
      new_server_public_key: data.new_server_public_key.to_vec(),
    }))
  }
}
