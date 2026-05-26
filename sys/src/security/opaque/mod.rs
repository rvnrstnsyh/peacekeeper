//! OPAQUE: An Asymmetric Password-Authenticated Key Exchange Protocol
//!
//! Server-side implementation of [RFC 9807] — the OPAQUE asymmetric PAKE
//! protocol — using the **ristretto255-SHA512** ciphersuite.
//!
//! # Ciphersuite
//!
//! | Primitive     | Algorithm                    | RFC         |
//! |---------------|------------------------------|-------------|
//! | Group         | ristretto255                 | [RFC 9496]  |
//! | Hash          | SHA-512                      | FIPS 180-4  |
//! | KSF           | Argon2id                     | [RFC 9106]  |
//! | KDF           | HKDF-SHA512                  | [RFC 5869]  |
//! | MAC           | HMAC-SHA512                  | [RFC 2104]  |
//! | KE            | X25519 with 3DH              | [RFC 7748]  |
//!
//! Mode: **Base** (no mutual auth extension) with **internal** envelope key mode.
//!
//! # Protocol Overview
//!
//! ```text
//!                Registration Phase                  Authentication (AKE) Phase
//!
//!   CLIENT                    SERVER         CLIENT                    SERVER
//!   (password)            (parameters)    (password)        (parameters + record)
//!   ─────────────────────────────────     ──────────────────────────────────────
//!       ──── REG Request ────>                  ──── KE1 (blinded pw) ────>
//!       <─── REG Response ───                   <─── KE2 (masked env) ────
//!       ──── REG Record ─────>                  ──── KE3 (client MAC) ────>
//!   ─────────────────────────────────     ──────────────────────────────────────
//!   exportKey             record          (exportKey, sessionKey)   sessionKey
//! ```
//!
//! The **server** only participates in:
//! - Registration step 2: [`create_registration_response`]
//! - AKE step 2: [`generate_ke2`]
//! - AKE step 4: [`server_finish`]
//! - Combined change-password: [`create_change_password_response`]
//!
//! All client-side OPAQUE operations (blind, finalize, generateKE1, generateKE3)
//! remain in TypeScript (`src/shared/utils/zero-access.utils/`).
//!
//! # Module Layout
//!
//! | Module        | Contents                                      |
//! |---------------|-----------------------------------------------|
//! | [`config`]    | Protocol constants (Nh, Nn, Nm …), DST, context |
//! | [`primitives`]| Low-level crypto: hash-to-group, scalar ops   |
//! | [`helpers`]   | HKDF, key derivation, OPRF, preamble building |
//! | [`protocol`]  | Top-level server-side protocol functions      |
//! | [`errors`]    | [`OpaqueError`] type + gRPC mapping           |
//!
//! # Security Notes
//!
//! - **No protocol details are ever leaked to the client.** All `OpaqueError`
//!   variants map to a generic `tonic::Status::internal` (see [`errors`]).
//! - DH private keys and OPRF seeds are wrapped in [`zeroize::Zeroizing`] or
//!   zeroed on `drop` where they persist in memory.
//! - All MACs use constant-time comparison ([`server_finish`]).
//!
//! [RFC 9807]: https://datatracker.ietf.org/doc/html/rfc9807
//! [RFC 9496]: https://datatracker.ietf.org/doc/html/rfc9496
//! [RFC 9106]: https://datatracker.ietf.org/doc/html/rfc9106
//! [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869
//! [RFC 2104]: https://datatracker.ietf.org/doc/html/rfc2104
//! [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748

pub mod config;
pub mod errors;
pub mod helpers;
pub mod primitives;
pub mod protocol;

pub use errors::OpaqueError;
pub use helpers::OpaqueRecord;
pub use protocol::{create_change_password_response, create_registration_response, generate_ke2, server_finish, ChangePasswordData, Ke1Data, Ke2Data, Ke2State};
