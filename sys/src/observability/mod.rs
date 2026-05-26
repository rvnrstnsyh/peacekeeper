//! Observability utilities for the gRPC server.
//!
//! Currently exposes the [`logger`] module, which mirrors the Winston
//! logger from `src/configs/logger.configs.ts`.

pub mod logger;

pub use logger::{LogGuard, Redacted, SENSITIVE_KEYS, init, is_sensitive_field, log_grpc_request, redact};
