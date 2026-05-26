/// OPAQUE protocol error types.
///
/// Internal errors are logged server-side and mapped to a generic
/// `tonic::Status::internal` to avoid leaking protocol details to clients.
#[derive(Debug)]
pub enum OpaqueError {
  /// Key or element has wrong byte length.
  InvalidLength { context: &'static str, expected: usize, got: usize },
  /// X25519 public key is a low-order point (small subgroup attack).
  LowOrderPoint,
  /// Cryptographic element is the identity (neutral) element.
  IdentityElement,
  /// ristretto255 element failed to decompress or is otherwise invalid.
  InvalidElement(String),
  /// OPAQUE envelope fields have invalid lengths.
  InvalidEnvelope(String),
  /// A derived scalar is zero (exceptionally rare; indicates broken RNG or impl bug).
  ZeroScalar(&'static str),
  /// X25519 Diffie-Hellman produced an all-zero shared secret.
  ZeroSharedSecret,
  /// HKDF-Expand failed (output length exceeds 255 * HashLen).
  HkdfExpand,
  /// Generic invalid input.
  InvalidInput(String),
}

impl std::fmt::Display for OpaqueError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::InvalidLength { context, expected, got } => {
        write!(f, "Invalid {context} length: expected {expected}, got {got}")
      }
      Self::LowOrderPoint => write!(f, "Invalid X25519 public key: low-order point"),
      Self::IdentityElement => write!(f, "Cryptographic identity element not allowed"),
      Self::InvalidElement(msg) => write!(f, "Invalid ristretto255 element: {msg}"),
      Self::InvalidEnvelope(msg) => write!(f, "Invalid OPAQUE envelope: {msg}"),
      Self::ZeroScalar(ctx) => write!(f, "Zero scalar produced in {ctx}"),
      Self::ZeroSharedSecret => write!(f, "DH produced all-zero shared secret"),
      Self::HkdfExpand => write!(f, "HKDF-Expand failed"),
      Self::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
    }
  }
}

impl std::error::Error for OpaqueError {}

/// Map any `OpaqueError` to a generic gRPC internal status.
///
/// Logs the original error server-side but returns "internal error" to the
/// caller to prevent leaking protocol or key information.
impl From<OpaqueError> for tonic::Status {
  fn from(err: OpaqueError) -> tonic::Status {
    tracing::error!(error = %err, "OPAQUE operation failed");
    tonic::Status::internal("internal error")
  }
}
