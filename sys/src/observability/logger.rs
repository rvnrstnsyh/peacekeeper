//! Structured logging system for the Rust gRPC server.
//!
//! Mirrors the Winston logger in `src/configs/logger.configs.ts`.
//!
//! # Configuration (environment variables)
//!
//! | Variable      | Values                      | Default       |
//! |---------------|-----------------------------|---------------|
//! | `NODE_ENV`    | `development` / `production`| `development` |
//! | `LOG_TO_FILE` | `true` / `false`            | `false`       |
//! | `LOG_DIR`     | directory path              | `./logs`      |
//! | `RUST_LOG`    | tracing filter directive    | level-based   |
//!
//! Default filter when `RUST_LOG` is not set:
//! - Development → `debug` (all DEBUG and above)
//! - Production  → `info`  (all INFO and above)
//!
//! # Log files (production or `LOG_TO_FILE=true`)
//!
//! | File prefix   | Content         | Winston equivalent        |
//! |---------------|-----------------|---------------------------|
//! | `application` | INFO and above  | `application-%DATE%.log`  |
//! | `error`       | ERROR only      | `error-%DATE%.log`        |
//! | `grpc`        | gRPC requests   | `http-%DATE%.log`         |
//! | `debug`       | DEBUG (dev only)| `debug-%DATE%.log`        |
//!
//! Files are named `{prefix}.{YYYY-MM-DD}` inside `LOG_DIR` (daily rotation).

use std::{env, fs};

use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_subscriber::{
  EnvFilter,
  filter::{LevelFilter, filter_fn},
  fmt,
  layer::{Layer, SubscriberExt},
  util::SubscriberInitExt,
  Registry,
};

// ─── Sensitive-field helpers ─────────────────────────────────────────────────

/// Field name substrings that are redacted in production log output.
///
/// Mirrors `SENSITIVE_KEYS` in `src/shared/constants/common.constants.ts`.
pub const SENSITIVE_KEYS: &[&str] = &["password", "token", "authorization", "cookie", "secret", "key", "seed", "private"];

/// Returns `true` if `name` contains any [`SENSITIVE_KEYS`] substring
/// (case-insensitive).
pub fn is_sensitive_field(name: &str) -> bool {
  let lower: String = name.to_lowercase();
  SENSITIVE_KEYS.iter().any(|&k| lower.contains(k))
}

/// Redact a value in production; return its debug representation in development.
///
/// Use at call sites when logging potentially sensitive data:
///
/// ```rust
/// tracing::info!(credential_id = %redact(&id), "registration complete");
/// ```
///
/// - `NODE_ENV=production` → `"[REDACTED]"`
/// - Otherwise → `"{:?}"` of the value
pub fn redact<T: std::fmt::Debug>(value: &T) -> Redacted<'_, T> {
  Redacted {
    value,
    is_production: is_production(),
  }
}

/// Wrapper returned by [`redact`]. Implements [`std::fmt::Display`].
pub struct Redacted<'a, T> {
  value: &'a T,
  is_production: bool,
}

impl<T: std::fmt::Debug> std::fmt::Display for Redacted<'_, T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if self.is_production { f.write_str("[REDACTED]") } else { write!(f, "{:?}", self.value) }
  }
}

// ─── Field visitor ────────────────────────────────────────────────────────────

/// Visits tracing event fields and collects them into a message string and a
/// JSON map of structured fields.
///
/// The special `"message"` field is stored separately; all other fields become
/// entries in the JSON map and are pretty-printed after the message text.
struct FieldCollector {
  message: String,
  fields: serde_json::Map<String, serde_json::Value>,
}

impl FieldCollector {
  fn new() -> Self {
    Self {
      message: String::new(),
      fields: serde_json::Map::new(),
    }
  }
}

impl tracing::field::Visit for FieldCollector {
  fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
    self.fields.insert(field.name().to_owned(), serde_json::json!(value));
  }

  fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
    self.fields.insert(field.name().to_owned(), serde_json::Value::Number(value.into()));
  }

  fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
    self.fields.insert(field.name().to_owned(), serde_json::Value::Number(value.into()));
  }

  fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
    self.fields.insert(field.name().to_owned(), serde_json::Value::Bool(value));
  }

  fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
    if field.name() == "message" {
      self.message = value.to_owned();
    } else {
      self.fields.insert(field.name().to_owned(), serde_json::Value::String(value.to_owned()));
    }
  }

  fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
    let s: String = format!("{value:?}");
    if field.name() == "message" {
      self.message = s;
    } else {
      self.fields.insert(field.name().to_owned(), serde_json::Value::String(s));
    }
  }

  fn record_error(&mut self, field: &tracing::field::Field, value: &(dyn std::error::Error + 'static)) {
    self.fields.insert(field.name().to_owned(), serde_json::Value::String(value.to_string()));
  }
}

// ─── NodeLikeFormatter ───────────────────────────────────────────────────────

/// Returns `(open_ansi, close_ansi)` color sequences for a tracing level.
///
/// Mirrors Winston's color map:
/// - ERROR → red    — WARN → yellow — INFO → green — DEBUG → white — TRACE → dim
fn ansi_level_color(level: &tracing::Level) -> (&'static str, &'static str) {
  match *level {
    tracing::Level::ERROR => ("\x1b[31m", "\x1b[0m"),
    tracing::Level::WARN => ("\x1b[33m", "\x1b[0m"),
    tracing::Level::INFO => ("\x1b[32m", "\x1b[0m"),
    tracing::Level::DEBUG => ("\x1b[37m", "\x1b[0m"),
    tracing::Level::TRACE => ("\x1b[2m", "\x1b[0m"),
  }
}

/// Custom `tracing-subscriber` event formatter that matches the Winston output
/// used by the Node.js layer.
///
/// # Output format
///
/// ```text
/// YYYY-MM-DD HH:MM:SS [LEVEL]: message {
///   "field": "value"
/// }
/// ```
///
/// - Timestamps are in UTC, formatted as `YYYY-MM-DD HH:MM:SS`.
/// - Level labels are uppercased and bracketed: `[INFO]`, `[DEBUG]`, …
/// - Structured fields are appended as a pretty-printed JSON object.
/// - Span context and target module paths are suppressed (like Winston).
/// - When `ansi` is `true`, level labels are colorized.
struct NodeLikeFormatter {
  ansi: bool,
}

impl<S, N> tracing_subscriber::fmt::format::FormatEvent<S, N> for NodeLikeFormatter
where
  S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
  N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
  fn format_event(&self, _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>, mut writer: tracing_subscriber::fmt::format::Writer<'_>, event: &tracing::Event<'_>) -> std::fmt::Result {
    use time::macros::format_description;

    let now: time::OffsetDateTime = time::OffsetDateTime::now_utc();
    let ts: String = now
      .format(format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"))
      .unwrap_or_else(|_| String::from("0000-00-00 00:00:00"));

    let level: &tracing::Level = event.metadata().level();
    let level_str: &str = level.as_str();

    let mut collector: FieldCollector = FieldCollector::new();
    event.record(&mut collector);

    if self.ansi {
      let (open, close) = ansi_level_color(level);
      write!(writer, "{ts} {open}[{level_str}]{close}: {}", collector.message)?;
    } else {
      write!(writer, "{ts} [{level_str}]: {}", collector.message)?;
    }

    if !collector.fields.is_empty() {
      let json: String = serde_json::to_string_pretty(&collector.fields).unwrap_or_default();
      write!(writer, " {json}")?;
    }

    writeln!(writer)
  }
}

// ─── LogGuard ────────────────────────────────────────────────────────────────

/// Guards that keep the background log-writer threads alive.
///
/// Must be held for the entire program lifetime. Dropping it flushes and
/// closes all non-blocking file writers.
///
/// ```rust
/// // In main():
/// let _log_guard = sys::observability::logger::init();
/// ```
#[allow(dead_code)] // inner Vec exists solely to keep WorkerGuards alive (RAII)
pub struct LogGuard(Vec<WorkerGuard>);

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn is_production() -> bool {
  env::var("NODE_ENV").as_deref() == Ok("production")
}

// ─── init ─────────────────────────────────────────────────────────────────────

/// Initialize the global [`tracing`] subscriber.
///
/// Sets up one or more sinks based on the environment:
///
/// | Sink                | Dev | Prod | `LOG_TO_FILE=true` |
/// |---------------------|-----|------|--------------------|
/// | Console (pretty)    | ✓   |      |                    |
/// | Console (JSON)      |     | ✓    |                    |
/// | `application.log`   |     | ✓    | ✓                  |
/// | `error.log`         |     | ✓    | ✓                  |
/// | `grpc.log`          |     | ✓    | ✓                  |
/// | `debug.log`         |     |      | ✓ (dev only)       |
///
/// # Panics
///
/// - If a global subscriber has already been set (call only once).
/// - If `LOG_DIR` cannot be created.
pub fn init() -> LogGuard {
  let prod: bool = is_production();
  let log_to_file: bool = env::var("LOG_TO_FILE").map(|v| matches!(v.as_str(), "true" | "1" | "yes")).unwrap_or(false);
  let log_dir: String = env::var("LOG_DIR").unwrap_or_else(|_| "./logs".to_string());

  let env_filter: EnvFilter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(if prod { "info" } else { "debug" }));

  let mut guards: Vec<WorkerGuard> = Vec::new();
  let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();

  // ── Console layer ─────────────────────────────────────────────────────────
  // Mirrors Winston format: "YYYY-MM-DD HH:MM:SS [LEVEL]: message { ...fields }"
  // ANSI colors enabled in development (like Winston colorize); plain text in production.
  layers.push(fmt::layer().event_format(NodeLikeFormatter { ansi: !prod }).boxed());

  // ── File layers ───────────────────────────────────────────────────────────
  if prod || log_to_file {
    fs::create_dir_all(&log_dir).unwrap_or_else(|e| panic!("Failed to create log directory '{log_dir}': {e}"));

    // application.YYYY-MM-DD — INFO and above (equiv. Winston 14-day rotate)
    {
      let (writer, guard) = tracing_appender::non_blocking(rolling::daily(&log_dir, "application"));
      guards.push(guard);
      layers.push(fmt::layer().json().with_writer(writer).with_ansi(false).with_filter(LevelFilter::INFO).boxed());
    }

    // error.YYYY-MM-DD — ERROR only (equiv. Winston 30-day rotate)
    {
      let (writer, guard) = tracing_appender::non_blocking(rolling::daily(&log_dir, "error"));
      guards.push(guard);
      layers.push(fmt::layer().json().with_writer(writer).with_ansi(false).with_filter(LevelFilter::ERROR).boxed());
    }

    // grpc.YYYY-MM-DD — gRPC request events only (equiv. Winston http 7-day rotate)
    // Captures all events emitted with target = "grpc_request".
    {
      let (writer, guard) = tracing_appender::non_blocking(rolling::daily(&log_dir, "grpc"));
      guards.push(guard);
      layers.push(
        fmt::layer()
          .json()
          .with_writer(writer)
          .with_ansi(false)
          .with_filter(filter_fn(|meta| meta.target() == "grpc_request"))
          .boxed(),
      );
    }

    // debug.YYYY-MM-DD — DEBUG, development + LOG_TO_FILE only (3-day equiv.)
    if !prod {
      let (writer, guard) = tracing_appender::non_blocking(rolling::daily(&log_dir, "debug"));
      guards.push(guard);
      layers.push(fmt::layer().json().with_writer(writer).with_ansi(false).with_filter(LevelFilter::DEBUG).boxed());
    }
  }

  // layers must be added to Registry directly (before env_filter changes the
  // subscriber type), because Vec<Box<dyn Layer<Registry>>> implements
  // Layer<Registry>, not Layer<Layered<EnvFilter, Registry>>.
  // EnvFilter is added outermost so it evaluates first.
  tracing_subscriber::registry().with(layers).with(env_filter).init();

  LogGuard(guards)
}

// ─── gRPC request logging ─────────────────────────────────────────────────────

/// Emit a structured gRPC request log event.
///
/// Analogous to `logRequest(method, path, statusCode, durationMs)` in
/// `src/configs/logger.configs.ts`. Uses `target = "grpc_request"` so the
/// dedicated `grpc.log` file appender captures it independently of the main
/// application log stream.
///
/// # Log level mapping
///
/// | gRPC status      | Level | Analogous HTTP |
/// |------------------|-------|----------------|
/// | `0`  (OK)        | INFO  | 2xx            |
/// | `1–12, 16`       | WARN  | 4xx            |
/// | `13–15`          | ERROR | 5xx            |
///
/// # Arguments
///
/// * `service`     — Fully-qualified service name (e.g. `"v0.ZeroAccess"`).
/// * `method`      — RPC method name (e.g. `"GenerateKE2"`).
/// * `status`      — gRPC status code (0 = OK, 13 = INTERNAL, …).
/// * `duration_ms` — Request duration in milliseconds.
///
/// # Equivalent TypeScript
///
/// ```ts
/// logRequest(method, path, statusCode, durationMs)
/// ```
pub fn log_grpc_request(service: &str, method: &str, status: u32, duration_ms: f64) {
  match status {
    0 => tracing::info!(
      target: "grpc_request",
      grpc_service = service,
      grpc_method = method,
      grpc_status = status,
      duration_ms = duration_ms,
      "gRPC request"
    ),
    13 | 14 | 15 => tracing::error!(
      target: "grpc_request",
      grpc_service = service,
      grpc_method = method,
      grpc_status = status,
      duration_ms = duration_ms,
      "gRPC request"
    ),
    _ => tracing::warn!(
      target: "grpc_request",
      grpc_service = service,
      grpc_method = method,
      grpc_status = status,
      duration_ms = duration_ms,
      "gRPC request"
    ),
  }
}
