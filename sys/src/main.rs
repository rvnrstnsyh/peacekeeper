#![allow(clippy::needless_return, clippy::match_single_binding)]

use std::{env, path::PathBuf};

use anyhow::Result;
use dotenvy::from_path;

use sys::observability::logger;
use sys::transport::grpc::server;

#[tokio::main]
async fn main() -> Result<()> {
  // Load .env before logger init so NODE_ENV / LOG_DIR / LOG_TO_FILE are set.
  from_path(PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("..").join(".env")).expect("Failed to load .env");

  // Keep the guard alive for the entire process lifetime — dropping it would
  // flush and close all background file-writer threads.
  let _log_guard: logger::LogGuard = logger::init();

  let hostname: String = env::var("GRPC_HOSTNAME").expect("GRPC_HOSTNAME not set");
  let port: String = env::var("GRPC_PORT").expect("GRPC_PORT not set");
  let address: String = format!("{}:{}", hostname, port);

  server::listen(address.parse()?).await
}
