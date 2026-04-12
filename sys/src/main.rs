#![allow(clippy::needless_return, clippy::match_single_binding)]

use std::{env, path::PathBuf};

use anyhow::Result;
use dotenvy::from_path;

use sys::transport::grpc::server;

#[tokio::main]
async fn main() -> Result<()> {
  tracing_subscriber::fmt::init();

  from_path(PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("..").join(".env")).expect("Failed to load .env");

  let hostname: String = env::var("GRPC_HOSTNAME").expect("GRPC_HOSTNAME not set");
  let port: String = env::var("GRPC_PORT").expect("GRPC_PORT not set");
  let address: String = format!("{}:{}", hostname, port);

  server::listen(address.parse()?).await
}
