use std::net::SocketAddr;

use tokio::signal;
use anyhow::Result;
use tonic::transport::Server;

use crate::transport::grpc::{proto, services::public::PublicService, services::zero_access::ZeroAccessService, interceptors::authentication::AuthInterceptor};

async fn shutdown() {
  #[cfg(unix)]
  {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm: signal::unix::Signal = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = signal::ctrl_c() => {
            tracing::info!("received Ctrl+C");
        }
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM");
        }
    }
  }

  #[cfg(not(unix))]
  {
    signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    tracing::info!("received Ctrl+C");
  }
}

pub async fn listen(address: SocketAddr) -> Result<()> {
  let common_service: PublicService = PublicService::default();
  let zero_access_service: ZeroAccessService = ZeroAccessService::new().expect("OPAQUE server keys must be set (OPAQUE_SERVER_PRIVATE_KEY, OPAQUE_SERVER_PUBLIC_KEY, OPAQUE_SEED)");

  tracing::info!("gRPC server listening on {}", address);

  Server::builder()
    .add_service(
      tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()?,
    )
    .add_service(proto::public_server::PublicServer::with_interceptor(common_service, AuthInterceptor))
    .add_service(proto::zero_access_server::ZeroAccessServer::with_interceptor(zero_access_service, AuthInterceptor))
    .serve_with_shutdown(address, shutdown())
    .await?;

  tracing::info!("gRPC server shutdown complete");

  return Ok(());
}
