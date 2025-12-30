use std::env;
use tonic::{metadata::MetadataValue, service::Interceptor};

#[derive(Clone, Default)]
pub struct AuthInterceptor;

impl Interceptor for AuthInterceptor {
  fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
    let access_token: String = env::var("GRPC_ACCESS_TOKEN").expect("GRPC_ACCESS_TOKEN not set");
    let token: MetadataValue<_> = format!("Bearer {}", access_token).parse().unwrap();
    match request.metadata().get("authorization") {
      Some(value) if token == value => Ok(request),
      _ => Err(tonic::Status::unauthenticated("Unauthorized")),
    }
  }
}
