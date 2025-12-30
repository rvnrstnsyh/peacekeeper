use tokio::sync::{RwLock, RwLockWriteGuard};

use crate::transport::grpc::proto;

type State = std::sync::Arc<RwLock<u64>>;

#[derive(Debug, Default)]
pub struct PublicService {
  state: State,
}

impl PublicService {
  async fn increment_counter(&self) {
    let mut count: RwLockWriteGuard<'_, u64> = self.state.write().await;
    *count += 1;
  }
}

#[tonic::async_trait]
impl proto::public_server::Public for PublicService {
  async fn health(&self, request: tonic::Request<proto::HealthRequest>) -> Result<tonic::Response<proto::HealthResponse>, tonic::Status> {
    self.increment_counter().await;

    let input: &proto::HealthRequest = request.get_ref();

    tracing::info!("HealthRequest {}", serde_json::to_string_pretty(input).unwrap());

    let response: proto::HealthResponse = proto::HealthResponse {
      payload: input.payload.clone(),
      data: "gRPC Gateway".to_string(),
    };

    return Ok(tonic::Response::new(response));
  }
}
