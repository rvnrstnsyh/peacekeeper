use crate::transport::grpc::proto;

#[derive(Debug, Default)]
pub struct ZeroAccessService {
  //
}

impl ZeroAccessService {
  //
}

#[tonic::async_trait]
impl proto::zero_access_server::ZeroAccess for ZeroAccessService {
  //
}
