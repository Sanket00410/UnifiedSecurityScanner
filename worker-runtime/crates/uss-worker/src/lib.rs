pub mod adapter;
pub mod executors;

pub mod proto {
    tonic::include_proto!("uss.worker.v1");
}
