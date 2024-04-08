use thiserror::Error;
/// Represents an error in key aggregation, signing, or verification.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ZkSchnorrError {
    /// This error occurs when a verification key is not valid
    #[error("Signature verification failed")]
    InvalidSignature,

    /// This error occurs when a set of signatures failed to verify as a batch
    #[error("Batch signature verification failed")]
    InvalidBatch,
}
