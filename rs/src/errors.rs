/// Error types mirroring the Python exception hierarchy.
/// All custom errors derive from BlockChainError.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockChainError {
    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Block validation failed: {0}")]
    BlockValidation(String),

    #[error("Block difficulty too low")]
    BlockDifficulty,

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Duplicate transaction input: {0}")]
    TransactionDuplicateInput(String),

    #[error("Transaction validation failed: {0}")]
    TransactionValidation(String),

    #[error("Index integrity error: {0}")]
    IndexIntegrity(String),

    #[error("Database integrity error: {0}")]
    DbIntegrity(String),

    #[error("Key validation error: {0}")]
    KeyValidation(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, BlockChainError>;
