use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error), // handles generic I/O errors

    #[error("Filesystem error for path {path:?}: {source}")]
    FileSystem {
        path: PathBuf,
        #[source]
        source: std::io::Error, // specific to file operations where path is known
    },

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON processing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("SSH key processing error: {0}")]
    SshKey(#[from] ssh_key::Error),

    #[error("Substrate core error: {0}")]
    SubstrateCore(String), // for Substrate-specific logic errors

    #[error("Hex processing error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("Base58 processing error: {0}")]
    Bs58(#[from] bs58::decode::Error),

    #[error("Key management error: {0}")]
    KeyManagement(String), // for errors from keyring or general key logic

    #[error("Address resolution failed: {0}")]
    AddressResolution(String),

    #[error("User input error: {0}")]
    UserInput(String), // for issues like empty passphrase, invalid choices

    #[error("Failed to parse integer: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("Light client error: {0}")]
    LightClient(String),

    #[error("Chain interaction error: {0}")]
    ChainInteraction(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Operation cancelled by user")]
    UserCancelled, // if user explicitly cancels an operation

    #[error("Feature not yet implemented: {0}")]
    NotImplemented(String),

    #[error("Invalid amount specified: {0}")]
    InvalidAmount(String),
}

// Helper for sp_core::crypto::SecretStringError (this is good)
impl From<sp_core::crypto::SecretStringError> for AppError {
    fn from(e: sp_core::crypto::SecretStringError) -> Self {
        // Providing more context in the message
        AppError::SubstrateCore(format!("Secret string handling error: {:?}", e))
    }
}
