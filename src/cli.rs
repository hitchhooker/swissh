// src/cli.rs
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use swissh::types::AssetType;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Show the SS58 address and balance of the SSH identity
    Balance {
        /// Path to the SSH identity file
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,

        /// The type of asset to check
        #[arg(short = 't', long = "asset-type", default_value = "DOT")]
        token: AssetType,
    },

    /// Transfer assets to a target address
    Transfer {
        /// The amount of assets to transfer
        amount: f64,

        /// The target address or identifier (e.g., SS58 address, gh:username, nickname.dot)
        target: String,

        /// The type of asset to transfer
        #[arg(short = 't', long = "asset-type", default_value = "DOT")]
        token: AssetType,

        /// Path to the SSH identity file for signing the transaction
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,
    },

    /// Export the private key from the specified SSH identity
    ExportPrivateKey {
        /// Path to the SSH identity file
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,
    },
}
