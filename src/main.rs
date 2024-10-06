// main.rs
mod cli;
use cli::{Cli, Commands};
use clap::Parser;
use swissh::balance;
use swissh::transfer;
use swissh::export_private_key;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Balance { identity_file, asset_type } => {
            balance::check_balance(&identity_file, asset_type)
        },
        Commands::Transfer { amount, target, asset_type, identity_file } => {
            transfer::send_assets(amount, &target, asset_type, &identity_file)
        },
        Commands::ExportPrivateKey { identity_file } => {
            export_private_key::export(&identity_file)
        },
    }
}
