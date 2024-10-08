// main.rs
mod cli;
use cli::{Cli, Commands};
use clap::Parser;
use swissh::{balance, transfer, export_private_key, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Create the Client instance
    let client = Client::new().await?;

    match cli.command {
        Commands::Balance { identity_file, token } => {
            balance::check_balance(&client, &identity_file, token).await?
        },
        Commands::Transfer { amount, target, token, identity_file } => {
            transfer::send_assets(&client, amount, &target, token, &identity_file).await?
        },
        Commands::ExportPrivateKey { identity_file } => {
            export_private_key::export(&identity_file)?
        },
    }
    Ok(())
}
