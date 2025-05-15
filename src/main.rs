// main.rs
mod cli; // Your existing CLI module

use clap::Parser;
use cli::{Cli, Commands}; // Assuming Cli and Commands are pub in cli.rs

// Import the functions and error type from your refactored swissh library
use swissh::{
    check_and_print_balance,
    create_and_send_transfer,
    export_hex_private_key_interactive,
    AppError, // Using the specific error type from your library
};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli_args = Cli::parse();

    match cli_args.command {
        Commands::Balance { identity_file, token } => {
            // `check_and_print_balance` is now async
            check_and_print_balance(&identity_file, token).await
        }
        Commands::Transfer { amount, target, token, identity_file } => {
            // `create_and_send_transfer` is now async
            // `amount` is already f64 from clap, matching the function signature
            create_and_send_transfer(&identity_file, amount, &target, token).await
        }
        Commands::Export { identity_file } => {
            export_hex_private_key_interactive(&identity_file)
        }
    }
}
