// Declare modules
pub mod error;
pub mod config;
pub mod types;
pub mod key_mgmt;
pub mod resolver;
pub mod chain;
pub mod ops;

// Re-export the primary error type for convenience
pub use error::AppError;

// Re-export public functions that the CLI (main.rs) will use
pub use ops::balance::check_and_print_balance;
pub use ops::transfer::create_and_send_transfer;
pub use ops::export::export_hex_private_key_interactive;
// If main.rs needs to manage client lifecycle, you might re-export init functions from client.
