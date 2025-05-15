use crate::error::AppError;
use crate::key_mgmt::load_ed25519_keypair_from_file;
use crate::resolver::expand_tilde_to_home;
use std::path::PathBuf;
use std::io::{self, Write};

pub fn export_hex_private_key_interactive(identity_file: &PathBuf) -> Result<(), AppError> {
    let expanded_id_path = expand_tilde_to_home(identity_file);

    eprintln!("WARNING: Exporting your private key is extremely dangerous and may lead to a total loss of funds if mishandled.");
    eprintln!("Only proceed if you absolutely understand the risks and are using this for a trusted, secure application.");
    eprint!("Are you sure you want to export the private key? (y/N): ");
    io::stderr().flush().map_err(AppError::Io)?;

    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation).map_err(AppError::Io)?;
    if confirmation.trim().to_lowercase() != "y" {
        println!("Private key export cancelled by user.");
        return Err(AppError::UserCancelled);
    }

    let keypair = load_ed25519_keypair_from_file(&expanded_id_path)?;
    let private_key_seed_hex = hex::encode(keypair.seed()); // .seed() gives the 32-byte private key (seed)

    println!("Private Key (Hex Encoded Seed): 0x{}", private_key_seed_hex);
    eprintln!("CRITICAL: Keep this key absolutely secret and secure. Do not share it with anyone or store it insecurely.");

    Ok(())
}
