use crate::error::AppError;
use crate::key_mgmt::ss58_address_from_ssh_public_key_str;
use crate::config::POLKADOT_SS58_PREFIX; // Default prefix for GitHub keys for now
use std::path::PathBuf;
use std::io::{self, Write};
use sp_core::crypto::AccountId32; // For SS58 validation
use sp_core::crypto::Ss58Codec;


/// Expands a tilde (~) in a path to the user's home directory.
pub fn expand_tilde_to_home(path: &PathBuf) -> PathBuf {
    if path.starts_with("~") {
        if let Some(home_dir) = dirs::home_dir() {
            if let Ok(stripped_path) = path.strip_prefix("~") {
                return home_dir.join(stripped_path);
            }
        }
    }
    path.to_path_buf()
}

/// Resolves an identifier (like gh:username, .dot name, or direct SS58) to an SS58 address.
/// Prompts for selection if multiple GitHub keys are found.
pub fn resolve_target_address_interactive(identifier: &str) -> Result<String, AppError> {
    if let Some((_name, domain)) = identifier.rsplit_once('.') {
        match domain.to_lowercase().as_str() {
            "dot" => Err(AppError::NotImplemented("Polkadot Name System (.dot) resolution not implemented yet.".to_string())),
            _ => Err(AppError::AddressResolution(format!("Unrecognized domain format in identifier: '{}'", identifier))),
        }
    } else if let Some(github_username) = identifier.strip_prefix("gh:") {
        if github_username.is_empty() {
            return Err(AppError::AddressResolution("GitHub username cannot be empty for 'gh:' identifier.".to_string()));
        }
        let addresses = fetch_ss58_addresses_for_github_user(github_username)?;
        if addresses.is_empty() {
            Err(AppError::AddressResolution(format!("No valid Ed25519 SSH keys found for GitHub user '{}'", github_username)))
        } else if addresses.len() == 1 {
            Ok(addresses[0].clone())
        } else {
            eprintln!("Multiple SS58-compatible Ed25519 keys found for GitHub user '{}'. Please select one:", github_username);
            select_address_by_index_interactive(&addresses)
        }
    } else if let Some(_keybase_username) = identifier.strip_prefix("kb:") {
        Err(AppError::NotImplemented("Keybase (kb:) resolution not implemented yet.".to_string()))
    } else {
        // Assume it's a direct SS58 address; validate it.
        if AccountId32::from_ss58check(identifier).is_ok() {
            Ok(identifier.to_string())
        } else {
            Err(AppError::AddressResolution(format!(
                "'{}' is not a recognized identifier format (e.g., gh:user, user.dot) nor a valid SS58 address.",
                identifier
            )))
        }
    }
}

fn fetch_ss58_addresses_for_github_user(username: &str) -> Result<Vec<String>, AppError> {
    let url = format!("https://github.com/{}.keys", username);
    // Using blocking reqwest here as per original code. For a fully async lib, this would change.
    let response_text = reqwest::blocking::get(&url)?.text()?;

    let mut ss58_addresses = Vec::new();
    for line in response_text.lines() {
        // Basic filter for Ed25519 keys, which are the only ones we can convert.
        if line.starts_with("ssh-ed25519 ") {
            match ss58_address_from_ssh_public_key_str(line, POLKADOT_SS58_PREFIX) {
                Ok(address) => ss58_addresses.push(address),
                Err(AppError::KeyManagement(_)) => { /* Key was not Ed25519 or other conversion issue, ignore */ },
                Err(e) => return Err(e), // Propagate other errors
            }
        }
    }
    Ok(ss58_addresses)
}

fn select_address_by_index_interactive(addresses: &[String]) -> Result<String, AppError> {
    for (i, address) in addresses.iter().enumerate() {
        eprintln!("[{}] {}", i, address);
    }
    eprint!("Select key by index: ");
    io::stderr().flush().map_err(AppError::Io)?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(AppError::Io)?;

    let index: usize = input.trim().parse().map_err(|e| AppError::UserInput(format!("Invalid index format: {}", e)))?;

    addresses.get(index).cloned().ok_or_else(|| AppError::UserInput("Selected index is out of bounds.".to_string()))
}
