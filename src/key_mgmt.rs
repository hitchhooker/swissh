// key_mgmt.rs
use crate::error::AppError; // Use the refined AppError
use keyring::Entry;
use sp_core::crypto::{AccountId32, Ss58AddressFormat, Ss58Codec};
use sp_core::ed25519::Pair as Ed25519Pair;
use sp_core::Pair as PairTrait;
use ssh_key::{Algorithm, PrivateKey as SshPrivateKey, PublicKey as SshPublicKey};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use rpassword;

const KEYRING_SERVICE_NAME: &str = "swissh-keys";

/// Creates a standardized error for keyring operations, mapping to `AppError::KeyManagement`.
fn map_keyring_error(e: keyring::Error, operation: &str, key_name: &str) -> AppError {
    AppError::KeyManagement(format!(
        "Keyring operation '{}' failed for key '{}': {}",
        operation, key_name, e
    ))
}

/// Prompts the user for a passphrase once, without offering to store it.
fn prompt_passphrase_once(key_path_display: &str) -> Result<String, AppError> {
    eprintln!("SSH key '{}' is encrypted.", key_path_display);
    let prompt_message = format!("Enter passphrase for {}: ", key_path_display);

    let passphrase = rpassword::prompt_password(prompt_message).map_err(|e| {
        AppError::UserInput(format!("Failed to read passphrase for '{}': {}", key_path_display, e))
    })?;

    if passphrase.is_empty() {
        // Using a more specific error variant if user cancels or enters nothing.
        Err(AppError::UserCancelled) // Or AppError::UserInput("Passphrase entry was empty.".to_string())
    } else {
        Ok(passphrase)
    }
}

/// Prompts for a passphrase and, if provided, asks the user if they want to store it in the keyring.
fn prompt_and_potentially_store_passphrase(entry: &Entry, key_path_display: &str) -> Result<String, AppError> {
    let passphrase = prompt_passphrase_once(key_path_display)?;

    eprint!("Store passphrase in system keyring for '{}'? (y/N): ", key_path_display);
    io::stdout().flush()?; // Uses #[from] std::io::Error -> AppError::Io

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?; // Uses #[from] std::io::Error -> AppError::Io

    if choice.trim().eq_ignore_ascii_case("y") {
        match entry.set_password(&passphrase) {
            Ok(_) => eprintln!("Passphrase stored in system keyring for {}.", key_path_display),
            Err(e) => {
                eprintln!("{}", map_keyring_error(e, "set_password", key_path_display));
            }
        }
    }
    Ok(passphrase)
}

/// Obtains a passphrase for an encrypted key.
fn obtain_passphrase_for_key(entry: &Entry, key_path_display: &str) -> Result<String, AppError> {
    match entry.get_password() {
        Ok(pass) => {
            eprintln!("Using stored passphrase for {}", key_path_display);
            Ok(pass)
        }
        Err(keyring::Error::NoEntry) => {
            prompt_and_potentially_store_passphrase(entry, key_path_display)
        }
        Err(e) => {
            eprintln!(
                "Keyring error when retrieving passphrase for {}: {}. Will prompt without offering to store.",
                key_path_display, e
            );
            // map_keyring_error could be used here too if consistent formatting is desired for the eprintln
            prompt_passphrase_once(key_path_display)
        }
    }
}

/// Loads an Ed25519 keypair from an OpenSSH private key file using only Rust libraries.
pub fn load_ed25519_keypair_from_file(identity_file: &PathBuf) -> Result<Ed25519Pair, AppError> {
    let file_contents = fs::read_to_string(identity_file)
        .map_err(|e| AppError::FileSystem { path: identity_file.clone(), source: e })?; // Explicitly use FileSystem for path context

    let key_path_display = identity_file.to_string_lossy();
    let keyring_entry = Entry::new(KEYRING_SERVICE_NAME, &key_path_display)
        .map_err(|e| map_keyring_error(e, "access keyring for", &key_path_display))?;

    match SshPrivateKey::from_openssh(&file_contents) { // Uses #[from] ssh_key::Error -> AppError::SshKey via ?
        Ok(ssh_private_key) => {
            if ssh_private_key.is_encrypted() {
                let passphrase = obtain_passphrase_for_key(&keyring_entry, &key_path_display)?;
                // Uses #[from] ssh_key::Error -> AppError::SshKey via ?
                let decrypted_key = ssh_private_key.decrypt(passphrase.as_bytes())?; 
                
                eprintln!("Key '{}' decrypted successfully using internal library method.", key_path_display);
                extract_ed25519_keypair(&decrypted_key)

            } else {
                extract_ed25519_keypair(&ssh_private_key)
            }
        }
        // If SshPrivateKey::from_openssh returns Err(e), `e` is ssh_key::Error.
        // The `?` operator would have converted it via `AppError::SshKey(#[from] ssh_key::Error)`.
        // So, if we reach the Err arm here, it means the previous line's `?` has already propagated the AppError::SshKey.
        // The original code's `match SshPrivateKey::from_openssh()` was designed to handle the error *itself*
        // to then apply custom logic (like checking `file_contents.contains(...)`).
        // To keep that custom logic, we should not use `?` on `from_openssh` directly if we want to inspect its specific error.
        Err(ssh_err) => { // ssh_err is ssh_key::Error
            if file_contents.contains("ENCRYPTED PRIVATE KEY") || (file_contents.contains("Proc-Type: 4,ENCRYPTED") && file_contents.contains("BEGIN EC PRIVATE KEY")) {
                // Here, ssh_err is the original parsing error from ssh-key crate.
                // We are creating a new, more specific AppError::KeyManagement error.
                Err(AppError::KeyManagement(format!(
                    "Failed to parse SSH key '{}'. Original error: '{}'. The key appears to be encrypted in a format not directly supported by the application's internal Rust libraries. Please convert the key to a modern OpenSSH format or ensure it's an unencrypted key if this issue persists.",
                    key_path_display, ssh_err 
                )))
            } else {
                // Convert the original ssh_key::Error into our AppError::SshKey variant
                Err(AppError::SshKey(ssh_err))
            }
        }
    }
}

/// Helper function to extract an Ed25519Pair from an `ssh_key::PrivateKey`.
fn extract_ed25519_keypair(ssh_private_key: &SshPrivateKey) -> Result<Ed25519Pair, AppError> {
    if ssh_private_key.is_encrypted() {
        return Err(AppError::KeyManagement( // Specific logic error
            "Internal error: extract_ed25519_keypair called with an encrypted key.".to_string(),
        ));
    }

    if ssh_private_key.algorithm() != Algorithm::Ed25519 {
        return Err(AppError::KeyManagement(format!( // Specific logic error
            "The SSH key is not an Ed25519 key. Detected algorithm: {:?}.",
            ssh_private_key.algorithm()
        )));
    }

    let key_data = ssh_private_key.key_data();
    let ed25519_key_data = key_data.ed25519().ok_or_else(|| {
        AppError::KeyManagement( // Specific logic error
            "Failed to extract Ed25519 data from key, despite algorithm match.".to_string(),
        )
    })?;

    // sp_core::crypto::PairError doesn't have a #[from] in AppError.
    Ed25519Pair::from_seed_slice(ed25519_key_data.private.as_ref())
        .map_err(|e| AppError::SubstrateCore(format!("Failed to create Ed25519 pair from seed: {:?}", e)))
}

/// Derives an SS58 address from a Substrate Ed25519 keypair.
pub fn ss58_address_from_pair(keypair: &Ed25519Pair, ss58_prefix: u16) -> String {
    keypair
        .public()
        .to_ss58check_with_version(Ss58AddressFormat::custom(ss58_prefix))
}

/// Derives an SS58 address from an OpenSSH public key string.
pub fn ss58_address_from_ssh_public_key_str(
    ssh_public_key_str: &str,
    ss58_prefix: u16,
) -> Result<String, AppError> {
    let ssh_public_key = SshPublicKey::from_openssh(ssh_public_key_str)?; // Uses #[from] ssh_key::Error -> AppError::SshKey

    if ssh_public_key.algorithm() != Algorithm::Ed25519 {
        return Err(AppError::KeyManagement(format!( // Specific logic error
            "The SSH public key is not an Ed25519 key. Detected algorithm: {:?}.",
            ssh_public_key.algorithm()
        )));
    }

    let ed25519_public_key_data = ssh_public_key.key_data().ed25519().ok_or_else(|| {
        AppError::KeyManagement("Failed to extract Ed25519 data from public key.".to_string()) // Specific logic error
    })?;

    let account_id = AccountId32::from(ed25519_public_key_data.0);
    Ok(account_id.to_ss58check_with_version(Ss58AddressFormat::custom(ss58_prefix)))
}
