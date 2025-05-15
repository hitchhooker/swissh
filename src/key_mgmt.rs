// key_mgmt.rs
use crate::error::AppError;
//use crate::config::POLKADOT_SS58_PREFIX;
use sp_core::crypto::{AccountId32, Ss58AddressFormat, Ss58Codec};
use sp_core::ed25519::Pair as Ed25519Pair;
use sp_core::Pair as PairTrait;
use ssh_key::{PrivateKey as SshPrivateKey, PublicKey as SshPublicKey};
use std::fs;
use std::path::PathBuf;
use rpassword;

/// Loads an Ed25519 keypair from an OpenSSH private key file.
/// Handles encrypted keys by prompting for a passphrase.
pub fn load_ed25519_keypair_from_file(identity_file: &PathBuf) -> Result<Ed25519Pair, AppError> {
    let file_contents = fs::read_to_string(identity_file)
        .map_err(|e| AppError::FileSystem { path: identity_file.clone(), source: e })?;

    // add mut if decrypting
    let ssh_private_key = SshPrivateKey::from_openssh(&file_contents)?;

    if ssh_private_key.is_encrypted() {
        eprintln!("SSH key '{}' is encrypted.", identity_file.display());

         let passphrase = rpassword::prompt_password(format!("Enter passphrase for {}: ", identity_file.display()))?;
         if passphrase.is_empty() { // rpassword might return empty if user just hits enter
             return Err(AppError::KeyManagement("Passphrase entry was cancelled or empty.".to_string()));
         }

        // TODO: add pw support
        //ssh_private_key.decrypt(passphrase.as_bytes())
        //    .map_err(|e| AppError::KeyManagement(format!("Failed to decrypt key (likely incorrect passphrase): {}", e)))?;
        //eprintln!("Key decrypted successfully.");
        return Err(AppError::KeyManagement("not supported atm.".to_string()));
    }

    let ed25519_key_data = ssh_private_key
        .key_data()
        .ed25519() // This gives an ssh_key::Ed25519Keypair
        .ok_or_else(|| AppError::KeyManagement(
            "The SSH key is not an Ed25519 key, or decryption failed to reveal an Ed25519 key.".to_string()
        ))?;

    // The `private` field of ssh_key::Ed25519Keypair is the 32-byte seed.
    let seed_bytes: &[u8; 32] = ed25519_key_data.private.as_ref();
    Ed25519Pair::from_seed_slice(seed_bytes).map_err(|e| AppError::SubstrateCore(format!("{:?}", e)))
}

/// Derives an SS58 address from a Substrate Ed25519 keypair.
pub fn ss58_address_from_pair(keypair: &Ed25519Pair, ss58_prefix: u16) -> String {
    keypair.public().to_ss58check_with_version(Ss58AddressFormat::custom(ss58_prefix))
}

/// Derives an SS58 address from an OpenSSH public key string (e.g., from GitHub).
pub fn ss58_address_from_ssh_public_key_str(ssh_public_key_str: &str, ss58_prefix: u16) -> Result<String, AppError> {
    let ssh_public_key = SshPublicKey::from_openssh(ssh_public_key_str)?;

    let ed25519_public_key_data = ssh_public_key
        .key_data()
        .ed25519() // This gives an ssh_key::Ed25519PublicKey
        .ok_or_else(|| AppError::KeyManagement("The SSH public key is not an Ed25519 key.".to_string()))?;

    // use POLKADOT_SS58_PREFIX?
    let public_key_bytes: [u8; 32] = ed25519_public_key_data.0;

    let account_id = AccountId32::from(public_key_bytes);
    Ok(account_id.to_ss58check_with_version(Ss58AddressFormat::custom(ss58_prefix)))
}
