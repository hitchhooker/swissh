use clap::Parser;
use sp_core::crypto::{Ss58AddressFormatRegistry, Ss58Codec};
use sp_core::ed25519::Pair as Ed25519Pair;
use sp_core::Pair as PairTrait;
use ssh_key::{PrivateKey, PublicKey};
use std::fs;
use blake2_rfc::blake2b::Blake2b;
use bs58;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Selects a file from which the identity (private key) is read
    #[arg(short = 'i', long = "identity_file")]
    identity_file: Option<String>,

    /// Specify a public key file
    #[arg(short = 'p', long = "public_key_file")]
    public_key_file: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let address = if let Some(public_key_file) = args.public_key_file {
        let file_contents = fs::read_to_string(&public_key_file)?;
        generate_address_from_public_key(&file_contents)?
    } else if let Some(identity_file) = args.identity_file {
        let file_contents = fs::read_to_string(&identity_file)?;
        generate_address_from_private_key(&file_contents)?
    } else {
        return Err("Please provide either a private key file (-i) or a public key file (-p)".into());
    };

    println!("Polkadot address: {}", address);
    Ok(())
}

fn generate_address_from_private_key(ssh_private_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let private_key = PrivateKey::from_openssh(ssh_private_key)?;
    let ed25519_keypair = private_key
        .key_data()
        .ed25519()
        .ok_or("The provided key is not an Ed25519 key")?;
    let secret_bytes: &[u8; 32] = ed25519_keypair.private.as_ref();
    println!("Private key (hex): {:?}", hex::encode(secret_bytes));
    let pair = Ed25519Pair::from_seed_slice(secret_bytes)?;
    Ok(pair
        .public()
        .to_ss58check_with_version(Ss58AddressFormatRegistry::PolkadotAccount.into()))
}

fn generate_address_from_public_key(ssh_public_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let public_key = PublicKey::from_openssh(ssh_public_key)?;
    let ed25519_public = public_key
        .key_data()
        .ed25519()
        .ok_or("The provided key is not an Ed25519 key")?;
    
    let public_key_bytes = ed25519_public.as_ref();
    let network_id: u8 = 0;
    let mut address = vec![network_id];
    address.extend_from_slice(public_key_bytes);
    let mut hasher = Blake2b::new(64);
    hasher.update(b"SS58PRE");
    hasher.update(&address);
    let checksum = hasher.finalize();
    address.extend_from_slice(&checksum.as_bytes()[0..2]);
    Ok(bs58::encode(address).into_string())
}
