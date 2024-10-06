use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
use sp_core::ed25519::Pair as Ed25519Pair;
use sp_core::Pair as PairTrait;
use ssh_key::{PrivateKey, PublicKey};
use std::fs;
use blake2_rfc::blake2b::Blake2b;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

const ASSET_HUB_SS58_PREFIX: u16 = 0; // Polkadot

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "upper")]
enum AssetType {
    Dot, // native
    Ibtc = 1986,
    Rnet = 181,
    Usdc = 1337,
    Usdt = 1984,
}

#[derive(Subcommand)]
enum Commands {
    /// Show the SS58 address and balance of the SSH identity
    Balance {
        /// Path to the SSH identity file (default: ~/.ssh/id_ed25519)
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,

        /// The type of asset to check (default: DOT)
        #[arg(short = 't', long = "asset-type", default_value = "DOT")]
        asset_type: AssetType,
    },

    /// Transfer assets to a target address
    Transfer {
        /// The amount of assets to transfer
        amount: f64, // -> amount: u128,

        /// The target address or identifier (e.g., SS58 address, gh:username)
        target: String,

        /// The type of asset to transfer (default: DOT)
        #[arg(short = 't', long = "asset-type", default_value = "DOT")]
        asset_type: AssetType,

        /// Path to the SSH identity file for signing the transaction (default: ~/.ssh/id_ed25519)
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,
    },

    /// Export the private key from the specified SSH identity
    ExportPrivateKey {
        /// Path to the SSH identity file (default: ~/.ssh/id_ed25519)
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Balance { identity_file, asset_type } => {
            let identity_path = expand_tilde(identity_file);
            let address = get_ss58_address(&identity_path)?;
            let balance = 0.0; // TODO: Implement balance fetching
            println!("Address: {}", address);
            println!("Balance: {} {:?}", balance, asset_type);
        },
        Commands::Transfer { amount, target, asset_type, identity_file } => {
            let identity_path = expand_tilde(identity_file);
            let to_address = resolve_address(target)?;
            let keypair = get_keypair(&identity_path)?;
            let from_address = keypair.public().to_ss58check_with_version(Ss58AddressFormat::custom(ASSET_HUB_SS58_PREFIX));

            match asset_type {
                AssetType::Dot => {
                    println!("Sending {} DOT from {} to {}", amount, from_address, to_address);
                    // TODO: Implement native DOT transfer using smoldot
                },
                _ => {
                    let asset_id = asset_type.clone() as u128;
                    println!("Sending {} {:?} (ID: {}) from {} to {}", amount, asset_type, asset_id, from_address, to_address);
                    // TODO: Implement asset transfer using smoldot
                },
            }
        },
        Commands::ExportPrivateKey { identity_file } => {
            let identity_path = expand_tilde(identity_file);
            export_private_key(&identity_path)?;
        },
    }

    Ok(())
}

fn expand_tilde(path: &PathBuf) -> PathBuf {
    if path.starts_with("~") {
        if let Some(home) = dirs::home_dir() {
            return home.join(path.strip_prefix("~").unwrap());
        }
    }
    path.to_path_buf()
}

fn resolve_address(identifier: &str) -> Result<String, Box<dyn std::error::Error>> {
    match identifier.split(':').collect::<Vec<&str>>().as_slice() {
        ["gh", username] => {
            let addresses = fetch_github_ss58_addresses(username)?;
            if addresses.is_empty() {
                Err("No valid SS58 addresses found for this GitHub user".into())
            } else if addresses.len() == 1 {
                Ok(addresses[0].clone())
            } else {
                select_key_by_index(&addresses)
            }
        },
        ["kb", _username] => Err("Keybase support not implemented yet".into()),
        ["dot", _name] => Err("Polkadot DNS support not implemented yet".into()),
        _ => Ok(identifier.to_string()), // TODO: dont assume it's already an SS58 address
    }
}

fn get_ss58_address(identity_file: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let file_contents = fs::read_to_string(identity_file)?;
    generate_address_from_private_key(&file_contents)
}

fn get_keypair(identity_file: &PathBuf) -> Result<Ed25519Pair, Box<dyn std::error::Error>> {
    let file_contents = fs::read_to_string(identity_file)?;
    let private_key = PrivateKey::from_openssh(&file_contents)?;
    let ed25519_keypair = private_key
        .key_data()
        .ed25519()
        .ok_or("The provided key is not an Ed25519 key")?;
    let secret_bytes: &[u8; 32] = ed25519_keypair.private.as_ref();
    Ok(Ed25519Pair::from_seed_slice(secret_bytes)?)
}

fn generate_address_from_private_key(ssh_private_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let private_key = PrivateKey::from_openssh(ssh_private_key)?;
    let ed25519_keypair = private_key
        .key_data()
        .ed25519()
        .ok_or("The provided key is not an Ed25519 key")?;
    let secret_bytes: &[u8; 32] = ed25519_keypair.private.as_ref();
    let pair = Ed25519Pair::from_seed_slice(secret_bytes)?;
    Ok(pair.public().to_ss58check_with_version(Ss58AddressFormat::custom(ASSET_HUB_SS58_PREFIX)))
}

fn generate_address_from_public_key(ssh_public_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let public_key = PublicKey::from_openssh(ssh_public_key)?;
    let ed25519_public = public_key
        .key_data()
        .ed25519()
        .ok_or("The provided key is not an Ed25519 key")?;
    
    let public_key_bytes = ed25519_public.as_ref();
    let mut address = vec![ASSET_HUB_SS58_PREFIX as u8];
    address.extend_from_slice(public_key_bytes);
    let mut hasher = Blake2b::new(64);
    hasher.update(b"SS58PRE");
    hasher.update(&address);
    let checksum = hasher.finalize();
    address.extend_from_slice(&checksum.as_bytes()[0..2]);
    Ok(bs58::encode(address).into_string())
}

fn fetch_github_ss58_addresses(username: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://github.com/{}.keys", username);
    let response = reqwest::blocking::get(&url)?.text()?;
    let public_keys: Vec<&str> = response.lines().collect();
    
    if public_keys.is_empty() {
        return Err("No SSH keys found".into());
    }

    let mut addresses = Vec::new();
    for public_key in public_keys {
        if let Ok(address) = generate_address_from_public_key(public_key) {
            addresses.push(address);
        }
    }

    if addresses.is_empty() {
        return Err("No valid Ed25519 keys found".into());
    }

    Ok(addresses)
}

fn select_key_by_index(addresses: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    println!("Multiple keys found. Please select a key by entering its index:");
    for (i, address) in addresses.iter().enumerate() {
        println!("[{}] {}", i, address);
    }

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let index: usize = input.trim().parse()?;

    addresses.get(index).cloned().ok_or_else(|| "Invalid index".into())
}

fn export_private_key(identity_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("WARNING: Exporting your private key can be very dangerous and may lead to loss of funds if mishandled.");
    println!("Only proceed if you fully understand the risks and are using this for a trusted application.");
    println!("Are you sure you want to continue? (y/N)");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() != "y" {
        println!("Export cancelled.");
        return Ok(());
    }

    let keypair = get_keypair(identity_file)?;
    let private_key_hex = hex::encode(keypair.seed());
    println!("Private key (hex): 0x{}", private_key_hex);
    println!("IMPORTANT: Keep this key secret and secure. Do not share it with anyone.");

    Ok(())
}
