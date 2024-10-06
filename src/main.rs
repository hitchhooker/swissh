use clap::{Parser, Subcommand};
use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
use sp_core::ed25519::Pair as Ed25519Pair;
use sp_core::Pair as PairTrait;
use ssh_key::{PrivateKey, PublicKey};
use std::fs;
use std::path::PathBuf;
use blake2_rfc::blake2b::Blake2b;

const ASSET_HUB_SS58_PREFIX: u16 = 0; // Polkadot

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ShowAddress {
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,
    },
    SendMoney {
        #[arg(short = 'f', long = "from")]
        from: String,
        #[arg(short = 't', long = "to")]
        to: String,
        #[arg(short = 'a', long = "amount")]
        amount: u128,
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,
    },
    FetchKey {
        #[arg(short = 'u', long = "user")]
        user: String,
    },
    ExportPrivateKey {
        #[arg(short = 'i', long = "identity", default_value = "~/.ssh/id_ed25519")]
        identity_file: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::ShowAddress { identity_file } => {
            let identity_path = expand_tilde(identity_file);
            let address = get_ss58_address(&identity_path)?;
            println!("SS58 Address: {}", address);
        },
        Commands::SendMoney { from, to, amount, identity_file } => {
            let identity_path = expand_tilde(identity_file);
            let from_address = resolve_address(from)?;
            let to_address = resolve_address(to)?;
            let keypair = get_keypair(&identity_path)?;
            
            if keypair.public().to_ss58check_with_version(Ss58AddressFormat::custom(ASSET_HUB_SS58_PREFIX)) != from_address {
                return Err("The provided identity does not match the 'from' address".into());
            }
            
            println!("Sending {} from {} to {}", amount, from_address, to_address);
            // TODO: Implement actual money sending logic using smoldot
        },
        Commands::FetchKey { user } => {
            match user.split(':').collect::<Vec<&str>>().as_slice() {
                ["gh", username] => {
                    let addresses = fetch_github_ss58_addresses(username)?;
                    if addresses.len() == 1 {
                        println!("SS58 Address: {}", addresses[0]);
                    } else {
                        let selected_address = select_key_by_index(&addresses)?;
                        println!("Selected SS58 Address: {}", selected_address);
                    }
                },
                ["kb", _username] => return Err("Keybase support not implemented yet".into()),
                ["dot", _name] => return Err("Polkadot DNS support not implemented yet".into()),
                _ => {
                    let address = resolve_address(user)?;
                    println!("SS58 Address: {}", address);
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

// TODO: Implement smoldot integration for blockchain interactions
#[allow(dead_code)]
mod smoldot_integration {

    pub fn initialize_client() -> Result<(), Box<dyn std::error::Error>> {
        // TODO: init smoldot
        unimplemented!()
    }

    pub fn send_transaction(_from: &str, _to: &str, _amount: u128) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: send transaction using smoldot
        // author.submitExtrinsic(signed_call_data)
        unimplemented!()
    }

    pub fn get_balance(_address: &str) -> Result<u128, Box<dyn std::error::Error>> {
        // TODO: get balance using smoldot
        unimplemented!()
    }
}
