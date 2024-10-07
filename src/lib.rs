use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
use sp_core::ed25519::Pair as Ed25519Pair;
use sp_core::Pair as PairTrait;
use ssh_key::{PrivateKey, PublicKey};
use std::fs;
use blake2_rfc::blake2b::Blake2b;
use std::path::PathBuf;

pub mod types;

// Constants
pub const ASSET_HUB_SS58_PREFIX: u16 = 0; // Polkadot
pub const ASSET_HUB_POLKADOT_SPEC_URL: &str = "https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/cumulus/parachains/chain-specs/asset-hub-polkadot.json";
pub const ASSET_HUB_POLKADOT_WS_URL: &str = "wss://asset-hub-polkadot.dotters.network";
pub const PEOPLE_POLKADOT_SPEC_URL: &str = "https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/cumulus/parachains/chain-specs/people-polkadot.json";
pub const PEOPLE_POLKADOT_WS_URL: &str = "wss://people-polkadot.dotters.network";
pub const POLKADOT_WS_URL: &str = "wss://polkadot.dotters.network";
pub const POLKADOT_SPEC_URL: &str = "https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/polkadot/node/service/chain-specs/polkadot.json";

pub const ASSET_HUB_POLKADOT_SPEC_FILE: &str = "asset_hub_polkadot_spec.json";
pub const PEOPLE_POLKADOT_SPEC_FILE: &str = "people_polkadot_spec.json";
pub const POLKADOT_SPEC_FILE: &str = "polkadot_spec.json";

pub mod client {
    use super::*;
    use std::fs;
    use reqwest;
    use subxt_lightclient::{LightClient, ChainConfig, LightClientRpc, LightClientError};

    /// Downloads the chain specifications for the parachains and relay chain.
    pub fn download_specs() -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();

        // Download and save Asset Hub Polkadot spec
        let asset_hub_spec = client.get(ASSET_HUB_POLKADOT_SPEC_URL).send()?.text()?;
        fs::write(ASSET_HUB_POLKADOT_SPEC_FILE, asset_hub_spec)?;

        // Download and save People Polkadot spec
        let people_spec = client.get(PEOPLE_POLKADOT_SPEC_URL).send()?.text()?;
        fs::write(PEOPLE_POLKADOT_SPEC_FILE, people_spec)?;

        // Download and save Polkadot relay chain spec
        let polkadot_spec = client.get(POLKADOT_SPEC_URL).send()?.text()?;
        fs::write(POLKADOT_SPEC_FILE, polkadot_spec)?;

        Ok(())
    }

    /// Retrieves the chain configuration based on the chain identifier.
    pub fn get_chain_config(chain: &str) -> Result<ChainConfig, Box<dyn std::error::Error>> {
        let spec_file = match chain {
            "asset_hub" => ASSET_HUB_POLKADOT_SPEC_FILE,
            "people" => PEOPLE_POLKADOT_SPEC_FILE,
            "polkadot" => POLKADOT_SPEC_FILE,
            _ => return Err("Invalid chain specified".into()),
        };

        // Create ChainConfig from the spec file
        let chain_config = ChainConfig::chain_spec(spec_file);
        Ok(chain_config)
    }

    /// Establishes a connection to the Polkadot relay chain.
    pub fn get_relay_client() -> Result<(LightClient, LightClientRpc), Box<dyn std::error::Error>> {
        let _ws_url = POLKADOT_WS_URL;
        let spec_file = POLKADOT_SPEC_FILE;

        // Get the chain configuration for the Polkadot relay chain
        let chain_config = ChainConfig::chain_spec(spec_file);

        // Establish the relay chain connection using the LightClient::relay_chain method
        let relay_client = LightClient::relay_chain(chain_config)?;

        Ok(relay_client)
    }

    /// Establishes a connection to a parachain using an existing relay chain client.
    pub fn get_parachain_client(
        relay_client: &LightClient, 
        chain: &str
    ) -> Result<LightClientRpc, Box<dyn std::error::Error>> {
        let (_ws_url, spec_file) = match chain {
            "asset_hub" => (ASSET_HUB_POLKADOT_WS_URL, ASSET_HUB_POLKADOT_SPEC_FILE),
            "people" => (PEOPLE_POLKADOT_WS_URL, PEOPLE_POLKADOT_SPEC_FILE),
            _ => return Err("Invalid parachain specified".into()),
        };

        // Get the chain configuration for the parachain
        let chain_config = ChainConfig::chain_spec(spec_file);

        // Establish connection to the parachain using the relay chain client
        let parachain_client = relay_client.parachain(chain_config)?;

        Ok(parachain_client)
    }
}

pub mod balance {
    use super::*;
    use crate::types::AssetType;


    pub fn check_balance(identity_file: &PathBuf, token: AssetType) -> Result<(), Box<dyn std::error::Error>> {
        let identity_path = utils::expand_tilde(identity_file);
        let address = crypto::get_ss58_address(&identity_path)?;
        let balance = 0.0; // TODO: Implement balance fetching
        println!("Address: {}", address);
        println!("Balance: {} {:?}", balance, token);
        Ok(())
    }
}

pub mod transfer {
    use super::*;
    use crate::types::AssetType;

    pub fn send_assets(amount: f64, target: &str, token: AssetType, identity_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let identity_path = utils::expand_tilde(identity_file);
        let to_address = utils::resolve_address(target)?;
        let keypair = crypto::get_keypair(&identity_path)?;
        let from_address = keypair.public().to_ss58check_with_version(Ss58AddressFormat::custom(ASSET_HUB_SS58_PREFIX));

        match token {
            AssetType::Dot => {
                println!("Sending {} {:?} from {} to {}", amount, token, from_address, to_address);
                // TODO: Implement native DOT transfer using smoldot
            },
            _ => {
                let asset_id = token.clone() as u128;
                println!("Sending {} {:?} (ID: {}) from {} to {}", amount, token, asset_id, from_address, to_address);
                // TODO: Implement asset transfer using smoldot
            },
        }

        Ok(())
    }
}

pub mod export_private_key {
    use super::*;

    pub fn export(identity_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let identity_path = utils::expand_tilde(identity_file);
        
        println!("WARNING: Exporting your private key can be very dangerous and may lead to loss of funds if mishandled.");
        println!("Only proceed if you fully understand the risks and are using this for a trusted application.");
        println!("Are you sure you want to continue? (y/N)");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Export cancelled.");
            return Ok(());
        }

        let keypair = crypto::get_keypair(&identity_path)?;
        let private_key_hex = hex::encode(keypair.seed());
        println!("Private key (hex): 0x{}", private_key_hex);
        println!("IMPORTANT: Keep this key secret and secure. Do not share it with anyone.");

        Ok(())
    }
}

mod crypto {
    use super::*;

    pub fn get_ss58_address(identity_file: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
        let file_contents = fs::read_to_string(identity_file)?;
        generate_address_from_private_key(&file_contents)
    }

    pub fn get_keypair(identity_file: &PathBuf) -> Result<Ed25519Pair, Box<dyn std::error::Error>> {
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

    pub fn generate_address_from_public_key(ssh_public_key: &str) -> Result<String, Box<dyn std::error::Error>> {
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
}

mod utils {
    use super::*;

    pub fn expand_tilde(path: &PathBuf) -> PathBuf {
        if path.starts_with("~") {
            if let Some(home) = dirs::home_dir() {
                return home.join(path.strip_prefix("~").unwrap());
            }
        }
        path.to_path_buf()
    }

    pub fn resolve_address(identifier: &str) -> Result<String, Box<dyn std::error::Error>> {
        if let Some((_name, domain)) = identifier.rsplit_once('.') {
            // Domain-like matching for .dot nicknames
            match domain {
                "dot" => Err("Polkadot DNS support not implemented yet".into()),
                _ => Err("Unrecognized domain format".into()),
            }
        } else {
            // Colon-based matching for github and keybase
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
                _ => Err("Unrecognized identifier format".into()),
            }
        }
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
            if let Ok(address) = crypto::generate_address_from_public_key(public_key) {
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
}
