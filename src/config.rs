use std::path::PathBuf;
use crate::error::AppError;

// Default SS58 prefix for generic Polkadot ecosystem addresses
pub const POLKADOT_SS58_PREFIX: u16 = 0;

pub struct ChainMetadata {
    pub name: &'static str,
    pub spec_url: &'static str,
    pub ws_url: &'static str,
    pub spec_filename: &'static str,
    pub default_ss58_prefix: u16,
}

impl ChainMetadata {
    /// Provides a suggested path for this chain's light client database
    /// relative to a base light client DB directory.
    pub fn light_client_db_path(&self, base_light_client_db_dir: &PathBuf) -> PathBuf {
        base_light_client_db_dir.join(self.name)
    }
}

pub const POLKADOT_RELAY_CHAIN: ChainMetadata = ChainMetadata {
    name: "polkadot_relay",
    spec_url: "https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/polkadot/node/service/chain-specs/polkadot.json",
    ws_url: "wss://rpc.polkadot.io", // Official Polkadot RPC
    spec_filename: "polkadot_spec.json",
    default_ss58_prefix: POLKADOT_SS58_PREFIX,
};

pub const ASSET_HUB_POLKADOT_CHAIN: ChainMetadata = ChainMetadata {
    name: "asset_hub_polkadot",
    spec_url: "https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/cumulus/parachains/chain-specs/asset-hub-polkadot.json",
    ws_url: "wss://polkadot-asset-hub-rpc.polkadot.io", // Official Asset Hub RPC
    spec_filename: "asset_hub_polkadot_spec.json",
    default_ss58_prefix: POLKADOT_SS58_PREFIX, // Uses Polkadot's prefix for accounts
};

pub const PEOPLE_POLKADOT_CHAIN: ChainMetadata = ChainMetadata {
    name: "people_polkadot",
    spec_url: "https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/cumulus/parachains/chain-specs/people-polkadot.json",
    ws_url: "wss://people-polkadot.dotters.network", // Keep if this is preferred; official might exist
    spec_filename: "people_polkadot_spec.json",
    default_ss58_prefix: POLKADOT_SS58_PREFIX,
};

// Application-specific data directories
fn get_app_base_data_dir() -> Result<PathBuf, AppError> {
    dirs::data_dir()
        .map(|p| p.join("swissh"))
        .ok_or_else(|| AppError::Configuration("Failed to determine application data directory.".to_string()))
}

pub fn get_chain_specs_cache_dir() -> Result<PathBuf, AppError> {
    get_app_base_data_dir().map(|p| p.join("chain-specs-cache"))
}

pub fn get_light_client_db_dir() -> Result<PathBuf, AppError> {
    get_app_base_data_dir().map(|p| p.join("light-client-databases"))
}
